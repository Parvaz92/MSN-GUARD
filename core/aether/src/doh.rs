//! DNS-over-HTTPS — RFC 8484 — HTTP/1.1 (Aether DohWire style).
//!
//! Only active when the user writes a `https://` entry. Uses the same stack
//! egress as DoT and plain UDP. Body is POST `application/dns-message` over
//! HTTP/1.1 on a pooled TLS connection — no h2. Matches Aether's
//! SmartDnsTransport.DohWire (HTTP/1.1, length-prefixed / chunked framing,
//! keep-alive pooling).

use crate::error::{AetherError, Result};
use crate::netstack::StackHandle;
use crate::stackstream::StackStream;

use std::sync::Mutex;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_BODY_BYTES: usize = 65_535;
const MAX_HEAD_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct DohServer {
    pub addr: std::net::SocketAddr,
    pub host: String,
    pub path: String,
}

impl DohServer {
    pub fn parse(entry: &str) -> Option<Self> {
        let rest = entry.strip_prefix("https://")?;
        let rest = rest.trim();
        if rest.is_empty() {
            return None;
        }
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a.trim(), format!("/{}", p.trim())),
            None => (rest, "/dns-query".to_string()),
        };
        if authority.is_empty() {
            return None;
        }
        let (host_part, port) = if let Some(rest) = authority.strip_prefix('[') {
            let (h, r) = rest.split_once(']')?;
            let port = r.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            (h.trim(), port)
        } else if authority.matches(':').count() > 1 {
            (authority, None)
        } else {
            match authority.split_once(':') {
                Some((h, p)) => (h.trim(), p.trim().parse::<u16>().ok()),
                None => (authority, None),
            }
        };
        if host_part.is_empty() {
            return None;
        }
        match host_part.parse::<std::net::IpAddr>() {
            Ok(ip) => Some(DohServer {
                addr: std::net::SocketAddr::new(ip, port.unwrap_or(443)),
                host: host_part.to_string(),
                path,
            }),
            Err(_) => {
                if host_part.contains('.') && !host_part.contains(' ') {
                    Some(DohServer {
                        addr: std::net::SocketAddr::new("0.0.0.0".parse().unwrap(), port.unwrap_or(443)),
                        host: host_part.to_string(),
                        path,
                    })
                } else {
                    None
                }
            }
        }
    }
}

pub async fn resolve_a(stack: &StackHandle, server: &DohServer, name: &str) -> Result<std::net::IpAddr> {
    let addr = if server.addr.ip().to_string() == "0.0.0.0" {
        let before = Instant::now();
        let ip = match resolve_hostname(stack, &server.host).await {
            Ok(ip) => {
                let ms = before.elapsed().as_millis();
                if ms > 1500 {
                    log::info!("doh: hostname {} -> {ip} ({ms}ms) — resolving {name}", server.host);
                }
                ip
            }
            Err(e) => {
                log::warn!(
                    "doh: hostname {} failed ({ms}ms): {e} — resolving {name}",
                    server.host,
                    ms = before.elapsed().as_millis()
                );
                return Err(e);
            }
        };
        std::net::SocketAddr::new(ip, server.addr.port())
    } else {
        server.addr
    };
    let key = pool_key(addr, &server.host, &server.path);

    // Reuse an idle pooled TLS connection; on failure open a fresh one.
    if let Some(conn) = crate::dnspool::acquire(&key).await {
        match query_doh(conn, server, name).await {
            Ok(ip) => return Ok(ip),
            Err(e) => log::debug!("doh: pooled connection unusable, reopening: {e}"),
        }
    }

    let stream = StackStream::open(stack, addr).await?;
    let tls = crate::tls::connect_doh(&server.host, stream).await?;
    let conn = crate::dnspool::install_doh(key, tls);
    query_doh(conn, server, name).await
}

/// Pool key for a DoH resolver: the *resolved* address, the host and the path.
fn pool_key(addr: std::net::SocketAddr, host: &str, path: &str) -> String {
    format!("doh|{addr}|https://{host}{path}")
}

/// Run one A lookup over a pooled (or freshly installed) HTTP/1.1 TLS connection.
async fn query_doh(
    mut conn: crate::dnspool::PooledConn,
    server: &DohServer,
    name: &str,
) -> Result<std::net::IpAddr> {
    let (query, id) = crate::socks::build_dns_query_public(name, crate::socks::QTYPE_A);
    let outcome = exchange_doh(&mut conn, server, &query, id, name).await;
    if outcome.is_ok() {
        crate::dnspool::release(conn);
    }
    outcome
}

async fn exchange_doh(
    conn: &mut crate::dnspool::PooledConn,
    server: &DohServer,
    query: &[u8],
    id: u16,
    name: &str,
) -> Result<std::net::IpAddr> {
    let tls = conn.doh();
    let path = if server.path.is_empty() { "/dns-query" } else { &server.path };
    let host_hdr = if server.addr.port() == 443 {
        server.host.clone()
    } else {
        format!("{}:{}", server.host, server.addr.port())
    };
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: Aether\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        query.len()
    );
    tls.write_all(head.as_bytes()).await.map_err(map_io)?;
    tls.write_all(query).await.map_err(map_io)?;
    tls.flush().await.map_err(map_io)?;

    let body = read_http_response_body(tls).await?;
    if body.len() < 12 {
        return Err(AetherError::Other("doh: reply too short".into()));
    }
    // RFC 8484: server may answer with id 0 — restore the query's id before matching.
    let mut buf = body;
    buf[0] = query[0];
    buf[1] = query[1];
    if !crate::socks::dns_response_matches_public(&buf, id, name, crate::socks::QTYPE_A) {
        return Err(AetherError::Other("doh: reply did not match the query".into()));
    }
    crate::socks::parse_dns_a_public(&buf)
        .ok_or_else(|| AetherError::Other("doh: no A record in reply".into()))
}

async fn read_http_response_body(tls: &mut tokio_boring::SslStream<StackStream>) -> Result<Vec<u8>> {
    // Read status line + headers without over-reading (pooled connection).
    let mut head = Vec::with_capacity(4096);
    let mut matched: usize = 0;
    let mut byte = [0u8; 1];
    while head.len() < MAX_HEAD_BYTES {
        tls.read_exact(&mut byte).await.map_err(map_io)?;
        head.push(byte[0]);
        matched = match byte[0] {
            b'\r' if matched == 0 || matched == 2 => matched + 1,
            b'\n' if matched == 1 || matched == 3 => matched + 1,
            b'\r' => 1,
            _ => 0,
        };
        if matched == 4 {
            break;
        }
    }
    if matched != 4 {
        return Err(AetherError::Other("doh: incomplete HTTP headers".into()));
    }
    let head_str = String::from_utf8_lossy(&head).to_string();
    let (status, content_length, chunked, close) = parse_head(&head_str)
        .ok_or_else(|| AetherError::Other("doh: bad HTTP head".into()))?;
    if !(200..300).contains(&status) {
        return Err(AetherError::Other(format!("doh: HTTP {status}")));
    }
    let body = if chunked {
        read_chunked(tls).await?
    } else if let Some(len) = content_length {
        if len > MAX_BODY_BYTES {
            return Err(AetherError::Other("doh: body too large".into()));
        }
        let mut buf = vec![0u8; len];
        if len > 0 {
            tls.read_exact(&mut buf).await.map_err(map_io)?;
        }
        buf
    } else {
        // No length and not chunked: read to close (rare for DoH).
        // For pooled keep-alive this path means !close wasn't signaled; treat as error.
        if close {
            let mut out = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                match tls.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if out.len() + n > MAX_BODY_BYTES {
                            return Err(AetherError::Other("doh: body too large".into()));
                        }
                        out.extend_from_slice(&tmp[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(map_io(e)),
                }
            }
            out
        } else {
            return Err(AetherError::Other("doh: no content-length and not chunked".into()));
        }
    };
    // For keep-alive pooling, caller decides reuse; body already consumed.
    let _ = close;
    Ok(body)
}

fn parse_head(text: &str) -> Option<(u16, Option<usize>, bool, bool)> {
    let lines: Vec<&str> = text.split("\r\n").filter(|s| !s.is_empty()).collect();
    let status_line = lines.first()?;
    let parts: Vec<&str> = status_line.split(' ').collect();
    if parts.len() < 2 || !parts[0].starts_with("HTTP/") {
        return None;
    }
    let status: u16 = parts[1].parse().ok()?;
    let mut length: Option<usize> = None;
    let mut chunked = false;
    let mut close = parts[0] == "HTTP/1.0";
    for line in lines.iter().skip(1) {
        let Some(colon) = line.find(':') else { continue };
        let name = line[..colon].trim().to_ascii_lowercase();
        let value = line[colon + 1..].trim().to_ascii_lowercase();
        match name.as_str() {
            "content-length" => length = value.parse().ok(),
            "transfer-encoding" => chunked = value.contains("chunked"),
            "connection" => {
                if value.contains("close") { close = true; }
                if value.contains("keep-alive") { close = false; }
            }
            _ => {}
        }
    }
    Some((status, length, chunked, close))
}

async fn read_chunked(tls: &mut tokio_boring::SslStream<StackStream>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line = read_line(tls).await?.ok_or_else(|| AetherError::Other("doh: chunk size missing".into()))?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| AetherError::Other("doh: bad chunk size".into()))?;
        if size == 0 {
            // consume trailers
            for _ in 0..32 {
                let t = read_line(tls).await?.ok_or_else(|| AetherError::Other("doh: chunk trailer missing".into()))?;
                if t.is_empty() { break; }
            }
            break;
        }
        if out.len() + size > MAX_BODY_BYTES {
            return Err(AetherError::Other("doh: body too large".into()));
        }
        let mut chunk = vec![0u8; size];
        tls.read_exact(&mut chunk).await.map_err(map_io)?;
        out.extend_from_slice(&chunk);
        // trailing CRLF after chunk
        let mut crlf = [0u8; 2];
        tls.read_exact(&mut crlf).await.map_err(map_io)?;
        if crlf != [b'\r', b'\n'] {
            // tolerate bare LF
            if crlf[1] != b'\n' {
                return Err(AetherError::Other("doh: bad chunk terminator".into()));
            }
        }
    }
    Ok(out)
}

async fn read_line(tls: &mut tokio_boring::SslStream<StackStream>) -> Result<Option<String>> {
    let mut s = Vec::new();
    let mut byte = [0u8; 1];
    while s.len() < 4096 {
        match tls.read(&mut byte).await {
            Ok(0) => return Ok(None),
            Ok(_) => {
                if byte[0] == b'\n' {
                    if s.last() == Some(&b'\r') { s.pop(); }
                    return Ok(Some(String::from_utf8_lossy(&s).to_string()));
                }
                s.push(byte[0]);
            }
            Err(e) => return Err(map_io(e)),
        }
    }
    Ok(None)
}

fn map_io(e: std::io::Error) -> AetherError {
    AetherError::Other(format!("doh: {e}"))
}

async fn resolve_hostname(stack: &StackHandle, host: &str) -> Result<std::net::IpAddr> {
    if let Some(ip) = cached_hostname(host) {
        log::debug!("doh: hostname {host} hit {ip} (cache)");
        return Ok(ip);
    }
    let udp = stack.open_udp().await?;
    let (sender, mut rx) = udp.into_split();
    let r = crate::socks::dns_exchange_doh_hostname(&sender, &mut rx, host).await;
    sender.close().await;
    if let Ok(ip) = r {
        remember_hostname(host, ip);
    }
    r
}

fn hostname_cache() -> &'static Mutex<std::collections::HashMap<String, (std::net::IpAddr, Instant)>> {
    use std::sync::OnceLock;
    static C: OnceLock<Mutex<std::collections::HashMap<String, (std::net::IpAddr, Instant)>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn cached_hostname(host: &str) -> Option<std::net::IpAddr> {
    let now = Instant::now();
    hostname_cache()
        .lock()
        .ok()
        .and_then(|m| m.get(host).filter(|(_, exp)| *exp > now).map(|(ip, _)| *ip))
}

fn remember_hostname(host: &str, ip: std::net::IpAddr) {
    let _ = hostname_cache().lock().map(|mut m| {
        if m.len() > 32 {
            m.clear();
        }
        m.insert(host.to_string(), (ip, Instant::now() + CACHE_TTL));
    });
}

const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const BACKOFF: std::time::Duration = std::time::Duration::from_secs(30);

fn answer_cache() -> &'static Mutex<std::collections::HashMap<String, (std::net::IpAddr, Instant)>> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Mutex<std::collections::HashMap<String, (std::net::IpAddr, Instant)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

pub(crate) fn cached_answer(server: &DohServer, name: &str) -> Option<std::net::IpAddr> {
    let now = Instant::now();
    answer_cache()
        .lock()
        .ok()
        .and_then(|map| {
            map.get(&format!("{}|{name}", server.host))
                .filter(|(_, exp)| *exp > now)
                .map(|(ip, _)| *ip)
        })
}

pub(crate) fn remember_answer(server: &DohServer, name: &str, ip: std::net::IpAddr) {
    use std::collections::HashMap;
    let _ = answer_cache().lock().map(|mut map| {
        if map.len() > 512 {
            map.clear();
        }
        map.insert(
            format!("{}|{name}", server.host),
            (ip, Instant::now() + CACHE_TTL),
        );
        let _: &HashMap<String, (std::net::IpAddr, Instant)> = &map;
    });
}

fn backoff_state() -> &'static Mutex<std::collections::HashMap<String, Instant>> {
    use std::sync::OnceLock;
    static STATE: OnceLock<Mutex<std::collections::HashMap<String, Instant>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn backoff_key(server: &DohServer) -> String {
    if server.addr.ip().to_string() == "0.0.0.0" {
        format!("{}|{}", server.host, server.path)
    } else {
        format!("{}|{}", server.addr, server.path)
    }
}

pub(crate) fn is_backing_off(server: &DohServer) -> bool {
    let now = Instant::now();
    let key = backoff_key(server);
    backoff_state()
        .lock()
        .map(|map| map.get(&key).is_some_and(|until| *until > now))
        .unwrap_or(false)
}

pub(crate) fn mark_failure(server: &DohServer) {
    let _ = backoff_state()
        .lock()
        .map(|mut map| map.insert(backoff_key(server), Instant::now() + BACKOFF));
}

pub(crate) fn doh_servers() -> Vec<DohServer> {
    let configured = std::env::var("AETHER_DNS").unwrap_or_default();
    let mut out = Vec::new();
    for token in configured.split([',', ' ', ';']) {
        if let Some(server) = DohServer::parse(token) {
            let key = (server.host.as_str(), server.path.as_str());
            if !out.iter().any(|s: &DohServer| (s.host.as_str(), s.path.as_str()) == key) {
                out.push(server);
            }
        }
    }
    out
}
