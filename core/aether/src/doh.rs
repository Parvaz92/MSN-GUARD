//! DNS-over-HTTPS — RFC 8484.
//!
//! Only active when the user writes a `https://` entry. Uses the same stack
//! egress as DoT and plain UDP. Body is POST `application/dns-message` over h2.

use crate::error::{AetherError, Result};
use crate::netstack::StackHandle;
use crate::stackstream::StackStream;

use std::sync::Mutex;
use std::time::Instant;

const H2_MAX_FRAME_SIZE: u32 = 64 * 1024;

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
    let started = Instant::now();
    let addr = if server.addr.ip().to_string() == "0.0.0.0" {
        let before = Instant::now();
        let ip = match resolve_hostname(stack, &server.host).await {
            Ok(ip) => {
                let ms = before.elapsed().as_millis();
                if ms > 1500 {
                    log::info!("doh: hostname {} → {ip} ({ms}ms) — resolving {name}", server.host);
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
    let stream = StackStream::open(stack, addr).await?;
    if started.elapsed() > std::time::Duration::from_millis(2500) {
        log::info!(
            "doh: slow setup {host} ({ms}ms) — resolving {name}",
            host = server.host,
            ms = started.elapsed().as_millis()
        );
    }
    let (query, id) = crate::socks::build_dns_query_public(name, crate::socks::QTYPE_A);
    let tls = crate::tls::connect_doh(&server.host, stream).await?;
    let (h2_send, h2_conn) = h2::client::Builder::new()
        .initial_window_size(crate::sysprofile::h2_stream_window_bytes())
        .initial_connection_window_size(crate::sysprofile::h2_connection_window_bytes())
        .max_frame_size(H2_MAX_FRAME_SIZE)
        .handshake(tls)
        .await
        .map_err(|e| AetherError::Other(format!("doh: h2 handshake: {e}")))?;
    let drive = tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            log::debug!("doh h2 connection ended: {e}");
        }
    });
    let mut h2_send = h2_send
        .ready()
        .await
        .map_err(|e| AetherError::Other(format!("doh: h2 ready: {e}")))?;
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("https://{}{}", server.host, server.path))
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .header("user-agent", "MSN-Guard/1.0")
        .body(())
        .map_err(|e| AetherError::Other(format!("doh: build request: {e}")))?;
    let (resp_fut, mut send_stream) = h2_send
        .send_request(request, false)
        .map_err(|e| AetherError::Other(format!("doh: send request: {e}")))?;
    send_stream
        .send_data(bytes::Bytes::from(query), true)
        .map_err(|e| AetherError::Other(format!("doh: send body: {e}")))?;
    let response = resp_fut
        .await
        .map_err(|e| AetherError::Other(format!("doh: no response: {e}")))?;
    if !response.status().is_success() {
        drive.abort();
        return Err(AetherError::Other(format!(
            "doh: {} returned status {}",
            server.host,
            response.status().as_u16()
        )));
    }
    let mut body = response.into_body();
    let mut buf = Vec::new();
    while let Some(frame) = body.data().await {
        let frame = frame.map_err(|e| AetherError::Other(format!("doh: read body: {e}")))?;
        buf.extend_from_slice(&frame);
        if buf.len() > 65535 {
            break;
        }
    }
    let _ = drive.await;
    if buf.len() < 12 {
        return Err(AetherError::Other("doh: reply too short".into()));
    }
    if !crate::socks::dns_response_matches_public(&buf, id, name, crate::socks::QTYPE_A) {
        return Err(AetherError::Other("doh: reply did not match the query".into()));
    }
    crate::socks::parse_dns_a_public(&buf)
        .ok_or_else(|| AetherError::Other("doh: no A record in reply".into()))
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
