//! DNS-over-TLS — RFC 7858.
//!
//! Only active when the user writes a `tls://` entry in the DNS field.
//! Plain UDP stays the default. Every connection goes through the tunnel
//! stack so an Iran-only resolver behind a foreign edge is still reachable.

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{AetherError, Result};
use crate::netstack::StackHandle;
use crate::stackstream::StackStream;

#[derive(Clone, Debug)]
pub struct DotServer {
    pub addr: SocketAddr,
    pub sni: String,
}

impl DotServer {
    pub fn parse(entry: &str) -> Option<Self> {
        let rest = entry
            .strip_prefix("tls://")
            .or_else(|| entry.strip_prefix("dot://"))?;
        let rest = rest.trim();
        if rest.is_empty() {
            return None;
        }
        let (host_part, sni) = match rest.split_once('#') {
            Some((h, s)) => (h.trim(), s.trim().to_string()),
            None => (rest, String::new()),
        };
        if host_part.is_empty() {
            return None;
        }
        if let Ok(a) = host_part.parse::<SocketAddr>() {
            let sni = if sni.is_empty() { a.ip().to_string() } else { sni };
            return Some(DotServer { addr: a, sni });
        }
        if let Ok(ip) = host_part.parse::<std::net::IpAddr>() {
            let addr = SocketAddr::new(ip, 853);
            let sni = if sni.is_empty() { addr.ip().to_string() } else { sni };
            return Some(DotServer { addr, sni });
        }
        if host_part.contains('.') && !host_part.contains(' ') {
            let sni_host = if sni.is_empty() { host_part.to_string() } else { sni };
            let (h, p) = match host_part.rsplit_once(':') {
                Some((hh, pp)) if pp.parse::<u16>().is_ok() => (hh, pp.parse().unwrap()),
                _ => (host_part, 853),
            };
            let _ = h;
            let addr = SocketAddr::new("0.0.0.0".parse().unwrap(), p);
            return Some(DotServer { addr, sni: sni_host });
        }
        None
    }

    fn is_hostname_placeholder(&self) -> bool {
        self.addr.ip().to_string() == "0.0.0.0"
    }
}

pub async fn resolve_a(stack: &StackHandle, server: &DotServer, name: &str) -> Result<std::net::IpAddr> {
    let (addr, sni) = if server.is_hostname_placeholder() {
        let ip = resolve_hostname(stack, &server.sni).await?;
        (SocketAddr::new(ip, server.addr.port()), server.sni.clone())
    } else {
        (server.addr, server.sni.clone())
    };
    let stream = StackStream::open(stack, addr).await?;
    let (query, id) = crate::socks::build_dns_query_public(name, crate::socks::QTYPE_A);
    let mut tls = crate::tls::connect_dot(&sni, stream).await?;
    let len = (query.len() as u16).to_be_bytes();
    tls.write_all(&len).await.map_err(map_io)?;
    tls.write_all(&query).await.map_err(map_io)?;
    tls.flush().await.map_err(map_io)?;
    let mut hdr = [0u8; 2];
    tls.read_exact(&mut hdr).await.map_err(map_io)?;
    let reply_len = u16::from_be_bytes(hdr) as usize;
    if reply_len < 12 {
        return Err(AetherError::Other("dot: reply too short".into()));
    }
    let mut buf = vec![0u8; reply_len];
    tls.read_exact(&mut buf).await.map_err(map_io)?;
    let _ = tls.flush().await;
    if !crate::socks::dns_response_matches_public(&buf, id, name, crate::socks::QTYPE_A) {
        return Err(AetherError::Other("dot: reply did not match the query".into()));
    }
    crate::socks::parse_dns_a_public(&buf)
        .ok_or_else(|| AetherError::Other("dot: no A record in reply".into()))
}

pub(crate) fn dot_servers() -> Vec<DotServer> {
    let configured = std::env::var("AETHER_DNS").unwrap_or_default();
    let mut out = Vec::new();
    for token in configured.split([',', ' ', ';']) {
        if let Some(server) = DotServer::parse(token) {
            if !out.iter().any(|s: &DotServer| s.addr == server.addr && s.sni == server.sni) {
                out.push(server);
            }
        }
    }
    out
}

fn map_io(e: io::Error) -> AetherError {
    AetherError::Other(format!("dot: {e}"))
}

async fn resolve_hostname(stack: &StackHandle, host: &str) -> Result<std::net::IpAddr> {
    let udp = stack.open_udp().await?;
    let (sender, mut rx) = udp.into_split();
    let r = crate::socks::dns_exchange_public(&sender, &mut rx, host).await;
    sender.close().await;
    r
}

const BACKOFF: std::time::Duration = std::time::Duration::from_secs(30);

fn backoff_state() -> &'static Mutex<std::collections::HashMap<String, Instant>> {
    use std::sync::OnceLock;
    static STATE: OnceLock<Mutex<std::collections::HashMap<String, Instant>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn backoff_key(server: &DotServer) -> String {
    if server.addr.ip().to_string() == "0.0.0.0" {
        format!("{}:{}", server.sni, server.addr.port())
    } else {
        server.addr.to_string()
    }
}

pub(crate) fn is_backing_off(server: &DotServer) -> bool {
    let now = Instant::now();
    let key = backoff_key(server);
    backoff_state()
        .lock()
        .map(|m| m.get(&key).is_some_and(|until| *until > now))
        .unwrap_or(false)
}

pub(crate) fn mark_failure(server: &DotServer) {
    let _ = backoff_state()
        .lock()
        .map(|mut m| m.insert(backoff_key(server), Instant::now() + BACKOFF));
}
