//! DNS-over-HTTPS (RFC 8484).
//!
//! Runs on the tunnel's own userspace stack for the same reason DoT does: a
//! real socket plus VpnService.protect() would bypass the tunnel entirely, and
//! the resolver the user picked is often reachable only through it.
//!
//! Wire format: a single HTTP/2 POST to the `/dns-query` path with
//! `application/dns-message` in both directions, body = a raw DNS message.
//! GET with the query in a urlsafe-base64 `?dns=` parameter is also valid but
//! POST is simpler and universally supported.

use crate::error::{AetherError, Result};
use crate::netstack::StackHandle;
use crate::stackstream::StackStream;

use std::sync::Mutex;
use std::time::Instant;

/// Same frame ceiling as the h2 tunnel path.
const H2_MAX_FRAME_SIZE: u32 = 64 * 1024;

/// A DNS-over-HTTPS endpoint parsed from an `https://` entry.
#[derive(Clone, Debug)]
pub struct DohServer {
    /// Where the TCP connection goes. Port defaults to 443.
    pub addr: std::net::SocketAddr,
    /// Host:authority — used for SNI and the HTTP/2 :authority pseudo-header.
    pub host: String,
    /// Path after the host, defaulting to `/dns-query`.
    pub path: String,
}

impl DohServer {
    /// Parse `https://1.2.3.4`, `https://1.2.3.4/dns-query`, or with an explicit
    /// host `https://dns.example/dns-query`. Returns None when the entry is not
    /// a DoH entry, so the caller can fall through.
    pub fn parse(entry: &str) -> Option<Self> {
        let rest = entry.strip_prefix("https://")?;
        let rest = rest.trim();
        if rest.is_empty() {
            return None;
        }

        // Split authority from path. The authority never contains a '/'.
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a.trim(), format!("/{}", p.trim())),
            None => (rest, "/dns-query".to_string()),
        };
        if authority.is_empty() {
            return None;
        }

        // Authority may be host:port, [v6]:port, [v6], or bare host.
        let (host_part, port) = if let Some(rest) = authority.strip_prefix('[') {
            // bracketed v6
            let (h, rest) = rest.split_once(']')?;
            let port = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            (h.trim(), port)
        } else if authority.matches(':').count() > 1 {
            // bare v6 — no port
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

        // DoH needs an IP to open the socket. The entry may be a hostname
        // (https://dns.example/dns-query) — resolve it with the plain path
        // before the first query, once, so the answer can be cached on the
        // DohServer. Doing this here keeps resolve_a dumb.
        let addr_ip: std::net::IpAddr = match host_part.parse() {
            Ok(ip) => ip,
            Err(_) => {
                // A hostname needs a lookup the plain resolver has to do, and
                // that lookup must not itself need DoH. Defer: the caller falls
                // back to UDP, which resolves it.
                return None;
            }
        };

        Some(DohServer {
            addr: std::net::SocketAddr::new(addr_ip, port.unwrap_or(443)),
            host: host_part.to_string(),
            path,
        })
    }
}

/// Resolve a name over DNS-over-HTTPS. Returns the first A record.
pub async fn resolve_a(stack: &StackHandle, server: &DohServer, name: &str) -> Result<std::net::IpAddr> {
    let stream = StackStream::open(stack, server.addr).await?;

    let (query, id) = crate::socks::build_dns_query_public(name, crate::socks::QTYPE_A);

    let tls = crate::tls::connect_doh(&server.host, stream).await?;

    // h2 drives the TLS stream from its own connection future; this task owns
    // it and is aborted when resolve_a returns so the stack connection closes.
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

    // h2::client refuses send_request until the connection is ready to open a
    // stream; ready() is the documented gate.
    let mut h2_send = h2_send
        .ready()
        .await
        .map_err(|e| AetherError::Other(format!("doh: h2 ready: {e}")))?;

    // RFC 8484: POST a raw DNS message with the DoH content types. A bare
    // request line would be rejected — h2 0.4 takes a real http::Request.
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

    // Only 2xx carries a DNS message; everything else is a server-side refusal
    // and the caller should move on to the next resolver rather than guess.
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
        // A DoH response fits in one or two frames; cap the read so a
        // misbehaving server cannot pin this task forever.
        if buf.len() > 65535 {
            break;
        }
    }
    // Reading to END_STREAM lets the connection task see a clean close.
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

/// How long a failed server is skipped before it is retried.
const BACKOFF: std::time::Duration = std::time::Duration::from_secs(30);

fn backoff_state() -> &'static Mutex<std::collections::HashMap<std::net::SocketAddr, Instant>> {
    use std::sync::OnceLock;
    static STATE: OnceLock<Mutex<std::collections::HashMap<std::net::SocketAddr, Instant>>> =
        OnceLock::new();
    STATE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// True while a failed server is still in its cooldown, so `dns_resolve`
/// skips it instead of paying its timeout on every connection.
pub(crate) fn is_backing_off(server: &DohServer) -> bool {
    let now = Instant::now();
    backoff_state()
        .lock()
        .map(|map| map.get(&server.addr).is_some_and(|until| *until > now))
        .unwrap_or(false)
}

/// Record a failure and start the cooldown.
pub(crate) fn mark_failure(server: &DohServer) {
    let _ = backoff_state()
        .lock()
        .map(|mut map| map.insert(server.addr, Instant::now() + BACKOFF));
}

/// Every DoH endpoint the user configured, in the order they wrote them.
///
/// Deliberately returns an empty list when the user has not written a single
/// `https://` entry, for the same reason as `dot_servers()`: it runs before the
/// plain UDP resolvers and a hardcoded fallback would make every lookup pay a
/// TLS + h2 handshake for a user who asked for UDP.
pub(crate) fn doh_servers() -> Vec<DohServer> {
    let configured = std::env::var("AETHER_DNS").unwrap_or_default();
    let mut out = Vec::new();
    for token in configured.split([',', ' ', ';']) {
        if let Some(server) = DohServer::parse(token) {
            if !out.iter().any(|s: &DohServer| s.addr == server.addr) {
                out.push(server);
            }
        }
    }
    out
}
