//! Idle-connection pool for the encrypted DNS resolvers (DoT / DoH).
//!
//! Without this, every name lookup opened its own TCP connection through the
//! tunnel stack and paid a full TLS handshake — plus an h2 handshake for DoH —
//! on the critical path of every connection the device makes. On a WARP edge
//! answering at 400-800ms that is three to four round trips per name, which is
//! exactly the stall visible in the first seconds after connecting.
//!
//! The pool is a map of owned connections keyed by resolver identity. Borrowing
//! takes the connection *out* of the map, so two lookups can never share a
//! stream and a stream whose reply is half-read cannot be handed out twice. A
//! successful exchange puts it back ([`release`]); any error, a timeout, or a
//! dropped task drops it where it stands, closing the TCP connection in the
//! userspace stack via `StackStream`'s `Drop`. No connection is ever reused
//! after it has seen an error, and none is held while a query is in flight.
//!
//! Concurrency: the `tokio::sync::Mutex` guards only the map swap, never the
//! query itself, so a slow lookup never blocks a second resolver — and a burst
//! of lookups opens at most one extra connection per resolver rather than one
//! per name.

use std::collections::HashMap;
use std::sync::OnceLock;

use tokio::sync::Mutex;

use crate::stackstream::StackStream;

/// How many idle connections the pool keeps. One per resolver is the common
/// case; the cap only matters if the user configures many resolvers.
const MAX_IDLE: usize = 8;

type PoolMap = HashMap<String, PooledConn>;

fn pool() -> &'static Mutex<PoolMap> {
    static POOL: OnceLock<Mutex<PoolMap>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

/// One live TLS (+h2) connection to a resolver.
///
/// Owned by the pool when idle and by a single lookup when borrowed. Dropping it
/// closes the stream: `SslStream` drops the `StackStream` underneath, whose
/// `Drop` tears the TCP connection down in the userspace stack instead of
/// leaving it idle until the tunnel stops.
pub(crate) struct PooledConn {
    key: String,
    inner: ConnInner,
}

enum ConnInner {
    /// DNS-over-TLS: a ready `SslStream` over the tunnel's TCP channel.
    Dot(tokio_boring::SslStream<StackStream>),
    /// DNS-over-HTTPS: an h2 client that can open request streams, plus the task
    /// driving the connection. Dropping `drive` ends the connection, which is
    /// how an idle DoH entry is reaped.
    Doh(DohConn),
    /// Test-only entry, for exercising pool semantics without a network.
    #[cfg(test)]
    Test,
}

/// The h2 half of a pooled DoH connection.
pub(crate) struct DohConn {
    /// Opens a new request stream on the live h2 connection.
    pub send: h2::client::SendResponse<bytes::Bytes>,
    /// Background task pumping the h2 connection. Owned by the pool entry, so an
    /// idle DoH connection stays driven and a borrowed one cannot outlive it.
    pub drive: tokio::task::JoinHandle<()>,
}

impl PooledConn {
    fn new_dot(key: String, tls: tokio_boring::SslStream<StackStream>) -> Self {
        PooledConn { key, inner: ConnInner::Dot(tls) }
    }

    fn new_doh(
        key: String,
        send: h2::client::SendResponse<bytes::Bytes>,
        drive: tokio::task::JoinHandle<()>,
    ) -> Self {
        PooledConn { key, inner: ConnInner::Doh(DohConn { send, drive }) }
    }

    /// The DoT TLS stream. Panics if this entry is an h2 (DoH) connection — the
    /// two resolver paths never share a key.
    pub(crate) fn dot(&mut self) -> &mut tokio_boring::SslStream<StackStream> {
        match &mut self.inner {
            ConnInner::Dot(tls) => tls,
            ConnInner::Doh(_) => unreachable!("dot() on a doh pooled connection"),
            #[cfg(test)]
            ConnInner::Test => unreachable!("dot() on a test pooled connection"),
        }
    }

    /// The DoH h2 client. Panics if this entry is a DoT connection.
    pub(crate) fn doh(&mut self) -> &mut DohConn {
        match &mut self.inner {
            ConnInner::Doh(c) => c,
            ConnInner::Dot(_) => unreachable!("doh() on a dot pooled connection"),
            #[cfg(test)]
            ConnInner::Test => unreachable!("doh() on a test pooled connection"),
        }
    }

    fn key(&self) -> &str {
        &self.key
    }
}

/// Take the idle connection for `key` out of the pool, if there is one.
///
/// Removing it (rather than cloning a handle) is the whole safety argument: the
/// caller owns the stream for the duration of the exchange, so a second lookup
/// for the same resolver opens its own connection instead of interleaving
/// writes on this one.
pub(crate) async fn acquire(key: &str) -> Option<PooledConn> {
    pool().lock().await.remove(key)
}

/// Wrap a freshly handshaked DoT connection for the caller. It is not pooled
/// until [`release`] puts it back, so a failed first query closes it.
pub(crate) fn install_dot(
    key: String,
    tls: tokio_boring::SslStream<StackStream>,
) -> PooledConn {
    PooledConn::new_dot(key, tls)
}

/// Wrap a freshly handshaked DoH connection. See [`install_dot`].
pub(crate) fn install_doh(
    key: String,
    send: h2::client::SendResponse<bytes::Bytes>,
    drive: tokio::task::JoinHandle<()>,
) -> PooledConn {
    PooledConn::new_doh(key, send, drive)
}

/// Return a connection that completed its exchange successfully.
///
/// A connection that errored, or whose task was cancelled by the outer timeout,
/// never reaches here — it is dropped, closing the stream.
pub(crate) fn release(conn: PooledConn) {
    let key = conn.key().to_string();
    let mut map = match pool().try_lock() {
        Ok(map) => map,
        Err(_) => {
            log::debug!("dnspool: pool locked, closing an idle connection");
            return;
        }
    };
    map.insert(key.clone(), conn);
    if map.len() > MAX_IDLE {
        // Evict an arbitrary *other* idle entry: all entries cost the same, and
        // never evicting our own key keeps the connection just proven good.
        let victim = map.keys().find(|k| k.as_str() != key).cloned();
        if let Some(victim) = victim {
            map.remove(&victim);
        }
    }
}

/// Remove and close the pool entry for `key`. Safe under a live borrow: the
/// borrower owns its connection, so this only reaps the idle one.
pub(crate) async fn discard(key: &str) {
    let _ = pool().lock().await.remove(key);
}

/// True if the pool holds an idle entry for `key`. Diagnostic only.
#[allow(dead_code)]
pub(crate) async fn has(key: &str) -> bool {
    pool().lock().await.contains_key(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_conn(key: &str) -> PooledConn {
        PooledConn { key: key.to_string(), inner: ConnInner::Test }
    }

    /// A borrowed connection is not visible to a second acquire.
    #[tokio::test]
    async fn borrowed_is_invisible() {
        let key = "dot|1.1.1.1:853|one.one.one.one";
        release(test_conn(key));
        let conn = acquire(key).await.expect("idle entry present");
        assert!(acquire(key).await.is_none(), "a borrowed conn must not be handed out twice");
        release(conn);
        discard(key).await;
    }

    /// `release` makes the connection reusable by the next lookup.
    #[tokio::test]
    async fn release_makes_it_reusable() {
        let key = "doh|1.1.1.1:443|https://cloudflare-dns.com/dns-query";
        release(test_conn(key));
        let conn = acquire(key).await.expect("idle entry present");
        release(conn);
        assert!(acquire(key).await.is_some(), "release must put the connection back");
        discard(key).await;
    }

    /// Keys for different resolvers must never collide.
    #[tokio::test]
    async fn keys_do_not_collide() {
        let dot = "dot|1.1.1.1:853|one.one.one.one";
        let doh = "doh|1.1.1.1:443|https://cloudflare-dns.com/dns-query";
        release(test_conn(dot));
        release(test_conn(doh));
        assert!(acquire(dot).await.is_some());
        assert!(acquire(doh).await.is_some());
        assert!(acquire(dot).await.is_none());
        discard(dot).await;
        discard(doh).await;
    }

    /// The cap on idle entries drops one rather than growing without bound.
    #[tokio::test]
    async fn cap_evicts_an_idle_entry() {
        for i in 0..(MAX_IDLE + 4) {
            release(test_conn(&format!("dot|10.0.0.{i}:853|sni")));
        }
        let len = pool().lock().await.len();
        assert!(len <= MAX_IDLE, "pool must stay bounded, was {len}");
        for i in 0..(MAX_IDLE + 4) {
            discard(&format!("dot|10.0.0.{i}:853|sni")).await;
        }
    }
}
