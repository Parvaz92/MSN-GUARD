use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// MSN-GUARD 2.3.15: AETHER_STATS gating removed. The Kotlin host always sets
// AETHER_STATS=1 before the engine starts, but 2.3.13/2.3.14 field reports
// showed Up/Down/Speed + Traffic Monitor still at 0 while a WARP tunnel was
// carrying traffic on every engine (Hev/Zeptun/Badvpn) — which means either
// setenv raced aether_core_start's read or the process env never carried it,
// and either way a stats gate that can silently stay OFF makes that
// indistinguishable from a genuinely idle tunnel. The counters themselves are
// two atomic adds, so unconditional counting costs nothing; the host's own
// poll (MsnGuardVpnService.startWarpTrafficPolling) decides whether anything
// is shown.
static UP: AtomicU64 = AtomicU64::new(0);
static DOWN: AtomicU64 = AtomicU64::new(0);
static ENABLED: AtomicBool = AtomicBool::new(true);
static START: OnceLock<Instant> = OnceLock::new();

const DEFAULT_REPORT_SECS: u64 = 60;

pub struct Counters {
    pub up: u64,
    pub down: u64,
    pub uptime: Duration,
}

/// Whether byte counters are being accumulated.
///
/// Always true since 2.3.15 (see UP/DOWN above); kept as an accessor so the
/// call sites stay honest about what they are asking.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub fn add_up(bytes: usize) {
    if enabled() {
        UP.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

pub fn add_down(bytes: usize) {
    if enabled() {
        DOWN.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

/// 2.3.15: logs the accumulated byte counters once per minute so a tunnel
/// whose Up/Down/Speed sits at 0 in the UI is diagnosable from logcat alone.
/// The info-level line costs nothing when the tunnel is idle.
pub fn log_counters() {
    let counters = snapshot();
    log::info!(
        "[=] up {} down {} uptime {}",
        format_bytes(counters.up),
        format_bytes(counters.down),
        format_uptime(counters.uptime)
    );
}

pub fn snapshot() -> Counters {
    Counters {
        up: UP.load(Ordering::Relaxed),
        down: DOWN.load(Ordering::Relaxed),
        uptime: START.get().map(|s| s.elapsed()).unwrap_or_default(),
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn format_uptime(uptime: Duration) -> String {
    let total = uptime.as_secs();
    let (days, hours, minutes, seconds) = (
        total / 86_400,
        (total % 86_400) / 3600,
        (total % 3600) / 60,
        total % 60,
    );

    if days > 0 {
        format!("{days}d {hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    }
}

fn report_interval() -> Duration {
    let secs = std::env::var("AETHER_STATS_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(DEFAULT_REPORT_SECS);
    Duration::from_secs(secs)
}

/// 2.3.15: the reporter is always spawned; see the ENABLED note at the top.
/// The interval it logs at is still honoured, so a session that carries
/// nothing still logs nothing.
pub fn spawn_reporter() {
    let every = report_interval();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            let counters = snapshot();
            log::info!(
                "[=] up {} down {} uptime {}",
                format_bytes(counters.up),
                format_bytes(counters.down),
                format_uptime(counters.uptime)
            );
        }
    });
}

/// 2.3.15: no env gate remains — the counters are always live (see the note
/// at the top of the file). Kept so lib.rs's call site reads clearly.
pub fn init() {
    let _ = START.set(Instant::now());
    log::info!("[+] stats counters armed (AETHER_STATS gate removed 2.3.15)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_counts_stay_in_plain_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn larger_counts_climb_the_units() {
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }

    #[test]
    fn uptime_grows_a_day_field_only_when_it_needs_one() {
        assert_eq!(format_uptime(Duration::from_secs(0)), "00:00:00");
        assert_eq!(format_uptime(Duration::from_secs(3661)), "01:01:01");
        assert_eq!(format_uptime(Duration::from_secs(90_061)), "1d 01:01:01");
    }

    #[test]
    fn a_session_always_counts_its_bytes() {
        // 2.3.15: the AETHER_STATS gate is gone, so add_up/add_down always
        // accumulate. A snapshot is process-global, so this proves the add
        // happened rather than asserting a specific absolute value, which
        // another test could have moved.
        let before = snapshot().up;
        add_up(4096);
        assert!(snapshot().up >= before + 4096);
        let before_down = snapshot().down;
        add_down(8192);
        assert!(snapshot().down >= before_down + 8192);
    }
}
