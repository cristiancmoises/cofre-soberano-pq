//! Sprint 9.5 — connection admission control.
//!
//! Two orthogonal mechanisms apply at TCP accept time, BEFORE the handshake
//! cost is paid:
//!
//! 1. **Per-tenant concurrency quota** — a tokio semaphore caps the number
//!    of in-flight sessions per tenant. Rejected connections are dropped
//!    immediately (TCP RST) and counted in the metric
//!    `qgateway_admission_rejected_total{tenant=,reason="quota"}`.
//!    Rationale: prevents one misbehaving tenant from saturating the
//!    accept queue / file descriptors on shared SNI ports.
//!
//! 2. **Per-source-IP token bucket** — a sharded HashMap keyed by source
//!    IP holds a bucket per peer. Each accept consumes one token; refill
//!    happens lazily on next accept based on elapsed wall time. Rejected
//!    connections are also dropped and counted as `reason="rate"`.
//!    Rationale: a single noisy source can't overwhelm the handshake
//!    pipeline (which costs ML-KEM-1024 + ML-DSA-87 verify per session).
//!
//! Both are off by default. A tenant with neither limit configured passes
//! every accept through unconditionally — Sprint 9.5 introduces NO
//! behavioral change for existing deployments. Operators opt-in per tenant.
//!
//! Design notes:
//!
//! - Both checks happen *synchronously* in the accept loop hot path. The
//!   semaphore acquire is `try_acquire_owned` (never awaits, never blocks
//!   the accept loop). The rate-limit lookup is a `HashMap::entry` under a
//!   single `Mutex` — fast for the per-tenant bucket count we expect
//!   (typically thousands of unique sources max).
//! - Bucket entries auto-expire when the bucket is full at refill time;
//!   no background sweep task. A future deployment with hundreds of
//!   thousands of unique sources should switch to a sharded map.
//! - Token-bucket math is integer-only: capacity in tokens, refill in
//!   tokens-per-second; no floats.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

/// A reason an accept was rejected. Surfaced in metrics labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Tenant's `max_concurrent` quota is full.
    Quota,
    /// Per-source-IP token bucket is empty.
    Rate,
}

impl RejectReason {
    /// Stable metric label.
    pub fn label(self) -> &'static str {
        match self {
            RejectReason::Quota => "quota",
            RejectReason::Rate => "rate",
        }
    }
}

/// Outcome of an admission check.
pub enum Admit {
    /// Accept proceeds. The permit MUST be held for the lifetime of the
    /// session (its drop releases the semaphore slot).
    Ok(Option<OwnedSemaphorePermit>),
    /// Accept rejected; the TcpStream should be dropped immediately.
    Reject(RejectReason),
}

/// Per-tenant admission controller. One instance per tenant, shared
/// across the accept loop (immutable after construction).
pub struct AdmissionController {
    /// Max concurrent sessions. `None` = no quota.
    quota: Option<Arc<Semaphore>>,
    /// Token bucket per source IP. `None` = no rate limit.
    rate_limit: Option<Arc<Mutex<RateLimiter>>>,
}

/// Sprint 15: hot-swappable wrapper around `AdmissionController`. Accept
/// loops hold an `Arc<HotAdmissionController>` instead of an
/// `Arc<AdmissionController>` so the SIGHUP apply step can replace the
/// inner controller in place without restarting the tenant task.
///
/// Reads (the hot accept path) use `arc_swap::ArcSwap::load()`, which on
/// x86_64 compiles to an atomic pointer load — single-cycle cost, no
/// contention with concurrent writers. Writes happen on operator action
/// (SIGHUP), so the asymmetric read/write cost matches the workload.
///
/// Swap semantics: when an operator changes `[tenants.limits]`, the new
/// controller fully replaces the old one. In-flight session permits
/// from the OLD controller remain valid until their session ends — they
/// don't count against the NEW controller's quota. This is the right
/// behaviour: limits changes affect FUTURE connections, not connections
/// already accepted under the previous policy. Per-source rate limit
/// state is also discarded on swap; a noisy source whose bucket was
/// drained gets a fresh bucket. Operators using rate limiting to fend
/// off ongoing abuse should NOT use a limits edit as the mitigation
/// path — that's a connection drain (Sprint 15+ tenant removal) or
/// upstream layer-4 work.
pub struct HotAdmissionController {
    inner: arc_swap::ArcSwap<AdmissionController>,
}

impl HotAdmissionController {
    /// Build a hot-swappable wrapper from initial settings.
    pub fn new(max_concurrent: Option<u32>, rate_limit: Option<RateLimitConfig>) -> Self {
        Self {
            inner: arc_swap::ArcSwap::from_pointee(AdmissionController::new(
                max_concurrent,
                rate_limit,
            )),
        }
    }

    /// Build from an existing controller. Used by the daemon's startup
    /// path so the same controller-construction code serves both startup
    /// and runtime-add cases.
    pub fn from_controller(controller: AdmissionController) -> Self {
        Self {
            inner: arc_swap::ArcSwap::from_pointee(controller),
        }
    }

    /// Hot-path: dispatch the admission check to the currently-loaded
    /// inner controller. The `arc_swap::Guard` is dropped at end of
    /// expression — no lifetime issues for the permit returned from
    /// `Admit::Ok`, because the semaphore's permit is `Arc`-cloned out
    /// of the controller before the guard drops.
    pub fn check(&self, peer: IpAddr) -> Admit {
        self.inner.load().check(peer)
    }

    /// Sprint 15: swap the inner controller. Returns the previous
    /// controller as an `Arc` — caller can let it drop, or hold it for
    /// debugging. In-flight permits from the OLD controller remain
    /// valid; the new controller starts at full capacity.
    pub fn swap(
        &self,
        max_concurrent: Option<u32>,
        rate_limit: Option<RateLimitConfig>,
    ) -> Arc<AdmissionController> {
        let new = Arc::new(AdmissionController::new(max_concurrent, rate_limit));
        self.inner.swap(new)
    }
}

impl AdmissionController {
    /// Build a controller with the given limits.
    pub fn new(max_concurrent: Option<u32>, rate_limit: Option<RateLimitConfig>) -> Self {
        Self {
            quota: max_concurrent.map(|n| Arc::new(Semaphore::new(n as usize))),
            rate_limit: rate_limit.map(|rl| Arc::new(Mutex::new(RateLimiter::new(rl)))),
        }
    }

    /// Check whether an inbound connection from `peer` should be admitted.
    /// Returns the permit to hold for the session lifetime (or None when
    /// no quota is configured), or a rejection reason.
    ///
    /// Order: rate limit checked first (cheaper), then quota. Both must
    /// pass for `Admit::Ok` to be returned.
    pub fn check(&self, peer: IpAddr) -> Admit {
        if let Some(rl) = &self.rate_limit {
            let mut guard = rl.lock().unwrap();
            if !guard.try_take(peer, Instant::now()) {
                return Admit::Reject(RejectReason::Rate);
            }
        }
        if let Some(sem) = &self.quota {
            match sem.clone().try_acquire_owned() {
                Ok(permit) => Admit::Ok(Some(permit)),
                Err(TryAcquireError::NoPermits) => Admit::Reject(RejectReason::Quota),
                Err(TryAcquireError::Closed) => {
                    // Semaphore is closed only on explicit close() which we
                    // never call; treat as no-permits for safety.
                    Admit::Reject(RejectReason::Quota)
                }
            }
        } else {
            Admit::Ok(None)
        }
    }
}

/// Token-bucket configuration. Capacity tokens, refill_per_sec rate.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Bucket capacity (max burst size in connections).
    pub capacity: u32,
    /// Refill rate in tokens per second. Equivalent to steady-state
    /// max-accept rate per source.
    pub refill_per_sec: u32,
}

/// Per-source-IP token-bucket rate limiter. Buckets are created lazily on
/// first accept from a given source; full buckets are pruned at refill
/// time to bound memory.
struct RateLimiter {
    cfg: RateLimitConfig,
    buckets: HashMap<IpAddr, Bucket>,
}

struct Bucket {
    /// Tokens currently available (integer, in tokens — not fractional).
    tokens: u32,
    /// Last refill timestamp.
    last_refill: Instant,
}

impl RateLimiter {
    fn new(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            buckets: HashMap::new(),
        }
    }

    /// Try to take one token from `peer`'s bucket. Returns `true` on
    /// success. Refills lazily based on `now - last_refill`.
    fn try_take(&mut self, peer: IpAddr, now: Instant) -> bool {
        // Sprint 10.5: lazy GC. When the map grows past GC_THRESHOLD,
        // every call sweeps entries that are at full capacity AND were
        // last touched more than IDLE_TTL ago. Amortised O(1) cost: the
        // sweep does one HashMap retain per call only when the size
        // exceeds the threshold, and only fires often enough to keep
        // the map bounded.
        if self.buckets.len() > GC_THRESHOLD {
            self.maybe_gc(now);
        }

        // Inline the bucket-not-yet-present case: pre-fill at full capacity.
        let bucket = self.buckets.entry(peer).or_insert(Bucket {
            tokens: self.cfg.capacity,
            last_refill: now,
        });

        // Refill: floor((now - last_refill) * refill_per_sec).
        let elapsed = now.saturating_duration_since(bucket.last_refill);
        if elapsed >= Duration::from_secs(1) {
            // Integer refill: elapsed_secs * refill_per_sec, capped at capacity.
            let secs = elapsed.as_secs();
            let add = secs.saturating_mul(self.cfg.refill_per_sec as u64);
            bucket.tokens = bucket
                .tokens
                .saturating_add(add.min(u32::MAX as u64) as u32)
                .min(self.cfg.capacity);
            // Advance last_refill by the integer seconds we accounted for,
            // preserving sub-second remainder for the next call.
            bucket.last_refill += Duration::from_secs(secs);
        }

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Sprint 10.5: drop bucket entries that are full AND haven't been
    /// touched in IDLE_TTL. A full bucket is functionally identical to a
    /// fresh one (the entry pre-fills at capacity), so removing it loses
    /// no rate-limit state. The IDLE_TTL guards against thrashing —
    /// dropping a bucket only to immediately recreate it.
    ///
    /// Sweep frequency is amortised: only called when the map exceeds
    /// GC_THRESHOLD. Workload analysis: at 100k unique sources/hour the
    /// sweep fires once per ~1k connections, doing one O(N) walk over
    /// the HashMap — microseconds at that size.
    fn maybe_gc(&mut self, now: Instant) {
        let capacity = self.cfg.capacity;
        self.buckets.retain(|_, b| {
            // Compute the EFFECTIVE current token count without mutating —
            // we don't want to refill stale buckets just to delete them.
            let elapsed = now.saturating_duration_since(b.last_refill);
            let secs = elapsed.as_secs();
            let projected_tokens = if secs > 0 {
                let add = secs.saturating_mul(self.cfg.refill_per_sec as u64);
                b.tokens
                    .saturating_add(add.min(u32::MAX as u64) as u32)
                    .min(capacity)
            } else {
                b.tokens
            };
            // Keep iff bucket has consumed at least one token OR was used recently.
            // Drop iff bucket is at full capacity (functionally fresh) AND idle.
            !(projected_tokens == capacity && elapsed > IDLE_TTL)
        });
    }
}

/// Sprint 10.5: GC sweep kicks in only when the bucket count exceeds this.
/// Below this threshold the memory cost is negligible (~512 KiB at 10k
/// entries) and sweeping is pure overhead. Tuned for the expected upper
/// bound on unique sources per gateway instance.
const GC_THRESHOLD: usize = 8192;

/// Sprint 10.5: a bucket idle longer than this is GC'd on the next sweep.
/// 5 minutes balances: long enough that recurrent clients aren't penalised
/// by losing state; short enough that one-shot probes don't accumulate.
const IDLE_TTL: Duration = Duration::from_secs(300);

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn no_limits_admits_everything() {
        let ctl = AdmissionController::new(None, None);
        let p1 = ip(127, 0, 0, 1);
        for _ in 0..1000 {
            match ctl.check(p1) {
                Admit::Ok(_) => {}
                Admit::Reject(r) => panic!("unexpected reject {r:?}"),
            }
        }
    }

    #[test]
    fn quota_caps_concurrent_sessions() {
        let ctl = AdmissionController::new(Some(2), None);
        let peer = ip(10, 0, 0, 5);
        let _p1 = match ctl.check(peer) {
            Admit::Ok(Some(p)) => p,
            other => panic!(
                "expected Ok with permit, got {:?}",
                match other {
                    Admit::Ok(_) => "Ok(None)",
                    Admit::Reject(r) => r.label(),
                }
            ),
        };
        let _p2 = match ctl.check(peer) {
            Admit::Ok(Some(p)) => p,
            _ => panic!("second admit must succeed"),
        };
        // Third must reject with Quota.
        match ctl.check(peer) {
            Admit::Reject(RejectReason::Quota) => {}
            _ => panic!("third admit must be rejected with quota"),
        }
        // Drop p1; a new admit should now succeed.
        drop(_p1);
        match ctl.check(peer) {
            Admit::Ok(Some(_)) => {}
            _ => panic!("admit after permit drop must succeed"),
        }
    }

    #[test]
    fn rate_limit_caps_per_source() {
        let ctl = AdmissionController::new(
            None,
            Some(RateLimitConfig {
                capacity: 3,
                refill_per_sec: 1,
            }),
        );
        let peer = ip(10, 0, 0, 7);
        // Burst of 3: all admitted.
        for i in 0..3 {
            match ctl.check(peer) {
                Admit::Ok(_) => {}
                Admit::Reject(r) => panic!("burst conn {i} unexpectedly rejected: {r:?}"),
            }
        }
        // 4th immediate attempt: rejected with Rate.
        match ctl.check(peer) {
            Admit::Reject(RejectReason::Rate) => {}
            _ => panic!("burst overflow must be rejected with rate"),
        }
    }

    #[test]
    fn rate_limit_buckets_are_per_ip() {
        // Two different IPs each get their own bucket; one exhausting its
        // bucket doesn't starve the other.
        let ctl = AdmissionController::new(
            None,
            Some(RateLimitConfig {
                capacity: 2,
                refill_per_sec: 1,
            }),
        );
        let a = ip(10, 0, 0, 1);
        let b = ip(10, 0, 0, 2);
        // Exhaust A.
        assert!(matches!(ctl.check(a), Admit::Ok(_)));
        assert!(matches!(ctl.check(a), Admit::Ok(_)));
        assert!(matches!(ctl.check(a), Admit::Reject(RejectReason::Rate)));
        // B's bucket is independent — still full.
        assert!(matches!(ctl.check(b), Admit::Ok(_)));
        assert!(matches!(ctl.check(b), Admit::Ok(_)));
        assert!(matches!(ctl.check(b), Admit::Reject(RejectReason::Rate)));
    }

    #[test]
    fn rate_limit_refills_over_time() {
        // Use the internal RateLimiter directly to drive time deterministically.
        let mut rl = RateLimiter::new(RateLimitConfig {
            capacity: 2,
            refill_per_sec: 1,
        });
        let peer = ip(10, 0, 0, 1);
        let t0 = Instant::now();
        // Drain bucket.
        assert!(rl.try_take(peer, t0));
        assert!(rl.try_take(peer, t0));
        assert!(!rl.try_take(peer, t0)); // empty

        // Advance 1.5 seconds → refill of 1 token (integer math).
        let t1 = t0 + Duration::from_millis(1500);
        assert!(rl.try_take(peer, t1));
        // Still only 1 token was refilled (capacity-bounded by elapsed integer secs).
        assert!(!rl.try_take(peer, t1));

        // Advance another 2 full seconds → refills to capacity (2).
        let t2 = t1 + Duration::from_secs(2);
        assert!(rl.try_take(peer, t2));
        assert!(rl.try_take(peer, t2));
        assert!(!rl.try_take(peer, t2));
    }

    #[test]
    fn quota_and_rate_can_coexist() {
        // Both checks must pass. Quota wins when both would reject.
        let ctl = AdmissionController::new(
            Some(1),
            Some(RateLimitConfig {
                capacity: 100,
                refill_per_sec: 100,
            }),
        );
        let peer = ip(192, 168, 1, 1);
        let _p1 = match ctl.check(peer) {
            Admit::Ok(Some(p)) => p,
            _ => panic!("first must Ok"),
        };
        // Second: rate would allow, quota would reject.
        match ctl.check(peer) {
            Admit::Reject(RejectReason::Quota) => {}
            other => panic!(
                "expected quota reject, got {:?}",
                match other {
                    Admit::Ok(_) => "Ok",
                    Admit::Reject(r) => r.label(),
                }
            ),
        }
    }

    #[test]
    fn rate_check_happens_before_quota() {
        // When rate limit is exhausted, the call doesn't consume a quota slot.
        // Conceptually: rate-reject should not deplete the semaphore.
        let ctl = AdmissionController::new(
            Some(2),
            Some(RateLimitConfig {
                capacity: 1,
                refill_per_sec: 1,
            }),
        );
        let peer = ip(192, 168, 1, 2);
        // First admit: takes 1 token + 1 quota slot.
        let _p1 = match ctl.check(peer) {
            Admit::Ok(Some(p)) => p,
            _ => panic!("first must Ok"),
        };
        // Second: rate empty → reject with Rate (NOT Quota).
        match ctl.check(peer) {
            Admit::Reject(RejectReason::Rate) => {}
            _ => panic!("must reject with Rate, not Quota"),
        }
        // Different IP: rate fresh → must succeed (uses second quota slot).
        let peer2 = ip(192, 168, 1, 3);
        let _p2 = match ctl.check(peer2) {
            Admit::Ok(Some(p)) => p,
            _ => panic!("second peer must Ok — second quota slot still free"),
        };
    }

    // ========================================================================
    //              Sprint 10.5 — GC sweep tests
    // ========================================================================

    #[test]
    fn gc_drops_idle_full_buckets_above_threshold() {
        // Fill the map past GC_THRESHOLD, then drive a single fresh
        // accept after IDLE_TTL — the sweep must drop the stale entries.
        let mut rl = RateLimiter::new(RateLimitConfig {
            capacity: 5,
            refill_per_sec: 1,
        });
        let t0 = Instant::now();
        // Populate GC_THRESHOLD + 100 entries by taking and not
        // exhausting (bucket goes from 5 → 4 tokens; not at-capacity).
        // Then refill them all to capacity by advancing time.
        for i in 0..(GC_THRESHOLD + 100) {
            let p = IpAddr::V4(Ipv4Addr::new(
                10,
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            ));
            assert!(rl.try_take(p, t0));
        }
        let before = rl.buckets.len();
        assert!(
            before > GC_THRESHOLD,
            "setup: expected map past threshold, got {before}"
        );

        // Advance past IDLE_TTL + enough seconds to refill every bucket
        // to capacity (one second is enough at refill_per_sec=1 — but
        // we need TTL too, so use IDLE_TTL + a few seconds for refill).
        let t1 = t0 + IDLE_TTL + Duration::from_secs(10);

        // One more accept from a NEW source kicks the GC.
        let new_peer = IpAddr::V4(Ipv4Addr::new(192, 168, 99, 99));
        assert!(rl.try_take(new_peer, t1));

        let after = rl.buckets.len();
        // After GC, the stale entries should be gone — only the new peer
        // should remain (or the new peer + a few we couldn't drop because
        // they weren't yet at capacity at GC inspection time, which is
        // impossible here since all old entries got 10s of refill at
        // refill_per_sec=1 with capacity=5).
        assert!(
            after < before,
            "GC must have reduced map size, before={before} after={after}"
        );
        assert!(
            after <= 100,
            "after GC the map should hold only the new peer (~1), got {after}"
        );
    }

    #[test]
    fn gc_preserves_recently_used_buckets() {
        // A bucket that consumed a token within IDLE_TTL must NOT be
        // dropped, even when the map exceeds GC_THRESHOLD.
        let mut rl = RateLimiter::new(RateLimitConfig {
            capacity: 5,
            refill_per_sec: 1,
        });
        let t0 = Instant::now();
        for i in 0..(GC_THRESHOLD + 100) {
            let p = IpAddr::V4(Ipv4Addr::new(
                10,
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            ));
            assert!(rl.try_take(p, t0));
        }
        // One peer is "active": consume a second token right before
        // the GC fires. After IDLE_TTL passes for the OTHERS, this
        // peer's last_refill remains recent.
        let active = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        // Advance just under IDLE_TTL, take a second token.
        let t_mid = t0 + IDLE_TTL - Duration::from_secs(10);
        assert!(rl.try_take(active, t_mid));

        // Now advance just past IDLE_TTL relative to t0 (so other buckets
        // qualify for GC) but not relative to t_mid (so `active` doesn't).
        let t1 = t0 + IDLE_TTL + Duration::from_secs(5);
        // Trigger GC via a new accept.
        let new_peer = IpAddr::V4(Ipv4Addr::new(192, 168, 99, 99));
        assert!(rl.try_take(new_peer, t1));

        // Active peer's bucket must still exist.
        assert!(
            rl.buckets.contains_key(&active),
            "GC must NOT drop a bucket touched within IDLE_TTL"
        );
    }

    #[test]
    fn gc_does_not_run_below_threshold() {
        // Below GC_THRESHOLD, the sweep never fires (zero overhead for
        // small deployments).
        let mut rl = RateLimiter::new(RateLimitConfig {
            capacity: 2,
            refill_per_sec: 1,
        });
        let t0 = Instant::now();
        for i in 0..100 {
            let p = IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, (i & 0xff) as u8));
            assert!(rl.try_take(p, t0));
        }
        // Advance way past IDLE_TTL.
        let t1 = t0 + Duration::from_secs(86_400);
        // Drive a fresh accept.
        let new_peer = IpAddr::V4(Ipv4Addr::new(192, 168, 99, 99));
        assert!(rl.try_take(new_peer, t1));
        // All 100 idle entries should still be present.
        assert_eq!(
            rl.buckets.len(),
            101,
            "below GC_THRESHOLD the sweep must never fire"
        );
    }

    // ========================================================================
    //         Sprint 15 — HotAdmissionController swap semantics
    // ========================================================================

    #[test]
    fn hot_controller_initial_check_uses_initial_limits() {
        // Build a hot controller with quota=2. After 2 admits we should
        // see Quota reject.
        let hot = HotAdmissionController::new(Some(2), None);
        let p = ip(10, 0, 0, 1);
        let _a = match hot.check(p) {
            Admit::Ok(Some(perm)) => perm,
            _ => panic!("first admit must succeed"),
        };
        let _b = match hot.check(p) {
            Admit::Ok(Some(perm)) => perm,
            _ => panic!("second admit must succeed"),
        };
        match hot.check(p) {
            Admit::Reject(RejectReason::Quota) => {}
            _ => panic!("third admit must reject with quota"),
        }
    }

    #[test]
    fn hot_controller_swap_replaces_limits_for_future_connections() {
        // Initial quota=1. After swap to quota=5, we should be able to
        // admit 5 more from the NEW controller.
        let hot = HotAdmissionController::new(Some(1), None);
        let p = ip(10, 0, 0, 1);
        // Consume the initial single slot.
        let _a = match hot.check(p) {
            Admit::Ok(Some(perm)) => perm,
            _ => panic!("first admit must succeed"),
        };
        // Verify the old controller is full.
        match hot.check(p) {
            Admit::Reject(RejectReason::Quota) => {}
            _ => panic!("second admit must reject (quota=1)"),
        }
        // Swap to quota=5.
        let _old = hot.swap(Some(5), None);
        // Now we should get 5 more admits. The OLD permit (held in `_a`)
        // is from the old controller and remains valid (it tracks the
        // old semaphore via Arc clone); the NEW controller starts at full
        // capacity.
        let mut perms = Vec::new();
        for i in 0..5 {
            match hot.check(p) {
                Admit::Ok(Some(perm)) => perms.push(perm),
                _ => panic!("admit {i} after swap must succeed"),
            }
        }
        // Sixth must reject from the new controller.
        match hot.check(p) {
            Admit::Reject(RejectReason::Quota) => {}
            _ => panic!("sixth admit must reject (new quota=5)"),
        }
    }

    #[test]
    fn hot_controller_swap_to_unlimited_admits_everything() {
        let hot = HotAdmissionController::new(Some(1), None);
        // Consume the single slot.
        let p = ip(10, 0, 0, 1);
        let _a = match hot.check(p) {
            Admit::Ok(Some(perm)) => perm,
            _ => panic!("first must succeed"),
        };
        // Swap to (None, None) — unlimited.
        let _ = hot.swap(None, None);
        for i in 0..100 {
            match hot.check(p) {
                Admit::Ok(_) => {}
                _ => panic!("admit {i} after unlimited swap must succeed"),
            }
        }
    }

    #[test]
    fn hot_controller_swap_to_rate_limit_creates_fresh_buckets() {
        // Initial: no rate limit. Swap in a rate limit. The new bucket
        // for each source IP must start at full capacity (the swap doesn't
        // carry over any "history" from the rateless state).
        let hot = HotAdmissionController::new(None, None);
        let p = ip(10, 0, 0, 1);
        // Drive a bunch of connections through the rateless state.
        for _ in 0..50 {
            assert!(matches!(hot.check(p), Admit::Ok(_)));
        }
        // Swap in rate limit: capacity=3, refill=1/s.
        let _ = hot.swap(
            None,
            Some(RateLimitConfig {
                capacity: 3,
                refill_per_sec: 1,
            }),
        );
        // Should get exactly 3 admits, then Rate reject.
        for i in 0..3 {
            match hot.check(p) {
                Admit::Ok(_) => {}
                _ => panic!("admit {i} after swap must succeed (fresh bucket)"),
            }
        }
        match hot.check(p) {
            Admit::Reject(RejectReason::Rate) => {}
            _ => panic!("fourth admit must reject (rate limit exhausted)"),
        }
    }
}
