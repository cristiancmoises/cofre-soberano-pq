//! Non-blocking audit emitter.
//!
//! The proxy hot path MUST NOT block on disk I/O. Audit entries are sent via
//! an mpsc channel to a dedicated background task that owns a mutable
//! `AuditLog` and persists entries to disk after each batch.
//!
//! The channel is bounded; on backpressure we drop the oldest pending entry
//! and increment `audit_failures` so operators see drops in Prometheus.

use qaudit_core::{AuditEvent, AuditLog};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, warn};

use crate::metrics::MetricsRegistry;

/// Handle that the proxy uses to emit events.
#[derive(Clone)]
pub struct AuditHandle {
    tx: mpsc::Sender<AuditEvent>,
    metrics: MetricsRegistry,
}

impl AuditHandle {
    /// Sprint 21: construct an AuditHandle that drops all events. Used
    /// by unit tests that need a `SniTenantContext` but don't exercise
    /// the audit path. The handle's mpsc receiver is dropped immediately,
    /// so every emit() resolves to TrySendError::Closed and bumps the
    /// audit_failures counter; tests that don't read that counter are
    /// unaffected.
    #[cfg(test)]
    pub(crate) fn test_noop() -> Self {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        Self {
            tx,
            metrics: MetricsRegistry::new("test-noop"),
        }
    }

    /// Send an event to the audit task. Non-blocking; drops on backpressure.
    pub fn emit(&self, event: AuditEvent) {
        match self.tx.try_send(event) {
            Ok(()) => {
                self.metrics
                    .inner()
                    .audit_events
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("audit channel full; event dropped");
                self.metrics
                    .inner()
                    .audit_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.metrics
                    .inner()
                    .audit_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

/// The audit channel — owns the writer task lifetime.
///
/// Sprint 19: `handle` and `join` moved into `Mutex<Option<...>>` to
/// support idempotent `shutdown_async(&self)` callable from any owner
/// of an `Arc<AuditChannel>`. The first call takes the values out
/// (dropping the handle signals the task to exit, awaiting the join
/// returns when it does); subsequent calls return immediately. The
/// existing `shutdown(self)` consuming method is preserved for the
/// daemon-shutdown path that owns the channel by value.
pub struct AuditChannel {
    handle: std::sync::Mutex<Option<AuditHandle>>,
    join: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Sprint 8: send `RotationRequest` here to trigger a hot rotation
    /// of the underlying audit log. Bounded channel of 1 — if a request
    /// is already pending the new one is dropped (idempotent SIGUSR2).
    rotation_tx: tokio::sync::mpsc::Sender<RotationRequest>,
    /// Sprint 8.5: shared counter incremented on every event appended to
    /// the current segment. Reset to 0 inside `perform_rotation` after a
    /// successful rotation. Cloned into the RotationHandle for monitor reads.
    entries_since_rotation: Arc<std::sync::atomic::AtomicU64>,
    /// Sprint 8.5: UNIX timestamp (seconds) of channel creation or last
    /// successful rotation.
    segment_open_unix: Arc<std::sync::atomic::AtomicI64>,
}

/// Sprint 8: cloneable handle to request rotations from outside the
/// channel. The signal handler holds one per tenant.
///
/// Sprint 8.5: also exposes counters needed by the auto-rotation monitor —
/// `entries_in_current_segment()` tracks events appended since the last
/// rotation (or since channel creation), and `seconds_since_last_rotation()`
/// tracks age of the current segment.
#[derive(Clone)]
pub struct RotationHandle {
    rotation_tx: tokio::sync::mpsc::Sender<RotationRequest>,
    /// Sprint 8.5: shared counter incremented on every successful event
    /// append, reset to 0 on every successful rotation. Used by the
    /// auto-rotation monitor to drive `max_entries` triggers.
    entries_since_rotation: Arc<std::sync::atomic::AtomicU64>,
    /// Sprint 8.5: UNIX timestamp (seconds) of channel creation or last
    /// successful rotation. Used by the monitor for `max_age_secs`.
    segment_open_unix: Arc<std::sync::atomic::AtomicI64>,
}

impl RotationHandle {
    /// Fire-and-forget rotation request. If the channel already has a
    /// rotation queued, the new one is dropped — idempotent in face of
    /// SIGUSR2 bursts.
    pub fn request_rotation_silent(&self, archive_path: PathBuf, new_label: impl Into<String>) {
        let req = RotationRequest {
            archive_path,
            new_label: new_label.into(),
            ack: None,
        };
        let _ = self.rotation_tx.try_send(req);
    }

    /// Sprint 8.5: how many events were appended to the CURRENT log
    /// segment (i.e. since channel creation or since the last successful
    /// rotation). Used by the auto-rotation monitor.
    pub fn entries_in_current_segment(&self) -> u64 {
        self.entries_since_rotation
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Sprint 8.5: how many seconds have elapsed since the current segment
    /// was opened (channel creation or last successful rotation).
    pub fn seconds_since_segment_open(&self) -> u64 {
        let open = self
            .segment_open_unix
            .load(std::sync::atomic::Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp();
        (now - open).max(0) as u64
    }
}

/// Sprint 8: a single rotation request handed to an `AuditChannel`. The
/// channel's background task drains the request, calls `AuditLog::rotate_to`,
/// saves the sealed old log to `archive_path`, and continues writing the new
/// log to the same `log_path` used since channel creation.
#[derive(Debug)]
pub struct RotationRequest {
    /// Where to write the sealed old log. Must not exist; the writer will
    /// fail-soft (logs an error, keeps the old log open) if it does.
    pub archive_path: PathBuf,
    /// Label for the new log's header.
    pub new_label: String,
    /// Reply with the rotation outcome — `Ok(())` on success, `Err(msg)` on
    /// failure with the file unchanged. Optional: pass `None` for fire-and-
    /// forget (signal-driven rotation).
    pub ack: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
}

/// Sprint 8: factory that mints a fresh `Box<dyn Signer>` for each rotation.
/// Typically wraps the same underlying audit key — the new log's header just
/// records the same pubkey. Cross-key rotation isn't done here; that's a
/// library-level operation that callers handle outside the channel.
///
/// Must be `Send + Sync` because the background task holds a reference to it
/// across `.await` points while waiting on the rotation/event channels.
pub trait SignerFactory: Send + Sync + 'static {
    /// Build a new signer for the next log segment. Called once per rotation.
    fn new_signer(&self) -> qaudit_core::Result<Box<dyn qaudit_core::Signer>>;
}

impl AuditChannel {
    /// Spawn a background task that owns `log` and drains the channel.
    /// The task persists the log to `log_path` after each event (durable, slow)
    /// or after a batch of up to `batch_size` events (faster, batched).
    ///
    /// Sprint 8: the returned channel can be rotated via [`AuditChannel::rotate`].
    /// `signer_factory` mints a fresh signer for the new log segment on each
    /// rotation cycle. Pass `None` to opt out of rotation support — `rotate()`
    /// will fail-soft with a clear error.
    pub fn spawn(
        log: AuditLog,
        log_path: PathBuf,
        metrics: MetricsRegistry,
        capacity: usize,
        batch_size: usize,
    ) -> Self {
        Self::spawn_inner(log, log_path, metrics, capacity, batch_size, None)
    }

    /// Sprint 8: spawn variant that supports rotation. `signer_factory` is
    /// invoked once per `rotate()` to mint a fresh `Box<dyn Signer>` for the
    /// new log segment.
    pub fn spawn_with_rotation<F: SignerFactory>(
        log: AuditLog,
        log_path: PathBuf,
        metrics: MetricsRegistry,
        capacity: usize,
        batch_size: usize,
        signer_factory: F,
    ) -> Self {
        Self::spawn_inner(
            log,
            log_path,
            metrics,
            capacity,
            batch_size,
            Some(Box::new(signer_factory)),
        )
    }

    fn spawn_inner(
        mut log: AuditLog,
        log_path: PathBuf,
        metrics: MetricsRegistry,
        capacity: usize,
        batch_size: usize,
        signer_factory: Option<Box<dyn SignerFactory>>,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(capacity);
        let (rot_tx, mut rot_rx) = mpsc::channel::<RotationRequest>(1);
        let handle = AuditHandle {
            tx,
            metrics: metrics.clone(),
        };
        // Sprint 8.5: atomic counters cloned into the background task and
        // into RotationHandle. The task increments on every successful
        // append and resets on every successful rotation; the monitor task
        // reads these to decide if a threshold is crossed.
        let entries_since_rotation = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let segment_open_unix = Arc::new(std::sync::atomic::AtomicI64::new(
            chrono::Utc::now().timestamp(),
        ));
        let entries_task = entries_since_rotation.clone();
        let segment_open_task = segment_open_unix.clone();
        let join = tokio::spawn(async move {
            let mut pending: Vec<AuditEvent> = Vec::with_capacity(batch_size);
            let current_log_path = log_path.clone();
            loop {
                tokio::select! {
                    biased;
                    maybe_rot = rot_rx.recv() => {
                        if let Some(req) = maybe_rot {
                            // Drain any in-flight events from the MPSC queue
                            // FIRST — they belong in the OLD log. Without
                            // this, events emitted just before rotate() would
                            // race against the biased select and land in the
                            // NEW log instead.
                            while let Ok(ev) = rx.try_recv() {
                                pending.push(ev);
                            }
                            let _ = flush(&mut log, &current_log_path, &mut pending, &metrics).await;
                            let outcome = perform_rotation(
                                &mut log,
                                &current_log_path,
                                &req,
                                signer_factory.as_deref(),
                                &metrics,
                            ).await;
                            if outcome.is_ok() {
                                // Sprint 8.5: reset segment counters after
                                // a successful rotation. Triggers in the
                                // monitor task now compare against the new
                                // segment, not the cumulative history.
                                entries_task.store(0, std::sync::atomic::Ordering::Relaxed);
                                segment_open_task.store(
                                    chrono::Utc::now().timestamp(),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                            }
                            if let Some(ack) = req.ack {
                                let _ = ack.send(outcome.clone());
                            }
                            if let Err(e) = &outcome {
                                error!("audit rotation failed for {}: {e}",
                                    current_log_path.display());
                            }
                        }
                        continue;
                    }
                    maybe = rx.recv() => {
                        match maybe {
                            Some(ev) => pending.push(ev),
                            None => {
                                let _ = flush(&mut log, &current_log_path, &mut pending, &metrics).await;
                                entries_task.store(
                                    log.entries().len() as u64,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                return;
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(500)), if !pending.is_empty() => {
                        let _ = flush(&mut log, &current_log_path, &mut pending, &metrics).await;
                        entries_task.store(
                            log.entries().len() as u64,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                }
                while pending.len() < batch_size {
                    match rx.try_recv() {
                        Ok(ev) => pending.push(ev),
                        Err(_) => break,
                    }
                }
                if pending.len() >= batch_size {
                    let _ = flush(&mut log, &current_log_path, &mut pending, &metrics).await;
                    entries_task.store(
                        log.entries().len() as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
            }
        });
        Self {
            handle: std::sync::Mutex::new(Some(handle)),
            join: tokio::sync::Mutex::new(Some(join)),
            rotation_tx: rot_tx,
            entries_since_rotation,
            segment_open_unix,
        }
    }

    /// Sprint 8: request a rotation of this channel's audit log. The
    /// background task seals the current log to `archive_path` (must not
    /// exist) and starts writing a fresh log at the original `log_path`
    /// with `new_label` in its header. The new log's first event is the
    /// `audit.rotation_open` sentinel; the old log's last event is
    /// `audit.rotation_close`. Returns the rotation outcome (Ok or a
    /// human-readable error). Fire-and-forget variants can call
    /// [`AuditChannel::request_rotation_silent`].
    pub async fn rotate(
        &self,
        archive_path: PathBuf,
        new_label: impl Into<String>,
    ) -> Result<(), String> {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        let req = RotationRequest {
            archive_path,
            new_label: new_label.into(),
            ack: Some(ack_tx),
        };
        self.rotation_tx
            .send(req)
            .await
            .map_err(|_| "audit channel closed".to_string())?;
        ack_rx
            .await
            .map_err(|_| "audit channel dropped ack".to_string())?
    }

    /// Sprint 8: fire-and-forget variant. The signal handler uses this so a
    /// burst of SIGUSR2 in quick succession collapses to at most one queued
    /// request (the channel has capacity 1 and `try_send` drops overflow).
    pub fn request_rotation_silent(&self, archive_path: PathBuf, new_label: impl Into<String>) {
        let req = RotationRequest {
            archive_path,
            new_label: new_label.into(),
            ack: None,
        };
        // try_send drops on full — that's what we want (idempotent signal).
        let _ = self.rotation_tx.try_send(req);
    }

    /// Get a cheap handle to emit events.
    ///
    /// Returns `None` if `shutdown_async` has already been called and the
    /// internal sender was taken out — emitting events after shutdown is
    /// not supported. Callers MUST hold the returned handle for the
    /// lifetime of any session that may emit events.
    #[must_use]
    pub fn handle(&self) -> AuditHandle {
        // Sprint 19: the inner handle was wrapped in Mutex<Option<_>> to
        // support idempotent shutdown. handle() returns a clone of the
        // currently-held sender, panicking with a clear message if called
        // after shutdown. The only legitimate caller path (accept loop
        // spawn) happens before shutdown by construction.
        self.handle
            .lock()
            .expect("audit channel handle mutex poisoned")
            .as_ref()
            .expect("audit channel handle() called after shutdown")
            .clone()
    }

    /// Sprint 8: cloneable rotation handle for the SIGUSR2 path.
    pub fn rotation_handle(&self) -> RotationHandle {
        RotationHandle {
            rotation_tx: self.rotation_tx.clone(),
            entries_since_rotation: self.entries_since_rotation.clone(),
            segment_open_unix: self.segment_open_unix.clone(),
        }
    }

    /// Cleanly close the channel and await the background task. Any pending
    /// events are flushed to disk before this returns.
    ///
    /// Consuming variant — preferred for the daemon-shutdown path that
    /// owns the channel by value. For shared-channel cleanup (Sprint 19
    /// SIGHUP REMOVE), see [`shutdown_async`].
    pub async fn shutdown(self) {
        // Drop the inner sender (if not already taken by shutdown_async).
        drop(self.handle.lock().expect("handle mutex poisoned").take());
        // Take the join handle and await it. If shutdown_async already took
        // it, the option is empty; nothing to await.
        let join_opt = self.join.lock().await.take();
        if let Some(join) = join_opt {
            let _ = join.await;
        }
    }

    /// Sprint 19: idempotent graceful shutdown callable from any owner of
    /// `&AuditChannel` (typically wrapped in `Arc`). The first call drops
    /// the internal sender (signaling the writer task to drain its buffer
    /// and exit) and awaits the writer task's `JoinHandle`. Subsequent
    /// calls return immediately — internal state has already been taken.
    ///
    /// Used by the SIGHUP REMOVE path to drain a tenant's audit channel
    /// before the entry is purged from the shared map. The drop-based
    /// best-effort cleanup documented in Sprint 18 §13.26.3 is replaced
    /// by this method.
    pub async fn shutdown_async(&self) {
        // Take the handle out — this drops the last sender, signalling
        // the writer task to exit its mpsc loop after draining buffered
        // events. Idempotent: if already taken, take() returns None.
        let _ = self.handle.lock().expect("handle mutex poisoned").take();
        // Take the join handle and await it. If already taken by another
        // call (or by the consuming shutdown), join_opt is None.
        let join_opt = self.join.lock().await.take();
        if let Some(join) = join_opt {
            let _ = join.await;
        }
    }
}

/// Sprint 8.5: tenant-scoped auto-rotation monitor. Periodically checks
/// configured thresholds (entries, bytes, age) against the current segment
/// and fires `request_rotation_silent` when any one is crossed.
///
/// Design notes:
/// - Polls at a fixed cadence (default 5 seconds). Misses no triggers
///   meaningfully — production policies use thresholds measured in minutes/MB.
/// - `max_bytes` reads `metadata(log_path).len()` — accurate after the last
///   batched save; the practical threshold is `max_bytes + batch_size *
///   avg_entry_size`, as documented in `RotationPolicy::max_bytes`.
/// - On a triggered rotation, the monitor reads the per-tenant counter from
///   `RotationCounters`, increments it, and renders `archive_pattern` for
///   the archive filename.
/// - Failures to read the log file size (e.g. log file temporarily moved by
///   an external tool) are logged at debug level and ignored — the next tick
///   retries.
pub struct RotationMonitor {
    tenant_name: String,
    rotation_handle: RotationHandle,
    log_path: PathBuf,
    policy: crate::RotationPolicy,
    counter: Arc<std::sync::atomic::AtomicU64>,
    poll_interval: std::time::Duration,
}

impl RotationMonitor {
    /// Build a monitor. The monitor does not run until `spawn()` is called.
    pub fn new(
        tenant_name: impl Into<String>,
        rotation_handle: RotationHandle,
        log_path: PathBuf,
        policy: crate::RotationPolicy,
        counter: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self {
            tenant_name: tenant_name.into(),
            rotation_handle,
            log_path,
            policy,
            counter,
            poll_interval: std::time::Duration::from_secs(5),
        }
    }

    /// Override the default 5-second poll interval (test hook).
    pub fn with_poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Spawn the monitor onto the current tokio runtime. Returns the join
    /// handle; the monitor runs until the rotation channel is closed (which
    /// happens when the `AuditChannel` is dropped) or until the task is
    /// aborted.
    pub fn spawn(self, shutdown: Arc<tokio::sync::Notify>) -> tokio::task::JoinHandle<()> {
        let Self {
            tenant_name,
            rotation_handle,
            log_path,
            policy,
            counter,
            poll_interval,
        } = self;
        tokio::spawn(async move {
            // If the policy has no auto-trigger, do nothing — the monitor
            // exists only to honor SIGUSR2 (which goes through a separate
            // path). This is the policy-less default in main.rs.
            if !policy.has_auto_trigger() {
                return;
            }
            loop {
                tokio::select! {
                    _ = shutdown.notified() => return,
                    _ = tokio::time::sleep(poll_interval) => {
                        let fired = check_thresholds(
                            &policy,
                            &log_path,
                            &rotation_handle,
                        );
                        if let Some(reason) = fired {
                            let n = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                            let now = chrono::Utc::now();
                            let archive_name =
                                policy.render_archive_name(&tenant_name, n, now);
                            let archive_path = log_path
                                .parent()
                                .unwrap_or_else(|| std::path::Path::new("."))
                                .join(&archive_name);
                            let new_label = format!("{}-{}", tenant_name, n);
                            tracing::info!(
                                tenant = %tenant_name,
                                reason = %reason,
                                archive = %archive_path.display(),
                                new_label = %new_label,
                                "auto-rotation triggered"
                            );
                            rotation_handle
                                .request_rotation_silent(archive_path, new_label);
                        }
                    }
                }
            }
        })
    }
}

/// Returns `Some("reason")` when at least one threshold is crossed,
/// `None` otherwise. The reason string is used in log lines.
fn check_thresholds(
    policy: &crate::RotationPolicy,
    log_path: &Path,
    rh: &RotationHandle,
) -> Option<String> {
    if let Some(max) = policy.max_entries {
        let cur = rh.entries_in_current_segment();
        if cur >= max {
            return Some(format!("max_entries reached ({cur} >= {max})"));
        }
    }
    if let Some(max) = policy.max_age_secs {
        let cur = rh.seconds_since_segment_open();
        if cur >= max {
            return Some(format!("max_age_secs reached ({cur}s >= {max}s)"));
        }
    }
    if let Some(max) = policy.max_bytes {
        if let Ok(md) = std::fs::metadata(log_path) {
            let cur = md.len();
            if cur >= max {
                return Some(format!("max_bytes reached ({cur} >= {max})"));
            }
        }
    }
    None
}

async fn perform_rotation(
    log: &mut AuditLog,
    current_log_path: &Path,
    req: &RotationRequest,
    signer_factory: Option<&dyn SignerFactory>,
    metrics: &MetricsRegistry,
) -> Result<(), String> {
    use std::sync::atomic::Ordering;
    if req.archive_path.exists() {
        return Err(format!(
            "archive_path {} already exists; refusing to overwrite",
            req.archive_path.display()
        ));
    }
    let factory = signer_factory.ok_or_else(|| {
        "channel was spawned without a SignerFactory; rotation unsupported".to_string()
    })?;
    let new_signer = factory
        .new_signer()
        .map_err(|e| format!("signer factory failed: {e}"))?;

    // Take ownership of `log` temporarily to call rotate_to (which consumes self).
    // We use mem::replace with a placeholder; the placeholder is overwritten with
    // the new log immediately after.
    let placeholder =
        make_placeholder_log().map_err(|e| format!("internal: placeholder log: {e}"))?;
    let old_log = std::mem::replace(log, placeholder);

    let (sealed_old, new_open) = old_log
        .rotate_to(new_signer, req.new_label.clone(), "")
        .map_err(|e| format!("rotate_to: {e}"))?;

    // Persist sealed old log to archive_path, new log to current_log_path.
    sealed_old
        .save(&req.archive_path)
        .map_err(|e| format!("save sealed log to {}: {e}", req.archive_path.display()))?;
    new_open
        .save(current_log_path)
        .map_err(|e| format!("save new log to {}: {e}", current_log_path.display()))?;

    // Install the new log in place of the placeholder.
    *log = new_open;
    metrics
        .inner()
        .audit_rotations
        .fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Throwaway log used only to satisfy mem::replace ownership during rotation.
/// Never written to disk, never seen by callers — replaced with the real new
/// log within microseconds.
fn make_placeholder_log() -> qaudit_core::Result<AuditLog> {
    let kp = qaudit_core::KeyPair::generate()?;
    AuditLog::create_with_label(kp, "__placeholder")
}

async fn flush(
    log: &mut AuditLog,
    log_path: &PathBuf,
    pending: &mut Vec<AuditEvent>,
    metrics: &MetricsRegistry,
) -> Result<(), ()> {
    if pending.is_empty() {
        return Ok(());
    }
    for ev in pending.drain(..) {
        if let Err(e) = log.append(ev) {
            error!("audit append failed: {e}");
            metrics
                .inner()
                .audit_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(());
        }
    }
    if let Err(e) = log.save(log_path) {
        error!("audit save failed: {e}");
        metrics
            .inner()
            .audit_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qaudit_core::KeyPair;
    use tempfile::TempDir;

    #[tokio::test(flavor = "current_thread")]
    async fn emits_and_persists() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.qa");
        let kp = KeyPair::generate().unwrap();
        let log = AuditLog::create_with_label(kp, "audit-channel-test").unwrap();
        // Persist initial empty log so the file exists.
        log.save(&log_path).unwrap();

        // For the channel we need a fresh writable log; keep the same on-disk
        // file by reusing the path.
        let kp2 = KeyPair::generate().unwrap();
        let log_for_channel = AuditLog::create_with_label(kp2, "audit-channel-test").unwrap();

        let metrics = MetricsRegistry::new("test");
        let ch = AuditChannel::spawn(log_for_channel, log_path.clone(), metrics.clone(), 16, 4);
        let h = ch.handle();
        for i in 0..6 {
            h.emit(
                AuditEvent::builder()
                    .actor("svc:qgateway")
                    .action("test.event")
                    .resource(format!("test://{i}"))
                    .meta("seq", i.to_string())
                    .build(),
            );
        }
        // Allow batch flush.
        tokio::time::sleep(Duration::from_millis(800)).await;
        drop(h);
        ch.shutdown().await;

        let reopened = AuditLog::open(&log_path).unwrap();
        assert_eq!(reopened.len(), 6);
        reopened.verify().unwrap();
        assert_eq!(
            metrics
                .inner()
                .audit_events
                .load(std::sync::atomic::Ordering::Relaxed),
            6
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn backpressure_increments_failure_counter() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.qa");
        let kp = KeyPair::generate().unwrap();
        let log = AuditLog::create_with_label(kp, "bp").unwrap();
        log.save(&log_path).unwrap();
        let kp2 = KeyPair::generate().unwrap();
        let writable = AuditLog::create_with_label(kp2, "bp").unwrap();

        let metrics = MetricsRegistry::new("test");
        // Tiny capacity to trigger backpressure quickly.
        let ch = AuditChannel::spawn(writable, log_path.clone(), metrics.clone(), 2, 1024);
        let h = ch.handle();
        for _ in 0..200 {
            h.emit(
                AuditEvent::builder()
                    .actor("a")
                    .action("b")
                    .resource("c")
                    .build(),
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(h);
        ch.shutdown().await;
        let failures = metrics
            .inner()
            .audit_failures
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(failures > 0, "expected backpressure drops, got 0");
    }

    // ========================================================================
    //              Sprint 8 — channel rotation tests
    // ========================================================================

    /// SignerFactory that mints a fresh same-pubkey software signer. The new
    /// log's header carries the same pubkey as the old one.
    struct CloneKeyFactory(qaudit_core::PublicKey, qaudit_core::SecretKey);
    impl SignerFactory for CloneKeyFactory {
        fn new_signer(&self) -> qaudit_core::Result<Box<dyn qaudit_core::Signer>> {
            let kp = KeyPair::from_parts(self.0.clone(), self.1.clone());
            Ok(Box::new(kp))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rotate_seals_old_log_and_opens_new() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.qa");
        let archive_path = tmp.path().join("audit-archived.qa");

        let kp = KeyPair::generate().unwrap();
        let pk = kp.public().clone();
        let sk = kp.secret().clone();
        let log = AuditLog::create_with_label(kp, "rot-test").unwrap();
        log.save(&log_path).unwrap();
        let kp2 = KeyPair::from_parts(pk.clone(), sk.clone());
        let writable = AuditLog::create_with_label(kp2, "rot-test").unwrap();

        let metrics = MetricsRegistry::new("test");
        let factory = CloneKeyFactory(pk, sk);
        let ch = AuditChannel::spawn_with_rotation(
            writable,
            log_path.clone(),
            metrics.clone(),
            16,
            4,
            factory,
        );
        let h = ch.handle();
        // Emit a few events.
        for i in 0..3 {
            h.emit(
                AuditEvent::builder()
                    .action("test.before_rotation")
                    .meta("i", i.to_string())
                    .build(),
            );
        }
        // Trigger rotation. The channel's rotation arm drains any pending
        // events from the MPSC queue before sealing the old log, so all 3
        // events above land in the OLD log along with the rotation_close
        // sentinel.
        ch.rotate(archive_path.clone(), "rot-test-2")
            .await
            .expect("rotation must succeed");

        // Emit one more after rotation.
        h.emit(AuditEvent::builder().action("test.after_rotation").build());
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(h);
        ch.shutdown().await;

        // Verify both files exist and form a valid chain.
        assert!(archive_path.exists(), "archive must be written");
        assert!(log_path.exists(), "new log must be at original path");
        let old_log = AuditLog::open(&archive_path).expect("open archive");
        let new_log = AuditLog::open(&log_path).expect("open new log");
        AuditLog::verify_chain(&[&old_log, &new_log]).expect("chain must verify");

        // The new log's label is the rotation argument.
        assert_eq!(new_log.header().label, "rot-test-2");
        // Old log has 3 + 1 (rotation_close) = 4 events.
        assert_eq!(old_log.entries().len(), 4);
        // New log has 1 (rotation_open) + 1 (after_rotation) = 2 events.
        assert_eq!(new_log.entries().len(), 2);

        let rotations = metrics
            .inner()
            .audit_rotations
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(rotations, 1, "audit_rotations metric must increment");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rotate_without_signer_factory_fails_soft() {
        // A channel spawned via plain `spawn` (no factory) MUST return a
        // clear error on rotate() — never panic, never silently swallow.
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.qa");
        let archive_path = tmp.path().join("audit-archived.qa");
        let kp = KeyPair::generate().unwrap();
        let log = AuditLog::create_with_label(kp, "no-rot").unwrap();
        log.save(&log_path).unwrap();
        let kp2 = KeyPair::generate().unwrap();
        let writable = AuditLog::create_with_label(kp2, "no-rot").unwrap();

        let metrics = MetricsRegistry::new("test");
        let ch = AuditChannel::spawn(writable, log_path, metrics, 16, 4);

        let err = ch
            .rotate(archive_path, "new-label")
            .await
            .expect_err("must fail without factory");
        assert!(
            err.contains("SignerFactory") || err.contains("unsupported"),
            "expected factory-missing error, got: {err}"
        );
        ch.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rotate_refuses_existing_archive_path() {
        // Atomicity: if archive_path already exists, rotation aborts with a
        // clear error and the channel keeps writing to the original log.
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.qa");
        let archive_path = tmp.path().join("audit-archived.qa");
        // Pre-create the archive path.
        std::fs::write(&archive_path, b"existing junk").unwrap();

        let kp = KeyPair::generate().unwrap();
        let pk = kp.public().clone();
        let sk = kp.secret().clone();
        let log = AuditLog::create_with_label(kp, "no-overwrite").unwrap();
        log.save(&log_path).unwrap();
        let kp2 = KeyPair::from_parts(pk.clone(), sk.clone());
        let writable = AuditLog::create_with_label(kp2, "no-overwrite").unwrap();

        let metrics = MetricsRegistry::new("test");
        let factory = CloneKeyFactory(pk, sk);
        let ch =
            AuditChannel::spawn_with_rotation(writable, log_path, metrics.clone(), 16, 4, factory);

        let err = ch
            .rotate(archive_path, "should-fail")
            .await
            .expect_err("must refuse overwrite");
        assert!(err.contains("already exists"), "got: {err}");

        // No rotation should have been counted.
        let rotations = metrics
            .inner()
            .audit_rotations
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(rotations, 0);
        ch.shutdown().await;
    }

    // ========================================================================
    //              Sprint 8.5 — auto-rotation monitor tests
    // ========================================================================

    use crate::RotationPolicy;

    #[tokio::test(flavor = "current_thread")]
    async fn monitor_fires_rotation_on_max_entries() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.qa");

        let kp = KeyPair::generate().unwrap();
        let pk = kp.public().clone();
        let sk = kp.secret().clone();
        let log = AuditLog::create_with_label(kp, "mon").unwrap();
        log.save(&log_path).unwrap();
        let kp2 = KeyPair::from_parts(pk.clone(), sk.clone());
        let writable = AuditLog::create_with_label(kp2, "mon").unwrap();

        let metrics = MetricsRegistry::new("test");
        let factory = CloneKeyFactory(pk, sk);
        let ch = AuditChannel::spawn_with_rotation(
            writable,
            log_path.clone(),
            metrics.clone(),
            16,
            1,
            factory,
        );
        let policy = RotationPolicy {
            max_entries: Some(2),
            max_bytes: None,
            max_age_secs: None,
            poll_interval_ms: None,
            archive_pattern: "{label}-{counter}.qa".to_string(),
        };
        assert!(policy.has_auto_trigger());

        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let monitor = crate::RotationMonitor::new(
            "mon",
            ch.rotation_handle(),
            log_path.clone(),
            policy,
            counter.clone(),
        )
        .with_poll_interval(Duration::from_millis(50));
        let mon_handle = monitor.spawn(shutdown.clone());

        let h = ch.handle();
        // Emit 5 events — the monitor should fire rotation when entries >= 2.
        for i in 0..5 {
            h.emit(
                AuditEvent::builder()
                    .action("test")
                    .meta("i", i.to_string())
                    .build(),
            );
            // Yield so the channel's background task flushes batch_size=1.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Wait a few monitor cycles.
        tokio::time::sleep(Duration::from_millis(300)).await;

        let rotations = metrics
            .inner()
            .audit_rotations
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            rotations >= 1,
            "monitor must have fired at least one rotation, got 0"
        );
        assert!(
            counter.load(std::sync::atomic::Ordering::Relaxed) >= 1,
            "rotation counter must have incremented"
        );

        shutdown.notify_waiters();
        let _ = mon_handle.await;
        drop(h);
        ch.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn monitor_with_no_triggers_exits_immediately() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.qa");

        let kp = KeyPair::generate().unwrap();
        let pk = kp.public().clone();
        let sk = kp.secret().clone();
        let log = AuditLog::create_with_label(kp, "no-trig").unwrap();
        log.save(&log_path).unwrap();
        let kp2 = KeyPair::from_parts(pk.clone(), sk.clone());
        let writable = AuditLog::create_with_label(kp2, "no-trig").unwrap();
        let metrics = MetricsRegistry::new("test");
        let factory = CloneKeyFactory(pk, sk);
        let ch =
            AuditChannel::spawn_with_rotation(writable, log_path.clone(), metrics, 16, 4, factory);

        // Policy with no thresholds set.
        let policy = RotationPolicy {
            max_entries: None,
            max_bytes: None,
            max_age_secs: None,
            poll_interval_ms: None,
            archive_pattern: "x.qa".to_string(),
        };
        assert!(!policy.has_auto_trigger());

        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let monitor =
            crate::RotationMonitor::new("no-trig", ch.rotation_handle(), log_path, policy, counter);
        let mon_handle = monitor.spawn(shutdown.clone());
        // Monitor must return immediately because policy has no triggers.
        tokio::time::timeout(Duration::from_secs(1), mon_handle)
            .await
            .expect("monitor must exit promptly")
            .expect("monitor task panicked");
        ch.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn monitor_respects_shutdown_signal() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.qa");

        let kp = KeyPair::generate().unwrap();
        let pk = kp.public().clone();
        let sk = kp.secret().clone();
        let log = AuditLog::create_with_label(kp, "sd").unwrap();
        log.save(&log_path).unwrap();
        let kp2 = KeyPair::from_parts(pk.clone(), sk.clone());
        let writable = AuditLog::create_with_label(kp2, "sd").unwrap();
        let metrics = MetricsRegistry::new("test");
        let factory = CloneKeyFactory(pk, sk);
        let ch =
            AuditChannel::spawn_with_rotation(writable, log_path.clone(), metrics, 16, 4, factory);

        // Policy with a never-fires threshold so the monitor only exits on shutdown.
        let policy = RotationPolicy {
            max_entries: Some(u64::MAX),
            max_bytes: None,
            max_age_secs: None,
            poll_interval_ms: None,
            archive_pattern: "x.qa".to_string(),
        };

        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let monitor =
            crate::RotationMonitor::new("sd", ch.rotation_handle(), log_path, policy, counter)
                .with_poll_interval(Duration::from_millis(50));
        let mon_handle = monitor.spawn(shutdown.clone());

        // Let the monitor enter the select loop and register its waker on
        // the Notify before we signal it. Without this yield, notify_waiters
        // races against the spawn and may signal before any future is
        // listening — Notify is not sticky.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Signal shutdown; monitor must exit promptly.
        shutdown.notify_waiters();
        tokio::time::timeout(Duration::from_secs(1), mon_handle)
            .await
            .expect("monitor must exit on shutdown")
            .expect("monitor task panicked");
        ch.shutdown().await;
    }

    // ====================================================================
    //         Sprint 19 — shutdown_async + Arc<AuditChannel>
    // ====================================================================

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_async_flushes_pending_events() {
        // Sprint 19: shutdown_async() must wait for the writer task to
        // drain its buffer before returning. Emit events, immediately
        // call shutdown_async(), then re-open the log and verify all
        // events made it to disk.
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.qa");
        let kp = KeyPair::generate().unwrap();
        let log = AuditLog::create_with_label(kp, "sprint19-test").unwrap();
        log.save(&log_path).unwrap();
        let kp2 = KeyPair::generate().unwrap();
        let log_for_channel = AuditLog::create_with_label(kp2, "sprint19-test").unwrap();
        let metrics = MetricsRegistry::new("sprint19-tenant");
        // Larger batch so events sit in buffer until shutdown forces flush.
        let ch = Arc::new(AuditChannel::spawn(
            log_for_channel,
            log_path.clone(),
            metrics,
            64,
            32,
        ));
        let h = ch.handle();
        for i in 0..10 {
            h.emit(
                AuditEvent::builder()
                    .actor("svc:test")
                    .action("test.event")
                    .resource(format!("test://{i}"))
                    .build(),
            );
        }
        drop(h);
        // shutdown_async must drain ALL events before returning.
        ch.shutdown_async().await;

        let reopened = AuditLog::open(&log_path).unwrap();
        assert_eq!(reopened.len(), 10, "shutdown_async must flush all events");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_async_is_idempotent() {
        // Sprint 19: calling shutdown_async() multiple times must be
        // safe. First call drains; subsequent calls are no-ops.
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.qa");
        let kp = KeyPair::generate().unwrap();
        let log = AuditLog::create_with_label(kp, "sprint19-idempotent").unwrap();
        log.save(&log_path).unwrap();
        let kp2 = KeyPair::generate().unwrap();
        let log_for_channel = AuditLog::create_with_label(kp2, "sprint19-idempotent").unwrap();
        let metrics = MetricsRegistry::new("sprint19-tenant");
        let ch = Arc::new(AuditChannel::spawn(
            log_for_channel,
            log_path,
            metrics,
            16,
            4,
        ));
        let h = ch.handle();
        h.emit(
            AuditEvent::builder()
                .actor("svc:test")
                .action("test.event")
                .resource("test://1")
                .build(),
        );
        drop(h);

        // Three concurrent shutdowns — exactly one drains, others are no-ops.
        // None must hang or panic.
        let ch1 = ch.clone();
        let ch2 = ch.clone();
        let ch3 = ch.clone();
        let (r1, r2, r3) = tokio::join!(
            ch1.shutdown_async(),
            ch2.shutdown_async(),
            ch3.shutdown_async(),
        );
        let _ = (r1, r2, r3);
        // Drop the original Arc cleanly.
        drop(ch);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_async_then_consuming_shutdown_safe() {
        // Sprint 19: after shutdown_async, the consuming shutdown(self)
        // must still complete cleanly (internal Option already taken,
        // nothing to do).
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.qa");
        let kp = KeyPair::generate().unwrap();
        let log = AuditLog::create_with_label(kp, "sprint19-both").unwrap();
        log.save(&log_path).unwrap();
        let kp2 = KeyPair::generate().unwrap();
        let log_for_channel = AuditLog::create_with_label(kp2, "sprint19-both").unwrap();
        let metrics = MetricsRegistry::new("sprint19-tenant");
        let ch = AuditChannel::spawn(log_for_channel, log_path, metrics, 16, 4);
        ch.shutdown_async().await;
        // Consume by value. Must not hang or panic.
        ch.shutdown().await;
    }
}
