//! Dedicated writer thread of the host-audit lane.
//!
//! The writer takes slots from the front of the lanes (global queue order,
//! so every chain's FIFO order is kept) and appends them with one
//! `append_batch_with_principal` call. That call signs the entries in slice
//! order against each chain's durable head and commits the batch atomically
//! under the audit log's durable append lock, so the chain position and the
//! signature are assigned where they become durable. A failed batch is
//! retried as-is before anything queued behind it is taken, so a failure
//! never reorders entries.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use astrid_audit::AuditLog;
use astrid_core::{PrincipalId, SessionId, Timestamp};
use astrid_storage::ScopedKvStore;
use tracing::warn;

use super::HostAuditPolicy;
use super::lane::{Lanes, Lifecycle, Slot, SlotKind, gap_entry};
use super::marker::{GapDuty, LaneMarker};

/// Attempts at a failing batch once shutdown has been requested.
const SHUTDOWN_ATTEMPTS: u32 = 3;
/// Longest wait between attempts at a failing batch.
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// State shared by host-call producers and the writer.
pub(super) struct Shared {
    pub(super) lanes: Mutex<Lanes>,
    /// Wakes the writer: new slot or shutdown.
    pub(super) wake: Condvar,
    pub(super) health: Mutex<HealthState>,
}

impl Shared {
    pub(super) fn lanes(&self) -> MutexGuard<'_, Lanes> {
        self.lanes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn health(&self) -> MutexGuard<'_, HealthState> {
        self.health.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn note_error(&self, error: String) {
        warn!(security_event = true, %error, "host-audit lane degraded");
        self.health().last_error = Some(error);
    }

    fn note_marker_error(&self) {
        let mut health = self.health();
        health.marker_errors = health.marker_errors.saturating_add(1);
    }
}

/// Counters behind [`AuditSinkHealth`](super::AuditSinkHealth).
#[derive(Default)]
pub(super) struct HealthState {
    pub(super) persisted: u64,
    pub(super) lost: u64,
    pub(super) failed: u64,
    pub(super) collapsed_repeats: u64,
    pub(super) gaps_recorded: u64,
    pub(super) dropped_after_shutdown: u64,
    pub(super) marker_errors: u64,
    pub(super) worker_alive: bool,
    pub(super) last_error: Option<String>,
}

/// What the writer needs besides the shared state.
pub(super) struct WriterConfig {
    pub(super) audit_log: Arc<AuditLog>,
    pub(super) session: SessionId,
    pub(super) policy: HostAuditPolicy,
    pub(super) marker: Option<ScopedKvStore>,
}

/// One unit of writer work.
struct Work {
    slots: Vec<Slot>,
    register: Vec<PrincipalId>,
}

/// Gap bookkeeping of the current lane run.
struct Gaps {
    /// Per-chain gap entries not yet durable.
    chain_entries: usize,
    /// System-chain gap entries not yet durable.
    system: Vec<GapDuty>,
}

struct Writer<'a> {
    shared: &'a Shared,
    config: &'a WriterConfig,
    runtime: tokio::runtime::Runtime,
    marker: Option<LaneMarker>,
    /// Chains whose registration failed; retried with the next work item
    /// rather than at once, so a failing marker store is not hammered.
    unregistered: Vec<PrincipalId>,
    gaps: Gaps,
}

/// Writer thread body.
pub(super) fn run(shared: &Shared, config: &WriterConfig) {
    shared.health().worker_alive = true;
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            shared.note_error(format!("failed to create audit writer runtime: {error}"));
            stop(shared);
            return;
        },
    };
    let mut writer = Writer {
        shared,
        config,
        runtime,
        marker: None,
        unregistered: Vec::new(),
        gaps: Gaps {
            chain_entries: 0,
            system: Vec::new(),
        },
    };
    writer.open_marker();
    let mut drained = true;
    while let Some(work) = writer.next_work() {
        writer.register(work.register);
        writer.record_system_gaps();
        if !writer.persist(&work.slots) {
            drained = false;
            break;
        }
        writer.settle_gaps();
    }
    let abandoned = shared.lanes().lifecycle == Lifecycle::Abandoned;
    if drained && !abandoned {
        writer.close_marker();
    }
    stop(shared);
}

/// Refuse further calls.
fn stop(shared: &Shared) {
    {
        let mut lanes = shared.lanes();
        if lanes.lifecycle != Lifecycle::Abandoned {
            lanes.lifecycle = Lifecycle::Closed;
        }
    }
    shared.health().worker_alive = false;
}

impl Writer<'_> {
    fn open_marker(&mut self) {
        let Some(store) = self.config.marker.clone() else {
            return;
        };
        let epoch = uuid::Uuid::new_v4().to_string();
        match LaneMarker::open(&self.runtime, store, epoch, Timestamp::now()) {
            Ok((marker, duties)) => {
                self.marker = Some(marker);
                self.queue_gaps(duties);
            },
            Err(error) => {
                self.shared.note_marker_error();
                self.shared.note_error(error);
            },
        }
    }

    /// Put a gap slot in front of every chain a stopped run registered, and
    /// queue one system-chain gap entry per stopped run.
    fn queue_gaps(&mut self, duties: Vec<GapDuty>) {
        let now = Instant::now();
        let mut lanes = self.shared.lanes();
        // Each gap goes in front of its chain, so push the newest run first
        // and the oldest run's gap ends up at the very front.
        for duty in duties.iter().rev() {
            for chain in &duty.chains {
                let Ok(principal) = PrincipalId::new(chain.as_str()) else {
                    continue;
                };
                lanes.push_gap_front(&principal, duty.epoch.clone(), duty.opened_at, now);
                self.gaps.chain_entries = self.gaps.chain_entries.saturating_add(1);
            }
        }
        drop(lanes);
        self.gaps.system = duties;
        self.shared.wake.notify_one();
    }

    fn next_work(&self) -> Option<Work> {
        let policy = &self.config.policy;
        let mut lanes = self.shared.lanes();
        loop {
            if lanes.lifecycle == Lifecycle::Abandoned {
                return None;
            }
            let draining = lanes.lifecycle == Lifecycle::Draining;
            let queued = lanes.queued_slots();
            if queued == 0 && !lanes.urgent() {
                if draining {
                    // Refuse further calls in the same critical section that
                    // saw the queue empty, so none is queued after the drain.
                    lanes.lifecycle = Lifecycle::Closed;
                    return None;
                }
                lanes = self
                    .shared
                    .wake
                    .wait(lanes)
                    .unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            let now = Instant::now();
            let waited = lanes.pending_since().map_or(policy.coalesce, |since| {
                now.saturating_duration_since(since)
            });
            let due = draining
                || lanes.urgent()
                || queued >= policy.max_batch
                || waited >= policy.coalesce;
            if !due {
                lanes = self
                    .shared
                    .wake
                    .wait_timeout(lanes, policy.coalesce.saturating_sub(waited))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
                continue;
            }
            let register = lanes.take_unregistered();
            let slots = lanes.take(policy.max_batch, now);
            return Some(Work { slots, register });
        }
    }

    /// Add chains to the lane marker before their first entry is written.
    ///
    /// If the marker cannot be written, the entries are still appended: a
    /// crash then leaves no gap entry in those chains, only the system-chain
    /// gap entry, and health reports the marker error.
    fn register(&mut self, principals: Vec<PrincipalId>) {
        self.unregistered.extend(principals);
        if self.unregistered.is_empty() {
            return;
        }
        let Some(marker) = self.marker.as_mut() else {
            self.unregistered.clear();
            return;
        };
        match marker.register(&self.runtime, &self.unregistered) {
            Ok(()) => self.unregistered.clear(),
            Err(error) => {
                self.shared.note_marker_error();
                self.shared.note_error(error);
            },
        }
    }

    fn record_system_gaps(&mut self) {
        while let Some(duty) = self.gaps.system.first() {
            let (action, authorization, outcome) = gap_entry(&duty.epoch, duty.opened_at);
            let appended = self.runtime.block_on(self.config.audit_log.append(
                self.config.session.clone(),
                action,
                authorization,
                outcome,
            ));
            match appended {
                Ok(_) => {
                    self.gaps.system.remove(0);
                    let mut health = self.shared.health();
                    health.gaps_recorded = health.gaps_recorded.saturating_add(1);
                },
                Err(error) => {
                    self.shared
                        .note_error(format!("system-chain gap entry failed: {error}"));
                    return;
                },
            }
        }
    }

    /// Clear the marker's gap duties once every gap entry is durable.
    fn settle_gaps(&mut self) {
        if self.gaps.chain_entries > 0 || !self.gaps.system.is_empty() {
            return;
        }
        if let Some(marker) = self.marker.as_mut()
            && let Err(error) = marker.gaps_recorded(&self.runtime)
        {
            self.shared.note_marker_error();
            self.shared.note_error(error);
        }
    }

    fn close_marker(&mut self) {
        self.record_system_gaps();
        self.settle_gaps();
        if let Some(marker) = self.marker.as_mut()
            && let Err(error) = marker.close(&self.runtime)
        {
            self.shared.note_marker_error();
            self.shared.note_error(error);
        }
    }

    /// Append `slots` in order, retrying until durable. Returns `false` when
    /// shutdown gave up on a failing batch.
    fn persist(&mut self, slots: &[Slot]) -> bool {
        let mut attempt = 0_u32;
        loop {
            if slots.is_empty() {
                return true;
            }
            let requests = slots
                .iter()
                .map(|slot| slot.request(&self.config.session))
                .collect();
            let results = self
                .runtime
                .block_on(self.config.audit_log.append_batch_with_principal(requests));
            let error = if results.len() == slots.len() {
                results
                    .into_iter()
                    .find_map(Result::err)
                    .map(|error| error.to_string())
            } else {
                Some("audit batch returned a partial result".to_owned())
            };
            let Some(error) = error else {
                self.settle(slots);
                return true;
            };
            attempt = attempt.saturating_add(1);
            {
                let mut health = self.shared.health();
                health.failed = health.failed.saturating_add(1);
            }
            self.shared
                .note_error(format!("host-audit batch append failed: {error}"));
            if !self.backoff(attempt) {
                return false;
            }
        }
    }

    /// Wait before the next attempt. Returns `false` when shutdown has used
    /// up its attempts.
    fn backoff(&self, attempt: u32) -> bool {
        let mut lanes = self.shared.lanes();
        if lanes.lifecycle == Lifecycle::Abandoned
            || (lanes.lifecycle == Lifecycle::Draining && attempt >= SHUTDOWN_ATTEMPTS)
        {
            return false;
        }
        let factor = 1_u32
            .checked_shl(attempt.saturating_sub(1).min(16))
            .unwrap_or(u32::MAX);
        let delay = Duration::from_millis(100)
            .saturating_mul(factor)
            .min(MAX_BACKOFF);
        let deadline = Instant::now().checked_add(delay);
        let was = lanes.lifecycle;
        while let Some(remaining) = deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .filter(|remaining| !remaining.is_zero())
        {
            lanes = self
                .shared
                .wake
                .wait_timeout(lanes, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
            if lanes.lifecycle != was {
                break;
            }
        }
        lanes.lifecycle != Lifecycle::Abandoned
    }

    /// Account a durable batch.
    fn settle(&mut self, slots: &[Slot]) {
        let settled: u64 = slots.iter().map(Slot::calls).sum();
        {
            let mut lanes = self.shared.lanes();
            lanes.queued_calls = lanes.queued_calls.saturating_sub(settled);
        }
        let mut health = self.shared.health();
        for slot in slots {
            let calls = slot.calls();
            match &slot.kind {
                SlotKind::Run { .. } => {
                    health.persisted = health.persisted.saturating_add(calls);
                    health.collapsed_repeats = health
                        .collapsed_repeats
                        .saturating_add(calls.saturating_sub(1));
                },
                SlotKind::Loss { .. } => health.lost = health.lost.saturating_add(calls),
                SlotKind::Gap { .. } => {
                    health.gaps_recorded = health.gaps_recorded.saturating_add(1);
                    self.gaps.chain_entries = self.gaps.chain_entries.saturating_sub(1);
                },
            }
        }
    }
}
