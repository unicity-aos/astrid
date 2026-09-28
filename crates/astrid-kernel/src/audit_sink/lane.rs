//! Per-chain ordered lanes of pending host-audit records.
//!
//! Every principal's chain has a FIFO of slots. A call is placed in its
//! chain's FIFO under the one `Lanes` mutex, so FIFO order is call order, and
//! the writer only ever removes slots from the front. A slot becomes one
//! signed entry, so append order equals call order.
//!
//! Consecutive calls fold into the chain's tail slot while it is still
//! queued: allowed and failed calls of any class share one run, and identical
//! denials share one run. A different denial or a loss closes the run. Folding needs no queue capacity.
//!
//! When the queue is full, a call that cannot fold into the tail slot goes
//! into a loss slot at the tail of its chain instead. Later calls fold into
//! that loss slot while the queue stays full, so each chain holds at most one
//! loss slot beyond capacity and memory stays bounded.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use astrid_audit::host_call::{
    HostCallFold, HostCallOutcome, HostCallRef, HostCallSummary, HostCallTally, host_call_class,
    host_call_digest,
};
use astrid_audit::{AuditAction, AuditOutcome, AuthorizationProof};
use astrid_core::{PrincipalId, SessionId, Timestamp};
use astrid_crypto::ContentHash;

use super::MANIFEST_GATED_REASON;

/// Authorization reason on entries the lane writes about itself (loss and
/// gap records).
const LANE_ACCOUNTING_REASON: &str = "host-audit lane accounting";
/// Loss reason for calls that met a full queue.
pub(super) const QUEUE_FULL: &str = "queue_full";
/// Gap reason for a lane run that stopped without draining.
pub(super) const UNCLEAN_SHUTDOWN: &str = "unclean_shutdown";

/// One host call, as a single-call entry would record it.
pub(super) struct Call {
    pub(super) action: AuditAction,
    pub(super) outcome: HostCallOutcome,
    /// Error (failed) or denial reason (denied); empty for ok.
    pub(super) detail: String,
    pub(super) at: Timestamp,
}

impl Call {
    fn digest(&self) -> ContentHash {
        host_call_digest(&HostCallRef {
            action: &self.action,
            outcome: self.outcome,
            detail: &self.detail,
            at: &self.at,
        })
        .unwrap_or_else(ContentHash::zero)
    }

    fn run_key(&self) -> RunKey {
        if self.outcome != HostCallOutcome::Denied {
            return RunKey::Calls;
        }
        let mut identity = serde_json::to_vec(&self.action).unwrap_or_default();
        identity.push(0);
        identity.extend_from_slice(self.detail.as_bytes());
        RunKey::Denied(ContentHash::hash(&identity))
    }
}

/// Which calls may share a run.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RunKey {
    /// Allowed and failed calls of any class.
    Calls,
    /// Denials with this action and reason.
    Denied(ContentHash),
}

/// Running summary of consecutive calls; see [`HostCallSummary`].
pub(super) struct Summary {
    count: u64,
    failed: u64,
    first_at: Timestamp,
    last_at: Timestamp,
    fold: HostCallFold,
    tally: Vec<HostCallTally>,
}

impl Summary {
    pub(super) fn new(call: Call) -> Self {
        let mut summary = Self {
            count: 0,
            failed: 0,
            first_at: call.at,
            last_at: call.at,
            fold: HostCallFold::new(),
            tally: Vec::new(),
        };
        summary.push(call);
        summary
    }

    pub(super) fn push(&mut self, call: Call) {
        self.fold.push(&call.digest());
        self.count = self.count.saturating_add(1);
        if call.outcome == HostCallOutcome::Failed {
            self.failed = self.failed.saturating_add(1);
        }
        self.last_at = call.at;
        let class = host_call_class(&call.action).unwrap_or("unknown");
        if let Some(tally) = self
            .tally
            .iter_mut()
            .find(|tally| tally.class == class && tally.outcome == call.outcome)
        {
            tally.count = tally.count.saturating_add(1);
            return;
        }
        self.tally.push(HostCallTally {
            class: class.to_owned(),
            outcome: call.outcome,
            count: 1,
            first: call.action,
            first_detail: (!call.detail.is_empty()).then_some(call.detail),
        });
    }

    pub(super) fn count(&self) -> u64 {
        self.count
    }

    fn signed(&self) -> HostCallSummary {
        HostCallSummary {
            count: self.count,
            first_at: self.first_at,
            last_at: self.last_at,
            fold: self.fold.value(),
            tally: self.tally.clone(),
        }
    }

    /// The single call of a one-call run, as its own entry.
    fn single(&self) -> Option<(AuditAction, AuthorizationProof, AuditOutcome)> {
        let tally = self.tally.first()?;
        let detail = tally.first_detail.clone().unwrap_or_default();
        let (authorization, outcome) = match tally.outcome {
            HostCallOutcome::Ok => (manifest_gated(), AuditOutcome::success()),
            HostCallOutcome::Failed => (manifest_gated(), AuditOutcome::failure(detail)),
            HostCallOutcome::Denied => (
                AuthorizationProof::Denied {
                    reason: detail.clone(),
                },
                AuditOutcome::failure(detail),
            ),
        };
        Some((tally.first.clone(), authorization, outcome))
    }
}

fn manifest_gated() -> AuthorizationProof {
    AuthorizationProof::System {
        reason: MANIFEST_GATED_REASON.into(),
    }
}

fn lane_accounting() -> AuthorizationProof {
    AuthorizationProof::System {
        reason: LANE_ACCOUNTING_REASON.into(),
    }
}

/// What a slot becomes on the chain.
pub(super) enum SlotKind {
    /// Consecutive calls sharing a run key.
    Run { key: RunKey, calls: Summary },
    /// Calls that met a full queue.
    Loss { calls: Summary },
    /// A previous lane run stopped without draining.
    Gap { epoch: String, opened_at: Timestamp },
}

/// One future entry on a principal's chain.
pub(super) struct Slot {
    order: u64,
    pub(super) principal: PrincipalId,
    pub(super) kind: SlotKind,
}

/// Entry fields the batch append API takes.
pub(super) type AppendRequest = (
    SessionId,
    PrincipalId,
    AuditAction,
    AuthorizationProof,
    AuditOutcome,
);

impl Slot {
    /// Calls this slot records (run) or accounts for (loss).
    pub(super) fn calls(&self) -> u64 {
        match &self.kind {
            SlotKind::Run { calls, .. } | SlotKind::Loss { calls } => calls.count(),
            SlotKind::Gap { .. } => 0,
        }
    }

    /// The signed entry this slot becomes.
    pub(super) fn request(&self, session: &SessionId) -> AppendRequest {
        let (action, authorization, outcome) = match &self.kind {
            SlotKind::Run { key, calls } => run_entry(*key, calls),
            SlotKind::Loss { calls } => (
                AuditAction::HostCallLoss {
                    calls: calls.signed(),
                    reason: QUEUE_FULL.to_owned(),
                },
                lane_accounting(),
                AuditOutcome::failure(format!(
                    "{} host calls not recorded individually: {QUEUE_FULL}",
                    calls.count()
                )),
            ),
            SlotKind::Gap { epoch, opened_at } => gap_entry(epoch, *opened_at),
        };
        (
            session.clone(),
            self.principal.clone(),
            action,
            authorization,
            outcome,
        )
    }
}

fn run_entry(key: RunKey, calls: &Summary) -> (AuditAction, AuthorizationProof, AuditOutcome) {
    if calls.count() == 1
        && let Some(single) = calls.single()
    {
        return single;
    }
    let action = AuditAction::HostCallRun {
        calls: calls.signed(),
    };
    match key {
        RunKey::Calls if calls.failed == 0 => (action, manifest_gated(), AuditOutcome::success()),
        RunKey::Calls => (
            action,
            manifest_gated(),
            AuditOutcome::failure(format!(
                "{} of {} host calls failed",
                calls.failed,
                calls.count()
            )),
        ),
        RunKey::Denied(_) => {
            let reason = calls
                .tally
                .first()
                .and_then(|tally| tally.first_detail.clone())
                .unwrap_or_default();
            (
                action,
                AuthorizationProof::Denied {
                    reason: reason.clone(),
                },
                AuditOutcome::failure(reason),
            )
        },
    }
}

/// The gap entry for a lane run that stopped without draining.
pub(super) fn gap_entry(
    epoch: &str,
    opened_at: Timestamp,
) -> (AuditAction, AuthorizationProof, AuditOutcome) {
    (
        AuditAction::HostCallGap {
            epoch: epoch.to_owned(),
            opened_at,
            reason: UNCLEAN_SHUTDOWN.to_owned(),
        },
        lane_accounting(),
        AuditOutcome::failure(format!("host-audit lane {epoch} stopped without draining")),
    )
}

#[derive(Default)]
struct ChainLane {
    fifo: VecDeque<Slot>,
    /// Whether this chain was queued for the lane marker in this lane run.
    registered: bool,
}

/// Result of offering one call to the lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Pushed {
    /// Folded into the chain's queued tail run.
    Folded,
    /// Queued as a new run slot.
    Queued,
    /// Accounted in a loss slot because the queue was full.
    Lost,
    /// The writer has stopped; nothing was queued.
    Closed,
}

/// Life of a lane run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Lifecycle {
    /// Accepting calls.
    Open,
    /// Shutdown requested: the writer drains without waiting for the window.
    Draining,
    /// The writer has stopped; calls are no longer queued.
    Closed,
    /// Test hook: the writer stopped at once without draining or closing the
    /// lane marker, as if the process had died.
    Abandoned,
}

impl Lifecycle {
    fn refuses_calls(self) -> bool {
        matches!(self, Self::Closed | Self::Abandoned)
    }
}

/// All pending slots, keyed by principal chain.
pub(super) struct Lanes {
    chains: HashMap<PrincipalId, ChainLane>,
    queued_slots: usize,
    capacity: usize,
    next_order: u64,
    /// When the oldest slot not yet taken was queued.
    pending_since: Option<Instant>,
    /// Chains that have entries in this lane run but are not yet in the
    /// lane marker.
    unregistered: Vec<PrincipalId>,
    track_chains: bool,
    /// Where the lane run is in its life.
    pub(super) lifecycle: Lifecycle,
    /// Calls offered to the lanes (queued, folded or lost).
    pub(super) accepted: u64,
    /// Calls queued or lost whose entry is not durable yet.
    pub(super) queued_calls: u64,
    /// Calls that met a full queue and went into a loss slot.
    pub(super) queue_full: u64,
}

impl Lanes {
    pub(super) fn new(capacity: usize, track_chains: bool) -> Self {
        Self {
            chains: HashMap::new(),
            queued_slots: 0,
            capacity,
            // Order 0 is reserved for gap slots, which precede every call.
            next_order: 1,
            pending_since: None,
            unregistered: Vec::new(),
            track_chains,
            lifecycle: Lifecycle::Open,
            accepted: 0,
            queued_calls: 0,
            queue_full: 0,
        }
    }

    fn lane_mut(&mut self, principal: &PrincipalId) -> &mut ChainLane {
        let lane = self.chains.entry(principal.clone()).or_default();
        if self.track_chains && !lane.registered {
            lane.registered = true;
            self.unregistered.push(principal.clone());
        }
        lane
    }

    fn push_back(&mut self, principal: &PrincipalId, kind: SlotKind, now: Instant) {
        let order = self.next_order;
        self.next_order = self.next_order.saturating_add(1);
        self.queued_slots = self.queued_slots.saturating_add(1);
        self.pending_since.get_or_insert(now);
        self.lane_mut(principal).fifo.push_back(Slot {
            order,
            principal: principal.clone(),
            kind,
        });
    }

    /// Queue one call behind everything already queued for its chain.
    pub(super) fn push_call(
        &mut self,
        principal: &PrincipalId,
        call: Call,
        now: Instant,
    ) -> Pushed {
        if self.lifecycle.refuses_calls() {
            return Pushed::Closed;
        }
        self.accepted = self.accepted.saturating_add(1);
        self.queued_calls = self.queued_calls.saturating_add(1);
        let full = self.queued_slots >= self.capacity;
        let key = call.run_key();
        match self
            .chains
            .get_mut(principal)
            .and_then(|lane| lane.fifo.back_mut())
            .map(|slot| &mut slot.kind)
        {
            Some(SlotKind::Run {
                key: tail_key,
                calls,
            }) if *tail_key == key => {
                calls.push(call);
                return Pushed::Folded;
            },
            Some(SlotKind::Loss { calls }) if full => {
                calls.push(call);
                self.queue_full = self.queue_full.saturating_add(1);
                return Pushed::Lost;
            },
            _ => {},
        }
        let calls = Summary::new(call);
        if full {
            self.queue_full = self.queue_full.saturating_add(1);
            self.push_back(principal, SlotKind::Loss { calls }, now);
            Pushed::Lost
        } else {
            self.push_back(principal, SlotKind::Run { key, calls }, now);
            Pushed::Queued
        }
    }

    /// Put a gap slot in front of everything queued for `principal`.
    pub(super) fn push_gap_front(
        &mut self,
        principal: &PrincipalId,
        epoch: String,
        opened_at: Timestamp,
        now: Instant,
    ) {
        self.queued_slots = self.queued_slots.saturating_add(1);
        self.pending_since.get_or_insert(now);
        self.lane_mut(principal).fifo.push_front(Slot {
            order: 0,
            principal: principal.clone(),
            kind: SlotKind::Gap { epoch, opened_at },
        });
    }

    /// Number of queued slots.
    pub(super) fn queued_slots(&self) -> usize {
        self.queued_slots
    }

    /// When the oldest queued slot arrived.
    pub(super) fn pending_since(&self) -> Option<Instant> {
        self.pending_since
    }

    /// Whether a chain registration is waiting, so the writer should not
    /// wait for the window.
    pub(super) fn urgent(&self) -> bool {
        !self.unregistered.is_empty()
    }

    /// Chains to add to the lane marker before their first entry is written.
    pub(super) fn take_unregistered(&mut self) -> Vec<PrincipalId> {
        std::mem::take(&mut self.unregistered)
    }

    /// Remove up to `max` slots in global queue order. Slots only ever leave
    /// from the front of their chain's FIFO, so each chain keeps its order.
    pub(super) fn take(&mut self, max: usize, now: Instant) -> Vec<Slot> {
        let mut taken = Vec::new();
        while taken.len() < max {
            let Some(principal) = self
                .chains
                .iter()
                .filter_map(|(principal, lane)| {
                    lane.fifo.front().map(|slot| (slot.order, principal))
                })
                .min_by_key(|(order, _)| *order)
                .map(|(_, principal)| principal.clone())
            else {
                break;
            };
            self.take_front(&principal, &mut taken);
        }
        self.pending_since = (self.queued_slots > 0).then_some(now);
        taken
    }

    fn take_front(&mut self, principal: &PrincipalId, taken: &mut Vec<Slot>) {
        let Some(slot) = self
            .chains
            .get_mut(principal)
            .and_then(|lane| lane.fifo.pop_front())
        else {
            return;
        };
        self.queued_slots = self.queued_slots.saturating_sub(1);
        taken.push(slot);
    }
}

#[cfg(test)]
#[path = "lane_tests.rs"]
mod tests;
