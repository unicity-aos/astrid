//! Per-chain ordered lanes of pending host-audit records.
//!
//! Every principal's chain has a FIFO of slots. A call is placed in its
//! chain's FIFO under the one `Lanes` mutex, so FIFO order is call order, and
//! the writer only ever removes slots from the front. A slot becomes one
//! signed entry, so append order equals call order.
//!
//! Consecutive host calls of one capsule fold into the chain's tail slot
//! while it is still queued: allowed and failed calls of any class share one
//! run, and identical denials share one run. The capsule (the call's actor) is
//! part of the run key, so a run never spans capsules. A call of another
//! capsule, a different denial, a record that is not a host call, a
//! write-ahead admission or a loss closes the run. Folding needs no queue
//! capacity.
//!
//! Records that are not host calls (HTTP exchanges, tool calls, approval
//! decisions) never fold: each is its own slot and entry. A committed record
//! also carries a sender the writer answers once its entry is durable.
//!
//! When the queue is full, a record that cannot fold into the tail slot goes
//! into a loss slot at the tail of its chain instead. Later records fold into
//! that loss slot while the queue stays full, so each chain holds at most one
//! loss slot beyond capacity and memory stays bounded. The loss tally keeps
//! each capsule's calls apart. Committed records and admissions are never
//! lost to a full queue: their callers wait for them, which bounds them.

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use astrid_audit::host_call::{
    HostCallFold, HostCallOutcome, HostCallRef, HostCallSummary, HostCallTally, host_call_class,
    lane_call_digest, lane_record_class,
};
use astrid_audit::{AuditAction, AuditEntryId, AuditOutcome, AuthorizationProof, CapsuleActor};
use astrid_core::{PrincipalId, SessionId, Timestamp};
use astrid_crypto::ContentHash;

use super::MANIFEST_GATED_REASON;
use super::marker::GapDuty;

/// Authorization reason on entries the lane writes about itself (loss and
/// gap records).
const LANE_ACCOUNTING_REASON: &str = "host-audit lane accounting";
/// Loss reason for calls that met a full queue.
pub(super) const QUEUE_FULL: &str = "queue_full";

/// Tells a committed record's caller its entry id once the entry is durable,
/// or why the append failed.
pub(super) type CommitSender = tokio::sync::oneshot::Sender<Result<AuditEntryId, String>>;

/// One host call or other lane record, as a single-call entry would record
/// it.
pub(super) struct Call {
    pub(super) action: AuditAction,
    pub(super) outcome: HostCallOutcome,
    /// Error (failed) or denial reason (denied); empty for ok.
    pub(super) detail: String,
    pub(super) at: Timestamp,
}

impl Call {
    fn digest(&self) -> ContentHash {
        lane_call_digest(&HostCallRef {
            action: &self.action,
            outcome: self.outcome,
            detail: &self.detail,
            at: &self.at,
        })
        .unwrap_or_else(ContentHash::zero)
    }

    /// Whether this is a host call, which may share a run.
    fn is_host_call(&self) -> bool {
        host_call_class(&self.action).is_some()
    }

    /// Tally class: the host-call class, or the record's type tag.
    fn class(&self) -> Cow<'static, str> {
        host_call_class(&self.action).map_or_else(
            || Cow::Owned(lane_record_class(&self.action)),
            Cow::Borrowed,
        )
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

/// Which calls may share a run, besides having the same actor.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RunKey {
    /// Allowed and failed calls of any class.
    Calls,
    /// Denials with this action (actor included) and reason.
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
        let class = call.class();
        if let Some(tally) = self.tally.iter_mut().find(|tally| {
            tally.class == class
                && tally.outcome == call.outcome
                && tally.first.actor() == call.action.actor()
        }) {
            tally.count = tally.count.saturating_add(1);
            return;
        }
        self.tally.push(HostCallTally {
            class: class.into_owned(),
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
        Some(call_entry(tally.first.clone(), tally.outcome, detail))
    }
}

/// The entry of one record: a manifest-gated (or, for tool calls and
/// approvals, the matching system reason) authorization for an allowed or
/// failed record, a denial otherwise.
pub(super) fn call_entry(
    action: AuditAction,
    outcome: HostCallOutcome,
    detail: String,
) -> (AuditAction, AuthorizationProof, AuditOutcome) {
    let (authorization, outcome) = match outcome {
        HostCallOutcome::Ok => (manifest_gated(), AuditOutcome::success()),
        HostCallOutcome::Failed => (manifest_gated(), AuditOutcome::failure(detail)),
        HostCallOutcome::Denied => (
            AuthorizationProof::Denied {
                reason: detail.clone(),
            },
            AuditOutcome::failure(detail),
        ),
    };
    let authorization = super::coverage::authorization(&action, authorization);
    (action, authorization, outcome)
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

/// Outcome of a write-ahead admission, shared by the waiting host call and
/// the writer.
pub(super) struct AdmitTicket {
    state: Mutex<AdmitState>,
    resolved: Condvar,
}

#[derive(Clone)]
enum AdmitState {
    Pending,
    Durable,
    Failed(String),
    /// The host call stopped waiting; a slot still queued is dropped.
    Abandoned,
}

impl AdmitTicket {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(AdmitState::Pending),
            resolved: Condvar::new(),
        }
    }

    /// Settle a pending admission. A ticket the caller abandoned stays
    /// abandoned.
    pub(super) fn resolve(&self, result: Result<(), String>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(*state, AdmitState::Pending) {
            *state = match result {
                Ok(()) => AdmitState::Durable,
                Err(error) => AdmitState::Failed(error),
            };
            self.resolved.notify_all();
        }
    }

    fn is_abandoned(&self) -> bool {
        matches!(
            *self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            AdmitState::Abandoned
        )
    }

    /// Wait until the writer settles the admission, or give up at `timeout`.
    pub(super) fn wait(&self, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now().checked_add(timeout);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            match &*state {
                AdmitState::Durable => return Ok(()),
                AdmitState::Failed(error) => return Err(error.clone()),
                AdmitState::Abandoned => return Err("admission abandoned".to_owned()),
                AdmitState::Pending => {},
            }
            let remaining = deadline.map_or(Duration::ZERO, |deadline| {
                deadline.saturating_duration_since(Instant::now())
            });
            if remaining.is_zero() {
                *state = AdmitState::Abandoned;
                return Err(format!(
                    "write-ahead entry not durable within {}ms",
                    timeout.as_millis()
                ));
            }
            state = self
                .resolved
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }
}

/// What a slot becomes on the chain.
pub(super) enum SlotKind {
    /// Consecutive host calls of one actor sharing a run key.
    Run {
        key: RunKey,
        actor: Option<CapsuleActor>,
        calls: Summary,
    },
    /// Records that met a full queue.
    Loss { calls: Summary },
    /// A record that is its own entry; `commit` is answered once it is
    /// durable (or its batch failed).
    Record {
        call: Box<Call>,
        commit: Option<CommitSender>,
    },
    /// Write-ahead entry of a fail-closed call.
    Admit {
        action: AuditAction,
        ticket: Arc<AdmitTicket>,
    },
    /// A previous lane run may have lost calls; see [`GapDuty`].
    Gap {
        epoch: String,
        opened_at: Timestamp,
        reason: String,
    },
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
    /// Whether a caller waits for this slot: an admission, or a committed
    /// record whose caller has not been answered yet.
    fn is_awaited(&self) -> bool {
        matches!(
            self.kind,
            SlotKind::Admit { .. }
                | SlotKind::Record {
                    commit: Some(_),
                    ..
                }
        )
    }

    /// Calls this slot records (run, record) or accounts for (loss).
    pub(super) fn calls(&self) -> u64 {
        match &self.kind {
            SlotKind::Run { calls, .. } | SlotKind::Loss { calls } => calls.count(),
            SlotKind::Record { .. } => 1,
            SlotKind::Admit { .. } | SlotKind::Gap { .. } => 0,
        }
    }

    /// Take the sender of a committed record whose caller is still waiting.
    pub(super) fn take_commit(&mut self) -> Option<CommitSender> {
        match &mut self.kind {
            SlotKind::Record { commit, .. } => commit.take(),
            _ => None,
        }
    }

    /// The signed entry this slot becomes.
    pub(super) fn request(&self, session: &SessionId) -> AppendRequest {
        let (action, authorization, outcome) = match &self.kind {
            SlotKind::Run { key, actor, calls } => run_entry(*key, actor.as_ref(), calls),
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
            SlotKind::Record { call, .. } => {
                call_entry(call.action.clone(), call.outcome, call.detail.clone())
            },
            SlotKind::Admit { action, .. } => (
                AuditAction::HostCallAdmitted {
                    call: Box::new(action.clone()),
                },
                manifest_gated(),
                AuditOutcome::success_with("write-ahead"),
            ),
            SlotKind::Gap {
                epoch,
                opened_at,
                reason,
            } => gap_entry(epoch, *opened_at, reason),
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

fn run_entry(
    key: RunKey,
    actor: Option<&CapsuleActor>,
    calls: &Summary,
) -> (AuditAction, AuthorizationProof, AuditOutcome) {
    if calls.count() == 1
        && let Some(single) = calls.single()
    {
        return single;
    }
    let action = AuditAction::HostCallRun {
        calls: calls.signed(),
        actor: actor.cloned(),
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

/// The gap entry for a lane run that may have lost calls.
pub(super) fn gap_entry(
    epoch: &str,
    opened_at: Timestamp,
    reason: &str,
) -> (AuditAction, AuthorizationProof, AuditOutcome) {
    (
        AuditAction::HostCallGap {
            epoch: epoch.to_owned(),
            opened_at,
            reason: reason.to_owned(),
        },
        lane_accounting(),
        AuditOutcome::failure(format!(
            "host calls of host-audit lane {epoch} may be missing: {reason}"
        )),
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
    /// Queued slots a caller waits for: write-ahead admissions and
    /// committed records not yet answered.
    awaited: usize,
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
            awaited: 0,
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

    /// Queue one record behind everything already queued for its chain. A
    /// host call may fold into the chain's tail run; any other record is its
    /// own slot.
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
        let host_call = call.is_host_call();
        let key = call.run_key();
        match self
            .chains
            .get_mut(principal)
            .and_then(|lane| lane.fifo.back_mut())
            .map(|slot| &mut slot.kind)
        {
            Some(SlotKind::Run {
                key: tail_key,
                actor,
                calls,
            }) if host_call && *tail_key == key && actor.as_ref() == call.action.actor() => {
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
        if full {
            self.queue_full = self.queue_full.saturating_add(1);
            let calls = Summary::new(call);
            self.push_back(principal, SlotKind::Loss { calls }, now);
            return Pushed::Lost;
        }
        let kind = if host_call {
            SlotKind::Run {
                key,
                actor: call.action.actor().cloned(),
                calls: Summary::new(call),
            }
        } else {
            SlotKind::Record {
                call: Box::new(call),
                commit: None,
            }
        };
        self.push_back(principal, kind, now);
        Pushed::Queued
    }

    /// Queue a record the caller waits for as its own slot behind everything
    /// already queued for its chain. Committed records are bounded by their
    /// waiting callers, so they may exceed the queue capacity. Returns the
    /// record when the writer has stopped, so the caller can append it
    /// another way.
    pub(super) fn push_commit(
        &mut self,
        principal: &PrincipalId,
        call: Call,
        commit: CommitSender,
        now: Instant,
    ) -> Result<(), Box<Call>> {
        if self.lifecycle.refuses_calls() {
            return Err(Box::new(call));
        }
        self.accepted = self.accepted.saturating_add(1);
        self.queued_calls = self.queued_calls.saturating_add(1);
        self.awaited = self.awaited.saturating_add(1);
        self.push_back(
            principal,
            SlotKind::Record {
                call: Box::new(call),
                commit: Some(commit),
            },
            now,
        );
        Ok(())
    }

    /// Queue a write-ahead admission. Admissions are bounded by concurrent
    /// host calls, so they may exceed the queue capacity.
    pub(super) fn push_admit(
        &mut self,
        principal: &PrincipalId,
        action: AuditAction,
        ticket: Arc<AdmitTicket>,
        now: Instant,
    ) -> bool {
        if self.lifecycle.refuses_calls() {
            return false;
        }
        self.awaited = self.awaited.saturating_add(1);
        self.push_back(principal, SlotKind::Admit { action, ticket }, now);
        true
    }

    /// Put a gap slot in front of everything queued for `principal`.
    pub(super) fn push_gap_front(&mut self, principal: &PrincipalId, duty: &GapDuty, now: Instant) {
        self.queued_slots = self.queued_slots.saturating_add(1);
        self.pending_since.get_or_insert(now);
        self.lane_mut(principal).fifo.push_front(Slot {
            order: 0,
            principal: principal.clone(),
            kind: SlotKind::Gap {
                epoch: duty.epoch.clone(),
                opened_at: duty.opened_at,
                reason: duty.reason.clone(),
            },
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

    /// Whether a host call is waiting on this queue (an admission, a
    /// committed record or a chain registration), so the writer should not
    /// wait for the window.
    pub(super) fn urgent(&self) -> bool {
        self.awaited > 0 || !self.unregistered.is_empty()
    }

    /// Chains to add to the lane marker before their first entry is written.
    pub(super) fn take_unregistered(&mut self) -> Vec<PrincipalId> {
        std::mem::take(&mut self.unregistered)
    }

    /// Remove up to `max` slots. Slots only ever leave from the front of
    /// their chain's FIFO, so each chain keeps its order. Chains with a slot
    /// a caller waits for (an admission or a committed record) go first, up
    /// to and including that slot, so the caller waits for its own chain's
    /// backlog only; the rest leave in global queue order. Abandoned
    /// admissions are dropped.
    pub(super) fn take(&mut self, max: usize, now: Instant) -> Vec<Slot> {
        let mut taken = Vec::new();
        if self.awaited > 0 {
            let waiting: Vec<PrincipalId> = self
                .chains
                .iter()
                .filter(|(_, lane)| lane.fifo.iter().any(Slot::is_awaited))
                .map(|(principal, _)| principal.clone())
                .collect();
            for principal in waiting {
                while taken.len() < max
                    && self
                        .chains
                        .get(&principal)
                        .is_some_and(|lane| lane.fifo.iter().any(Slot::is_awaited))
                {
                    self.take_front(&principal, &mut taken);
                }
            }
        }
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
        if slot.is_awaited() {
            self.awaited = self.awaited.saturating_sub(1);
        }
        if let SlotKind::Admit { ticket, .. } = &slot.kind
            && ticket.is_abandoned()
        {
            return;
        }
        taken.push(slot);
    }

    /// Remove every queued admission, for failing them while the log is
    /// unavailable.
    pub(super) fn take_admissions(&mut self) -> Vec<Arc<AdmitTicket>> {
        let mut tickets = Vec::new();
        for lane in self.chains.values_mut() {
            lane.fifo.retain(|slot| match &slot.kind {
                SlotKind::Admit { ticket, .. } => {
                    tickets.push(Arc::clone(ticket));
                    false
                },
                _ => true,
            });
        }
        self.queued_slots = self.queued_slots.saturating_sub(tickets.len());
        self.awaited = self.awaited.saturating_sub(tickets.len());
        tickets
    }

    /// Take the senders of every queued committed record, for answering
    /// their callers while the log is unavailable. The records stay queued
    /// and are still written in their place.
    pub(super) fn take_commits(&mut self) -> Vec<CommitSender> {
        let mut senders = Vec::new();
        for lane in self.chains.values_mut() {
            senders.extend(lane.fifo.iter_mut().filter_map(Slot::take_commit));
        }
        self.awaited = self.awaited.saturating_sub(senders.len());
        senders
    }
}

#[cfg(test)]
#[path = "lane_tests.rs"]
mod tests;
