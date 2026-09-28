//! Durable lane marker: detects a lane run that stopped without draining.
//!
//! The in-memory queue is lost when the daemon dies, so the lane keeps one
//! small record in kernel-owned storage: the current lane run (`epoch`), the
//! chains it has written to, and whether it closed cleanly. A chain is added
//! before the lane writes its first entry of the run there. Graceful shutdown
//! marks the run closed after the queue is fully drained.
//!
//! On the next start, a run that is not closed becomes a gap duty: a signed
//! gap entry in every chain the run registered, and one in the session's
//! system chain, which covers chains that were touched but not yet
//! registered. Duties stay in the marker until their entries are durable, so
//! a second crash does not lose them.

use astrid_core::{PrincipalId, Timestamp};
use astrid_storage::ScopedKvStore;
use serde::{Deserialize, Serialize};

const MARKER_KEY: &str = "lane";
const MARKER_VERSION: u32 = 1;

/// A lane run that stopped without draining, and the chains it wrote to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct GapDuty {
    pub(super) epoch: String,
    pub(super) opened_at: Timestamp,
    pub(super) chains: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MarkerState {
    version: u32,
    epoch: String,
    opened_at: Timestamp,
    closed: bool,
    chains: Vec<String>,
    pending_gaps: Vec<GapDuty>,
}

/// The lane marker of the current lane run.
pub(super) struct LaneMarker {
    store: ScopedKvStore,
    state: MarkerState,
}

impl LaneMarker {
    /// Load the previous marker, start a new lane run, and return the gap
    /// duties the new run must record.
    ///
    /// # Errors
    ///
    /// Returns an error when the marker cannot be read, parsed or written.
    pub(super) fn open(
        runtime: &tokio::runtime::Runtime,
        store: ScopedKvStore,
        epoch: String,
        opened_at: Timestamp,
    ) -> Result<(Self, Vec<GapDuty>), String> {
        let previous = runtime
            .block_on(store.get(MARKER_KEY))
            .map_err(|error| format!("read host-audit lane marker: {error}"))?
            .map(|bytes| serde_json::from_slice::<MarkerState>(&bytes))
            .transpose()
            .map_err(|error| format!("parse host-audit lane marker: {error}"))?;
        let mut duties = Vec::new();
        if let Some(previous) = previous {
            duties.extend(previous.pending_gaps);
            if !previous.closed {
                duties.push(GapDuty {
                    epoch: previous.epoch,
                    opened_at: previous.opened_at,
                    chains: previous.chains,
                });
            }
        }
        let marker = Self {
            store,
            state: MarkerState {
                version: MARKER_VERSION,
                epoch,
                opened_at,
                closed: false,
                chains: Vec::new(),
                pending_gaps: duties.clone(),
            },
        };
        marker.save(runtime)?;
        Ok((marker, duties))
    }

    fn save(&self, runtime: &tokio::runtime::Runtime) -> Result<(), String> {
        let bytes = serde_json::to_vec(&self.state)
            .map_err(|error| format!("encode host-audit lane marker: {error}"))?;
        runtime
            .block_on(self.store.set(MARKER_KEY, bytes))
            .map_err(|error| format!("write host-audit lane marker: {error}"))
    }

    /// Add chains before the lane writes to them in this run.
    ///
    /// # Errors
    ///
    /// Returns an error when the marker cannot be written; the chains are
    /// then not registered.
    pub(super) fn register(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        principals: &[PrincipalId],
    ) -> Result<(), String> {
        let before = self.state.chains.len();
        for principal in principals {
            if !self
                .state
                .chains
                .iter()
                .any(|chain| chain == principal.as_str())
            {
                self.state.chains.push(principal.as_str().to_owned());
            }
        }
        if self.state.chains.len() == before {
            return Ok(());
        }
        self.save(runtime).inspect_err(|_| {
            self.state.chains.truncate(before);
        })
    }

    /// Drop the gap duties once all their entries are durable.
    ///
    /// # Errors
    ///
    /// Returns an error when the marker cannot be written.
    pub(super) fn gaps_recorded(
        &mut self,
        runtime: &tokio::runtime::Runtime,
    ) -> Result<(), String> {
        if self.state.pending_gaps.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.state.pending_gaps);
        self.save(runtime).inspect_err(|_| {
            self.state.pending_gaps = pending;
        })
    }

    /// Mark the lane run closed after a complete drain.
    ///
    /// # Errors
    ///
    /// Returns an error when the marker cannot be written.
    pub(super) fn close(&mut self, runtime: &tokio::runtime::Runtime) -> Result<(), String> {
        self.state.closed = true;
        self.save(runtime)
    }
}
