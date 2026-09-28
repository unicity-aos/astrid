//! Supporting types for the host-observed audit actions: the code identity a
//! host-call entry is attributed to, and provider request ids on HTTP
//! completions.

use astrid_crypto::ContentHash;
use serde::{Deserialize, Serialize};

/// Code identity of the capsule a host-observed entry is attributed to.
///
/// Stamped by the host from the capsule it loaded, never taken from the
/// guest: `capsule_id` is the manifest package name and `wasm_hash` is the
/// BLAKE3 hash of the wasm component the host verified before loading it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleActor {
    /// Capsule id (manifest package name).
    pub capsule_id: String,
    /// BLAKE3 of the verified wasm component. `None` for capsules without a
    /// wasm component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm_hash: Option<ContentHash>,
}

/// A provider request id taken from an HTTP response header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRequestId {
    /// Lower-case response header name (for example `x-request-id`).
    pub header: String,
    /// Header value, truncated to a bounded length.
    pub value: String,
}

impl super::AuditAction {
    /// The capsule a host-observed entry is attributed to, if any.
    ///
    /// For a write-ahead admission this is the actor of the admitted call.
    #[must_use]
    pub fn actor(&self) -> Option<&CapsuleActor> {
        match self {
            Self::FileRead { actor, .. }
            | Self::FileWrite { actor, .. }
            | Self::FileDelete { actor, .. }
            | Self::NetConnect { actor, .. }
            | Self::NetBind { actor, .. }
            | Self::NetAccept { actor, .. }
            | Self::ProcessSpawn { actor, .. }
            | Self::HttpRequest { actor, .. }
            | Self::HttpResponse { actor, .. }
            | Self::CapsuleToolCall { actor, .. }
            | Self::ApprovalRequested { actor, .. }
            | Self::ApprovalGranted { actor, .. }
            | Self::ApprovalDenied { actor, .. }
            | Self::HostCallRun { actor, .. } => actor.as_ref(),
            Self::HostCallAdmitted { call } => call.actor(),
            _ => None,
        }
    }
}
