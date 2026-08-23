//! Error types for the governed context namespace.

use core::fmt;
use rvm_cap::CapError;

/// Errors returned by governed context operations.
///
/// Authorization failures deliberately collapse to [`Self::AccessDenied`].
/// The witness trail retains the attempted operation without exposing whether
/// an alias, revision, or tenant exists to an unauthorized caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    /// The capability, actor, scope, view, or requested right was not valid.
    AccessDenied,
    /// A trusted capability binding table reached its configured capacity.
    GrantTableFull,
    /// The capability already has a different trusted scope binding.
    GrantAlreadyBound,
    /// A delegated grant attempted to widen its parent's scope or views.
    ScopeEscalation,
    /// A capability-manager operation failed during issuance or revocation.
    Capability(CapError),
    /// The operation requires a pinned, immutable URI.
    PinnedUriRequired,
    /// The operation requires a versionless alias URI.
    VersionlessUriRequired,
    /// An immutable revision was targeted by a mutation.
    ImmutableRevision,
    /// The requested immutable revision is not present.
    RevisionNotFound,
    /// Existing bytes or logical identity conflict with an immutable revision.
    RevisionConflict,
    /// The requested versionless alias is not present.
    AliasNotFound,
    /// Compare-and-swap observed a different alias snapshot.
    AliasConflict,
    /// The alias generation counter cannot advance without wrapping.
    AliasGenerationExhausted,
    /// The configured object table reached capacity.
    ObjectTableFull,
    /// The configured alias table reached capacity.
    AliasTableFull,
    /// An RVF object exceeds the bounded in-memory resolver limit.
    ObjectTooLarge,
    /// A search query is empty or exceeds its bounded input limit.
    InvalidQuery,
    /// A requested result limit is zero or exceeds the public maximum.
    InvalidResultLimit,
    /// The alias or immutable object is a tombstone and has no readable body.
    Tombstoned,
    /// The request operation does not match the runtime entry point used.
    OperationMismatch,
    /// The supplied bytes do not hash to the pinned whole-RVF revision.
    RevisionHashMismatch,
    /// RVF structure, signatures, context profile, or view binding failed.
    RvfVerificationFailed,
    /// A witness epoch could not be snapshotted, sealed, or encoded.
    ReceiptSealFailed,
    /// A URI or stored identity is structurally unsuitable for the operation.
    InvalidTarget,
    /// A resolver returned a target outside the authorized request scope.
    ResolverScopeViolation,
    /// Durable storage, encryption, or retrieval infrastructure failed closed.
    BackendUnavailable,
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessDenied => f.write_str("context access denied"),
            Self::GrantTableFull => f.write_str("context grant table is full"),
            Self::GrantAlreadyBound => {
                f.write_str("capability already has a different context binding")
            }
            Self::ScopeEscalation => f.write_str("delegated context scope widens authority"),
            Self::Capability(error) => write!(f, "capability operation failed: {error}"),
            Self::PinnedUriRequired => f.write_str("operation requires a pinned ruv URI"),
            Self::VersionlessUriRequired => f.write_str("operation requires a versionless ruv URI"),
            Self::ImmutableRevision => f.write_str("immutable revision cannot be changed"),
            Self::RevisionNotFound => f.write_str("context revision was not found"),
            Self::RevisionConflict => f.write_str("immutable context revision conflicts"),
            Self::AliasNotFound => f.write_str("context alias was not found"),
            Self::AliasConflict => f.write_str("context alias compare-and-swap conflict"),
            Self::AliasGenerationExhausted => f.write_str("context alias generation is exhausted"),
            Self::ObjectTableFull => f.write_str("context object table is full"),
            Self::AliasTableFull => f.write_str("context alias table is full"),
            Self::ObjectTooLarge => f.write_str("context object exceeds the size limit"),
            Self::InvalidQuery => f.write_str("context search query is invalid"),
            Self::InvalidResultLimit => f.write_str("context result limit is invalid"),
            Self::Tombstoned => f.write_str("context object has been tombstoned"),
            Self::OperationMismatch => f.write_str("context runtime operation mismatch"),
            Self::RevisionHashMismatch => f.write_str("RVF bytes do not match the pinned revision"),
            Self::RvfVerificationFailed => f.write_str("RVF context profile verification failed"),
            Self::ReceiptSealFailed => f.write_str("context witness epoch seal failed"),
            Self::InvalidTarget => f.write_str("context target is invalid for this operation"),
            Self::ResolverScopeViolation => {
                f.write_str("resolver returned context outside the authorized scope")
            }
            Self::BackendUnavailable => f.write_str("context backend unavailable"),
        }
    }
}

impl From<CapError> for ContextError {
    fn from(error: CapError) -> Self {
        Self::Capability(error)
    }
}

/// Result type for governed context operations.
pub type ContextResult<T> = core::result::Result<T, ContextError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_have_nonempty_stable_messages() {
        use alloc::string::ToString;

        let errors = [
            ContextError::AccessDenied,
            ContextError::GrantTableFull,
            ContextError::ImmutableRevision,
            ContextError::AliasConflict,
            ContextError::Tombstoned,
            ContextError::Capability(CapError::StaleHandle),
        ];
        for error in errors {
            assert!(!error.to_string().is_empty());
        }
    }
}
