//! Audit binding retained after a context execution permit is consumed.

use crate::{
    emit, Instance, InstanceId, InstanceState, LaunchError, LaunchEvent, LaunchResult,
    LaunchWitnessContext,
};
use rvm_context::{ExecutionPermit, PinnedRuvUri};
use rvm_host::{HostAdapter, Placement, VerifiedPackage};
use rvm_types::PartitionId;
use rvm_witness::WitnessLog;

/// Evidence connecting a created instance to its governed `ruv://` permit.
#[derive(Debug, PartialEq, Eq)]
pub struct ContextLaunchAuthorization {
    actor: PartitionId,
    pinned_uri: PinnedRuvUri,
    capability_hash: u32,
    witness_sequence: u64,
}

impl ContextLaunchAuthorization {
    pub(crate) const fn new(
        actor: PartitionId,
        pinned_uri: PinnedRuvUri,
        capability_hash: u32,
        witness_sequence: u64,
    ) -> Self {
        Self {
            actor,
            pinned_uri,
            capability_hash,
            witness_sequence,
        }
    }

    /// Partition whose context capability authorized execution.
    #[must_use]
    pub const fn actor(&self) -> PartitionId {
        self.actor
    }

    /// Exact immutable skill name authorized by the runtime.
    #[must_use]
    pub const fn pinned_uri(&self) -> &PinnedRuvUri {
        &self.pinned_uri
    }

    /// Non-secret capability commitment from the context witness decision.
    #[must_use]
    pub const fn capability_hash(&self) -> u32 {
        self.capability_hash
    }

    /// Successful context-execution witness sequence.
    #[must_use]
    pub const fn witness_sequence(&self) -> u64 {
        self.witness_sequence
    }
}

impl<A: HostAdapter> Instance<A> {
    /// Prepare isolation only after consuming a matching governed context
    /// execution permit.
    ///
    /// The permit is non-cloneable and consumed even when the host boundary
    /// refuses. Its revision must equal the verified package identity and its
    /// actor must equal the target placement partition. Nothing executes.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchError::ContextPermitMismatch`] after witnessing a
    /// package/actor mismatch, or the same host errors as [`Self::create`].
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::needless_pass_by_value)] // Ownership makes the permit single-use.
    pub fn create_from_context<const N: usize>(
        id: InstanceId,
        adapter: A,
        package: VerifiedPackage,
        placement: Placement,
        permit: ExecutionPermit,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> LaunchResult<Self> {
        if package.identity() != permit.revision().as_bytes()
            || placement.partition != permit.actor()
        {
            let context = LaunchWitnessContext {
                instance: id,
                rvf_identity: *package.identity(),
                partition: placement.partition,
                timestamp_ns,
            };
            emit(
                log,
                LaunchEvent::ContextPermitRejected,
                &context,
                InstanceState::Created,
                permit.capability_hash(),
            );
            return Err(LaunchError::ContextPermitMismatch);
        }
        let authorization = ContextLaunchAuthorization::new(
            permit.actor(),
            permit.pinned_uri().clone(),
            permit.capability_hash(),
            permit.witness_sequence(),
        );
        let mut instance = Self::create(id, adapter, package, placement, log, timestamp_ns)?;
        instance.attach_context_authorization(authorization);
        Ok(instance)
    }
}
