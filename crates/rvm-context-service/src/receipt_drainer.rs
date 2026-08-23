//! Receipt persistence and witness-ring backpressure coordinator.

use crate::{
    DurableReceiptStore, PersistentContextResolver, ReceiptCursor, ServiceError, ServiceResult,
};
use rvm_context::{ContextClock, ContextError, ContextRequest, ContextRuntime};
use rvm_proof::WitnessSigner;
use rvm_types::WitnessRecord;

/// Coordinates signed epoch persistence before the runtime cursor advances.
pub struct ReceiptDrainer {
    store: DurableReceiptStore,
    max_unsealed: u64,
}

impl ReceiptDrainer {
    /// Construct a drainer with a fail-closed unsealed-record threshold.
    ///
    /// # Errors
    ///
    /// Refuses a zero threshold. [`Self::admit`] also verifies it leaves two
    /// records of headroom in the concrete runtime ring.
    pub fn new(store: DurableReceiptStore, max_unsealed: u64) -> ServiceResult<Self> {
        if max_unsealed == 0 {
            return Err(ServiceError::CorruptState(
                "receipt backpressure threshold is zero",
            ));
        }
        Ok(Self {
            store,
            max_unsealed,
        })
    }

    /// Durable signed receipt store used by this coordinator.
    #[must_use]
    pub const fn store(&self) -> &DurableReceiptStore {
        &self.store
    }

    /// Number of witness records not yet covered by a persisted receipt.
    #[must_use]
    pub fn pending<
        const CAPABILITIES: usize,
        const GRANTS: usize,
        const WITNESSES: usize,
        CLOCK: ContextClock,
    >(
        &self,
        runtime: &ContextRuntime<PersistentContextResolver, CAPABILITIES, GRANTS, WITNESSES, CLOCK>,
    ) -> u64 {
        runtime.witness_log().total_emitted().saturating_sub(
            runtime
                .receipt_chain_state()
                .next_checkpoint()
                .next_sequence(),
        )
    }

    /// Fail closed before admitting another ordinary request when a drainer is
    /// too far behind to guarantee receipt sealing before ring overwrite.
    ///
    /// # Errors
    ///
    /// Returns a runtime error at the configured threshold or a configuration
    /// error when the threshold does not leave two ring slots of headroom.
    pub fn admit<
        const CAPABILITIES: usize,
        const GRANTS: usize,
        const WITNESSES: usize,
        CLOCK: ContextClock,
    >(
        &self,
        runtime: &ContextRuntime<PersistentContextResolver, CAPABILITIES, GRANTS, WITNESSES, CLOCK>,
    ) -> ServiceResult<()> {
        let capacity = u64::try_from(WITNESSES)
            .map_err(|_| ServiceError::CorruptState("witness capacity is too large"))?;
        if self.max_unsealed > capacity.saturating_sub(2) {
            return Err(ServiceError::CorruptState(
                "receipt threshold leaves insufficient ring headroom",
            ));
        }
        if self.pending(runtime) >= self.max_unsealed {
            return Err(ServiceError::Runtime(
                "receipt drainer backpressure is active".to_owned(),
            ));
        }
        Ok(())
    }

    /// Seal, verify, and persist one epoch before advancing runtime state.
    ///
    /// # Errors
    ///
    /// Returns a runtime error for authorization/sealing failures and fails
    /// closed on receipt database authentication or commit errors.
    #[allow(clippy::too_many_arguments)]
    pub fn seal<
        const CAPABILITIES: usize,
        const GRANTS: usize,
        const WITNESSES: usize,
        CLOCK: ContextClock,
        S: WitnessSigner,
    >(
        &self,
        runtime: &mut ContextRuntime<
            PersistentContextResolver,
            CAPABILITIES,
            GRANTS,
            WITNESSES,
            CLOCK,
        >,
        request: &ContextRequest,
        namespace_root: [u8; 32],
        rvf_identity: [u8; 32],
        policy_hash: [u8; 32],
        detail_root: [u8; 32],
        signer: &S,
    ) -> ServiceResult<ReceiptCursor> {
        let mut scratch = vec![WitnessRecord::zeroed(); WITNESSES];
        runtime
            .seal_epoch_transactional(
                request,
                &mut scratch,
                namespace_root,
                rvf_identity,
                policy_hash,
                detail_root,
                signer,
                |receipt, following| {
                    let cursor = ReceiptCursor::from_chain_state(following);
                    self.store
                        .append_verified(receipt, cursor, signer)
                        .map_err(|_| ContextError::BackendUnavailable)
                },
            )
            .map_err(|error| ServiceError::Runtime(error.to_string()))?;
        Ok(ReceiptCursor::from_chain_state(
            runtime.receipt_chain_state(),
        ))
    }
}
