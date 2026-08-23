//! Atomic signed-receipt and runtime-cursor persistence.

use crate::{ServiceError, ServiceResult};
use redb::{Database, ReadableTable, TableDefinition};
use rvm_context::receipt::ContextReceiptError;
use rvm_context::{ReceiptChainState, SignedContextEpochReceipt};
use rvm_proof::WitnessSigner;
use rvm_witness::{compute_chain_hash, WitnessCheckpoint};
use std::path::Path;

const RECEIPTS: TableDefinition<u64, &[u8]> = TableDefinition::new("context_receipts_v1");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("context_receipt_meta_v1");
const CURSOR_KEY: &str = "cursor";
const CURSOR_BYTES: usize = 56;

/// Authenticated durable coordinates needed to resume a context runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptCursor {
    next_sequence: u64,
    chain_hash: u64,
    next_epoch_id: u64,
    previous_receipt_id: [u8; 32],
}

impl ReceiptCursor {
    /// Build a cursor from state returned by a successful epoch seal.
    #[must_use]
    pub fn from_chain_state(state: ReceiptChainState) -> Self {
        Self {
            next_sequence: state.next_checkpoint().next_sequence(),
            chain_hash: state.next_checkpoint().chain_hash(),
            next_epoch_id: state.next_epoch_id(),
            previous_receipt_id: state.previous_receipt_id(),
        }
    }

    /// Reconstruct the runtime state after this cursor has been authenticated.
    #[must_use]
    pub const fn into_chain_state(self) -> ReceiptChainState {
        ReceiptChainState::trusted_resume(
            WitnessCheckpoint::trusted_resume(self.next_sequence, self.chain_hash),
            self.next_epoch_id,
            self.previous_receipt_id,
        )
    }

    /// Next witness sequence that must be sealed.
    #[must_use]
    pub const fn next_sequence(self) -> u64 {
        self.next_sequence
    }

    /// Next receipt epoch identifier.
    #[must_use]
    pub const fn next_epoch_id(self) -> u64 {
        self.next_epoch_id
    }

    /// Identifier of the immediately preceding receipt.
    #[must_use]
    pub const fn previous_receipt_id(self) -> [u8; 32] {
        self.previous_receipt_id
    }

    fn encode(self) -> [u8; CURSOR_BYTES] {
        let mut bytes = [0u8; CURSOR_BYTES];
        bytes[..8].copy_from_slice(&self.next_sequence.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.chain_hash.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.next_epoch_id.to_le_bytes());
        bytes[24..].copy_from_slice(&self.previous_receipt_id);
        bytes
    }

    fn decode(bytes: &[u8]) -> ServiceResult<Self> {
        if bytes.len() != CURSOR_BYTES {
            return Err(ServiceError::CorruptState("invalid receipt cursor"));
        }
        let mut previous_receipt_id = [0u8; 32];
        previous_receipt_id.copy_from_slice(&bytes[24..]);
        Ok(Self {
            next_sequence: u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8])),
            chain_hash: u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8])),
            next_epoch_id: u64::from_le_bytes(bytes[16..24].try_into().unwrap_or([0; 8])),
            previous_receipt_id,
        })
    }
}

/// REDB-backed append-only signed receipt store.
pub struct DurableReceiptStore {
    database: Database,
}

impl DurableReceiptStore {
    /// Open or create a durable receipt database.
    ///
    /// # Errors
    ///
    /// Returns a database error when schema creation cannot commit.
    pub fn open(path: impl AsRef<Path>) -> ServiceResult<Self> {
        let database = Database::create(path).map_err(ServiceError::database)?;
        let transaction = database.begin_write().map_err(ServiceError::database)?;
        {
            let _ = transaction
                .open_table(RECEIPTS)
                .map_err(ServiceError::database)?;
            let _ = transaction
                .open_table(META)
                .map_err(ServiceError::database)?;
        }
        transaction.commit().map_err(ServiceError::database)?;
        Ok(Self { database })
    }

    /// Atomically append an authenticated receipt and its following cursor.
    ///
    /// # Errors
    ///
    /// Refuses invalid signatures, forks, replays, coordinate mismatches, and
    /// any transaction that cannot commit both values together.
    pub fn append_verified<S: WitnessSigner>(
        &self,
        receipt: &SignedContextEpochReceipt,
        following: ReceiptCursor,
        signer: &S,
    ) -> ServiceResult<()> {
        let verified = receipt
            .verify(signer)
            .map_err(|error| receipt_error(&error))?;
        let epoch = receipt.receipt().epoch_id();
        if following.next_epoch_id
            != epoch
                .checked_add(1)
                .ok_or(ServiceError::CorruptState("receipt epoch overflow"))?
            || following.previous_receipt_id != receipt.receipt_id()
            || following.next_sequence
                != receipt
                    .receipt()
                    .last_sequence()
                    .checked_add(1)
                    .ok_or(ServiceError::CorruptState("receipt sequence overflow"))?
        {
            return Err(ServiceError::CorruptState("receipt cursor mismatch"));
        }
        let mut expected_chain_hash = receipt.receipt().initial_chain_hash();
        for sequence in receipt.receipt().first_sequence()..=receipt.receipt().last_sequence() {
            expected_chain_hash = compute_chain_hash(expected_chain_hash, sequence);
        }
        if following.chain_hash != expected_chain_hash {
            return Err(ServiceError::CorruptState("receipt chain hash mismatch"));
        }

        let transaction = self
            .database
            .begin_write()
            .map_err(ServiceError::database)?;
        {
            let mut receipts = transaction
                .open_table(RECEIPTS)
                .map_err(ServiceError::database)?;
            let mut meta = transaction
                .open_table(META)
                .map_err(ServiceError::database)?;
            if receipts
                .get(epoch)
                .map_err(ServiceError::database)?
                .is_some()
            {
                return Err(ServiceError::CorruptState("receipt epoch replay"));
            }
            let existing_cursor = meta
                .get(CURSOR_KEY)
                .map_err(ServiceError::database)?
                .map(|value| value.value().to_vec());
            match existing_cursor {
                None => verified
                    .verify_genesis()
                    .map_err(|error| receipt_error(&error))?,
                Some(bytes) => {
                    let current = ReceiptCursor::decode(&bytes)?;
                    if current.next_epoch_id != epoch
                        || current.previous_receipt_id != *receipt.receipt().previous_receipt()
                    {
                        return Err(ServiceError::CorruptState("receipt cursor fork"));
                    }
                    if epoch == 0 {
                        return Err(ServiceError::CorruptState("genesis receipt fork"));
                    }
                    let previous_bytes = receipts
                        .get(epoch - 1)
                        .map_err(ServiceError::database)?
                        .ok_or(ServiceError::CorruptState("previous receipt missing"))?
                        .value()
                        .to_vec();
                    let previous = SignedContextEpochReceipt::from_bytes(&previous_bytes)
                        .map_err(|error| receipt_error(&error))?;
                    let previous_verified = previous
                        .verify(signer)
                        .map_err(|error| receipt_error(&error))?;
                    verified
                        .verify_successor(&previous_verified)
                        .map_err(|error| receipt_error(&error))?;
                }
            }
            let receipt_bytes = receipt.to_bytes();
            let cursor_bytes = following.encode();
            receipts
                .insert(epoch, receipt_bytes.as_slice())
                .map_err(ServiceError::database)?;
            meta.insert(CURSOR_KEY, cursor_bytes.as_slice())
                .map_err(ServiceError::database)?;
        }
        transaction.commit().map_err(ServiceError::database)
    }

    /// Load and structurally validate the durable resume cursor.
    ///
    /// # Errors
    ///
    /// Returns a corruption error for a malformed cursor.
    pub fn cursor(&self) -> ServiceResult<Option<ReceiptCursor>> {
        let transaction = self.database.begin_read().map_err(ServiceError::database)?;
        let table = transaction
            .open_table(META)
            .map_err(ServiceError::database)?;
        table
            .get(CURSOR_KEY)
            .map_err(ServiceError::database)?
            .map(|value| ReceiptCursor::decode(value.value()))
            .transpose()
    }

    /// Read one structurally validated signed receipt by epoch.
    ///
    /// Signature authentication remains the caller's responsibility.
    ///
    /// # Errors
    ///
    /// Returns a database or receipt decoding error.
    pub fn receipt(&self, epoch: u64) -> ServiceResult<Option<SignedContextEpochReceipt>> {
        let transaction = self.database.begin_read().map_err(ServiceError::database)?;
        let table = transaction
            .open_table(RECEIPTS)
            .map_err(ServiceError::database)?;
        table
            .get(epoch)
            .map_err(ServiceError::database)?
            .map(|value| {
                SignedContextEpochReceipt::from_bytes(value.value())
                    .map_err(|error| receipt_error(&error))
            })
            .transpose()
    }
}

fn receipt_error(error: &ContextReceiptError) -> ServiceError {
    ServiceError::Database(format!("receipt verification failed: {error}"))
}
