use base64::Engine as _;
use rvm_context::{
    CapabilityHandle, ContextAuthority, ContextError, ContextOperation, ContextProfile,
    ContextRequest, ContextRuntime, ContextScope, ContextViewMask, DerivedView, ProfileView,
    ProgressiveView, Revision, RuvUri,
};
use rvm_context_service::{
    ContextGateway, DurableReceiptStore, HashEmbedder, LocalKeyProvider, PersistentContextResolver,
    PurgeSink, ReceiptCursor, ReceiptDrainer, ResolverOptions, ServiceError, ServiceResult,
};
use rvm_proof::HmacSha256WitnessSigner;
use rvm_rvf::{
    content_hash, sha256, SegmentHeader, SEGMENT_HEADER_SIZE, SEGMENT_MAGIC, SEGMENT_VERSION,
    SEG_TYPE_PROFILE,
};
use rvm_types::{CapRights, PartitionId};
use rvm_witness::WitnessRecord;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::TempDir;

type ServiceRuntime = ContextRuntime<PersistentContextResolver, 32, 32, 256>;

fn root() -> RuvUri {
    RuvUri::parse("ruv://example.com/acme/user/alice/resources/docs").unwrap()
}

fn target() -> RuvUri {
    RuvUri::parse("ruv://example.com/acme/user/alice/resources/docs/item").unwrap()
}

fn request(
    handle: CapabilityHandle,
    operation: ContextOperation,
    target: RuvUri,
) -> ContextRequest {
    ContextRequest::new(handle, operation, target)
}

fn segment(segment_type: u8, segment_id: u64, payload: &[u8]) -> Vec<u8> {
    let total = SEGMENT_HEADER_SIZE + payload.len();
    let padded = total.div_ceil(64) * 64;
    let header = SegmentHeader {
        magic: SEGMENT_MAGIC,
        version: SEGMENT_VERSION,
        seg_type: segment_type,
        flags: 0,
        segment_id,
        payload_length: u64::try_from(payload.len()).unwrap(),
        timestamp_ns: segment_id,
        checksum_algo: 2,
        compression: 0,
        reserved_0: 0,
        reserved_1: 0,
        content_hash: content_hash(2, payload),
        uncompressed_len: 0,
        alignment_pad: u32::try_from(padded - total).unwrap(),
    };
    let mut bytes = header.to_bytes().to_vec();
    bytes.extend_from_slice(payload);
    bytes.resize(padded, 0);
    bytes
}

fn context_rvf(overview: &[u8], content: &[u8]) -> Vec<u8> {
    let content_revision = Revision::from_bytes(sha256(content));
    let profile = ContextProfile::new(vec![
        ProfileView::content(1, content_revision).unwrap(),
        ProfileView::derived(
            ProgressiveView::Overview,
            2,
            Revision::from_bytes(sha256(overview)),
            DerivedView::new(
                content_revision,
                Revision::from_bytes([2; 32]),
                Revision::from_bytes([3; 32]),
                Revision::from_bytes([4; 32]),
                Revision::from_bytes([5; 32]),
            )
            .unwrap(),
        )
        .unwrap(),
    ])
    .unwrap();
    let mut bytes = segment(0x07, 1, content);
    bytes.extend(segment(0x07, 2, overview));
    bytes.extend(segment(SEG_TYPE_PROFILE, 3, &profile.to_bytes()));
    bytes.extend(segment(0x05, 4, b"root"));
    bytes
}

fn content_only_rvf(content: &[u8]) -> Vec<u8> {
    let profile = ContextProfile::new(vec![ProfileView::content(
        1,
        Revision::from_bytes(sha256(content)),
    )
    .unwrap()])
    .unwrap();
    let mut bytes = segment(0x07, 1, content);
    bytes.extend(segment(SEG_TYPE_PROFILE, 2, &profile.to_bytes()));
    bytes.extend(segment(0x05, 3, b"root"));
    bytes
}

fn authority() -> (ContextAuthority<32, 32>, CapabilityHandle, PartitionId) {
    let owner = PartitionId::new(41);
    let mut authority = ContextAuthority::<32, 32>::with_defaults();
    let handle = authority
        .issue_root(
            ContextScope::from_uri(&root(), ContextViewMask::ALL),
            CapRights::READ | CapRights::WRITE | CapRights::EXECUTE | CapRights::PROVE,
            owner,
            PartitionId::HYPERVISOR,
        )
        .unwrap();
    (authority, handle, owner)
}

#[derive(Default)]
struct TogglePurgeSink {
    fail: AtomicBool,
    calls: AtomicUsize,
}

impl PurgeSink for TogglePurgeSink {
    fn purge(&self, _logical_uri: &RuvUri) -> ServiceResult<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            Err(ServiceError::CorruptState("injected purge failure"))
        } else {
            Ok(())
        }
    }
}

fn open_resolver(directory: &TempDir, sink: Arc<TogglePurgeSink>) -> PersistentContextResolver {
    PersistentContextResolver::open(
        directory.path(),
        ResolverOptions::default(),
        Arc::new(LocalKeyProvider::new("test-kek", [0x44; 32]).unwrap()),
        Arc::new(HashEmbedder::new(16).unwrap()),
        sink,
    )
    .unwrap()
}

#[test]
fn durable_alias_search_cas_and_restart() {
    let directory = TempDir::new().unwrap();
    let sink = Arc::new(TogglePurgeSink::default());
    let rvf = context_rvf(b"durable overview", b"durable full content");
    let revision = Revision::from_bytes(sha256(&rvf));
    let pinned = target().with_revision(revision).unwrap().into_uri();

    {
        let resolver = open_resolver(&directory, Arc::clone(&sink));
        let (authority, handle, owner) = authority();
        let mut runtime = ServiceRuntime::new(owner, authority, resolver);
        runtime
            .put(
                &request(handle, ContextOperation::Put, pinned.clone()),
                &rvf,
            )
            .unwrap();
        let snapshot = runtime
            .compare_and_swap_alias(
                &request(handle, ContextOperation::CompareAndSwapAlias, target()),
                None,
                revision,
            )
            .unwrap();
        assert_eq!(snapshot.revision(), revision);
        assert_eq!(runtime.resolver().object_count().unwrap(), 1);
        assert_eq!(runtime.resolver().alias_count().unwrap(), 1);

        let (_, content) = runtime
            .read(&request(handle, ContextOperation::Read, target()))
            .unwrap();
        assert_eq!(content, b"durable full content");
        let hits = runtime
            .search(
                &request(handle, ContextOperation::Search, root()),
                b"durable overview",
                4,
            )
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].revision(), revision);
        assert_eq!(hits[0].alias_generation(), Some(snapshot.generation()));
    }

    let resolver = open_resolver(&directory, Arc::clone(&sink));
    let (authority, handle, owner) = authority();
    let mut runtime = ServiceRuntime::new(owner, authority, resolver);
    let (_, content) = runtime
        .read(&request(handle, ContextOperation::Read, target()))
        .unwrap();
    assert_eq!(content, b"durable full content");
    assert_eq!(runtime.resolver().pending_index_jobs().unwrap(), 0);
    assert_eq!(runtime.resolver().pending_purge_jobs().unwrap(), 0);
}

#[test]
fn content_only_rvf_is_indexable_and_stale_cas_is_rejected() {
    let directory = TempDir::new().unwrap();
    let sink = Arc::new(TogglePurgeSink::default());
    let rvf = content_only_rvf(b"content-only searchable document");
    let revision = Revision::from_bytes(sha256(&rvf));
    let pinned = target().with_revision(revision).unwrap().into_uri();
    let resolver = open_resolver(&directory, sink);
    let (authority, handle, owner) = authority();
    let mut runtime = ServiceRuntime::new(owner, authority, resolver);
    runtime
        .put(&request(handle, ContextOperation::Put, pinned), &rvf)
        .unwrap();
    let snapshot = runtime
        .compare_and_swap_alias(
            &request(handle, ContextOperation::CompareAndSwapAlias, target()),
            None,
            revision,
        )
        .unwrap();
    assert_eq!(
        runtime.compare_and_swap_alias(
            &request(handle, ContextOperation::CompareAndSwapAlias, target(),),
            None,
            revision,
        ),
        Err(ContextError::AliasConflict)
    );
    let hits = runtime
        .search(
            &request(handle, ContextOperation::Search, root()),
            b"searchable document",
            4,
        )
        .unwrap();
    assert_eq!(hits[0].alias_generation(), Some(snapshot.generation()));
}

#[test]
fn forget_is_cryptographic_erasure_and_purge_recovers_after_restart() {
    let directory = TempDir::new().unwrap();
    let sink = Arc::new(TogglePurgeSink::default());
    sink.fail.store(true, Ordering::SeqCst);
    let rvf = context_rvf(b"secret overview", b"secret payload");
    let revision = Revision::from_bytes(sha256(&rvf));
    let pinned = target().with_revision(revision).unwrap().into_uri();

    {
        let resolver = open_resolver(&directory, Arc::clone(&sink));
        let (authority, handle, owner) = authority();
        let mut runtime = ServiceRuntime::new(owner, authority, resolver);
        runtime
            .put(
                &request(handle, ContextOperation::Put, pinned.clone()),
                &rvf,
            )
            .unwrap();
        let live = runtime
            .compare_and_swap_alias(
                &request(handle, ContextOperation::CompareAndSwapAlias, target()),
                None,
                revision,
            )
            .unwrap();
        let tombstone = runtime
            .forget(&request(handle, ContextOperation::Forget, target()), &live)
            .unwrap();
        assert!(tombstone.is_tombstone());
        assert_eq!(runtime.resolver().object_count().unwrap(), 0);
        assert_eq!(runtime.resolver().pending_index_jobs().unwrap(), 0);
        assert_eq!(runtime.resolver().pending_purge_jobs().unwrap(), 1);
        assert_eq!(
            runtime.read(&request(handle, ContextOperation::Read, target())),
            Err(ContextError::Tombstoned)
        );
        assert_eq!(
            runtime.read(&request(handle, ContextOperation::Read, pinned.clone())),
            Err(ContextError::RevisionNotFound)
        );
        assert!(runtime
            .search(
                &request(handle, ContextOperation::Search, root()),
                b"secret",
                4,
            )
            .unwrap()
            .is_empty());
    }

    sink.fail.store(false, Ordering::SeqCst);
    let mut resolver = open_resolver(&directory, Arc::clone(&sink));
    resolver.maintenance().unwrap();
    assert_eq!(resolver.object_count().unwrap(), 0);
    assert_eq!(resolver.alias_count().unwrap(), 1);
    assert_eq!(resolver.pending_purge_jobs().unwrap(), 0);
    assert!(sink.calls.load(Ordering::SeqCst) >= 2);
}

#[test]
fn signed_receipts_and_resume_cursor_commit_atomically() {
    let directory = TempDir::new().unwrap();
    let store = DurableReceiptStore::open(directory.path().join("receipts.redb")).unwrap();
    let signer = HmacSha256WitnessSigner::new([0x66; 32]);
    let (authority, handle, owner) = authority();
    let resolver = open_resolver(&directory, Arc::new(TogglePurgeSink::default()));
    let mut runtime = ServiceRuntime::new(owner, authority, resolver);
    let pinned = target()
        .with_revision(Revision::from_bytes([9; 32]))
        .unwrap()
        .into_uri();
    let seal_request = request(handle, ContextOperation::SealReceipt, pinned);
    let mut scratch = [WitnessRecord::zeroed(); 32];

    let (first, _) = runtime
        .seal_epoch(
            &seal_request,
            &mut scratch,
            [1; 32],
            [9; 32],
            [2; 32],
            [3; 32],
            &signer,
        )
        .unwrap();
    let first_cursor = ReceiptCursor::from_chain_state(runtime.receipt_chain_state());
    store
        .append_verified(&first, first_cursor, &signer)
        .unwrap();
    assert!(store
        .append_verified(&first, first_cursor, &signer)
        .is_err());

    let (second, _) = runtime
        .seal_epoch(
            &seal_request,
            &mut scratch,
            [4; 32],
            [9; 32],
            [5; 32],
            [6; 32],
            &signer,
        )
        .unwrap();
    let second_cursor = ReceiptCursor::from_chain_state(runtime.receipt_chain_state());
    store
        .append_verified(&second, second_cursor, &signer)
        .unwrap();
    assert_eq!(store.cursor().unwrap(), Some(second_cursor));
    assert_eq!(store.receipt(0).unwrap(), Some(first));
    assert_eq!(store.receipt(1).unwrap(), Some(second));
    assert_eq!(
        second_cursor.into_chain_state(),
        runtime.receipt_chain_state()
    );
}

#[test]
fn receipt_drainer_persists_before_advance_and_applies_backpressure() {
    let directory = TempDir::new().unwrap();
    let store = DurableReceiptStore::open(directory.path().join("drained.redb")).unwrap();
    let drainer = ReceiptDrainer::new(store, 8).unwrap();
    let signer = HmacSha256WitnessSigner::new([0x35; 32]);
    let (authority, handle, owner) = authority();
    let resolver = open_resolver(&directory, Arc::new(TogglePurgeSink::default()));
    let mut runtime = ServiceRuntime::new(owner, authority, resolver);
    let pinned = target()
        .with_revision(Revision::from_bytes([9; 32]))
        .unwrap()
        .into_uri();
    let seal_request = request(handle, ContextOperation::SealReceipt, pinned);
    let cursor = drainer
        .seal(
            &mut runtime,
            &seal_request,
            [1; 32],
            [9; 32],
            [2; 32],
            [3; 32],
            &signer,
        )
        .unwrap();
    assert_eq!(drainer.store().cursor().unwrap(), Some(cursor));
    assert_eq!(cursor.into_chain_state(), runtime.receipt_chain_state());
    assert_eq!(drainer.pending(&runtime), 1);

    while drainer.pending(&runtime) < 8 {
        let _ = runtime.resolve(&request(handle, ContextOperation::Resolve, target()));
    }
    assert!(matches!(
        drainer.admit(&runtime),
        Err(ServiceError::Runtime(_))
    ));
}

#[test]
fn https_and_mcp_dispatchers_share_canonical_authorized_operations() {
    let directory = TempDir::new().unwrap();
    let resolver = open_resolver(&directory, Arc::new(TogglePurgeSink::default()));
    let (authority, handle, owner) = authority();
    let runtime = ServiceRuntime::new(owner, authority, resolver);
    let gateway = ContextGateway::new(runtime, handle);
    let rvf = context_rvf(b"gateway overview", b"gateway content");
    let revision = Revision::from_bytes(sha256(&rvf));
    let pinned = target().with_revision(revision).unwrap().to_string();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&rvf);

    let put = gateway.dispatch(
        "/v1/put",
        serde_json::to_string(&serde_json::json!({
            "uri": pinned,
            "rvf_base64": encoded
        }))
        .unwrap()
        .as_bytes(),
    );
    assert_eq!(put.status(), 200, "{}", String::from_utf8_lossy(put.body()));
    let cas = gateway.dispatch(
        "/v1/cas",
        serde_json::to_string(&serde_json::json!({
            "uri": target().to_string(),
            "expected": null,
            "next_revision": revision.to_string()
        }))
        .unwrap()
        .as_bytes(),
    );
    assert_eq!(cas.status(), 200, "{}", String::from_utf8_lossy(cas.body()));
    let read = gateway.dispatch(
        "/v1/read",
        serde_json::to_string(&serde_json::json!({"uri": target().to_string()}))
            .unwrap()
            .as_bytes(),
    );
    let read_json: serde_json::Value = serde_json::from_slice(read.body()).unwrap();
    assert_eq!(read.status(), 200);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(read_json["payload_base64"].as_str().unwrap())
            .unwrap(),
        b"gateway content"
    );

    let mcp = gateway.dispatch_mcp(
        serde_json::to_string(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "ruv_resolve",
                "arguments": {"uri": target().to_string()}
            }
        }))
        .unwrap()
        .as_bytes(),
    );
    let mcp_json: serde_json::Value = serde_json::from_slice(mcp.body()).unwrap();
    assert_eq!(mcp.status(), 200);
    assert_eq!(mcp_json["id"], 7);
    assert_eq!(
        mcp_json["result"]["structuredContent"]["revision"],
        revision.to_string()
    );

    let hidden = gateway.dispatch(
        "/v1/resolve",
        br#"{"uri":"ruv://example.com/other/user/alice/resources/docs/item"}"#,
    );
    assert_eq!(hidden.status(), 404);
}
