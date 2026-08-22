//! End-to-end context-permit to instance-creation tests.

use super::*;
use crate::event_of;
use alloc::vec;
use rvm_context::{
    ContextAuthority, ContextOperation, ContextProfile, ContextRequest, ContextRuntime,
    ContextScope, ContextViewMask, MemoryResolver, ProfileView, Revision, RuvUri,
};
use rvm_host::{Placement, VerifiedPackage, WasmAdapter};
use rvm_rvf::format::{SEG_TYPE_MANIFEST, SEG_TYPE_META, SEG_TYPE_WASM};
use rvm_rvf::{
    content_hash, sha256, SegmentHeader, SEGMENT_HEADER_SIZE, SEGMENT_MAGIC, SEGMENT_VERSION,
    SEG_TYPE_PROFILE,
};
use rvm_types::{CapRights, PartitionId};

fn segment(segment_type: u8, segment_id: u64, payload: &[u8]) -> Vec<u8> {
    let total = SEGMENT_HEADER_SIZE + payload.len();
    let padded = total.div_ceil(SEGMENT_HEADER_SIZE) * SEGMENT_HEADER_SIZE;
    let header = SegmentHeader {
        magic: SEGMENT_MAGIC,
        version: SEGMENT_VERSION,
        seg_type: segment_type,
        flags: 0,
        segment_id,
        payload_length: u64::try_from(payload.len()).unwrap(),
        timestamp_ns: 0,
        checksum_algo: 2,
        compression: 0,
        reserved_0: 0,
        reserved_1: 0,
        content_hash: content_hash(2, payload),
        uncompressed_len: 0,
        alignment_pad: u32::try_from(padded - total).unwrap(),
    };
    let mut output = header.to_bytes().to_vec();
    output.extend_from_slice(payload);
    output.resize(padded, 0);
    output
}

fn executable_context_rvf() -> Vec<u8> {
    let wasm = rvm_host::testkit::MINIMAL_WASM;
    let profile = ContextProfile::new(vec![ProfileView::content(
        2,
        Revision::from_bytes(sha256(&wasm)),
    )
    .unwrap()])
    .unwrap();
    let mut rvf = segment(SEG_TYPE_META, 1, b"rvf.capabilities=memory");
    rvf.extend(segment(SEG_TYPE_WASM, 2, &wasm));
    rvf.extend(segment(SEG_TYPE_PROFILE, 3, &profile.to_bytes()));
    rvf.extend(segment(SEG_TYPE_MANIFEST, 4, b"root"));
    rvf
}

#[test]
fn context_permit_is_consumed_and_bound_to_identity_and_actor() {
    let rvf = executable_context_rvf();
    let revision = Revision::from_bytes(sha256(&rvf));
    let alias = RuvUri::parse("ruv://example.com/acme/agent/tool/skills/run").unwrap();
    let pinned = alias.clone().with_revision(revision).unwrap().into_uri();
    let scope = RuvUri::parse("ruv://example.com/acme/agent/tool/skills").unwrap();
    let owner = PartitionId::new(41);
    let mut authority = ContextAuthority::<16, 16>::with_defaults();
    let handle = authority
        .issue_root(
            ContextScope::from_uri(&scope, ContextViewMask::ALL),
            CapRights::WRITE | CapRights::EXECUTE,
            owner,
            PartitionId::HYPERVISOR,
        )
        .unwrap();
    let mut runtime = ContextRuntime::<MemoryResolver<8, 8>, 16, 16, 64>::new(
        owner,
        authority,
        MemoryResolver::new(),
    );
    runtime
        .put(
            &ContextRequest::new(handle, ContextOperation::Put, pinned.clone()),
            &rvf,
        )
        .unwrap();

    let report = rvm_rvf::verify(&rvf, &rvm_host::testkit::lenient_options()).unwrap();
    let package = VerifiedPackage::from_report(&report).unwrap();
    let placement = Placement::new(owner, 0, 16);
    let launch_log = WitnessLog::<128>::new();

    let mismatch_permit = runtime
        .authorize_execute(&ContextRequest::new(
            handle,
            ContextOperation::Execute,
            pinned.clone(),
        ))
        .unwrap();
    let mismatch = Instance::create_from_context(
        InstanceId::new(1),
        WasmAdapter::new(),
        rvm_host::testkit::package("memory"),
        placement,
        mismatch_permit,
        &launch_log,
        1,
    );
    assert!(matches!(mismatch, Err(LaunchError::ContextPermitMismatch)));
    assert_eq!(
        event_of(&launch_log.get(0).unwrap()),
        Some(LaunchEvent::ContextPermitRejected)
    );

    let permit = runtime
        .authorize_execute(&ContextRequest::new(
            handle,
            ContextOperation::Execute,
            pinned.clone(),
        ))
        .unwrap();
    let permit_sequence = permit.witness_sequence();
    let instance = Instance::create_from_context(
        InstanceId::new(2),
        WasmAdapter::new(),
        package,
        placement,
        permit,
        &launch_log,
        2,
    )
    .unwrap();
    let authorization = instance.context_authorization().unwrap();
    assert_eq!(authorization.actor(), owner);
    assert_eq!(authorization.pinned_uri().as_uri(), &pinned);
    assert_eq!(authorization.witness_sequence(), permit_sequence);
    assert_eq!(instance.state(), InstanceState::Created);
    assert_eq!(instance.agent(), None);
}
