//! Hosted context-service compiler, embedding, and durable lookup benchmarks.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rvm_context::{
    ContextAuthority, ContextOperation, ContextRequest, ContextRuntime, ContextScope,
    ContextViewMask, Revision, RuvUri,
};
use rvm_context_service::{
    ContextCompileRequest, ContextEmbedder, HashEmbedder, LocalKeyProvider, NoopPurgeSink,
    PersistentContextResolver, ResolverOptions, RvfContextCompiler,
};
use rvm_types::{CapRights, PartitionId};
use std::sync::Arc;

fn bench_context_service(c: &mut Criterion) {
    let compile_input = vec![0x41; 4096];
    c.bench_function("rvf_context_compile_4k", |b| {
        b.iter(|| {
            RvfContextCompiler::compile(ContextCompileRequest::data(black_box(
                compile_input.clone(),
            )))
            .unwrap()
        });
    });

    let embedder = HashEmbedder::new(384).unwrap();
    c.bench_function("context_hash_embed_4k_384d", |b| {
        b.iter(|| embedder.embed(black_box(&compile_input)).unwrap());
    });

    let directory = tempfile::TempDir::new().unwrap();
    let artifact =
        RvfContextCompiler::compile(ContextCompileRequest::data(b"lookup content".to_vec()))
            .unwrap();
    let alias =
        RuvUri::parse("ruv://context.example/acme/agent/bench/resources/docs/item").unwrap();
    let root = RuvUri::parse("ruv://context.example/acme/agent/bench/resources/docs").unwrap();
    let pinned = alias
        .clone()
        .with_revision(artifact.identity())
        .unwrap()
        .into_uri();
    let resolver = PersistentContextResolver::open(
        directory.path(),
        ResolverOptions::default(),
        Arc::new(LocalKeyProvider::new("bench", [0x77; 32]).unwrap()),
        Arc::new(HashEmbedder::new(16).unwrap()),
        Arc::new(NoopPurgeSink),
    )
    .unwrap();
    let actor = PartitionId::new(44);
    let mut authority = ContextAuthority::<16, 16>::with_defaults();
    let capability = authority
        .issue_root(
            ContextScope::from_uri(&root, ContextViewMask::ALL),
            CapRights::READ | CapRights::WRITE,
            actor,
            PartitionId::HYPERVISOR,
        )
        .unwrap();
    let mut runtime =
        ContextRuntime::<PersistentContextResolver, 16, 16, 16>::new(actor, authority, resolver);
    runtime
        .put(
            &ContextRequest::new(capability, ContextOperation::Put, pinned),
            artifact.rvf(),
        )
        .unwrap();
    runtime
        .compare_and_swap_alias(
            &ContextRequest::new(
                capability,
                ContextOperation::CompareAndSwapAlias,
                alias.clone(),
            ),
            None,
            Revision::from_bytes(*artifact.identity().as_bytes()),
        )
        .unwrap();
    let resolve = ContextRequest::new(capability, ContextOperation::Resolve, alias);
    c.bench_function("context_durable_authorized_resolve", |b| {
        b.iter(|| runtime.resolve(black_box(&resolve)).unwrap());
    });
}

criterion_group!(benches, bench_context_service);
criterion_main!(benches);
