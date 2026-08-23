//! Benchmarks for canonical `ruv://` parsing.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rvm_context::RuvUri;

const ALIAS: &str =
    "ruv://context.example/acme/agent/researcher/resources/projects/orion/spec?view=overview";
const PINNED: &str = concat!(
    "ruv://context.example/acme/agent/researcher/skills/web-search?rev=sha256:",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "&view=content",
);

fn bench_context_uri(c: &mut Criterion) {
    c.bench_function("ruv_uri_parse_alias", |b| {
        b.iter(|| RuvUri::parse(black_box(ALIAS)).unwrap());
    });
    c.bench_function("ruv_uri_parse_pinned", |b| {
        b.iter(|| RuvUri::parse(black_box(PINNED)).unwrap());
    });

    let parsed = RuvUri::parse(PINNED).unwrap();
    c.bench_function("ruv_uri_format_pinned", |b| {
        b.iter(|| black_box(&parsed).to_string());
    });
}

criterion_group!(benches, bench_context_uri);
criterion_main!(benches);
