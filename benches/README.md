# rvm-benches

Criterion benchmarks for performance-critical RVM subsystems.

This crate contains micro-benchmarks for the hot paths identified in the
RVM design constraints. It is not published and exists solely for
`cargo bench` performance validation.

## Benchmarks

| Benchmark | File | What it Measures |
|-----------|------|------------------|
| `coherence` | `benches/coherence.rs` | `EmaFilter::update` throughput (fixed-point EMA computation) |
| `witness` | `benches/witness.rs` | `WitnessLog::append` throughput (256-slot ring buffer) |
| `context` | `benches/context.rs` | Canonical `ruv://` parse and format latency |
| `context_service` | `benches/context_service.rs` | RVF compilation, deterministic embedding, and durable authorized resolution |
| `rvm_bench` | `benches/rvm_bench.rs` | Integrated witness, capability, proof, partition, coherence, memory, security, and GPU hot paths |

## Running

```bash
cargo bench -p rvm-benches
```

## Workspace Dependencies

- `rvm-types`
- `rvm-cap`
- `rvm-witness`
- `rvm-sched`
- `rvm-coherence`
- `criterion`
