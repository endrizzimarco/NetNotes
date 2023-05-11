# NetNotes

A novel cryptographic protocol enabling private transactions. Based on Mimblewimble, it uses one-out-of-many-proof by Jens Groth to achieve
fully private transactions by adding untraceability to the protocol.

:warning: This only serves as a proof of concept and is not intended to be used in production. ::warning::

## Run benchmarks

Make sure to optimise elliptic curve operations by compiling to use the SIMD backend:

```bash
export RUSTFLAGS="-C target_cpu=native"
```

To run benchmarks with `criterion`:

```bash
cargo bench
```

To benchmark a specific protocol, change the name of the bench in `Cargo.toml`:

```rust
[[bench]]
name = "netnotes_benchmark"
harness = false
```

## Run all tests

```bash
cargo test
```

## Run integration tests only

```bash
cargo test --test mimblewimble_test
```

```bash
cargo test --test netnotes_test
```
