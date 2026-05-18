# Cocoon Fuzz Targets

Requires nightly Rust and `cargo-fuzz`:

```bash
rustup default nightly
cargo install cargo-fuzz
```

## Running

```bash
cd fuzz
cargo fuzz run bundle_from_bytes -- -max_total_time=60
cargo fuzz run archive_path      -- -max_total_time=60
```
