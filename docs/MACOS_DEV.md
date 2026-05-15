# Cocoon macOS Development Guide

## 1. Install Dependencies

- Rust stable (`rustup`)
- `cargo-nextest` (optional)
- `just` (optional)
- `git`
- system `tar` is useful for inspection; Cocoon uses Rust gzip/tar libraries

## 2. Clone Repository

```bash
git clone https://github.com/a19q3/Cocoon.git
cd cocoon
```

## 3. Run Local Gate

```bash
cargo xtask test
```

This runs formatting, clippy with warnings denied, and workspace tests.

## 4. Build CLI

```bash
cargo build -p cocoon-cli
```

## 5. Build Example Capsule

```bash
cargo run -p cocoon-cli -- build examples/hello-service
```

## 6. Inspect Capsule

```bash
cargo run -p cocoon-cli -- inspect target/capsules/hello-service.cocoon
```

## 7. Verify Capsule

```bash
cargo run -p cocoon-cli -- verify target/capsules/hello-service.cocoon
cargo run -p cocoon-cli -- verify --strict target/capsules/hello-service.cocoon
```

P0 capsules are unsigned by default. The non-strict command reports that as a
warning; strict mode is intended for the future signed install path.

## 8. Permission Diff

```bash
cargo run -p cocoon-cli -- diff-permissions examples/v1.cocoon examples/v2.cocoon
```

## 9. Redox Integration

Use a Linux laptop or Linux VM for QEMU integration.
See [REDOX_TESTING.md](REDOX_TESTING.md).
