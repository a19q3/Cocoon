# Cocoon macOS Development Guide

## 1. Install Dependencies

- Rust stable (`rustup`)
- `cargo-nextest` (optional)
- `just` (optional)
- `git`
- `zstd` / `tar` (used by bundle compression)

## 2. Clone Repository

```bash
git clone https://github.com/a19q3/Cocoon.git
cd cocoon
```

## 3. Run Unit Tests

```bash
cargo test
```

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
```

## 8. Permission Diff

```bash
cargo run -p cocoon-cli -- diff-permissions examples/v1.cocoon examples/v2.cocoon
```

## 9. Redox Integration

Use a Linux laptop or Linux VM for QEMU integration.
See [REDOX_TESTING.md](REDOX_TESTING.md).
