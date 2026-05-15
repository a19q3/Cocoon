# Cocoon Redox Testing Guide

P1 testing starts with a smoke scaffold. The first goal is not full namespace
enforcement; it is to prove that the Cocoon lifecycle can move from host-side
verification into a Redox/QEMU execution path.

## Linux Dependencies

Use a Linux laptop or Linux VM with:

- Rust stable
- Git
- QEMU
- Redox build dependencies
- a local Redox checkout when moving beyond the scaffold

## P1 Scaffold

From the Cocoon repository:

```bash
cargo xtask redox-smoke
```

Expected early output:

```text
PASS host build cocoon
PASS redox target cargo check
PASS build hello-service.cocoon
PASS verify capsule
PASS generate runtime plan
PASS image overlay prepared
TODO redox binary link (requires Redox C sysroot/toolchain, not only rust-std)
TODO boot redox qemu
TODO run cocoon verify inside redox
TODO run cocoon plan inside redox
TODO install capsule inside redox
TODO run hello-service inside redox
TODO collect receipts/logs
```

If `PASS redox target cargo check` is replaced by TODO, install the Rust target:

```bash
rustup target add x86_64-unknown-redox
```

On macOS, `cargo build -p cocoon-cli --target x86_64-unknown-redox` can still
fail at the linker stage because the Rust target does not include the Redox C
sysroot and gcc runtime libraries. That is a toolchain/sysroot task, not a core
crate portability failure. `cargo check --target x86_64-unknown-redox` is the
current code-level portability gate.

The scaffold writes:

```text
target/redox-smoke/
  ├── hello-service.cocoon
  └── overlay/
      └── capsules/
          └── hello-service.cocoon
```

## Manual Steps

Build the capsule:

```bash
cargo run -p cocoon-cli -- build examples/hello-service \
  --output target/redox-smoke/hello-service.cocoon
```

Verify it:

```bash
cargo run -p cocoon-cli -- verify target/redox-smoke/hello-service.cocoon
```

Render the runtime plan:

```bash
cargo run -p cocoon-cli -- plan target/redox-smoke/hello-service.cocoon
```

Check Redox target portability:

```bash
cargo check -p cocoon-cli --target x86_64-unknown-redox
```

Prepare an image overlay:

```bash
./redox/scripts/build-image.sh
```

Boot QEMU once a Redox image path exists:

```bash
./redox/scripts/qemu.sh path/to/redox.img
```

## Future P1 Acceptance

The real Redox/QEMU smoke test should eventually prove:

- verify before install;
- staged install and atomic promote;
- constructed Redox namespace;
- preopened handles passed to the service;
- stdout/stderr log capture;
- install and run receipts;
- denied scheme/path access fails.

Until those checks exist, Cocoon only claims that P0 defines and verifies capsule
intent. Runtime isolation claims start with Redox/QEMU evidence.
