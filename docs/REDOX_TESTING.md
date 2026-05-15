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
== Host smoke ==
PASS host build cocoon
PASS build hello-service.cocoon
PASS verify capsule
PASS generate runtime plan
PASS image overlay prepared

== Redox target smoke ==
PASS redox link probe cargo check
PASS cocoon-cli redox cargo check
TODO redox link probe binary link (requires Redox C sysroot/toolchain)
TODO cocoon-cli redox binary link (requires Redox C sysroot/toolchain)

== Redoxer smoke ==
SKIP redoxer available (install with `cargo install redoxer`)
SKIP redoxer build redox-link-probe
SKIP redoxer build cocoon-cli
SKIP redoxer run cocoon --help

== QEMU smoke ==
TODO boot redox qemu
TODO run cocoon verify inside redox
TODO run cocoon plan inside redox
TODO install capsule inside redox
TODO run hello-service inside redox
TODO collect receipts/logs
```

If either Redox target `cargo check` line is replaced by TODO, install the Rust
target:

```bash
rustup target add x86_64-unknown-redox
```

On macOS, `cargo build -p redox-link-probe --target x86_64-unknown-redox` and
`cargo build -p cocoon-cli --target x86_64-unknown-redox` can still fail at the
linker stage because the Rust target does not include the Redox C sysroot and
gcc runtime libraries. If the minimal `redox-link-probe` crate also fails to
link, treat the issue as a toolchain/sysroot task, not a Cocoon architecture
failure. `cargo check --target x86_64-unknown-redox` is the current code-level
portability gate.

The scaffold writes:

```text
target/redox-smoke/
  ├── hello-service.cocoon
  └── overlay/
      └── capsules/
          └── hello-service.cocoon
```

Optional Redox target checks are quiet by default so the scaffold output stays
readable. To see the underlying linker or target diagnostics, run:

```bash
COCOON_SMOKE_VERBOSE=1 cargo xtask redox-smoke
```

## Redox Toolchain Bridge

P1.1a/P1.1b are about making the toolchain path reproducible before claiming a QEMU
execution smoke. Do not hand-roll linker flags as the default path.

There are two upstream-aligned routes to verify:

- Redox Cookbook recipe: the Redox build system uses Cookbook recipes to compile
  programs into Redox-specific binaries, stage files, and produce `pkgar` or
  legacy tar packages. This is the likely long-term image integration path for
  Cocoon.
- Redoxer: `redoxer` installs/manages a Redox toolchain, exposes a sysroot via
  `REDOXER_SYSROOT`, runs Cargo with the Redox environment, and can run commands
  inside a Redox QEMU image. This is the smallest path for a linking and
  execution probe.

Current investigation targets:

1. Build `redox-link-probe` with the Redox target.
2. If the probe links, build `cocoon-cli` with the same environment.
3. If both link, copy the Cocoon binary and `hello-service.cocoon` into an image
   overlay.
4. If the probe does not link, set up Redoxer or a Redox build-system checkout
   and repeat before changing Cocoon code.

Redoxer is optional for the default smoke scaffold. If it is installed, Cocoon
will try the official Redoxer build path:

```bash
cargo xtask redoxer-smoke
```

Expected progression:

```text
== Redoxer smoke ==
PASS redoxer available
PASS redoxer build redox-link-probe
PASS redoxer build cocoon-cli
PASS redoxer run cocoon --help
```

If Redoxer is missing, the command reports SKIP and exits successfully. If the
minimal probe fails under Redoxer, keep the failure classified as toolchain setup
until the Redoxer toolchain has been initialized.

Manual Redoxer setup:

```bash
cargo install redoxer
redoxer toolchain
redoxer build -p redox-link-probe
redoxer build -p cocoon-cli
redoxer run -p cocoon-cli -- --help
```

The Redoxer README describes `redoxer build` as a Cargo build run with the Redox
environment, `redoxer run` as running a Cargo target inside Redox, and
`REDOXER_SYSROOT` as the sysroot override when needed.

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
cargo check -p redox-link-probe --target x86_64-unknown-redox
cargo check -p cocoon-cli --target x86_64-unknown-redox
```

Probe Redox linking:

```bash
cargo build -p redox-link-probe --target x86_64-unknown-redox
cargo build -p cocoon-cli --target x86_64-unknown-redox
```

Probe Redoxer linking and execution:

```bash
cargo xtask redoxer-smoke
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

## References

- Redox build system reference: <https://doc.redox-os.org/book/build-system-reference.html>
- Including programs in Redox: <https://doc.redox-os.org/book/including-programs.html>
- Redox programs and libraries: <https://doc.redox-os.org/book/programs-libraries.html>
- Redoxer README: <https://docs.rs/crate/redoxer/latest/source/README.md>
