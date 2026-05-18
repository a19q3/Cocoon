# Cocoon Redox Testing Guide

P1 testing starts with a smoke scaffold. The first goal is not full namespace
enforcement; it is to prove that the Cocoon lifecycle can move from host-side
verification into a Redox/QEMU execution path.

For the concrete Linux-side Redoxer deployment flow, see
[LINUX_REDOXER_DEPLOYMENT_TEST.md](LINUX_REDOXER_DEPLOYMENT_TEST.md).

Current Redox smoke validation is CLI-only. Tests exercise the `cocoon` command
directly or through `cargo xtask`; they do not claim coverage for library API,
service manager, or other non-CLI entrypoints.

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
PASS build hello-service v2 capsule
PASS verify capsule
PASS generate bundle signing key
PASS build signed capsule
PASS strict verify signed capsule
PASS generate runtime plan
PASS image overlay prepared

== Redox target smoke ==
PASS redox link probe cargo check
PASS cocoon-cli redox cargo check
TODO redox link probe binary link (requires Redox C sysroot/toolchain)
TODO cocoon-cli redox binary link (requires Redox C sysroot/toolchain)

== QEMU smoke ==
SKIP boot redox qemu (install with `cargo install redoxer`)
SKIP run cocoon verify inside redox
SKIP run cocoon plan inside redox
SKIP report missing service status inside redox
SKIP reject check-install before install inside redox
SKIP reject run before install inside redox
SKIP reject locked capsule operations inside redox
SKIP install capsule inside redox
SKIP report installed service status inside redox
SKIP probe Redox authority inside redox
SKIP classify Redox FD-only service launch gap inside redox
SKIP probe Redox FD-only controlled service launch inside redox
SKIP probe Redox FD-only installed capsule entrypoint inside redox
SKIP cocoon run uses FD-only capsule entrypoint backend inside redox
SKIP P1.2g log-service FD run profile inside redox
SKIP P1.2g network-denied-service FD run profile inside redox
SKIP audit Redox authority probe receipt inside redox
SKIP audit Redox FD-only launch probe receipts inside redox
SKIP recover temporary install state inside redox
SKIP reject duplicate install inside redox
SKIP reject logs before run inside redox
SKIP reject tampered latest install receipt inside redox
SKIP reject unenforced authority run inside redox
SKIP run hello-service inside redox
SKIP report upgraded service status inside redox
SKIP roll back capsule inside redox
SKIP audit receipts inside redox
SKIP reject current rollback version inside redox
SKIP reject missing rollback version inside redox
SKIP reject tampered install inside redox
SKIP collect receipts/logs
```

The direct Redox binary link TODOs are reported but not executed by the
integrated smoke gate because the current native artifact path is Redoxer.
Run `cargo xtask redoxer-smoke` separately when checking only Redoxer build/run
readiness.

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

Run the CLI-only Redox/QEMU verify/plan smoke through Redoxer:

## Redox Release Artifact

Build the current Redoxer-backed release artifact directory:

```bash
cargo xtask redox-package
```

Expected output:

```text
== Redox package ==
PASS host build cocoon for package staging
PASS package signing key generated
PASS package signed capsule built
PASS package trust policy staged
PASS package redoxer cocoon binary staged
PASS package release manifest written
Package root: target/redox-package/cocoon-redox
```

The staged directory contains:

```text
target/redox-package/cocoon-redox/
  README.txt
  release-manifest.json
  bin/cocoon
  capsules/hello-service-signed.cocoon
  trust/trust-roots.json
```

`release-manifest.json` records artifact sizes and BLAKE3 hashes. The trust
config requires signed bundles and signed receipts, matching the production
trust policy path. If Redoxer is unavailable, the task still stages the signed
capsule and trust policy, but reports `SKIP package redoxer cocoon binary
staged`.

This is the current native Redox artifact path. Direct `x86_64-unknown-redox`
binary linking remains dependent on the Redox C sysroot/toolchain, and
pkgar/Cookbook integration remains a separate payload packaging alignment item.

```bash
cargo xtask qemu-smoke
```

The QEMU harness stages only the Redox binary and smoke capsules under
`target/redox-smoke/redoxer-root`, then maps that directory through Redoxer.
It does not copy the full repository or host `target/` tree into `/root`.
Required Redoxer commands expose non-zero exit status and combined stdout/stderr
instead of degrading failed execution into `TODO` output.
Run Redoxer/QEMU tasks serially; concurrent `redox-package`, `redox-smoke`, or
`qemu-smoke` invocations can contend for Redoxer temporary disk state and
produce wrapper-level failures even when the guest command exits successfully.

Expected output after Redoxer is installed and the host smoke capsule exists:

```text
== QEMU smoke ==
PASS boot redox qemu
PASS run cocoon verify inside redox
PASS run cocoon plan inside redox
PASS report missing service status inside redox
PASS reject check-install before install inside redox
PASS reject run before install inside redox
PASS reject locked capsule operations inside redox
PASS install capsule inside redox
PASS report installed service status inside redox
PASS probe Redox authority inside redox
PASS classify Redox FD-only service launch gap inside redox
PASS/BLOCKED probe Redox FD-only controlled service launch inside redox
PASS/BLOCKED probe Redox FD-only installed capsule entrypoint inside redox
PASS cocoon run uses FD-only capsule entrypoint backend inside redox
PASS P1.2g log-service FD run profile inside redox
PASS P1.2g network-denied-service FD run profile inside redox
PASS audit Redox authority probe receipt inside redox
PASS redox authority probe receipt audited
PASS audit Redox FD-only launch probe receipts inside redox
PASS recover temporary install state inside redox
PASS reject duplicate install inside redox
PASS reject logs before run inside redox
PASS reject tampered latest install receipt inside redox
PASS reject unenforced authority run inside redox
PASS run hello-service inside redox
PASS report upgraded service status inside redox
PASS roll back capsule inside redox
PASS audit receipts inside redox
PASS reject current rollback version inside redox
PASS reject missing rollback version inside redox
PASS reject tampered install inside redox
PASS collect receipts/logs
```

The final receipts/logs line includes `cocoon status hello-service`,
`cocoon logs hello-service --stream stdout`, and `cocoon check-install
hello-service` readback inside the same Redoxer/QEMU execution flow. `cocoon
logs` verifies the latest run receipt and captured log hashes before printing
the log, and `cocoon status` verifies latest receipt integrity before reporting
state. The flow also checks
checking not-installed status, confirming check-install and run are rejected
before install, confirming a held capsule lock blocks lifecycle operations,
checking installed status before the first run, recovering temporary install
state, confirming `--break-lock` clears an explicitly stale lock, confirming
logs are rejected before a run receipt exists, confirming duplicate install is
rejected, confirming default `cocoon run` rejects unenforced authority,
executing the smoke run only with `--allow-unenforced-authority`, installing a
second version, checking upgraded status before rollback, and recording the
smoke run as `smoke-unenforced` with stdout/stderr log hashes in run
receipt/status/audit output,
rolling back to the first, auditing lifecycle receipt body hashes, confirming
latest receipts are backed by archived receipt files, confirming
rollback to the already-current version and to a missing version are rejected,
and confirming a tampered installed executable is rejected by status and
check-install before any later run can use it.

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
- `probe-authority` proves an already-open file preopen remains readable after
  entering the Redox null namespace from a child process;
- `probe-authority` proves denied path/scheme opens fail after the namespace
  restriction;
- `audit` verifies the authority probe receipt body, archive link, and captured
  child stdout/stderr hashes;
- `probe-fd-exec` proves path-based exec is blocked after entering the null
  namespace and keeps FD-only service launch as the remaining production
  enforcement blocker;
- `probe-fd-launch` attempts a controlled fixture launch from an inherited
  executable FD under the restricted namespace and records either controlled
  enforcement evidence or a `redox-fd-launch-blocked` upstream API gap;
- `probe-capsule-fd-launch` opens the installed capsule entrypoint before
  restriction, fexecs it under a manifest-derived restricted namespace, and
  records `redox-enforced-capsule-entrypoint` evidence while keeping
  production `cocoon run` fail-closed;
- `run --enforce-redox-authority` uses the same FD-only installed-entrypoint
  backend, writes a normal `capsule_run` receipt, and keeps
  `production_arbitrary_service = false`;
- additional `log-service` and `network-denied-service` profiles use the same
  FD-only run backend and are verified through status, logs, and audit;
- `audit` verifies authority, controlled FD launch, installed entrypoint FD
  launch probe, and enforced run receipt bodies, archive links, and captured
  stdout/stderr hashes;
- constructed Redox namespace;
- preopened handles passed to the service;
- stdout/stderr log capture;
- install and run receipts;
- denied scheme/path access fails during actual service execution.

Until those checks exist, Cocoon only claims that P0 defines and verifies capsule
intent. Runtime isolation claims start with Redox/QEMU evidence.

## References

- Redox build system reference: <https://doc.redox-os.org/book/build-system-reference.html>
- Including programs in Redox: <https://doc.redox-os.org/book/including-programs.html>
- Redox programs and libraries: <https://doc.redox-os.org/book/programs-libraries.html>
- Redoxer README: <https://docs.rs/crate/redoxer/latest/source/README.md>
