# Cocoon Linux Redoxer Deployment Test Flow

This document describes the Linux-side deployment and Redoxer test flow for
Cocoon P1.1.

Cocoon P0 is host-side: it validates capsule intent, verifies bundle integrity,
renders authority diffs, and generates a normalized runtime plan. P1.1 moves the
project toward Redox execution by proving that Cocoon can be built through the
official Redox toolchain path and later exercised inside Redox/QEMU.

This flow does **not** claim full Redox runtime isolation yet. Namespace,
scheme-visibility, and preopened-handle enforcement belong to P1.2.

Current P1.1 validation is CLI-only. The acceptance surface is the `cocoon`
command and the `cargo xtask` smoke commands that drive it; this flow does not
claim separate library API, service manager, or non-CLI entrypoint coverage.

## Goals

The Linux deployment test flow proves:

1. The Cocoon workspace is healthy on Linux.
2. The Redox target check still passes.
3. Redoxer can build a minimal Redox Rust binary.
4. Redoxer can build the Cocoon CLI or reveal dependency portability blockers.
5. The hello capsule can be built, verified, diffed, and planned on the host.
6. The project is ready for the next QEMU image-overlay smoke test.

## Non-goals

This flow does **not** attempt to:

- replace Redox `pkg` or `pkgar`;
- build Docker/OCI compatibility;
- run Linux containers;
- provide production signing;
- enforce Redox namespace isolation;
- run a real Redox appliance;
- perform full `pkgar` payload integration.

## Prerequisites

Use a Linux laptop or Linux VM.

Required tools:

```bash
rustup
cargo
git
pkg-config
make
qemu-system-x86_64
```

Optional but expected for this stage:

```bash
redoxer
```

Install the Redox Rust target:

```bash
rustup target add x86_64-unknown-redox
```

Install Redoxer if not already available:

```bash
cargo install redoxer
```

If `redoxer` is unavailable, `cargo xtask redoxer-smoke` should report `SKIP`
rather than failing the normal host-side gate.

## Checkout

```bash
git clone https://github.com/a19q3/Cocoon.git
cd Cocoon
git checkout p1-redox-qemu-smoke
```

Confirm the expected branch:

```bash
git status
```

Expected:

```text
On branch p1-redox-qemu-smoke
nothing to commit, working tree clean
```

## Step 1: Host Quality Gate

Run the normal project gate:

```bash
cargo xtask test
```

This should run:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

Expected result:

```text
PASS
```

If this fails, stop. The Linux environment is not yet suitable for Redoxer
testing.

## Step 2: Host Cocoon Smoke

Run:

```bash
cargo xtask redox-smoke
```

Expected sections:

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

== Redoxer smoke ==
PASS/SKIP ...

== QEMU smoke ==
PASS/SKIP boot redox qemu
PASS/SKIP run cocoon verify inside redox
PASS/SKIP run cocoon plan inside redox
PASS/SKIP report missing service status inside redox
PASS/SKIP reject check-install before install inside redox
PASS/SKIP reject run before install inside redox
PASS/SKIP reject locked capsule operations inside redox
PASS/SKIP install capsule inside redox
PASS/SKIP report installed service status inside redox
PASS/SKIP probe Redox authority inside redox
PASS/SKIP classify Redox FD-only service launch gap inside redox
PASS/SKIP/BLOCKED probe Redox FD-only controlled service launch inside redox
PASS/SKIP/BLOCKED probe Redox FD-only installed capsule entrypoint inside redox
PASS/SKIP audit Redox authority probe receipt inside redox
PASS/SKIP audit Redox FD-only launch probe receipts inside redox
PASS/SKIP recover temporary install state inside redox
PASS/SKIP reject duplicate install inside redox
PASS/SKIP reject logs before run inside redox
PASS/SKIP reject tampered latest install receipt inside redox
PASS/SKIP reject unenforced authority run inside redox
PASS/SKIP run hello-service inside redox
PASS/SKIP report upgraded service status inside redox
PASS/SKIP roll back capsule inside redox
PASS/SKIP audit receipts inside redox
PASS/SKIP reject current rollback version inside redox
PASS/SKIP reject missing rollback version inside redox
PASS/SKIP reject tampered install inside redox
PASS/SKIP collect receipts/logs
```

Interpretation:

- `PASS` means the stage is currently implemented and successful.
- `SKIP` means the optional dependency, usually Redoxer, is not installed.
- `TODO` means the stage is intentionally scaffolded but not yet implemented.
- A `TODO` must not be treated as runtime success.

## Step 3: Direct Redox Target Check

Run the minimal probe check:

```bash
cargo check -p redox-link-probe --target x86_64-unknown-redox
```

Run the Cocoon CLI target check:

```bash
cargo check -p cocoon-cli --target x86_64-unknown-redox
```

Expected:

```text
Finished dev profile ...
```

Meaning:

- Cocoon's Rust code and dependency graph are checkable for Redox.
- This does not prove that the binary can link or run.

Known limitation:

```bash
cargo build -p cocoon-cli --target x86_64-unknown-redox
```

may reach link stage and fail without the Redox C sysroot/runtime, typically
around:

```text
-lc
-lgcc_eh
```

That is considered a Redox sysroot/toolchain setup issue, not a Cocoon
architecture failure.

## Step 4: Redoxer Smoke

Run:

```bash
cargo xtask redoxer-smoke
```

Expected ideal output:

```text
== Redoxer smoke ==
PASS redoxer available
PASS redoxer build redox-link-probe
PASS redoxer build cocoon-cli
PASS redoxer run cocoon --help
```

If Redoxer is not installed:

```text
SKIP redoxer available (install with `cargo install redoxer`)
SKIP redoxer build redox-link-probe
SKIP redoxer build cocoon-cli
SKIP redoxer run cocoon --help
```

Install Redoxer and retry:

```bash
cargo install redoxer
cargo xtask redoxer-smoke
```

## Step 5: Redox Release Artifact

Run:

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

The artifact directory contains a Redoxer-built `bin/cocoon` when Redoxer is
available, a signed smoke capsule, a production trust policy, and
`release-manifest.json` with BLAKE3 hashes. This is the current native Redox
artifact path until a Redox Cookbook/pkgar recipe is added.

## Step 6: Interpret Redoxer Results

### Case A: `redox-link-probe` fails

If the minimal probe fails, the issue is likely Redoxer/sysroot/toolchain setup.

Do not patch Cocoon core logic yet.

Record:

```text
- Linux distribution and version
- rustc version
- cargo version
- redoxer version
- full error log
```

Then ask in the Redox Build System room whether the current Redoxer setup path is
correct.

### Case B: `redox-link-probe` passes but `cocoon-cli` fails

This suggests a Cocoon dependency or platform-portability issue.

Likely suspects:

```text
clap
flate2
tar
filesystem metadata
path handling
temporary file usage
native compression backend
test-only dependencies leaking into runtime build
```

Recommended response:

1. Do not weaken the security model.
2. Do not move host-only assumptions into `cocoon-core`.
3. Check whether the failure is from CLI-only dependencies.
4. Consider a smaller Redox smoke binary if the full CLI is too heavy.

Possible future split:

```text
cocoon-cli          full host/developer CLI
cocoon-redox-smoke  minimal Redox-side verify/plan/install smoke binary
```

### Case C: both probe and Cocoon CLI pass

Proceed to P1.1c:

```text
QEMU verify/plan smoke
```

The next goal is to boot Redox/QEMU with:

```text
- Cocoon binary
- hello-service.cocoon
```

Then run inside Redox:

```bash
cocoon verify /capsules/hello-service.cocoon
cocoon plan /capsules/hello-service.cocoon
```

Do not start install/run/log smoke until verify/plan succeeds inside Redox.

## Step 6: Build Example Capsule

Build the hello-service capsule:

```bash
cargo run -p cocoon-cli -- build examples/hello-service
```

Expected output:

```text
target/capsules/hello-service.cocoon
```

Verify:

```bash
cargo run -p cocoon-cli -- verify target/capsules/hello-service.cocoon
```

Strict verify fails for unsigned local-development capsules:

```bash
cargo run -p cocoon-cli -- verify --strict target/capsules/hello-service.cocoon
```

Expected:

```text
Bundle signature is required but missing.
```

This is correct for P0 unsigned local development.

For a signed capsule, generate a signing key, sign during build, and verify
against the trusted key:

```bash
cargo run -p cocoon-cli -- keygen --output target/capsules/signing-key.json
cargo run -p cocoon-cli -- build examples/hello-service \
  --output target/capsules/hello-service-signed.cocoon \
  --signing-key target/capsules/signing-key.json
cargo run -p cocoon-cli -- verify --strict \
  target/capsules/hello-service-signed.cocoon \
  --trusted-key target/capsules/signing-key.json
```

Expected:

```text
Verification passed.
```

## Step 7: Runtime Plan Check

Generate the normalized Redox runtime contract:

```bash
cargo run -p cocoon-cli -- plan target/capsules/hello-service.cocoon
```

Expected content:

```text
Runtime plan
Entry
Schemes
Preopens
Permissions
Install root
Receipt inputs
```

This proves that Cocoon can compile a verified capsule into a Redox-oriented
runtime plan without pretending to enforce isolation on the host.

## Step 8: Authority Diff Demo

Build or use the permission-diff fixtures:

```bash
cargo run -p cocoon-cli -- build examples/permission-diff-v1
cargo run -p cocoon-cli -- build examples/permission-diff-v2
```

Run:

```bash
cargo run -p cocoon-cli -- diff-permissions \
  target/capsules/permission-diff-v1.cocoon \
  target/capsules/permission-diff-v2.cocoon
```

Expected behaviour:

- Added authority is grouped and severity-ranked.
- Removed authority is shown as reduction.
- Schemes, preopens, permissions, and network default are included in the diff.
- Deny rules do not count as authority expansion.

## Step 9: Record Environment

For every Linux Redoxer test run, record:

```bash
uname -a
rustc --version
cargo --version
redoxer --version || true
qemu-system-x86_64 --version || true
git rev-parse HEAD
```

Suggested output file:

```text
target/redoxer-smoke/environment.txt
```

## Step 10: Save Logs

Save all smoke logs under:

```text
target/redoxer-smoke/
```

Suggested files:

```text
target/redoxer-smoke/host-smoke.log
target/redoxer-smoke/redox-target-check.log
target/redoxer-smoke/redoxer-build-probe.log
target/redoxer-smoke/redoxer-build-cocoon.log
target/redoxer-smoke/qemu-smoke.log
```

These logs are useful when asking Redox community questions.

## Pass Criteria for P1.1b-real

P1.1b-real is considered passed when:

```text
PASS redoxer available
PASS redoxer build redox-link-probe
PASS redoxer build cocoon-cli
```

`PASS redoxer run cocoon --help` is a stronger execution probe when Redoxer can
run the built binary, but the build pass criteria above are enough to unblock
P1.1c QEMU image-overlay work.

If Cocoon CLI is too heavy for Redoxer at this point, an acceptable fallback is:

```text
PASS redoxer build redox-link-probe
PASS redoxer build cocoon-redox-smoke
DOCUMENT cocoon-cli dependency blocker
```

But that fallback must be explicitly documented and must not be presented as
full Cocoon CLI support.

## P1.1c QEMU Verify/Plan Smoke

After P1.1b-real passes, `cargo xtask qemu-smoke` runs the CLI-only P1.1c
smoke through Redoxer/QEMU:

```text
- prepare Redox image overlay;
- include Cocoon binary;
- include hello-service.cocoon;
- boot Redox in QEMU;
- run `cocoon verify`;
- run `cocoon plan`;
- collect serial output;
- assert expected output on the Linux host.
```

Expected current output when Redoxer is available and the host smoke capsule has
already been prepared:

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

P1.1c still does not claim full runtime isolation.

## P1.1d Install/Run/Log/Receipt Smoke

After verify/plan works inside Redox, `cargo xtask qemu-smoke` continues in the
same CLI-only flow:

```text
- read not-installed status before install;
- confirm check-install is rejected before install;
- confirm run is rejected before install;
- confirm a held capsule lock blocks
  install/recover/check-install/status/logs/run/audit/rollback;
- install capsule;
- read installed status before first run after latest receipt verification;
- run `cocoon probe-authority` to spawn a restricted Redox authority child,
  enter the Redox null namespace, confirm an already-open file preopen remains
  readable, and confirm denied path/scheme opens fail;
- run `cocoon probe-fd-exec` to confirm normal path-based exec is blocked after
  entering the null namespace, classifying the remaining FD-only service launch
  blocker without claiming production `run` enforcement;
- run `cocoon probe-fd-launch` to attempt a controlled fixture launch from an
  inherited executable FD under the restricted namespace, recording either
  controlled-service enforcement evidence or a precise blocked result;
- run `cocoon probe-capsule-fd-launch` to open the installed capsule entrypoint
  before restriction, fexec the entrypoint FD under a manifest-derived
  restricted namespace, and record `redox-enforced-capsule-entrypoint`
  evidence without changing production `cocoon run`;
- run `cocoon audit` to verify authority, controlled FD launch, and installed
  entrypoint FD launch probe receipt bodies, archive links, and captured
  stdout/stderr hashes;
- recover temporary install state left by an interrupted install;
- recover with `--break-lock` to clear an explicitly stale lock;
- confirm reinstalling the same capsule version is rejected;
- stage and promote install tree;
- confirm logs are rejected before any run receipt exists;
- confirm install rejects a rewritten latest install receipt before an upgrade;
- confirm `cocoon run` fails closed unless the operator explicitly acknowledges
  that Redox namespace/preopen enforcement is not active in the smoke runner;
- run hello-service with `--allow-unenforced-authority`;
- confirm the run receipt, status, and audit output record
  stdout/stderr log hashes and `smoke-unenforced` authority mode;
- capture stdout/stderr;
- write install/run receipts;
- collect logs.
- read the latest captured stdout through `cocoon logs` after latest-run
  receipt/log hash verification;
- install a second capsule version;
- read upgraded status before rollback after latest receipt verification;
- roll back to the first version;
- audit lifecycle receipt body hashes and latest-to-archive receipt links;
- confirm rollback to the already-current version is rejected;
- confirm rollback to a missing version is rejected;
- verify the current installed tree through `cocoon check-install`;
- tamper with the installed executable and confirm `cocoon check-install`
  and `cocoon status` reject the install before any later run can use it;
- read status back from the latest install/run receipts.
```

This stage still uses Redoxer/QEMU as an execution bridge and does not construct
the final Redox namespace enforcement model.

## Later Stage: P1.2 Runtime Enforcement

P1.2 is the first stage that should prove Redox runtime enforcement:

```text
- constructed namespace;
- scheme visibility;
- preopened handles;
- denied scheme/path access fails during actual service execution;
- service cannot access undeclared authority.
```

Until P1.2 passes, Cocoon should not claim to enforce Redox isolation.
The current P1.2c probe makes that boundary explicit: path-based launch is not
the production enforcement path after namespace restriction; arbitrary service
execution still needs an FD-only loader/exec implementation.
