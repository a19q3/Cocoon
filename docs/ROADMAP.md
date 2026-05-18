# Cocoon Roadmap

## Scope Boundary

Cocoon stays above Redox package management. It does not replace `pkg`, `pkgar`,
dependency resolution, package repositories, or whole-system updates. The payload
layer should converge on `pkgar`; Cocoon adds service authority: manifests,
permission diffs, runtime plans, receipts, and rollback policy.

For the live production-readiness gap list and acceptance tracker, see
[PRODUCTION_READINESS_TRACKER.md](PRODUCTION_READINESS_TRACKER.md).

## P0.1: Style Gate

Goal: make the workspace boring to maintain.

- `cargo fmt --all --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --workspace`
- No `unwrap()` in non-test code.
- Public APIs use typed domain values for security-sensitive concepts.

## P0.2: Strict Bundle Verifier

Goal: make `cocoon verify` an integrity primitive, not a demo command.

- Detect modified files.
- Detect missing files.
- Detect extra files.
- Reject duplicate archive paths.
- Reject parent traversal and absolute archive paths.
- Reject corrupted hash manifests.
- Detect manifest/hash mismatch.
- Reject capsules whose `entry.cmd` does not map to an executable payload file.
- Support unsigned local mode and strict signature-required mode.

## P0.3: Typed Permission AST

Goal: model Redox-native intent without pretending to enforce runtime isolation
on macOS.

- Use `[[scheme]]` for namespace/scheme visibility.
- Use `[[preopen]]` for preopened handles.
- Use `[[permission]]` for operation permissions.
- Keep legacy `[[capability]]` parsing only as a compatibility alias.
- Diff normalized permission rules instead of raw strings.
- Include scheme visibility, preopens, and network defaults in authority review.

## P0.4: Permission Diff Product Moment

Goal: make updates understandable before they are installed.

Expected output shape:

```text
Permission changes detected:
      HIGH: new permission: allow tcp connect api.example.com:443
    MEDIUM: new permission: allow file readwrite /app/cache/**

Removed permissions:
  - allow file read /app/assets/**
```

## P1: Redox/QEMU Runtime Smoke

Goal: prove the runtime path on Redox.

### P1.1: Redox Execution Smoke

Goal: prove the Cocoon lifecycle inside Redox/QEMU without claiming full
namespace enforcement.

#### P1.1a: Redox Toolchain Bridge

Goal: separate Cocoon portability from Redox sysroot/linker readiness.

- Keep host-side capsule build, verify, plan, and overlay preparation green.
- Add a minimal `redox-link-probe` binary crate.
- Check the probe and Cocoon CLI against `x86_64-unknown-redox`.
- Attempt Redox binary linking for the probe before debugging Cocoon-specific
  dependencies.
- Prefer Redoxer or a Redox Cookbook recipe path over custom linker flag hacks.

#### P1.1b: Redoxer / Cookbook Integration Spike

Goal: use the official Redox-supported build path to produce a linkable Cocoon
binary.

- Detect Redoxer without making it a default local dependency.
- Build `redox-link-probe` through Redoxer first.
- Build `cocoon-cli` through Redoxer only after the probe succeeds.
- Run `cocoon --help` through Redoxer or equivalent QEMU bridge.
- Keep a Cookbook recipe draft for the eventual image integration path.

- Build Cocoon CLI/runtime for the Redox target.
- Include Cocoon binary and hello-service capsule in a Redox image overlay.
- Boot QEMU.
- Run `cocoon verify` inside Redox.
- Run `cocoon plan` inside Redox.
- Install capsule via staged install.
- Promote to current.
- Run hello service.
- Capture stdout/stderr.
- Write install and run receipts.

Current `cargo xtask qemu-smoke` covers these P1.1 lifecycle steps through the
Cocoon CLI under Redoxer/QEMU, including status readback from install/run
receipts, per-capsule lifecycle lock rejection, and installed-payload tamper
rejection. `cocoon run` now fails closed unless the smoke flow passes
`--allow-unenforced-authority`, and run receipts/status/audit output record the
`smoke-unenforced` authority mode plus stdout/stderr log hashes so execution
evidence cannot be confused with an isolation proof.

P1.1 is an execution smoke, not an isolation proof.

### P1.2: Enforcement Smoke

Goal: prove Redox authority enforcement after the lifecycle is running.

- Add `cocoon probe-authority` as P1.2a evidence for Redox null namespace
  behavior: already-open file preopens remain usable, denied path/scheme opens
  fail.
- Add a P1.2b restricted authority child so the namespace proof happens in a
  child process with captured logs and audited `authority_probe` receipts.
- Add `cocoon probe-fd-exec` as P1.2c evidence that normal path-based exec is
  blocked after entering the null namespace, keeping FD-only service launch as
  the remaining production enforcement task.
- Add `cocoon probe-fd-launch` as P1.2d evidence for a controlled fixture
  launched from an inherited executable FD under the restricted namespace. This
  may pass as `redox-controlled-service-enforced` or report
  `redox-fd-launch-blocked` with upstream evidence.
- Add `cocoon probe-capsule-fd-launch` as P1.2e evidence that an installed
  capsule entrypoint payload can be opened before restriction and fexeced under
  a manifest-derived restricted namespace, recording
  `redox-enforced-capsule-entrypoint` without promoting final production
  `redox-enforced` yet.
- Add `cocoon run --enforce-redox-authority` as P1.2f evidence that normal run
  receipts can be produced by the same installed-entrypoint FD backend. Keep
  `production_arbitrary_service = false` until multiple service profiles pass.
- Add P1.2g multi-profile QEMU evidence for the same Redox FD run backend using
  `log-service` and `network-denied-service` profiles.
- Construct the service namespace.
- Pass preopened handles.
- Assert denied scheme/path access fails.

### P1 Acceptance

- Verify before install.
- Stage install and atomically promote.
- Run service under a constructed Redox namespace.
- Pass preopened handles.
- Capture stdout/stderr logs.
- Write install and run receipts.
- Assert denied scheme/path access fails.

## P2: pkgar-backed Payload

Goal: align the capsule payload with Redox package/security direction.

- Keep `.cocoon` as the policy and receipt envelope.
- Move service payload to `pkgar`.
- Preserve strict verification and permission diff semantics.
- Keep tar.gz only as a development/test fixture format if useful.
