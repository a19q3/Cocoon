# Cocoon Roadmap

## Scope Boundary

Cocoon stays above Redox package management. It does not replace `pkg`, `pkgar`,
dependency resolution, package repositories, or whole-system updates. The payload
layer should converge on `pkgar`; Cocoon adds service authority: manifests,
permission diffs, runtime plans, receipts, and rollback policy.

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
- Support unsigned local mode and strict signature-required mode.

## P0.3: Typed Permission AST

Goal: model Redox-native intent without pretending to enforce runtime isolation
on macOS.

- Use `[[scheme]]` for namespace/scheme visibility.
- Use `[[preopen]]` for preopened handles.
- Use `[[permission]]` for operation permissions.
- Keep legacy `[[capability]]` parsing only as a compatibility alias.
- Diff normalized permission rules instead of raw strings.

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

P1.1 is an execution smoke, not an isolation proof.

### P1.2: Enforcement Smoke

Goal: prove Redox authority enforcement after the lifecycle is running.

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
