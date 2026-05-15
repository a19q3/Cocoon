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
