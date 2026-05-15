# Cocoon Coding Style

Cocoon follows normal Rust formatting plus stricter service-runtime rules drawn
from Redox and Servo habits: small APIs, typed domain values, early returns, and
clear error boundaries.

## Required Checks

Run the full local gate before merging:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

`cargo xtask test` runs the same gate.

## Error Handling

- Library crates return typed errors.
- The CLI may use `anyhow` at the process boundary.
- `unwrap()` is not allowed in non-test code.
- `expect()` is only allowed for internal invariants, and the message must state
  why the failure is impossible.

## API Shape

- Public APIs use domain types for domain concepts: `CapsuleName`,
  `CapsuleVersion`, `SchemeName`, `GuestPath`, `CapsulePath`, and
  `PermissionRule`.
- Raw `String` is acceptable for prose metadata such as descriptions and author
  names, not for security-sensitive identifiers.
- Cross-platform crates must not depend on Redox syscalls.
- Redox-specific syscall and namespace work belongs behind
  `#[cfg(target_os = "redox")]` in `cocoon-runtime`.

## Readability

- Prefer early returns and `let Some(value) = ... else { ... };`.
- Keep nesting shallow.
- Do not commit dead code or commented-out branches.
- `unsafe` is prohibited unless a future Redox syscall boundary needs it; then it
  must include a tight `SAFETY:` comment and tests.
