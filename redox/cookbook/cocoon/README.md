# Cocoon Cookbook Integration Draft

This directory is a staging note for the eventual Redox Cookbook recipe. It is
not an active upstream recipe yet.

## Goal

Build and stage the Cocoon CLI/runtime binary through the Redox build system, then
inject service capsules separately for P1 smoke tests.

P1.1b should prove the binary can be produced by an official Redox toolchain path.
P1.1c should place that binary plus `hello-service.cocoon` into a bootable image
overlay and run `cocoon verify` / `cocoon plan` inside Redox.

## Draft Recipe Shape

The official Cookbook docs use `template = "cargo"` for Rust programs. Cocoon
has a package named `cocoon-cli` and a binary named `cocoon`, so a first draft
recipe should follow the Cargo bins pattern:

```toml
[source]
git = "https://github.com/a19q3/Cocoon.git"
branch = "main"

[build]
template = "cargo"
script = """
binary=cocoon
"${COOKBOOK_CARGO}" build \
    --manifest-path "${COOKBOOK_SOURCE}/Cargo.toml" \
    --package cocoon-cli \
    --bin "${binary}" \
    --release
mkdir -pv "${COOKBOOK_STAGE}/usr/bin"
cp -v \
    "target/${TARGET}/release/${binary}" \
    "${COOKBOOK_STAGE}/usr/bin/${binary}"
"""
```

## Open Questions

- Whether the recipe should live under `cookbook/recipes/sys/cocoon`,
  `cookbook/recipes/net/cocoon`, or another Redox category.
- Whether `hello-service.cocoon` should remain an image overlay fixture for P1 or
  become a separate test package later.
- Whether compression dependencies used by P0 tar capsules need Redox-specific
  feature gating before the full CLI links.

## Non-goals

- Do not make Cocoon a replacement for `pkg` or `pkgar`.
- Do not add dependency solving or repository management.
- Do not move to pkgar-backed capsules before the P2 milestone.
