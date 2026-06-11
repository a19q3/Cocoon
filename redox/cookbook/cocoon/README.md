# Cocoon Cookbook Integration Draft

This directory is a staging note for the eventual Redox Cookbook recipe. It is
not an active upstream recipe yet.

## Goal

Build and stage the Cocoon CLI/runtime binary through the Redox build system, then
inject service capsules separately for P1 smoke tests.

P1.1b should prove the binary can be produced by an official Redox toolchain path.
P1.1c should place that binary plus `hello-service.cocoon` into a bootable image
overlay and run `cocoon verify` / `cocoon plan` inside Redox.

## Draft Recipe

The draft recipe is checked in as [recipe.toml](recipe.toml). It follows the
current Redox Cookbook Cargo template pattern and points at the Cocoon CLI crate:

```toml
[source]
git = "https://github.com/a19q3/Cocoon.git"
branch = "main"

[build]
template = "cargo"
package_path = "crates/cocoon-cli"
```

This still needs to be tested inside a full Redox Cookbook checkout before it
can be treated as distribution evidence.

Validate the draft recipe shape against the tracked upstream Cookbook reference:

```bash
cargo xtask redox-track
cargo xtask redox-cookbook-check
```

The local check stages the recipe under
`target/redox-cookbook/cookbook/recipes/tools/cocoon` and writes
`target/redox-cookbook/recipe-check.json`. The `tools/cocoon` placement is
provisional until upstream review.

## Open Questions

- Whether the provisional `cookbook/recipes/tools/cocoon` placement should
  remain there, move to `cookbook/recipes/core/cocoon`, or use another Redox
  category.
- Whether `hello-service.cocoon` should remain an image overlay fixture for P1 or
  become a separate test package later.
- Whether compression dependencies used by P0 tar capsules need Redox-specific
  feature gating before the full CLI links.

## Non-goals

- Do not make Cocoon a replacement for `pkg` or `pkgar`.
- Do not add dependency solving or repository management.
- Do not move to pkgar-backed capsules before the P2 milestone.
