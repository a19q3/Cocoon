# Cocoon Architecture

> Cocoon packages Redox services into signed, capability-declared capsules with
> reproducible deployment, permission diffs, rollback metadata, and audit logs.

## Overview

```text
┌─────────────────────────────────────────────┐
│                cocoon CLI                    │
│ build / verify / inspect / diff-permissions │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│              Cocoon Core                     │
│ typed manifest / permission AST / diff       │
│ validation / hashes / shared errors          │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│              Cocoon Bundle                   │
│ P0 tar.gz capsule / hashes / signature meta  │
│ strict archive integrity verification        │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│          Cocoon Runtime on Redox             │
│ verify / materialize / namespace / spawn     │
│ receipts / logs / status / rollback          │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│                RedoxOS                       │
│ schemes / namespaces / fd capabilities / pkg │
└─────────────────────────────────────────────┘
```

## Native Runtime Contract

Cocoon is not a Linux container abstraction. The runtime contract is:

- Verify the capsule and normalized permission manifest before install.
- Materialize the service payload into the Cocoon install tree.
- Construct the Redox namespace and visible schemes for the service.
- Spawn the service with preopened capability handles and audited stdio.

P0 implements the cross-platform parts: typed manifest validation, bundle
integrity verification, permission diffing, staged materialization, and install
receipts. P0 defines and verifies capsule intent; it does not claim Redox
runtime isolation. P1 adds Redox/QEMU namespace and spawn checks.

## Package Infrastructure Boundary

Cocoon is an upper layer over Redox package infrastructure, not a competing
package manager.

```text
pkg / pkgar:
  payload package layer
  file contents, hashes, package updates, dependencies, relocatable payloads

Cocoon:
  service deployment layer
  permission manifest, permission diff, runtime plan, receipts, rollback policy

Redox namespace / fd capabilities:
  enforcement layer
  scheme visibility, preopened handles, process authority boundaries
```

Cocoon should use `pkg`/`pkgar` for payload installation where possible. Cocoon
adds the service authority model: schemes, preopens, operation permissions,
runtime plans, and audit receipts. It does not resolve general package
dependencies, update the whole system, host a package repository, or replace
Redox package management.

The intended service scope is narrow: long-running or sensitive services such as
network daemons, device-facing services, admin panels, update services, logging
daemons, appliance control services, and web consoles. Ordinary command-line
tools, libraries, fonts, themes, and editor packages should remain normal Redox
packages.

## Modules

| Crate | Responsibility |
|-------|----------------|
| `cocoon-core` | Domain types, manifest schema, permission rules, validation, diffing, hashes |
| `cocoon-bundle` | P0 `.cocoon` archive creation, parsing, path safety, hash verification |
| `cocoon-policy` | Permission diff severity and confirmation policy |
| `cocoon-cli` | Developer entrypoint: `build`, `verify`, `inspect`, `diff-permissions` |
| `cocoon-runtime` | Verified staged install, receipts, future Redox namespace/spawn runtime |
| `cocoon-testkit` | Fixture helpers and future QEMU integration harness |

## Security Model

- Trusted: Cocoon runtime, verified manifest, Redox namespace and fd capability enforcement.
- Partially trusted: capsule author and installed service binary.
- Untrusted: service runtime behavior, external network input, external bundle source.

Permission diffing compares normalized typed permission rules. New allowed
network, device, sys, sudo, memory, proc, or sensitive filesystem access is
reported with severity; removed permissions are reductions and do not require
confirmation.

## Artifact Direction

P0 keeps tar.gz because it is easy to build and inspect on macOS. The format is
strictly verified: every payload path must be relative, unique, normalized, and
covered by `manifest/hashes.json`.

The Redox-native target is:

```text
.cocoon envelope
  ├── Cocoon.toml permission manifest
  ├── policy metadata / receipts
  └── pkgar payload
```

That keeps Cocoon aligned with Redox package goals: atomic, minimal, secure, and
relocatable payload installation.

## Phases

### P0: Capsule Format and macOS Developer Workflow

- Typed `Cocoon.toml` schema.
- Manifest and permission validation.
- `.cocoon` build, inspect, verify, and permission diff.
- Bundle tamper detection and strict unsigned mode.
- Verified staged install and audit receipt generation.
- macOS development and coding-style guides.
- No claim of runtime isolation enforcement outside Redox.

### P1: Redox QEMU Runtime Smoke Test

- Redox image overlay.
- Runtime namespace/scheme visibility setup.
- Process spawn with preopened handles.
- Log capture and status reporting.
- QEMU smoke test via `cargo xtask redox-test`.
