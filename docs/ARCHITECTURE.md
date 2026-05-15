# Cocoon Architecture

## One-sentence

> Cocoon packages Redox services into signed, capability-declared capsules with reproducible deployment, permission diffs, rollback metadata, and audit logs.

## Overview

```text
┌─────────────────────────────────────────────┐
│                cocoon CLI                    │
│ build / verify / install / run / inspect     │
│ diff-permissions / rollback / logs           │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│              Cocoon Core                     │
│ manifest parser / validator / capability     │
│ diff engine / bundle metadata / receipt       │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│              Cocoon Bundle                   │
│ .cocoon archive / hash / signature / SBOM    │
│ capsule filesystem / service manifest         │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│          Cocoon Runtime on Redox             │
│ namespace setup / scheme visibility / spawn   │
│ logs / lifecycle / health / rollback          │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│                RedoxOS                       │
│ schemes / namespaces / capabilities / pkg     │
└─────────────────────────────────────────────┘
```

## Modules

| Crate | Responsibility |
|-------|---------------|
| `cocoon-core` | manifest data structures, capability model, validation, permission diff, shared errors |
| `cocoon-bundle` | `.cocoon` archive format, content hashing, signature metadata, bundle verification |
| `cocoon-policy` | allow/deny capability rules, permission diff severity, update-time policy check |
| `cocoon-cli` | developer/ops entrypoint: `build`, `verify`, `inspect`, `diff-permissions`, `install`, `run` |
| `cocoon-runtime` | Redox-specific runtime: namespace/scheme setup, process spawn, logs, rollback |
| `cocoon-testkit` | QEMU Redox integration harness, fixture generation, automated assertions |

## Trust Boundary

- **Trusted**: Cocoon runtime, verified capsule manifest, Redox namespace/capability enforcement
- **Partially trusted**: capsule author, installed service binary
- **Untrusted**: service runtime behaviour, network input, external bundle source

Cocoon does not assume the service is benign; it enforces that the service can only access resources declared in the manifest.

## Capsule Format

```text
hello.cocoon
  ├── Cocoon.toml
  ├── bin/
  │   └── hello-service
  ├── etc/
  │   └── config.toml
  ├── assets/
  ├── manifest/
  │   ├── hashes.json
  │   ├── signature.json
  │   └── sbom.json
  └── receipts/
      └── build-receipt.json
```

## Security Model

### Permission Diff on Update

If a new version expands permissions, Cocoon must report severity and require confirmation:

```text
Permission expansion detected:
  HIGH: new outbound network access
  MEDIUM: new writable filesystem path

Confirmation required.
```

### Receipt

Every install/update/run produces a signed receipt:

```json
{
  "event": "capsule_install",
  "capsule": "hello-service",
  "version": "0.1.0",
  "manifest_hash": "blake3:...",
  "bundle_hash": "blake3:...",
  "capability_hash": "blake3:...",
  "installed_at": "2026-05-15T00:00:00Z",
  "previous_receipt": "blake3:..."
}
```

## Phases

### P0: Capsule Format and macOS Developer Workflow
- Workspace setup
- `Cocoon.toml` schema
- Manifest validation
- `.cocoon` bundle build
- `inspect`, `verify`, `diff-permissions` commands
- `hello-service` example
- macOS development guide

### P1: Redox QEMU Runtime Smoke Test
- Redox image overlay
- `cocoon-runtime` minimal port
- Install, run, collect logs
- Basic namespace/scheme restriction experiment
- QEMU smoke test via `cargo xtask redox-test`
