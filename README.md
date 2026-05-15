# Cocoon

Capability-aware service capsules on top of Redox package infrastructure.

> Cocoon packages Redox services into signed, capability-declared capsules with reproducible deployment, permission diffs, rollback metadata, and audit logs.

## Philosophy

Docker packages a small Linux-shaped world.  
Cocoon packages a capability-bound Redox service.

## Package Management Boundary

Cocoon is not a replacement for Redox package management. It is a
capability-aware service capsule layer that can use `pkgar` as its payload
format and adds service manifests, permission diffs, runtime plans, rollback
policy, and audit receipts.

```text
pkg/pkgar = install bytes
Cocoon = install authority
Redox namespace/capability = enforce authority
```

Cocoon should not become a dependency solver, package repository, general app
store, or `pkg` replacement. It is for long-running services that need explicit
authority, runtime intent, and auditability.

## Quick Start

```bash
cargo run -p cocoon-cli -- build examples/hello-service
cargo run -p cocoon-cli -- inspect target/capsules/hello-service.cocoon
cargo run -p cocoon-cli -- verify target/capsules/hello-service.cocoon
```

## Docs

- [ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [CAPSULE_FORMAT.md](docs/CAPSULE_FORMAT.md)
- [SECURITY_MODEL.md](docs/SECURITY_MODEL.md)
- [ROADMAP.md](docs/ROADMAP.md)
- [CODING_STYLE.md](docs/CODING_STYLE.md)
- [MACOS_DEV.md](docs/MACOS_DEV.md)
- [REDOX_TESTING.md](docs/REDOX_TESTING.md)

## License

MIT
