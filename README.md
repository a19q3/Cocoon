# Cocoon

Capability-native service capsules for RedoxOS.

> Cocoon packages Redox services into signed, capability-declared capsules with reproducible deployment, permission diffs, rollback metadata, and audit logs.

## Philosophy

Docker packages a small Linux-shaped world.  
Cocoon packages a capability-bound Redox service.

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

## License

MIT
