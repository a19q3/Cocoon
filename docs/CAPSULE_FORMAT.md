# Cocoon Capsule Format

A `.cocoon` file is a gzipped tar archive containing:

```
hello.cocoon
  ├── Cocoon.toml          # Service manifest
  ├── bin/                 # Service binaries
  ├── etc/                 # Configuration files
  ├── assets/              # Static assets
  ├── manifest/
  │   ├── hashes.json      # Content-addressed file hashes
  │   ├── signature.json   # Signature metadata
  │   └── sbom.json        # Software bill of materials
  └── receipts/
      └── build-receipt.json
```

## Manifest Schema

See `crates/cocoon-core/src/manifest.rs` for the canonical Rust representation.

Key sections:
- `[capsule]` — name, version, description, authors, license
- `[entry]` — command, args, working directory
- `[filesystem]` — root, writable paths, readonly paths
- `[capabilities]` — allow/deny capability rules
- `[network]` — default policy
- `[resources]` — memory, process, fd limits
- `[update]` — signed, rollback, permission expansion confirmation
- `[audit]` — events, stdout, stderr logging

## Hash Manifest

`manifest/hashes.json` maps every file in the bundle to its BLAKE3 hash:

```json
{
  "files": {
    "Cocoon.toml": "blake3:abc...",
    "bin/hello-service": "blake3:def..."
  },
  "manifest_hash": "blake3:..."
}
```

## Signature

`manifest/signature.json` holds signing metadata:

```json
{
  "algorithm": "ed25519",
  "public_key": "base64...",
  "signature": "base64..."
}
```

P0 uses `"none"` as a placeholder.
