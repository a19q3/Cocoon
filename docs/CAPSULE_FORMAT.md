# Cocoon Capsule Format

P0 `.cocoon` files are gzipped tar archives so the macOS workflow stays simple.
This is provisional. The target Redox-native artifact is a `pkgar` payload with
Cocoon policy metadata as the outer capsule envelope.

Cocoon should not own the general package payload layer long term. File payloads,
content hashes, package dependencies, and relocatable installation should remain
aligned with Redox `pkg`/`pkgar`; Cocoon adds service-specific authority metadata
around that payload.

```text
hello.cocoon
  ├── Cocoon.toml
  ├── bin/
  ├── etc/
  ├── assets/
  └── manifest/
      ├── hashes.json
      ├── signature.json
      └── sbom.json
```

## Manifest Schema

The canonical Rust representation lives in `crates/cocoon-core/src/manifest.rs`.
The public schema is Redox-native: it describes scheme visibility, preopened
handles, and normalized permission rules rather than a container filesystem.

```toml
[capsule]
name = "hello-service"
version = "0.1.0"
description = "Minimal Cocoon demo service"
authors = ["Arthur Tsang"]
license = "MIT"

[entry]
cmd = "/app/bin/hello-service"
args = []
cwd = "/app"

[filesystem]
root = "/app"
writable = ["/app/data", "/app/tmp"]
readonly = ["/app/etc", "/app/assets"]

[[permission]]
scheme = "tcp"
action = "connect"
target = "api.example.com:443"

[[permission]]
effect = "deny"
scheme = "device"
action = "manage"
target = "/**"

[[preopen]]
scheme = "file"
host_path = "/pkg/cocoon/capsules/hello-service/current"
guest_path = "/app"
rights = ["read", "execute"]

[[scheme]]
name = "log"
visibility = "readwrite"
target = "service-log"

[network]
default = "deny"
```

## Validation Rules

- `capsule.name` is lowercase ASCII with digits, `.`, `_`, or `-`.
- `capsule.version` must be SemVer.
- `entry.cmd`, `entry.cwd`, filesystem paths, and preopen guest paths must stay
  inside `filesystem.root`.
- Readonly and writable filesystem paths must not overlap.
- Permission rules are normalized before diffing; only `effect = "allow"` rules
  count as permission expansion.
- Unknown manifest fields are rejected.

## Hash Manifest

`manifest/hashes.json` maps every payload file to its BLAKE3 hash:

```json
{
  "files": {
    "Cocoon.toml": "blake3:abc...",
    "bin/hello-service": "blake3:def..."
  },
  "manifest_hash": "blake3:abc..."
}
```

`manifest/hashes.json` and `manifest/signature.json` are generated metadata.
Every other archive file must be listed in `files`; extra, missing, duplicate,
absolute, or parent-traversing archive paths are invalid.

## Signature

`manifest/signature.json` currently holds P0 placeholder metadata:

```json
{
  "algorithm": "none",
  "public_key": null,
  "signature": "placeholder"
}
```

`cocoon verify` accepts the unsigned placeholder for local P0 demos.
`cocoon verify --strict` requires signature metadata and is the expected shape
for the future signed install path.
