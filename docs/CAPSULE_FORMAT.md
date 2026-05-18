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
- `entry.cmd` must map to an existing executable payload file. For example,
  `filesystem.root = "/app"` and `entry.cmd = "/app/bin/service"` require a
  capsule payload file at `bin/service`.
- Readonly and writable filesystem paths must not overlap.
- Permission rules are normalized before diffing; only `effect = "allow"` rules
  count as permission expansion.
- Scheme visibility, preopened handles, and `network.default` are part of the
  authority surface and should be reviewed with permission changes.
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

`manifest/hashes.json`, `manifest/signature.json`, and future
`manifest/sbom.json` are generated metadata. Every other archive file must be
listed in `files`; extra, missing, duplicate, absolute, or parent-traversing
archive paths are invalid.

P0 tar capsules preserve executable mode bits where the host platform exposes
them, so entrypoint payloads can survive materialization as runnable files.

## Signature

Unsigned local-development capsules keep placeholder metadata:

```json
{
  "algorithm": "none",
  "public_key": null,
  "signature": "placeholder"
}
```

Signed capsules use Ed25519 over a BLAKE3 digest of the canonical
`manifest/hashes.json` payload:

```json
{
  "algorithm": "ed25519-blake3-v1",
  "public_key": "hex-encoded-ed25519-public-key",
  "signature": "hex-encoded-ed25519-signature"
}
```

Generate a signing key and build a signed capsule:

```bash
cocoon keygen --output signing-key.json
cocoon build examples/hello-service \
  --output target/capsules/hello-service.cocoon \
  --signing-key signing-key.json
```

`cocoon verify` accepts unsigned capsules for local development, but invalid
signatures are integrity failures. `cocoon verify --strict --trusted-key
signing-key.json` and `cocoon install --strict --trusted-key signing-key.json`
require a valid signature from a configured trust root. Repeat `--trusted-key`
to accept multiple roots during an explicit key-rotation window.
Persistent trust roots live in `<install-root>/trust/trust-roots.json` and can
be managed with `cocoon trust add/list/remove`. `cocoon trust policy
--require-signed-bundles` turns signed-bundle verification into the install-root
default, so `cocoon install` enforces trusted signatures without repeating
`--strict`. `cocoon verify` can read the same policy with
`--trust-config <path>`.

Lifecycle receipts use the same structured signature object when
`--receipt-signing-key signing-key.json` is passed to `install`, `run`,
`rollback`, or `probe-authority`. Receipt signatures use algorithm
`ed25519-blake3-receipt-v1` and are verified by status/log/audit paths when
present.

For production-style receipt evidence, add `--require-receipt-signatures
--receipt-trusted-key signing-key.json` to `status`, `logs`, or `audit`.
Repeat `--receipt-trusted-key` to trust old and new receipt signers during a
rotation window. The same commands also read persistent receipt trust roots from
the install-root trust config. `cocoon trust policy --require-signed-receipts`
makes trusted receipt signatures the default for `status`, `logs`, and `audit`.
