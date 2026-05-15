# Cocoon Security Model

## Trust Boundary

| Layer | Trust Level |
|-------|-------------|
| Cocoon runtime | Trusted |
| Verified capsule manifest | Trusted |
| Redox namespace and fd capability enforcement | Trusted |
| Capsule author | Partially trusted |
| Installed service binary | Partially trusted |
| Service runtime behavior | Untrusted |
| Network input | Untrusted |
| External bundle source | Untrusted |

## Principle

Cocoon does not assume a service is benign. The service should only see schemes
and receive handles declared by the verified manifest. On Redox, enforcement is
expected to come from namespace construction, scheme visibility, and capability
handles rather than a Linux container boundary.

Cocoon is not the trusted package manager for all system software. It verifies
and records service authority. The underlying payload transport and package
installation layer should be Redox `pkg`/`pkgar` where possible; Cocoon's
security value is permission review, runtime intent, and receipt generation for
services.

## Bundle Verification

Before install, Cocoon verifies:

- archive paths are relative, normalized, and unique;
- every payload file is listed in `manifest/hashes.json`;
- every listed file exists in the archive;
- each payload BLAKE3 hash matches the hash manifest;
- generated metadata is not accepted as user payload;
- strict mode rejects unsigned capsules.

Unsigned P0 capsules are allowed for local development, but the issue remains
visible in `cocoon verify`.

## Permission Diff on Update

When a capsule update expands allowed permissions, Cocoon reports severity and
can require confirmation:

```text
Permission changes detected:
      HIGH: new permission: allow tcp connect api.example.com:443
    MEDIUM: new permission: allow file readwrite /app/cache/**

Permission expansion detected. Confirmation required.
```

Removed permissions are displayed as reductions. Deny rules do not count as
permission expansion.

## Receipts

Each verified install writes a receipt outside the signed payload area:

```json
{
  "receipt_version": 1,
  "event": "capsule_install",
  "body": {
    "capsule_name": "hello-service",
    "capsule_version": "0.1.0",
    "bundle_hash": "blake3:...",
    "manifest_hash": "blake3:...",
    "permission_hash": "blake3:...",
    "runtime_version": "0.1.0",
    "install_root": "/pkg/cocoon/capsules/hello-service/versions/0.1.0",
    "installed_at": "unix:1770998400",
    "previous_receipt": "blake3:..."
  },
  "body_hash": "blake3:...",
  "signature": null
}
```

`body_hash` is computed from the canonical receipt body, excluding `body_hash`
and `signature`, so the receipt is not self-referential. The `previous_receipt`
field points at the previous receipt body hash.
