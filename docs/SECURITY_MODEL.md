# Cocoon Security Model

## Trust Boundary

| Layer | Trust Level |
|-------|------------|
| Cocoon runtime | Trusted |
| Verified capsule manifest | Trusted |
| Redox namespace/capability enforcement | Trusted |
| Capsule author | Partially trusted |
| Installed service binary | Partially trusted |
| Service runtime behaviour | Untrusted |
| Network input | Untrusted |
| External bundle source | Untrusted |

## Principle

Cocoon does not assume the service is benign. The service can only access resources explicitly declared in the manifest. Redox runtime enforces this through scheme visibility and capability restrictions.

## Permission Diff on Update

When a capsule update expands capabilities, Cocoon reports severity and may require confirmation:

```
Permission expansion detected:
  HIGH: new outbound network access
  MEDIUM: new writable filesystem path

Confirmation required.
```

## Receipts

Every install/update/run produces a signed receipt for audit:

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
