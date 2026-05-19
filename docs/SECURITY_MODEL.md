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
- invalid signatures are integrity failures;
- strict mode rejects unsigned or untrusted capsules.

Unsigned P0 capsules are allowed for local development, but the issue remains
visible in `cocoon verify`.

Signed bundle mode uses `cocoon keygen` to create an Ed25519 signing key,
`cocoon build --signing-key` to sign the canonical hash manifest, and
`cocoon verify --strict --trusted-key` / `cocoon install --strict
--trusted-key` to require a signature from a configured trust root. Repeat
`--trusted-key` to accept multiple roots during an explicit key-rotation
window. Trust roots can also be persisted in
`<install-root>/trust/trust-roots.json` with:

```bash
cocoon trust add --key signing-key.json --kind bundle --install-root /pkg/cocoon
cocoon trust policy --require-signed-bundles --install-root /pkg/cocoon
```

`cocoon install` merges the persistent bundle trust roots with any explicit
`--trusted-key` values. When the trust policy requires signed bundles, install
uses strict verification even if `--strict` was not passed. `cocoon verify` can
use the same file and policy with
`--trust-config /pkg/cocoon/trust/trust-roots.json`.

## Permission Diff on Update

When a capsule update expands service authority, Cocoon reports severity and can
require confirmation. Authority includes allowed permissions, scheme visibility,
preopened handles, and network defaults:

```text
Authority changes detected:

Added permissions:
      HIGH  allow tcp connect api.example.com:443
    MEDIUM  allow file readwrite /app/cache/**

Modified schemes:
      HIGH  log readonly target=service-log -> log readwrite target=service-log

Confirmation required: yes
```

Removed permissions, schemes, and preopens are displayed as reductions. Deny
rules do not count as permission expansion.

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

Lifecycle receipts can be signed with the same local Ed25519 key format used for
bundle signing. Pass `--receipt-signing-key` to `install`, `run`, `rollback`, or
`probe-authority` to attach an `ed25519-blake3-receipt-v1` signature over the
canonical receipt body and event context. `cocoon status`, `cocoon logs`, and
`cocoon audit` continue to accept unsigned local-development receipts, but when
a receipt signature is present they verify it before trusting the receipt or
printing evidence. Tampering only with a receipt signature is therefore detected
without needing to change the receipt body hash.

Production-style CLI checks can require signed receipts by passing
`--require-receipt-signatures --receipt-trusted-key <key>` to `status`, `logs`,
or `audit`. Repeat `--receipt-trusted-key` to accept old and new receipt
signers during a key-rotation window. In that mode unsigned receipts, receipts
signed outside the trusted set, and malformed signatures are rejected before
evidence is printed.

Receipt trust roots can also be persisted with:

```bash
cocoon trust add --key signing-key.json --kind receipt --install-root /pkg/cocoon
cocoon trust policy --require-signed-receipts --install-root /pkg/cocoon
```

`status`, `logs`, and `audit` merge persistent receipt trust roots with explicit
`--receipt-trusted-key` values. When the trust policy requires signed receipts,
those commands enforce trusted receipt signatures even if
`--require-receipt-signatures` was not passed.

Each smoke run also writes a run receipt and stdout/stderr logs under the
capsule install tree. `cocoon status` reads the latest install and run receipts
to report the current version, last run result, and log paths; `cocoon logs`
prints the latest captured stdout/stderr. In P1.1 this is audit evidence for the
CLI execution flow, not a claim that Redox namespace enforcement has been
proven.

`cocoon audit` recomputes the body hash for the latest install, run, and
rollback receipts when present, verifies the latest install receipt's previous
receipt link, and checks that the current version matches the latest rollback
target or latest install version. It also confirms latest install/run/rollback
receipts are backed by their archived receipt files, so rewriting only a mutable
`latest.json` pointer is detected. It detects receipt body tampering, but does
not replace the future signed receipt trust chain. Run receipts also carry
stdout/stderr log hashes, and audit recomputes those hashes from the captured
log files so log tampering is detected.
Before installing a new version, Cocoon verifies the current latest install
receipt and its archived version receipt before using it as the new
`previous_receipt` link, so an upgrade cannot silently chain onto a rewritten
latest install pointer.
`cocoon status` verifies the current installed tree and latest receipt integrity
before reporting state, and `cocoon logs` performs the same current-tree,
latest-run receipt, and log hash verification before printing captured output,
so status and log readback fail closed on tampering.

Before running, reporting, auditing, or printing logs for an installed capsule,
Cocoon verifies the current install tree against the materialized
`manifest/hashes.json`, checks the manifest hash, and requires the declared
entrypoint to remain executable. `cocoon check-install` exposes the same
installed-tree integrity check for smoke tests and operators.
Because the current process launcher does not yet construct the Redox namespace,
scheme visibility, or preopened handles, `cocoon run` fails closed by default.
The `--allow-unenforced-authority` flag is only for CLI smoke execution and must
not be treated as an isolation guarantee. Run receipts record log hashes,
`authority_enforced`, and `authority_mode`; `cocoon status` / `cocoon audit`
surface those fields so smoke execution remains visible in later evidence.

`cocoon probe-authority` is P1.2a/P1.2b evidence for Redox authority mechanics.
On Redox the parent process spawns an authority child. The child opens declared
file preopen evidence before entering the null namespace, then verifies that the
already-open file remains readable while denied file paths and hidden schemes
cannot be opened by name. The parent captures the child logs, writes an
`authority_probe` receipt, and `cocoon audit` verifies the receipt body, archive
link, and log hashes. This proves the namespace/preopen primitive used by the
future runner; it does not yet mean `cocoon run` launches arbitrary services
under enforced authority.

`cocoon probe-fd-exec` is P1.2c gap evidence. On Redox it verifies the
installed capsule, then tries to enter the null namespace before launching the
current Cocoon binary by path. The expected result is that normal path-based
exec fails after the namespace is restricted. A passing probe therefore
classifies the remaining production blocker: Cocoon must launch arbitrary
services through an FD-only loader/exec path before `cocoon run` can mark
`authority_enforced=true`.

`cocoon probe-fd-launch` is P1.2d controlled-service evidence. On Redox it
opens the controlled fixture executable and declared preopen evidence before
restriction, spawns a child, enters the null namespace in that child, and then
attempts to launch the fixture through the inherited executable FD. A successful
probe records `redox-controlled-service-enforced`: a controlled fixture service
ran under the restricted namespace and proved declared preopen access plus
denied path/scheme rejection. This is still not production arbitrary-service
execution, so `cocoon run` remains fail-closed until installed capsule services
use the same FD-only launch boundary.

`cocoon probe-capsule-fd-launch` is P1.2e installed-entrypoint evidence. On
Redox it resolves `entry.cmd` from the installed manifest, opens the materialized
payload entrypoint and declared preopen evidence before restriction, enters a
manifest-derived restricted namespace, and fexecs the installed entrypoint FD.
A successful probe records `redox-enforced-capsule-entrypoint`: the installed
capsule payload started under the restricted boundary and proved declared
resource access plus denied ambient path and undeclared `tcp` rejection. This is
still a probe mode; the final `redox-enforced` production label is reserved for
`cocoon run` after the multi-profile boundary and service lifecycle semantics
are reviewed.

`cocoon run --enforce-redox-authority` is P1.2f run-backend evidence. On Redox
it calls the same installed-entrypoint FD launch backend used by the probe,
writes a normal `capsule_run` receipt, and exposes the evidence through
`status`, `logs`, and `audit`. Successful receipts use
`authority_mode = redox-enforced-capsule-entrypoint`,
`authority_enforced_for_service = true`, and
`production_arbitrary_service = false`. The default `cocoon run` path remains
fail-closed unless `--allow-unenforced-authority` is explicitly requested for
smoke testing or the explicit Redox FD backend flag is used.

P1.2g exercises the same Redox FD run backend with additional `log-service` and
`network-denied-service` profiles. This is multi-profile enforcement evidence,
not a promotion to the final `redox-enforced` production label.

P1.2h adds structured child results to the authority evidence path. The parent
parses structured results from controlled children and fexeced services, records
`structured_child_result = true` in run/probe receipt bodies, also requires
child exit success, writes receipts and logs, and `cocoon audit` verifies
receipt body hashes, archive links, and captured log hashes. Stdout markers
remain in the logs for human review, but they are not the primary parsed
evidence source for P1.2h paths.

Install, recover, audit, status, logs, run, rollback, and check-install acquire
a per-capsule lock under the install root before reading or mutating the active
capsule tree. If another operation already holds the lock, the CLI fails closed
instead of racing the current pointer, logs, receipts, or installed payload.

`cocoon recover` uses the same lock before removing recoverable temporary state
left by interrupted lifecycle operations, including staging directories,
`current.tmp`, `current-version.tmp`, and temporary latest receipt files. It
does not rewrite receipts or choose a new current version. By default it fails
closed when a capsule lock exists; `--break-lock` is an explicit operator escape
hatch for a known stale lock after a crash.
