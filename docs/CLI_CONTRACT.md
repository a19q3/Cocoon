# Cocoon CLI Contract

Last updated: 2026-06-10

This contract is for automation that drives Cocoon through the CLI. Current
production validation remains CLI-only.

## JSON Output

The following commands support `--json` and emit stable JSON to stdout on
success:

```bash
cocoon plan <capsule> --json
cocoon install <capsule> --json
cocoon run <capsule-name> --json
cocoon run <capsule-name> --enforce-redox-authority --json
cocoon start <capsule-name> --allow-unenforced-authority --json
cocoon stop <capsule-name> --json
cocoon restart <capsule-name> --allow-unenforced-authority --json
cocoon health <capsule-name> --json
cocoon probe-authority <capsule-name> --json
cocoon probe-fd-exec <capsule-name> --json
cocoon probe-fd-launch <capsule-name> --json
cocoon probe-capsule-fd-launch <capsule-name> --json
cocoon status <capsule-name> --json
cocoon logs <capsule-name> --json
cocoon check-install <capsule-name> --json
cocoon rollback <capsule-name> --to-version <version> --json
cocoon recover <capsule-name> --json
cocoon recover-all --json
cocoon audit <capsule-name> --json
```

Receipt-producing commands emit the same structured receipt objects written to
disk. `probe-capsule-fd-launch` writes `event = "capsule_fd_launch_probe"` and
uses `authority_mode = "redox-enforced-capsule-entrypoint"` only for the
P1.2e installed-entrypoint probe. `run --enforce-redox-authority` is the P1.2f
Redox-only run backend graduation path; on Redox it uses the same FD-only
capsule entrypoint backend and records `event = "capsule_run"` with
`authority_mode = "redox-enforced-capsule-entrypoint"`,
`authority_enforced_for_service = true`, and
`production_arbitrary_service = false`. On non-Redox platforms the flag fails
closed with `Redox FD-only run backend unavailable on this platform`. P1.2g
uses the same run receipt shape for additional Redox service profiles.
P1.2h adds `structured_child_result = true` to Redox authority probe, FD launch
probe, capsule FD launch probe, and enforced run receipts when the parent parsed
structured child/service evidence. P1.2i keeps the CLI shape unchanged and adds
negative tests so malformed or incomplete structured evidence is rejected before
receipts can claim enforced authority.

Install receipts include `body.payload_identity` when the payload layer can be
named. Current development capsules use `layer = "cocoon-bundle"` with the
bundle digest as the payload identity. Future `pkgar`-backed receipts should use
the same field to bind Cocoon authority evidence to the package-layer identity
that installed the bytes. Older receipts without `payload_identity` remain
valid for audit compatibility.

`start`, `stop`, `restart`, and `health` emit service lifecycle receipts or a
report containing those receipts. `start` and `restart` currently use the host
process supervisor and fail closed unless `--allow-unenforced-authority` is
passed; `--enforce-redox-authority` is reserved until a Redox service supervisor
backend exists. `status --json` includes `service_supervisor` with `running`,
`state`, and `latest_receipt`; `audit` verifies the latest service lifecycle
receipt when present.

`recover-all --json` scans every installed capsule under the install root and
returns `capsules_recovered`, aggregate `removed_paths`, and a `recovered`
array of per-capsule recovery reports. It is intended for boot-time cleanup of
recoverable temporary install state and stale service supervisor state after a
crash or reboot.

The final production `redox-enforced` label remains reserved for later
operational boundary review. `status --json` reports the latest
authority, controlled FD launch, and capsule FD launch probe receipts
separately. Aggregate commands use explicit automation fields such as `state`,
`current_version`, `checks`, `stdout`, `stderr`, and `receipt_input`.

`cocoon install` fails closed when an upgrade expands declared permissions,
schemes, preopens, or network defaults and the installed current manifest has
`update.permission_expansion_requires_confirmation = true`. The explicit
review override is `cocoon install <capsule> --allow-permission-expansion`.
Rejected upgrades exit non-zero, emit the authority diff on stderr, and do not
create a partial `versions/<version>` install.

## Exit Codes

| Exit code | Meaning |
| --- | --- |
| `0` | Command succeeded and stdout is complete. |
| non-zero | Command failed; stderr contains diagnostic context. Automation must not trust partial stdout. |

Current failures intentionally share the non-zero CLI failure class used by
`anyhow`. Scripts should key decisions from command success/failure and, where
needed, from JSON fields emitted only on success.
