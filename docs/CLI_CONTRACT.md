# Cocoon CLI Contract

Last updated: 2026-05-19

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
cocoon probe-authority <capsule-name> --json
cocoon probe-fd-exec <capsule-name> --json
cocoon probe-fd-launch <capsule-name> --json
cocoon probe-capsule-fd-launch <capsule-name> --json
cocoon status <capsule-name> --json
cocoon logs <capsule-name> --json
cocoon check-install <capsule-name> --json
cocoon rollback <capsule-name> --to-version <version> --json
cocoon recover <capsule-name> --json
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
structured child/service evidence.

The final production `redox-enforced` label remains reserved for later
operational boundary review. `status --json` reports the latest
authority, controlled FD launch, and capsule FD launch probe receipts
separately. Aggregate commands use explicit automation fields such as `state`,
`current_version`, `checks`, `stdout`, `stderr`, and `receipt_input`.

## Exit Codes

| Exit code | Meaning |
| --- | --- |
| `0` | Command succeeded and stdout is complete. |
| non-zero | Command failed; stderr contains diagnostic context. Automation must not trust partial stdout. |

Current failures intentionally share the non-zero CLI failure class used by
`anyhow`. Scripts should key decisions from command success/failure and, where
needed, from JSON fields emitted only on success.
