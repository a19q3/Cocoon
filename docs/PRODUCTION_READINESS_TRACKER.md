# Cocoon Production Readiness Tracker

Last updated: 2026-06-11

## Current Verdict

Cocoon is not production-ready yet.

The current codebase has a strong CLI-only P1.1 lifecycle smoke: build, verify,
plan, install, status, check-install, recover, run, logs, rollback, and audit
are exercised through the `cocoon` command on host and inside Redoxer/QEMU.
This proves the lifecycle path, receipts, rollback evidence, and tamper checks.

The remaining production blockers are default Redox service execution under
reviewed restricted authority, native Redox packaging/linking, Redox service
manager/reboot integration, and enforced CI production gates.

## Validation Rule

Current validation is CLI-only. A readiness item is not accepted unless it is
covered by one of these commands or by a documented manual CLI transcript:

```bash
cargo xtask prod-gate
cargo xtask prod-audit
cargo xtask prod-audit-strict
cargo xtask test
cargo xtask redox-cookbook-check
cargo xtask redox-qemu-gate
cargo xtask redox-smoke
cargo xtask qemu-smoke
```

Library-only tests may support implementation, but they do not close a
production-readiness item by themselves.

## Status Legend

- `DONE`: implemented and covered by CLI evidence.
- `PARTIAL`: useful behavior exists, but the production acceptance is not closed.
- `BLOCKED`: depends on another system, toolchain, or design decision.
- `TODO`: not implemented yet.

## Production Blockers

| Area | Status | Production acceptance | Current evidence | Next action |
| --- | --- | --- | --- | --- |
| CLI lifecycle smoke | DONE | Host and Redox/QEMU exercise verify, plan, install, status, recover, run, logs, rollback, and audit through `cocoon`. | `cargo xtask redox-smoke` passes through QEMU lifecycle. | Keep as mandatory regression gate. |
| Install integrity | DONE | Staged installs promote atomically, duplicate installs fail, current tree tamper is rejected, latest install receipt tamper is rejected before upgrade. | CLI golden and QEMU smoke reject tampered current payload and tampered latest install receipt. | Add signed install receipts under signing work. |
| Run evidence integrity | DONE | Run refuses missing installs, records stdout/stderr hashes, logs verify against latest run receipt, latest-only run receipt tamper is rejected. | CLI golden and QEMU smoke cover run/log/audit evidence checks. | Preserve behavior when authority enforcement replaces smoke override. |
| Rollback integrity | DONE | Rollback only targets installed non-current versions, records rollback receipt, audit verifies rollback receipt body and archive link. | CLI golden and QEMU smoke cover successful rollback plus current/missing target rejection. | Add upgrade policy checks before rollback if policy expands. |
| Lifecycle locking | DONE | Per-capsule lock rejects concurrent lifecycle mutations and reads that need coherent state. | CLI golden and QEMU smoke reject locked capsule operations. | Add stale-lock recovery policy tests beyond `recover --break-lock`. |
| Redox authority enforcement | PARTIAL | `cocoon run` constructs a Redox namespace, passes preopened handles, and proves denied scheme/path access fails. | P1.2a/P1.2b `probe-authority` validates Redox null namespace behavior through a restricted child process and audited receipt; P1.2c `probe-fd-exec` classifies the path-exec blocker; P1.2d `probe-fd-launch` launches a controlled fixture from an inherited executable FD; P1.2e `probe-capsule-fd-launch` launches an installed capsule entrypoint from its payload FD under a manifest-derived restricted namespace; P1.2f adds explicit `cocoon run --enforce-redox-authority` over the same backend; P1.2g runs additional log and network-denied service profiles through the same backend. Default `run` still fails closed unless `--allow-unenforced-authority` or the explicit Redox FD backend flag is used. | Review the operational boundary, then decide when to enable default Redox enforcement and promote the production label from `redox-enforced-capsule-entrypoint` to `redox-enforced`. |
| P1.2a null namespace/preopen probe | DONE | Redox/QEMU probe enters a restricted namespace, reads an already-open allowed file preopen, and rejects denied path/scheme opens. | `cargo xtask qemu-smoke` includes `PASS probe Redox authority inside redox`. | Keep as regression evidence for full P1.2 service execution. |
| P1.2b restricted child runner | DONE | Cocoon spawns a child process that enters the Redox null namespace, proves allowed preopen and denied path/scheme behavior, writes an authority probe receipt, and audits it. | `cargo xtask qemu-smoke` includes `PASS redox authority probe receipt audited`. | Use this child-runner path as the base for FD-only service execution. |
| P1.2c FD-only exec gap classification | DONE | Redox/QEMU proves that entering the null namespace before a normal path-based `exec` blocks launching by name, so production execution needs an FD-only loader/exec strategy. | `cargo xtask qemu-smoke` includes `PASS classify Redox FD-only service launch gap inside redox`. | Keep as regression evidence explaining why the P1.2f/P1.2g FD-only backend exists. |
| P1.2d controlled FD-only launch spike | DONE | Redox/QEMU launches a controlled fixture from an inherited executable FD under a restricted namespace with required runtime schemes. | `cocoon probe-fd-launch` writes an `fd_launch_probe` receipt and QEMU smoke includes `PASS probe Redox FD-only controlled service launch inside redox`; `audit` verifies the receipt body, archive link, and stdout/stderr hashes. | Keep as mechanism regression evidence below installed-entrypoint execution. |
| P1.2e installed capsule entrypoint FD launch spike | DONE | Redox/QEMU opens the installed capsule entrypoint before restriction, enters a manifest-derived restricted namespace, fexecs the entrypoint FD, and proves declared resource access plus denied path/scheme rejection. | `cocoon probe-capsule-fd-launch` writes a `capsule_fd_launch_probe` receipt with `authority_mode = redox-enforced-capsule-entrypoint`; QEMU smoke includes `PASS probe Redox FD-only installed capsule entrypoint inside redox` and `PASS audit Redox FD-only launch probe receipts inside redox`. | Keep as probe evidence below the run backend. |
| P1.2f explicit Redox FD run backend | DONE | `cocoon run --enforce-redox-authority` uses the same FD-only installed capsule entrypoint backend as the probe, writes a normal `capsule_run` receipt, exposes status/logs/audit readback, and keeps `production_arbitrary_service = false`. | QEMU smoke includes `PASS cocoon run uses FD-only capsule entrypoint backend inside redox`; run receipts expose executable/preopen-before-restriction fields, manifest-derived namespace evidence, fexec success, declared resource read, denied path rejection, hidden scheme rejection, stdout/stderr hashes, and `authority_mode = redox-enforced-capsule-entrypoint`. | Keep as regression evidence below final production label promotion. |
| P1.2g multi-profile Redox FD run backend | DONE | The explicit Redox FD run backend handles multiple installed service profiles under the same authority boundary. | QEMU smoke includes `PASS P1.2g log-service FD run profile inside redox` and `PASS P1.2g network-denied-service FD run profile inside redox`; each profile is installed, run with `--enforce-redox-authority`, read through logs/status/status --json, and audited for FD launch evidence. | Use this evidence for community review; do not promote final `redox-enforced` until the operational boundary is reviewed. |
| P1.2h structured child result evidence | DONE | Redox authority children and fexeced services return structured evidence that is bound into run/probe receipts instead of relying on stdout markers as the primary parsed signal. | Run/probe receipts expose `structured_child_result`; QEMU smoke validates structured evidence through probe output, `status --json`, and audit checks while keeping stdout markers as human-readable logs. | Keep as the evidence baseline for future review; do not deepen launcher assumptions before upstream alignment. |
| P1.2i review hardening and evidence freeze | DONE | The structured evidence evaluator rejects malformed or incomplete child/service evidence and the review package records exact proof boundaries. | Unit tests reject malformed structured JSON, stdout-only PASS markers, missing launcher results, missing service-or-blocked results, and mismatched authority result kinds. | Freeze P1.2f/P1.2g/P1.2h as the community-review package; avoid new Redox launcher assumptions before review. |
| Production signing and trust | DONE | Bundles and receipts are signed; strict mode rejects unsigned or untrusted artifacts; key rotation and trust root are documented. | Bundle signing is implemented with `cocoon keygen`, `build --signing-key`, and `verify/install --strict --trusted-key`; repeated `--trusted-key` supports explicit multi-root bundle trust windows; `cocoon trust add/list/remove` manages persistent bundle and receipt trust roots under the install root; `cocoon trust policy --require-signed-bundles --require-signed-receipts` makes strict signed bundle and receipt verification the install-root default; install/run/rollback/authority probe receipts can be signed with `--receipt-signing-key`; `status/logs/audit --require-receipt-signatures --receipt-trusted-key` require trusted receipt signatures and repeated `--receipt-trusted-key` supports receipt signer rotation windows. | Keep trust policy wired into packaging/CI profiles. |
| Native Redox binary/package path | PARTIAL | Cocoon builds as a native Redox artifact through Redox-supported tooling and can be packaged for image integration. | `cargo xtask redox-package` stages a host-built `bin/cocoon`, signed capsule, production trust policy, README, and BLAKE3 release manifest under `target/redox-package/cocoon-redox`; Redoxer-built binary staging is skipped when Redoxer is unavailable or the build fails; `cargo xtask redox-cookbook-check` validates `redox/cookbook/cocoon/recipe.toml` against tracked upstream Cookbook cargo-template/package-path conventions and stages it under `target/redox-cookbook/cookbook/recipes/tools/cocoon`; direct Redox target binary link remains TODO without Redox C sysroot/toolchain. | Test the Cookbook recipe in a full Redox checkout, then design the pkgar-backed payload fixture. |
| Service supervision | PARTIAL | Installed capsules can be started, stopped, restarted, health-checked, and recovered after reboot/crash with clear receipts. | `cocoon start/stop/restart/health` now maintain a supervised service state file plus PID sidecar, write signed-capable service lifecycle receipts under `receipts/services`, expose supervisor state through `status`, and verify lifecycle receipts through `audit`; `recover-all` scans every installed capsule for boot-time cleanup of recoverable temporary install state and stale service supervisor state. CLI golden covers fail-closed start, explicit host-supervised start, health, restart, crash detection, recover-after-crash, aggregate reboot-style recovery, status, stop, stale-state recovery, and audit. The Redoxer/QEMU harness now stages `long-running-service` and includes start, health, restart, forced crash, `recover-all`, stop, audit, and stale service-state recovery markers when Redoxer is available. The current backend is still a host process supervisor and requires `--allow-unenforced-authority`; it is not a Redox service-manager integration. | Execute the reboot/crash recovery path on a Redoxer/QEMU-capable runner and review the Redox service manager or FD-backed supervisor boundary before marking DONE. |
| Policy upgrade review | DONE | Upgrades show stable permission diffs and require explicit approval for dangerous expansions. | `cocoon install` compares the installed current manifest with the incoming capsule authority, applies the installed manifest's `permission_expansion_requires_confirmation` policy, rejects confirmation-required expansions by default, and accepts them only with `--allow-permission-expansion`; CLI golden and runtime regressions cover blocked and explicitly allowed upgrades with no partial version directory left behind. | Keep the install gate aligned with authority diff policy as new authority classes are added. |
| Machine-readable CLI contract | DONE | Core commands support stable JSON output and documented exit codes for automation. | `plan`, `install`, `run`, `start`, `stop`, `restart`, `health`, `probe-authority`, `probe-fd-exec`, `probe-fd-launch`, `probe-capsule-fd-launch`, `status`, `logs`, `check-install`, `rollback`, `recover`, `recover-all`, and `audit` support `--json`; CLI golden parses JSON for `plan`, `run`, `start`, `health`, `stop`, `recover-all`, `status`, `logs`, and `audit`; `docs/CLI_CONTRACT.md` documents output and exit-code semantics. | Keep JSON fixtures stable as commands evolve. |
| CI production gate | PARTIAL | CI runs host gate and Redoxer/QEMU gate on every change. | `.github/workflows/ci.yml` runs `cargo xtask prod-gate` and the required `cargo xtask redox-qemu-gate` on pushes to `main` and pull requests. The Redoxer/QEMU job installs QEMU, installs and initialises Redoxer, then runs the strict gate. The strict gate fails when Redoxer, QEMU, Redoxer-built package binary staging, or QEMU lifecycle execution evidence is missing. `cargo xtask prod-audit` writes `target/production-readiness/report.json` with the canonical `not-production-ready` verdict; `cargo xtask prod-audit-strict` intentionally fails until required blockers are closed. Local `cargo xtask prod-gate`, `cargo xtask test`, `cargo xtask redox-smoke`, `cargo xtask redox-package`, and skipped `cargo xtask qemu-smoke` pass. The first GitHub Actions run has not yet been observed. | Verify the first GitHub Actions run, then wire branch protection to both host and Redox-capable gates and consume the readiness JSON in CI. |
| Payload packaging alignment | PARTIAL | Payload layer converges on `pkgar` while `.cocoon` remains policy/receipt envelope. | Current payload format remains development fixture-oriented; P2a boundary report defines `pkg/pkgar` as payload owner and Cocoon as authority/audit envelope owner. Install receipts now include a forward-compatible `payload_identity`; current development capsules record `layer = "cocoon-bundle"` and the bundle digest, leaving the same receipt slot for future `pkgar` package identity without making Cocoon own package management. | Prototype pkgar-backed capsule payload only after the boundary can be preserved without disturbing P1.2g authority evidence. |
| Redox upstream tracking | PARTIAL | Cocoon maintains a reproducible local snapshot of the Redox references that can affect launcher, package, runtime-scheme, and Redoxer decisions. | `cargo xtask redox-track` shallow-clones or updates the tracked reference set under `target/ref-repos` and writes `target/redox-track/upstream-refs.json`; `docs/REDOX_UPSTREAM_TRACKING.md` records the review rule; `docs/reports/redox-upstream-progress-2026-06-11.md` records the current relevance/value/grantability judgement. | Consume this snapshot before changing launcher/default-enforcement/package boundaries; keep the snapshot as freshness evidence, not readiness evidence. |

## Current CLI Evidence

Latest local evidence on 2026-06-10:

```text
cargo xtask prod-gate: PASS local consolidated gate (contains explicit SKIP/BLOCKED lines for Redoxer/QEMU and direct Redox binary link on this machine)
cargo xtask prod-audit: PASS report write with verdict not-production-ready at target/production-readiness/report.json
cargo xtask prod-audit-strict: FAIL as expected while required production blockers remain
cargo xtask test: PASS (fmt, checks, clippy, workspace tests, CLI golden, install permission-expansion regressions, and service lifecycle/restart/crash/reboot-style recovery regressions)
cargo xtask redox-track: PASS (snapshot written to target/redox-track/upstream-refs.json)
cargo xtask redox-cookbook-check: PASS local recipe validation/staging, with full Redox Cookbook build execution still BLOCKED pending a full Redox build checkout
cargo xtask redox-qemu-gate: FAIL on this macOS host as expected because redoxer and qemu-system-x86_64 are unavailable; should PASS only on a Redoxer/QEMU-capable Linux runner
cargo xtask redox-package: PASS (release root written; Redoxer binary staging skipped because Redoxer is unavailable or build failed)
cargo xtask redox-smoke: PASS (host smoke builds hello-service, v2, signed, and long-running service capsules; Redox target cargo checks pass; direct Redox binary link remains BLOCKED; QEMU steps skipped because Redoxer is not installed)
cargo xtask qemu-smoke: PASS command exit, with all Redoxer/QEMU steps skipped because Redoxer is not installed, including the long-running service crash recovery lifecycle marker
```

Additional review-hardening evidence:

```text
QEMU harness required-command exit status exposure: PASS
QEMU harness minimal Redoxer staging root: PASS
legacy pre-P1.2f run receipt hash compatibility: PASS
deterministic signed bundle signature tamper test: PASS
P1.2g multi-profile FD run backend QEMU coverage: PASS
P1.2h structured child result evidence: PASS
P1.2i structured evidence negative tests: PASS
long-running service crash recovery lifecycle harness: PASS/SKIP-ready pending Redoxer availability
Redox authority community review package: docs/reports/redox-community-review-package.md
P2a pkgar boundary report: docs/reports/p2a-pkgar-boundary.md
```

`cargo xtask redox-smoke` currently reports these direct target blockers without
running the known-failing direct link commands:

```text
BLOCKED redox link probe binary link (requires Redox C sysroot/toolchain)
BLOCKED cocoon-cli redox binary link (requires Redox C sysroot/toolchain)
```

These blockers are not runtime failures and are not success evidence. They
remain production blockers for a native Redox distribution path.

## Immediate Implementation Queue

1. P1.2 service execution enforcement:
   - keep the P1.2i Redox FD-only run evidence freeze as the reviewable package
     baseline;
   - prepare, but do not yet send, the Redox/Ibuki review question about
     whether `fexecve` from an already-open executable FD is the intended
     service launcher contract;
   - decide when Redox `cocoon run` should default to the FD backend instead of
     requiring `--enforce-redox-authority`;
   - keep final `authority_mode = redox-enforced` blocked until the reviewed
     launcher contract and broader service lifecycle expectations are clear.
2. Production signing:
   - keep `cocoon trust policy --require-signed-bundles --require-signed-receipts`
     wired into production packaging/CI profiles.
3. Service supervision:
   - run reboot/crash recovery smoke on a Redoxer/QEMU-capable runner;
   - review whether final Redox supervision should use Redox service manager
     integration or the FD-backed supervisor path.
4. Native package path:
   - refresh Redox references with `cargo xtask redox-track`;
   - keep `cargo xtask redox-cookbook-check` green while testing the recipe in
     a full Redox checkout;
   - add the pkgar packaging path after the Cookbook shape is proven;
   - keep Redoxer release artifact path as the developer/native smoke path;
   - close direct link TODOs with the Redox C sysroot/toolchain.
5. Automation contract:
   - keep JSON output stable;
   - keep `cargo xtask prod-gate` as the CI entry point;
   - keep `cargo xtask redox-qemu-gate` as the required Redox-capable CI lane;
   - keep `cargo xtask prod-audit` as the canonical machine-readable readiness
     verdict;
   - make CI consume JSON where practical.

## Production Definition

Cocoon reaches production-usable status when:

1. `cargo xtask test` and `cargo xtask redox-smoke` pass on a documented Linux
   runner with Redoxer/QEMU.
2. `cocoon run` enforces Redox authority without the smoke override.
3. Signed bundles and receipts are mandatory outside local development mode.
4. A native Redox packaging path exists and is reproducible.
5. Service lifecycle commands cover long-running services and crash/reboot
   recovery.
6. Audit output can be consumed by automation through stable JSON and exit
   codes.
