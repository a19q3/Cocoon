# Cocoon Production Readiness Tracker

Last updated: 2026-05-18

## Current Verdict

Cocoon is not production-ready yet.

The current codebase has a strong CLI-only P1.1 lifecycle smoke: build, verify,
plan, install, status, check-install, recover, run, logs, rollback, and audit
are exercised through the `cocoon` command on host and inside Redoxer/QEMU.
This proves the lifecycle path, receipts, rollback evidence, and tamper checks.

The remaining production blockers are full Redox service execution under
restricted authority, production signing/trust, native Redox packaging/linking,
and service supervision semantics.

## Validation Rule

Current validation is CLI-only. A readiness item is not accepted unless it is
covered by one of these commands or by a documented manual CLI transcript:

```bash
cargo xtask test
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
| P1.2c FD-only exec gap classification | DONE | Redox/QEMU proves that entering the null namespace before a normal path-based `exec` blocks launching by name, so production execution needs an FD-only loader/exec strategy. | `cargo xtask qemu-smoke` includes `PASS classify Redox FD-only service launch gap inside redox`. | Replace classification with actual FD-only service launch when the loader path is implemented. |
| P1.2d controlled FD-only launch spike | DONE | Redox/QEMU launches a controlled fixture from an inherited executable FD under a restricted namespace with required runtime schemes. | `cocoon probe-fd-launch` writes an `fd_launch_probe` receipt and QEMU smoke includes `PASS probe Redox FD-only controlled service launch inside redox`; `audit` verifies the receipt body, archive link, and stdout/stderr hashes. | Keep as mechanism regression evidence below installed-entrypoint execution. |
| P1.2e installed capsule entrypoint FD launch spike | DONE | Redox/QEMU opens the installed capsule entrypoint before restriction, enters a manifest-derived restricted namespace, fexecs the entrypoint FD, and proves declared resource access plus denied path/scheme rejection. | `cocoon probe-capsule-fd-launch` writes a `capsule_fd_launch_probe` receipt with `authority_mode = redox-enforced-capsule-entrypoint`; QEMU smoke includes `PASS probe Redox FD-only installed capsule entrypoint inside redox` and `PASS audit Redox FD-only launch probe receipts inside redox`. | Keep as probe evidence below the run backend. |
| P1.2f explicit Redox FD run backend | DONE | `cocoon run --enforce-redox-authority` uses the same FD-only installed capsule entrypoint backend as the probe, writes a normal `capsule_run` receipt, exposes status/logs/audit readback, and keeps `production_arbitrary_service = false`. | QEMU smoke includes `PASS cocoon run uses FD-only capsule entrypoint backend inside redox`; run receipts expose executable/preopen-before-restriction fields, manifest-derived namespace evidence, fexec success, declared resource read, denied path rejection, hidden scheme rejection, stdout/stderr hashes, and `authority_mode = redox-enforced-capsule-entrypoint`. | Keep as regression evidence below final production label promotion. |
| P1.2g multi-profile Redox FD run backend | DONE | The explicit Redox FD run backend handles multiple installed service profiles under the same authority boundary. | QEMU smoke includes `PASS P1.2g log-service FD run profile inside redox` and `PASS P1.2g network-denied-service FD run profile inside redox`; each profile is installed, run with `--enforce-redox-authority`, read through logs/status, and audited for FD launch evidence. | Use this evidence for community review; do not promote final `redox-enforced` until the operational boundary is reviewed. |
| Production signing and trust | DONE | Bundles and receipts are signed; strict mode rejects unsigned or untrusted artifacts; key rotation and trust root are documented. | Bundle signing is implemented with `cocoon keygen`, `build --signing-key`, and `verify/install --strict --trusted-key`; repeated `--trusted-key` supports explicit multi-root bundle trust windows; `cocoon trust add/list/remove` manages persistent bundle and receipt trust roots under the install root; `cocoon trust policy --require-signed-bundles --require-signed-receipts` makes strict signed bundle and receipt verification the install-root default; install/run/rollback/authority probe receipts can be signed with `--receipt-signing-key`; `status/logs/audit --require-receipt-signatures --receipt-trusted-key` require trusted receipt signatures and repeated `--receipt-trusted-key` supports receipt signer rotation windows. | Keep trust policy wired into packaging/CI profiles. |
| Native Redox binary/package path | PARTIAL | Cocoon builds as a native Redox artifact through Redox-supported tooling and can be packaged for image integration. | `redoxer build` passes; `cargo xtask redox-package` stages a Redoxer-built `bin/cocoon`, signed capsule, production trust policy, README, and BLAKE3 release manifest under `target/redox-package/cocoon-redox`; direct Redox target binary link remains TODO without Redox C sysroot/toolchain. | Add Redox Cookbook/pkgar recipe for distribution integration. |
| Service supervision | TODO | Installed capsules can be started, stopped, restarted, health-checked, and recovered after reboot/crash with clear receipts. | Current `run` is a CLI execution smoke, not a supervisor. | Design supervisor contract and CLI commands; add QEMU smoke for long-running service lifecycle. |
| Policy upgrade review | PARTIAL | Upgrades show stable permission diffs and require explicit approval for dangerous expansions. | `plan` and verifier expose normalized authority; install itself does not enforce approval policy. | Add install/upgrade preflight gate for permission expansion. |
| Machine-readable CLI contract | DONE | Core commands support stable JSON output and documented exit codes for automation. | `plan`, `install`, `run`, `probe-authority`, `probe-fd-exec`, `probe-fd-launch`, `probe-capsule-fd-launch`, `status`, `logs`, `check-install`, `rollback`, `recover`, and `audit` support `--json`; CLI golden parses JSON for `plan`, `run`, `status`, `logs`, and `audit`; `docs/CLI_CONTRACT.md` documents output and exit-code semantics. | Keep JSON fixtures stable as commands evolve. |
| CI production gate | TODO | CI runs host gate on every change and optional Redoxer/QEMU gate on capable runners. | Local `cargo xtask test` and `cargo xtask redox-smoke` pass. | Add CI jobs with Redoxer/QEMU lane marked required where infrastructure supports it. |
| Payload packaging alignment | TODO | Payload layer converges on `pkgar` while `.cocoon` remains policy/receipt envelope. | Current payload format remains development fixture-oriented. | Prototype pkgar-backed capsule payload and verifier integration. |

## Current CLI Evidence

Latest local evidence on 2026-05-18:

```text
cargo fmt --all --check: PASS
cargo test -p cocoon-cli --test cli_golden inspect_verify_and_strict_verify_outputs_are_stable -- --nocapture: PASS
cargo test -p cocoon-cli --test cli_golden signed_bundle_trust_flow_is_cli_only -- --nocapture: PASS (signed bundles, signed receipts, multi-root rotation windows, persistent trust config, and production trust policy defaults)
cargo test -p cocoon-cli --test cli_golden inspect_verify_and_strict_verify_outputs_are_stable -- --nocapture: PASS (`plan --json` contract)
cargo check -p cocoon-runtime: PASS
cargo check -p cocoon-cli: PASS
cargo check -p cocoon-cli --target x86_64-unknown-redox: PASS
cargo clippy --all-targets --all-features -- -D warnings: PASS
cargo check -p xtask: PASS
cargo xtask test: PASS
cargo xtask qemu-smoke: PASS
cargo xtask redox-smoke: PASS
cargo xtask redox-package: PASS
```

Additional review-hardening evidence:

```text
QEMU harness required-command exit status exposure: PASS
QEMU harness minimal Redoxer staging root: PASS
legacy pre-P1.2f run receipt hash compatibility: PASS
deterministic signed bundle signature tamper test: PASS
P1.2g multi-profile FD run backend QEMU coverage: PASS
Redox authority community review package: docs/reports/redox-community-review-package.md
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
   - keep the P1.2g Redox FD-only run backend as the reviewable evidence
     baseline;
   - ask Redox/Ibuki to review whether `fexecve` from an already-open
     executable FD is the intended service launcher contract;
   - decide when Redox `cocoon run` should default to the FD backend instead of
     requiring `--enforce-redox-authority`;
   - keep final `authority_mode = redox-enforced` blocked until the reviewed
     launcher contract and broader service lifecycle expectations are clear.
2. Production signing:
   - keep `cocoon trust policy --require-signed-bundles --require-signed-receipts`
     wired into production packaging/CI profiles.
3. Service supervision:
   - define process lifecycle receipts;
   - implement start/stop/restart/status/health CLI;
   - add reboot/crash recovery smoke.
4. Native package path:
   - add Redox Cookbook or pkgar packaging path;
   - keep Redoxer release artifact path as the developer/native smoke path;
   - close direct link TODOs with the Redox C sysroot/toolchain.
5. Automation contract:
   - keep JSON output stable;
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
