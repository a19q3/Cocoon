# Redox Authority Community Review Package

Last updated: 2026-05-19

## Executive Summary

Cocoon now has a CLI-only Redox/QEMU evidence chain for service authority
enforcement. The current path proves that installed capsule entrypoints can be
opened before restriction, launched through an already-open executable FD under
a manifest-derived restricted namespace, and audited through normal run
receipts.

This is not yet a final production claim. Cocoon still uses the intermediate
authority label:

```text
authority_mode = redox-enforced-capsule-entrypoint
authority_enforced_for_service = true
production_arbitrary_service = false
```

The final `redox-enforced` production label remains reserved for community
review of the launcher boundary, broader service lifecycle work, and native
packaging integration.

## Architecture Boundary

Cocoon owns the service authority and audit lifecycle:

- typed capsule manifest and normalized authority
- permission diff and runtime plan
- install, probe, run, rollback, status, logs, and audit receipts
- receipt body hash, archive link, stdout/stderr log hashes, and trust policy
- fail-closed policy for unenforced Redox runs

Redox owns the enforcement mechanisms:

- namespaces and scheme visibility
- already-open FD capabilities
- `fexecve` or equivalent FD-based process launch
- runtime schemes required by ordinary Redox processes
- low-level FD passing or namespace manager behavior

`pkg/pkgar` owns the payload package layer. Cocoon should not become a package
manager, dependency solver, repository format, generic sandbox CLI, namespace
manager, or service supervisor before aligning with Redox service-management
direction.

## Evidence Chain

| Stage | Current result | QEMU evidence | Review meaning |
| --- | --- | --- | --- |
| P1.2a null namespace/preopen probe | DONE | `PASS probe Redox authority inside redox` | Already-open preopens remain usable and denied path/scheme opens fail after restriction. |
| P1.2b restricted child runner | DONE | `PASS redox authority probe receipt audited` | Namespace proof happens in a child process with captured logs and audited receipt evidence. |
| P1.2c FD-only exec classification | DONE | `PASS classify Redox FD-only service launch gap inside redox` | Path-based exec after a null namespace is blocked, so a production launcher needs an FD-only launch path. |
| P1.2d controlled FD launch | DONE | `PASS probe Redox FD-only controlled service launch inside redox` | A controlled fixture can launch from an inherited executable FD under restricted authority. |
| P1.2e installed capsule entrypoint probe | DONE | `PASS probe Redox FD-only installed capsule entrypoint inside redox` | A materialized capsule entrypoint can be opened before restriction and fexeced under a manifest-derived namespace. |
| P1.2f explicit run backend | DONE | `PASS cocoon run uses FD-only capsule entrypoint backend inside redox` | `cocoon run --enforce-redox-authority` uses the same backend and writes a normal `capsule_run` receipt. |
| P1.2g multi-profile backend | DONE | `PASS P1.2g log-service FD run profile inside redox`; `PASS P1.2g network-denied-service FD run profile inside redox` | The explicit Redox FD run backend works across multiple installed service profiles. |
| P1.2h structured child result evidence | DONE | Structured-result checks appear in probe/run/status --json/audit evidence | Parent parsing no longer treats stdout markers as the primary evidence source for authority booleans. |
| P1.2i review hardening and evidence freeze | DONE | Unit tests reject malformed/missing structured evidence; review package records PASS/BLOCKED boundaries | The current evidence package is frozen for review without adding deeper launcher assumptions. |

## Proof Boundary Matrix

| Stage | Proves | Does not prove |
| --- | --- | --- |
| P1.2d | A controlled fixture can run from an inherited executable FD under restricted Redox authority. | Installed capsule entrypoints or production `cocoon run`. |
| P1.2e | An installed capsule entrypoint can be opened before restriction and fexeced under a manifest-derived restricted namespace. | The normal run backend or multiple service profiles. |
| P1.2f | Explicit `cocoon run --enforce-redox-authority` uses the audited FD launch backend and writes normal run receipts. | Default Redox `run` enforcement or final `redox-enforced` production status. |
| P1.2g | The same explicit FD backend works across hello, log, and network-denied profiles in QEMU. | Broad arbitrary-service catalog coverage, supervision, or reboot lifecycle semantics. |
| P1.2h | Structured child/service results are bound into receipts and surfaced through status/status --json/audit. | Cryptographic attestation from the child process or a reviewed upstream launcher contract. |
| P1.2i | Malformed or incomplete structured evidence cannot be treated as enforced evidence by local evidence logic. | New Redox launcher behavior beyond the already-tested FD path. |

## Current Validation Commands

Latest local evidence records these gates as passing:

```bash
cargo fmt --all --check
cargo xtask test
cargo check -p cocoon-cli --target x86_64-unknown-redox
cargo xtask redox-package
cargo xtask qemu-smoke
cargo xtask redox-smoke
```

`cargo xtask redox-smoke` intentionally reports direct target binary link
blockers without executing the known-failing link commands:

```text
BLOCKED redox link probe binary link (requires Redox C sysroot/toolchain)
BLOCKED cocoon-cli redox binary link (requires Redox C sysroot/toolchain)
```

Those entries are packaging/toolchain blockers, not success evidence and not
failures of the QEMU authority runtime path. Redoxer/QEMU tasks should be run
serially because concurrent invocations can contend for Redoxer temporary disk
state.

The current P1.2 authority proof keeps stdout markers from controlled children
and services as human-readable log evidence. P1.2h adds structured child results
that are parsed by the parent and bound into run/probe receipt bodies. P1.2i
adds negative tests so malformed JSON, missing launcher results, missing service
or blocked results, and stdout-only PASS markers cannot become enforced
evidence. The harness also requires successful child/command exit status, and
Cocoon writes receipts and logs that are checked through status/status
--json/log/audit readback.

## What Cocoon Does Not Claim Yet

- Final production `authority_mode = redox-enforced`.
- Default Redox `cocoon run` enforcement without the explicit
  `--enforce-redox-authority` flag.
- Production arbitrary-service coverage across a broad service catalog.
- Long-running service supervision, restart, health check, or reboot recovery.
- `pkg/pkgar` payload integration.
- `contain` or generic sandbox CLI integration.
- Direct `x86_64-unknown-redox` binary linking without Redoxer.

## Review Questions For Redox/Ibuki

For the later upstream-facing draft, see
[redox-upstream-review-ask.md](redox-upstream-review-ask.md).

1. Is launching from an already-open executable FD with `fexecve` the intended
   Redox launcher contract for restricted service execution?
2. For larger service profiles, should Cocoon keep using inherited FDs, move to
   Unix-domain-socket FD passing, use bulk FD passing, or delegate to another
   Redox-native launcher API?
3. Which runtime schemes should ordinary Rust services expect in a restricted
   namespace? P1.2d/P1.2e showed that a pure null namespace is too strict for
   real Rust process startup, while `tcp` should remain hidden unless declared.
4. Should Cocoon model scheme visibility directly from its manifest, or should a
   Redox namespace manager own part of that policy translation?
5. Is CWD-as-capability or fd-relative access the preferred way to expose
   service resources after launch?
6. Should Cocoon remain directly on Redox namespace/FD primitives for now, or
   should it eventually wrap `contain` if `contain` exposes a stable service
   launcher interface?
7. What additional evidence would be required before promoting
   `redox-enforced-capsule-entrypoint` to final `redox-enforced`?

## Recommended Review Ask

Ask Redox reviewers to focus on the boundary, not the existence of the audit
layer:

- whether the FD-only launch contract is using Redox mechanisms correctly
- whether the manifest-derived namespace model is aligned with Redox authority
  semantics
- whether runtime scheme minimums are modeled correctly
- whether Cocoon should delegate any launcher step to upstream infrastructure
- what must be proven before default Redox `cocoon run` can use this backend

The expected conclusion is that Cocoon is complementary if it remains above the
mechanism layer: Redox provides namespaces, schemes, FD capabilities, and launch
primitives; Cocoon records service authority intent, diffs, plans, receipts,
rollback metadata, and audit readback.

## Next Cocoon Steps

1. Keep P1.2i as the reviewable evidence freeze.
2. Keep this report and the P1.2d/P1.2e/P1.2f/P1.2g/P1.2h/P1.2i reports ready for later
   Redox/Ibuki review, but avoid deepening unconfirmed launcher assumptions in
   the meantime.
3. Add more service profiles only after the launcher boundary is accepted or
   corrected.
4. Decide whether Redox should enable the FD backend by default for `cocoon run`.
5. Keep final `redox-enforced` blocked until the reviewed launcher contract,
   packaging path, and service lifecycle expectations are clear.
