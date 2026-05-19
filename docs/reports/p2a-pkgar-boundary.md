# P2a pkgar Boundary Report

Last updated: 2026-05-19

## Summary

P2a is a boundary report only. It does not migrate Cocoon payloads to `pkgar`,
does not change the `.cocoon` archive format, and does not alter the Redox
FD-only launch backend.

The intended long-term split is:

```text
pkg / pkgar:
  payload owner
  file contents, payload hashes/signatures, package repository metadata,
  dependency solving, package install/update mechanics

Cocoon:
  authority/audit envelope owner
  typed service manifest, permission diff, runtime plan, install/run/probe
  receipts, rollback metadata, trust policy, status/log/audit readback

Redox namespace / fd capabilities:
  enforcement owner
  namespace construction, scheme visibility, already-open FD capabilities,
  FD-only service launch primitives
```

The current P0 `.cocoon` tar.gz payload remains a development scaffold and
compatibility bridge. It should not become a competing Redox package payload
format.

## Current State

Cocoon currently builds a `.cocoon` artifact that includes:

- `Cocoon.toml`
- payload files
- `manifest/hashes.json`
- signature metadata

This is useful for CLI-only development and Redoxer/QEMU authority smoke tests.
It is not the final Redox-native payload story. The Redox-native target remains
a Cocoon authority envelope around a `pkgar` payload.

P1.2f/P1.2g already prove the authority side independently of payload migration:

- installed capsule entrypoints can be opened before restriction
- the service can be launched via the Redox FD-only backend
- declared access, denied ambient path, and hidden scheme behavior are checked
- run receipts expose FD launch evidence
- `status --json`, `logs`, and `audit` read back and verify the evidence

P2a therefore should not disturb the Redox launcher path. It only defines how
payload ownership should be delegated later.

## Ownership Boundary

| Area | Owner | Cocoon action |
| --- | --- | --- |
| Payload file format | `pkg` / `pkgar` | Delegate. Do not define a competing long-term payload format. |
| Payload hashes/signatures | `pkg` / `pkgar` | Consume and record references in Cocoon receipts where useful. |
| Package dependencies | `pkg` / `pkgar` | Avoid. Cocoon should not solve dependencies. |
| Package repository metadata | `pkg` / `pkgar` | Avoid. Cocoon should not host package repositories. |
| Service authority manifest | Cocoon | Own. Keep typed permissions, schemes, preopens, deny rules, and network defaults. |
| Permission diff | Cocoon | Own. Compare normalized service authority during review/update. |
| Runtime plan | Cocoon | Own. Translate accepted authority into a launch plan and evidence expectations. |
| Install/run/probe receipts | Cocoon | Own. Preserve receipt body hash, archive link, log hashes, trust policy, and launch evidence. |
| Rollback metadata | Cocoon plus package layer | Cocoon owns authority/receipt rollback evidence; package layer owns payload rollback mechanics. |
| Namespace/fd enforcement | Redox | Consume. Cocoon should not reimplement namespace manager or syscall mechanisms. |
| Service supervision | Redox service manager / rustysd direction | Integrate later. Do not implement in P2a. |

## Proposed Artifact Shape

The target shape is an authority envelope above a package payload:

```text
service.cocoon
  ├── Cocoon.toml
  ├── cocoon/authority-plan.json
  ├── cocoon/policy.json
  ├── cocoon/receipt-policy.json
  └── payload.pkgar
```

This is illustrative, not a committed file-format change. The important
boundary is that `payload.pkgar` remains a Redox package payload, while Cocoon
metadata describes service authority and audit expectations around that payload.

Alternative shapes are still open:

- external `.cocoon` metadata beside a `pkgar` package
- `pkgar` package plus Cocoon manifest installed under a standard metadata path
- Cookbook recipe that installs payload with `pkgar` and registers Cocoon
  authority metadata separately

P2a does not choose among these. It only rules out Cocoon owning a permanent
parallel payload package format.

## Receipt Implications

Future pkgar-backed receipts should be able to record:

- Cocoon manifest hash
- normalized permission hash
- `pkgar` package identity
- `pkgar` payload hash/signature reference
- install root and materialized service root
- authority mode and Redox FD launch evidence
- stdout/stderr log hashes
- previous receipt body hash
- rollback target and authority state

Receipt verification should not duplicate `pkgar`'s payload verifier. Cocoon
should verify or request proof that the package layer accepted the payload, then
record that package-layer identity in Cocoon's authority receipt chain.

## Install Flow Direction

Current scaffold:

```text
.cocoon tar.gz
  -> Cocoon verifies manifest and payload hashes
  -> Cocoon materializes payload
  -> Cocoon writes install receipt
```

Target Redox-native flow:

```text
pkgar payload
  -> pkg/pkgar verifies and materializes payload
  -> Cocoon verifies authority envelope and payload identity
  -> Cocoon writes install receipt linking authority to payload identity
  -> Cocoon run/probe uses Redox namespace/fd enforcement
```

The key invariant is that authority evidence must bind to the exact payload
identity that the package layer installed.

## Rollback Direction

Cocoon should not implement a full package rollback engine. A future rollback
should coordinate two facts:

- package layer restored or selected a payload version
- Cocoon restored or selected the matching authority metadata and receipt chain

Cocoon's rollback receipt should record the authority state and payload package
identity. It should not silently substitute a payload that the authority
manifest did not describe.

## Explicit Non-Goals

P2a does not implement:

- payload migration from `.cocoon` tar.gz to `pkgar`
- `pkgar` parser or package verifier inside Cocoon
- dependency solving
- package repository support
- Cookbook recipe generation
- service supervision
- `contain` backend
- dynamic FD broker
- bulk FD passing
- final `authority_mode = redox-enforced`

## Open Design Questions

These are local design questions to prepare before upstream review:

1. Should Cocoon's long-term artifact be a metadata envelope around a `pkgar`
   payload, or should Cocoon metadata live beside an installed package?
2. Which stable `pkgar` package identity should Cocoon record in install/run
   receipts?
3. Should `cocoon install` call `pkg/pkgar`, or should Redox package install
   call Cocoon to register authority metadata?
4. How should Cookbook recipes express service authority metadata without
   making Cocoon own package build mechanics?
5. How should rollback bind package payload version and Cocoon authority
   version?

## Recommended Next Step

Keep P2a as this boundary report until the Redox launcher boundary is reviewed
or until a small pkgar-backed fixture can be designed without changing P1.2g's
authority evidence path.

The next implementation should be a P2b prototype only if it can preserve this
ownership split:

```text
pkgar verifies and installs bytes;
Cocoon verifies and records service authority.
```
