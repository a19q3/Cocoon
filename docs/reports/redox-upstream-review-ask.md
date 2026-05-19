# Redox Upstream Review Ask Draft

Last updated: 2026-05-19

## Purpose

This is a draft for later Redox/Ibuki review. Do not send it yet. It exists so
the review question stays narrow while Cocoon avoids deepening unconfirmed Redox
launcher assumptions.

## Short Status

Cocoon now has a Redox/QEMU service-authority evidence path for installed
capsule entrypoints:

- opens the installed executable and declared preopens before restriction
- enters a manifest-derived restricted Redox namespace
- launches the service from the inherited executable FD
- verifies declared preopen access
- verifies denied ambient path access is rejected
- verifies hidden undeclared scheme access is rejected
- records structured child/service evidence in run/probe receipts
- exposes the evidence through `status`, `status --json`, logs, and `audit`

Current authority mode remains intentionally intermediate:

```text
authority_mode = redox-enforced-capsule-entrypoint
authority_enforced_for_service = true
production_arbitrary_service = false
```

Cocoon does not yet claim final production:

```text
authority_mode = redox-enforced
production_arbitrary_service = true
```

## Proposed Review Message

```text
I have Cocoon running a Redox/QEMU service-authority prototype for installed
capsule entrypoints.

The current path opens the service executable and declared preopens before
restriction, enters a manifest-derived restricted namespace, launches from the
already-open executable FD, verifies declared access, verifies denied ambient
path/scheme access, and records structured evidence in receipts that are read
back through status/status --json/logs/audit.

I am not treating this as final production redox-enforced yet. The current
receipt mode is redox-enforced-capsule-entrypoint with
production_arbitrary_service=false.

The review question is whether this is the intended Redox launcher boundary for
restricted service execution:

- fexecve from an already-open executable FD,
- inherited preopen FDs for declared resources,
- manifest-derived scheme visibility,
- or another Redox-native launcher/namespace-manager contract.

If this boundary is wrong, I would like to correct Cocoon before adding more
service profiles, supervisor behavior, contain integration, pkgar payload
migration, or a final redox-enforced production label.
```

## Specific Questions

1. Is `fexecve` from an already-open executable FD the intended Redox mechanism
   for restricted service launch?
2. Should inherited FDs remain the first launcher contract, or should Cocoon
   wait for Unix-domain-socket FD passing, bulk FD passing, or another
   namespace-manager API?
3. Should service launchers construct scheme visibility directly from a service
   manifest, or should that policy translation live in an upstream namespace
   manager?
4. Which runtime schemes should ordinary Rust services expect inside a
   restricted namespace?
5. Is CWD-as-capability or fd-relative access the preferred model for service
   resource roots after launch?
6. What extra evidence is required before Cocoon should promote
   `redox-enforced-capsule-entrypoint` to final `redox-enforced`?

## Review Links Inside This Repo

- [redox-community-review-package.md](redox-community-review-package.md)
- [p1.2f-run-backend-graduation.md](p1.2f-run-backend-graduation.md)
- [p1.2g-multi-profile-fd-run.md](p1.2g-multi-profile-fd-run.md)
- [p1.2h-structured-child-result.md](p1.2h-structured-child-result.md)
- [p1.2i-review-hardening.md](p1.2i-review-hardening.md)
- [p2a-pkgar-boundary.md](p2a-pkgar-boundary.md)
