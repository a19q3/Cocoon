# Redox Runtime Scheme Minimums

Date: 2026-05-17

## Summary

A pure Redox null namespace is suitable for proving denial, but it is too strict
for ordinary Rust service execution. P1.2d showed that a controlled Rust process
launched through `fexecve` can fail during startup if runtime-required schemes
are hidden.

The concrete failure was:

```text
failed to generate random data: Os { code: 19, kind: Uncategorized, message: "No such device" }
```

The fix was to construct a restricted namespace that includes only the runtime
schemes needed by the controlled fixture and declared by the manifest. P1.2d
uses:

```text
memory
pipe
rand
```

`tcp` remains absent and is still rejected as an undeclared scheme.

## Design Implication

Cocoon should not blindly use an empty namespace for real service launch.
Instead, it should construct manifest-derived restricted namespaces:

```text
declared schemes
declared preopened capability handles
runtime-minimum schemes required to start the process
no undeclared ambient schemes
```

This matches Cocoon's security model better than a toy null-namespace demo.
Cocoon's goal is not "no namespace contents"; it is "only manifest-authorized
schemes and capability handles."

## P1.2d Evidence

The controlled FD launch probe opens the executable and preopen evidence before
restriction, enters a restricted namespace, launches the fixture with `fexecve`,
and proves:

```text
PASS exec service from inherited executable FD
PASS service reads declared preopen
PASS service cannot open denied path by name
PASS service cannot open hidden/undeclared scheme
```

## Open Questions For Redox/Ibuki

- What is the intended stable minimum scheme set for ordinary Rust binaries
  launched under restricted authority?
- Should `rand` always be explicitly declared by services using Rust std, or
  should Redox provide a different startup contract?
- Are `memory` and `pipe` the correct minimal runtime schemes for this launch
  pattern?
- How should dynamic linker, interpreter/shebang, stdio, logging, and event
  scheme access be represented in a service authority manifest?
- Should FD-only launch use inherited FDs, bulk FD passing, or another Redox
  launcher contract for larger service profiles?

## Boundary

This note does not justify generic sandbox ownership in Cocoon. Redox owns the
namespace and capability mechanisms. Cocoon should consume those mechanisms and
record service authority evidence.

