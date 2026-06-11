# Redox Upstream Tracking

This workspace tracks Redox references that can affect Cocoon's production
readiness. The local clones are intentionally kept under `target/ref-repos`,
which is ignored by Git.

Run:

```bash
cargo xtask redox-track
```

The task shallow-clones or updates the reference repositories and writes:

```text
target/redox-track/upstream-refs.json
```

## Reference Set

| Repository | Why Cocoon Tracks It |
| --- | --- |
| `redox` | Primary OS, build system, recipes, namespaces, and integration signals. |
| `relibc` | POSIX compatibility, `openat`/fd semantics, libc startup expectations. |
| `pkgutils` | Native package-management tooling that Cocoon must not replace. |
| `cookbook` | Upstream recipe conventions for the Cocoon distribution path. |
| `pkgar` | Future Cocoon payload owner and package identity source. |
| `redoxer` | Current Redox toolchain and QEMU execution bridge for Cocoon smoke tests. |
| `contain` | Potential upstream sandbox/launcher boundary to compare with Cocoon. |
| `kernel` | Namespace, scheme, and fd-capability mechanism changes. |
| `drivers` | Runtime scheme/device behaviour that can affect restricted services. |

## Review Rule

Treat the snapshot as freshness evidence, not as product readiness evidence.
For production-readiness claims, the relevant gates remain:

```bash
cargo xtask test
cargo xtask redox-cookbook-check
cargo xtask redox-smoke
cargo xtask qemu-smoke
```

When upstream changes touch launch, namespaces, runtime schemes, `pkg`/`pkgar`,
or Redoxer, update the corresponding Cocoon tracker entry or report before
promoting any production label.

Latest judgement report:
`docs/reports/redox-upstream-progress-2026-06-11.md`.
