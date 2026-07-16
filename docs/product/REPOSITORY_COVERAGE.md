# Repository Coverage Harness

Milestone 27 adds deterministic repository coverage inventory contracts. The harness records discovered files, SHA-256 per file, language, component, state, and auditable exclusions.

It does not invent percentages. Consumers may compute percentages only from known numerator and denominator values in the inventory metrics.

`root_sha256` is path-sensitive and state-sensitive. It is calculated from canonical records containing relative path, file SHA-256, language, component, coverage state, exclusion reason, and declared exclusion metadata. Renames, content changes, and exclusion changes produce different inventory roots.

Inventory traversal never follows symbolic links. External, internal, and broken
symlinks are recorded as exclusions without being read or hashed. Generated-directory
components are excluded at every nesting depth. Regular files are resolved within the
canonical repository root before descriptor-based reads and are rechecked for identity
and content stability; permission failures, disappearance, and replacement races fail
closed as safe exclusions.

## Optional Graphify advisory graph

The official `graphifyy==0.9.16` CLI is isolated beneath the uv tool root. On this
VM, `numpy==2.5.1` caused SIGILL during import because the QEMU CPU lacks the newer
x86 features expected by that wheel. Pinning the official `numpy==2.2.6` wheel in
the Graphify tool environment restored compatibility without changing VulnHunter's
virtualenv or system Python.

Graphify artifacts are generated runtime intelligence and `graphify-out/` is
ignored by Git. `.graphifyignore` excludes virtualenvs, runtime/evidence/backup
directories, caches, databases, logs, environment files, keys, certificates, and
generated output. The VulnHunter adapter accepts only a current revision-bound,
size-limited, structurally valid graph beneath its approved output root. It rejects
symlinks, path escapes, secret paths, stale revisions, hooks, MCP, watch/install,
and global operations. Context delivery selects a bounded relevant subgraph and
falls back to deterministic trusted repository search or `ABSTAIN`.
