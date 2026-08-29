# GraceGraph 0.1.0a1 validation

Status: **capsule-core pre-alpha; software validation only**

The release gate runs the full unit and hostile suite in normal Python and repeats
the assertion-independent runtime probe under `python -O`. CI also checks Ruff,
formatting, pre-commit, the public-tree privacy scanner, source and test bytecode,
the synthetic live-replay example, wheel/sdist metadata, and an installed-wheel CLI
smoke test.

The hostile suite covers missing or changed artifacts, exact inventory drift,
symlinks, hardlinks, malformed and duplicate JSON, unsafe paths, claim-kind/domain
mismatches, dependency cycles, contradictions, stale backups, event-chain breakage,
projection drift, missing external memory checkpoints, capsule member tampering,
fixed-boundary escalation, incomplete publication, optimized-runtime behavior, and
overwrite attempts.

Static verification is explicitly named `PASS_SEALED_BYTES_ONLY`. It does not
semantically replay claim dispositions and cannot authenticate an unsigned capsule.
Only a successful recomputation from an independently supplied project root returns
`PASS_LIVE_REPLAY`.

This alpha does not establish biological truth, empirical performance, target
selection, experiment authority, molecular release, publication authority, or
clinical utility. It does not yet provide authenticated semantic evidence adapters,
external signatures, public-key transparency checkpoints, or a qualified biological
data plane.

Exact release counts and artifact hashes are recorded in the GitHub release notes
after the clean public checkout reproduces the gate.
