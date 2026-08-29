# Architecture

GraceGraph compiles a strict JSON specification and a declared project root into a
five-member capsule:

```text
specification + exact local inputs
              |
              v
  typed artifacts, memory checks, claims, and evidence edges
              |
              v
  fixed N=0 claim boundary + bounded next-action heuristic
              |
              v
 spec_lock.json  evaluation.json  frontier.json  report.md  manifest.json
```

The compiler has three deliberate trust levels:

1. `PASS_SEALED_BYTES_ONLY` verifies exact capsule membership, canonical JSON,
   content hashes, fixed alpha boundary fields, and derived report/frontier bytes. It
   is a byte-integrity check, not semantic replay or authentication.
2. `PASS_LIVE_REPLAY` recomputes the evaluation from the locked specification and a
   caller-supplied project root. It fails when the live inputs have drifted.
3. Scientific or operational authority is outside the compiler. Biological, human,
   and owner domains cannot be closed at empirical `N=0`.

## Typed nodes

- Artifacts bind one relative regular file, its expected SHA-256 digest, and an
  optional exact inventory manifest.
- Memory sources separately evaluate append-only SQLite chains, external head
  checkpoints, recovery backups, and event-to-projection replay.
- Claims use a closed kind/domain mapping and declare dependencies, evidence, and
  contradictions. Missing or conflicting inputs propagate `HOLD` or `CONFLICTING`.
- Actions name unresolved nodes and prerequisites. Their scores are deterministic
  triage heuristics over declared impact and cost fields; they are not proofs of
  optimality.

## Security model

All project locators must be relative and remain inside the project root. Symlinks
and hardlinks are rejected for artifacts, inventories, capsule members, memory
databases, and backup members. Publication is no-clobber and stages a complete
capsule before a single-directory rename.

GraceGraph does not sign capsules. Anyone who can rewrite an unsigned capsule and
its manifest can create a new byte-consistent capsule. Trustworthy distribution
therefore requires a trusted release digest, signature, or live replay against an
independently controlled project root.

## Extension boundary

Future evidence adapters should emit strict, sequence-free receipts with producer
identity, version, scope, calibration state, claim capability, exact input/output
digests, and license metadata. An adapter may contribute evidence; it may not raise
the fixed empirical or authorization boundary by itself.
