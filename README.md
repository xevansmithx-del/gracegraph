# GraceGraph capsule-core pre-alpha

GraceGraph 0.1.0a1 is the first fail-closed kernel of an evidence graph compiler. It binds exact artifact bytes,
complete file inventories, persistent-memory integrity, typed claims, authority
ceilings, dependency invalidation, and a deterministic next-action frontier into
one replayable capsule.

It is a research alpha. It does **not** infer biological truth, select targets,
authorize experiments, close wet-lab gates, or grant release authority. With the
current portfolio at empirical `N=0`, those states remain mechanically unreachable.
The v0.1 alpha emits a `PRIVATE_LOCAL_REPLAY` capsule because its locked input spec
contains relative project locators. The repository's example is synthetic and safe
to share; capsules built from private projects are not automatically public receipts.

## Why it exists

The portfolio already contains strong specialist tools, but each establishes a
local fact. GraceGraph answers the harder system question: exactly which bytes and
events support a claim, what authority those inputs possess, which downstream
claims become invalid after a change, and what bounded action would remove the most
current uncertainty?

Its first vertical slice directly prevents several observed failure classes:

- nonexistent and uninspected inputs cannot pass;
- exact inventories reject unmanifested files;
- SQLite event chains, backup coverage, and replay completeness are separate nodes;
- an unavailable check remains `HOLD`, never a pass;
- empirical, human, and owner authority cannot be manufactured by computation;
- capsules use canonical JSON, exact member sets, content digests, and atomic publish;
- action scores state their heuristic status and cannot close claims.

## Usage

GraceGraph requires Python 3.11 or later. The no-clobber capsule publisher is tested
on Linux and macOS.

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
gracegraph compile examples/public-demo.json \
  --project-root . \
  --out /tmp/gracegraph-capsule
gracegraph verify /tmp/gracegraph-capsule \
  --project-root .
```

`verify` without `--project-root` reports `PASS_SEALED_BYTES_ONLY`: it checks exact
membership, canonical encoding, digests, and derived report/frontier bytes. It does
not establish semantic correctness, authenticate its author, or replay external inputs;
a coherently rewritten unsigned capsule can pass that limited check.
Supplying the root reports `PASS_LIVE_REPLAY` and fails when the project has drifted.
`diff` reports node state changes between two valid capsules. `explain` returns a
node's bounded disposition, reasons, and direct incoming/outgoing evidence edges.

See `docs/ADR-0001-evidence-graph-compiler.md` for the architectural choice and
`docs/REQUIREMENTS_TRACEABILITY.md` for audit-to-test traceability. `VALIDATION.md`
records the reproduced alpha checks and explicit non-deliveries.
