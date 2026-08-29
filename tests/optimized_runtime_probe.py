"""Assertion-free hostile probe; output must match under normal Python and -O."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from gracegraph.canonical import GraceGraphError
from gracegraph.capsule import compile_capsule, verify_capsule


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def main() -> int:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        artifact = root / "evidence.txt"
        artifact.write_text("bound\n", encoding="utf-8")
        spec = {
            "schema_version": "gracegraph.spec.v1",
            "project_id": "optimized-runtime-probe",
            "claim_ceiling": "SOFTWARE",
            "artifacts": [
                {
                    "id": "e",
                    "path": "evidence.txt",
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "authority": "SOFTWARE",
                }
            ],
            "memory_sources": [],
            "claims": [
                {
                    "id": "c",
                    "claim_kind": "SOFTWARE_INTEGRITY",
                    "domain": "SOFTWARE",
                    "declared_state": "VERIFIED",
                    "evidence": ["e"],
                }
            ],
            "actions": [],
            "nonclaims": ["No biological conclusion."],
        }
        spec_path = root / "spec.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        capsule = root / "capsule"
        evaluation = compile_capsule(spec_path, root, capsule)
        verification = verify_capsule(capsule, root)
        if verification["status"] != "PASS_LIVE_REPLAY":
            fail("live replay did not pass")
        if evaluation["claim_boundary"] != {
            "empirical_n": 0,
            "biological_gate_closed": False,
            "target_selected": False,
            "experiment_authorized": False,
            "release_authorized": False,
        }:
            fail("fixed claim boundary changed")
        artifact.write_text("drifted\n", encoding="utf-8")
        try:
            verify_capsule(capsule, root)
        except GraceGraphError:
            drift_rejected = True
        else:
            drift_rejected = False
        if not drift_rejected:
            fail("live drift was accepted")
        print(
            json.dumps(
                {
                    "boundary": evaluation["claim_boundary"],
                    "drift_rejected": drift_rejected,
                    "initial_state": evaluation["nodes"][1]["state"],
                    "status": "PASS",
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
