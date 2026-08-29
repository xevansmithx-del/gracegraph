from __future__ import annotations

import json
import os

import pytest
from conftest import file_sha

from gracegraph.canonical import GraceGraphError, canonical_bytes, sha256_file, write_canonical
from gracegraph.capsule import (
    _report,
    compile_capsule,
    diff_capsules,
    explain_node,
    verify_capsule,
)


def write_spec(path, spec):
    path.write_text(json.dumps(spec), encoding="utf-8")


def with_artifact(tmp_path, basic_spec):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("bound\n", encoding="utf-8")
    basic_spec["artifacts"] = [
        {"id": "e", "path": "evidence.txt", "sha256": file_sha(evidence), "authority": "SOFTWARE"}
    ]
    basic_spec["claims"] = [
        {
            "id": "c",
            "claim_kind": "SOFTWARE_INTEGRITY",
            "domain": "SOFTWARE",
            "declared_state": "VERIFIED",
            "evidence": ["e"],
            "required_authority": "SOFTWARE",
        }
    ]
    spec = tmp_path / "spec.json"
    write_spec(spec, basic_spec)
    return spec, evidence


def test_compile_and_static_verify(tmp_path, basic_spec):
    spec, _ = with_artifact(tmp_path, basic_spec)
    capsule = tmp_path / "capsule"
    evaluation = compile_capsule(spec, tmp_path, capsule)
    result = verify_capsule(capsule)
    assert result["status"] == "PASS_SEALED_BYTES_ONLY"
    assert result["semantic_replay_performed"] is False
    assert result["run_id"] == evaluation["run_id"]
    assert result["members"] == [
        "evaluation.json",
        "frontier.json",
        "manifest.json",
        "report.md",
        "spec_lock.json",
    ]


def test_live_verify_detects_input_drift(tmp_path, basic_spec):
    spec, evidence = with_artifact(tmp_path, basic_spec)
    capsule = tmp_path / "capsule"
    compile_capsule(spec, tmp_path, capsule)
    assert verify_capsule(capsule, tmp_path)["live_match"] is True
    evidence.write_text("drifted\n", encoding="utf-8")
    with pytest.raises(GraceGraphError, match="no longer matches"):
        verify_capsule(capsule, tmp_path)


def test_tampering_is_detected(tmp_path, basic_spec):
    spec, _ = with_artifact(tmp_path, basic_spec)
    capsule = tmp_path / "capsule"
    compile_capsule(spec, tmp_path, capsule)
    (capsule / "report.md").write_text("tampered", encoding="utf-8")
    with pytest.raises(GraceGraphError, match="checksum mismatch"):
        verify_capsule(capsule)


def test_unmanifested_capsule_member_is_rejected(tmp_path, basic_spec):
    spec, _ = with_artifact(tmp_path, basic_spec)
    capsule = tmp_path / "capsule"
    compile_capsule(spec, tmp_path, capsule)
    (capsule / "extra.txt").write_text("unmanifested", encoding="utf-8")
    with pytest.raises(GraceGraphError, match="inventory mismatch"):
        verify_capsule(capsule)


def test_compiler_refuses_overwrite(tmp_path, basic_spec):
    spec, _ = with_artifact(tmp_path, basic_spec)
    capsule = tmp_path / "capsule"
    compile_capsule(spec, tmp_path, capsule)
    with pytest.raises(GraceGraphError, match="overwrite"):
        compile_capsule(spec, tmp_path, capsule)


def test_compile_is_deterministic(tmp_path, basic_spec):
    spec, _ = with_artifact(tmp_path, basic_spec)
    first = tmp_path / "one"
    second = tmp_path / "two"
    compile_capsule(spec, tmp_path, first)
    compile_capsule(spec, tmp_path, second)
    assert {path.name: path.read_bytes() for path in first.iterdir()} == {
        path.name: path.read_bytes() for path in second.iterdir()
    }


def test_diff_reports_state_change(tmp_path, basic_spec):
    spec, evidence = with_artifact(tmp_path, basic_spec)
    first = tmp_path / "one"
    compile_capsule(spec, tmp_path, first)
    evidence.write_text("changed", encoding="utf-8")
    second = tmp_path / "two"
    compile_capsule(spec, tmp_path, second)
    changes = diff_capsules(first, second)["state_changes"]
    assert {tuple(change.values()) for change in changes} >= {
        ("e", "VERIFIED", "INVALID"),
        ("c", "VERIFIED", "HOLD"),
    }


def test_run_identity_changes_when_observed_bytes_change(tmp_path, basic_spec):
    spec, evidence = with_artifact(tmp_path, basic_spec)
    first = tmp_path / "one"
    first_eval = compile_capsule(spec, tmp_path, first)
    evidence.write_text("changed", encoding="utf-8")
    second = tmp_path / "two"
    second_eval = compile_capsule(spec, tmp_path, second)
    assert first_eval["run_id"] != second_eval["run_id"]


def test_coherently_rehashed_claim_boundary_escalation_is_rejected(tmp_path, basic_spec):
    import hashlib

    spec, _ = with_artifact(tmp_path, basic_spec)
    capsule = tmp_path / "capsule"
    compile_capsule(spec, tmp_path, capsule)
    evaluation = json.loads((capsule / "evaluation.json").read_text())
    evaluation["claim_boundary"]["empirical_n"] = 999
    evaluation["claim_boundary"]["biological_gate_closed"] = True
    evaluation["claim_boundary"]["release_authorized"] = True
    identity = {
        "spec_sha256": evaluation["spec_sha256"],
        "nodes": evaluation["nodes"],
        "edges": evaluation["edges"],
        "claim_boundary": evaluation["claim_boundary"],
    }
    evaluation["evidence_sha256"] = hashlib.sha256(canonical_bytes(identity)).hexdigest()
    evaluation["run_id"] = evaluation["evidence_sha256"][:16]
    write_canonical(capsule / "evaluation.json", evaluation)
    write_canonical(
        capsule / "frontier.json",
        {
            "schema_version": "gracegraph.frontier.v1",
            "run_id": evaluation["run_id"],
            "actions": evaluation["frontier"],
        },
    )
    (capsule / "report.md").write_text(_report(evaluation), encoding="utf-8")
    manifest = json.loads((capsule / "manifest.json").read_text())
    manifest["run_id"] = evaluation["run_id"]
    manifest["members"] = {
        name: sha256_file(capsule / name)
        for name in ("spec_lock.json", "evaluation.json", "frontier.json", "report.md")
    }
    write_canonical(capsule / "manifest.json", manifest)
    with pytest.raises(GraceGraphError, match="locked specification"):
        verify_capsule(capsule)


def test_hardlinked_capsule_member_is_rejected(tmp_path, basic_spec):
    spec, _ = with_artifact(tmp_path, basic_spec)
    capsule = tmp_path / "capsule"
    compile_capsule(spec, tmp_path, capsule)
    outside = tmp_path / "report-copy.md"
    outside.write_bytes((capsule / "report.md").read_bytes())
    (capsule / "report.md").unlink()
    os.link(outside, capsule / "report.md")
    with pytest.raises(GraceGraphError, match="hard-linked"):
        verify_capsule(capsule)


def test_failed_publish_leaves_no_capsule_or_stage(tmp_path, basic_spec, monkeypatch):
    import gracegraph.capsule as module

    spec, _ = with_artifact(tmp_path, basic_spec)
    capsule = tmp_path / "capsule"

    def fail_after_stage(stage, locked, evaluation):
        (stage / "partial.txt").write_text("partial", encoding="utf-8")
        raise RuntimeError("injected")

    monkeypatch.setattr(module, "_write_capsule", fail_after_stage)
    with pytest.raises(RuntimeError, match="injected"):
        compile_capsule(spec, tmp_path, capsule)
    assert not capsule.exists()
    assert not list(tmp_path.glob(".capsule.stage-*"))


def test_explain_returns_node_reasons_and_edges(tmp_path, basic_spec):
    spec, _ = with_artifact(tmp_path, basic_spec)
    capsule = tmp_path / "capsule"
    compile_capsule(spec, tmp_path, capsule)
    explanation = explain_node(capsule, "c")
    assert explanation["verification"] == "PASS_SEALED_BYTES_ONLY"
    assert explanation["node"]["state"] == "VERIFIED"
    assert explanation["inbound_edges"] == [{"from": "e", "relation": "SUPPORTS", "to": "c"}]


def test_nonobject_manifest_fails_closed(tmp_path, basic_spec):
    spec, _ = with_artifact(tmp_path, basic_spec)
    capsule = tmp_path / "capsule"
    compile_capsule(spec, tmp_path, capsule)
    write_canonical(capsule / "manifest.json", [])

    with pytest.raises(GraceGraphError, match="manifest must be a JSON object"):
        verify_capsule(capsule)
