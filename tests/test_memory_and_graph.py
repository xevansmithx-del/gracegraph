from __future__ import annotations

import os

from conftest import file_sha, make_memory

from gracegraph.graph import evaluate_spec
from gracegraph.memory import evaluate_memory, verify_chain


def node_map(evaluation):
    return {node["id"]: node for node in evaluation["nodes"]}


def checkpoint(db):
    state = verify_chain(db)
    return {
        db.name: {
            "identity": state["identity"],
            "events": state["events"],
            "head_digest": state["head_digest"],
        }
    }


def test_valid_chain_exact_backup_and_replay_verify(tmp_path):
    db = make_memory(tmp_path / "memory")
    nodes = evaluate_memory(
        tmp_path,
        {"id": "memory", "directory": "memory", "expected_heads": checkpoint(db)},
    )
    states = {node["id"]: node["state"] for node in nodes}
    assert states == {
        "memory:chains": "VERIFIED",
        "memory:anchor": "VERIFIED",
        "memory:backup": "VERIFIED",
        "memory:projection": "VERIFIED",
        "memory": "VERIFIED",
    }


def test_stale_backup_is_separate_from_valid_chain(tmp_path):
    db = make_memory(tmp_path / "memory", stale_backup=True)
    states = {
        node["id"]: node["state"]
        for node in evaluate_memory(
            tmp_path,
            {"id": "memory", "directory": "memory", "expected_heads": checkpoint(db)},
        )
    }
    assert states["memory:chains"] == "VERIFIED"
    assert states["memory:backup"] == "STALE"
    assert states["memory"] == "HOLD"


def test_projection_gap_is_not_hidden_by_valid_chain(tmp_path):
    db = make_memory(tmp_path / "memory", projection_gap=True)
    states = {
        node["id"]: node["state"]
        for node in evaluate_memory(
            tmp_path,
            {"id": "memory", "directory": "memory", "expected_heads": checkpoint(db)},
        )
    }
    assert states["memory:chains"] == "VERIFIED"
    assert states["memory:projection"] == "HOLD"
    assert states["memory"] == "HOLD"


def test_materialized_state_drift_is_detected_even_with_complete_event(tmp_path):
    db = make_memory(tmp_path / "memory")
    import sqlite3

    conn = sqlite3.connect(db)
    conn.execute("UPDATE decisions SET status='CLOSED' WHERE id='D1'")
    conn.commit()
    conn.close()
    result = verify_chain(db)
    assert result["state"] == "VERIFIED"
    assert any(
        gap.get("reason") == "event replay differs from materialized state"
        for gap in result["projection_gaps"]
    )


def test_recovery_file_mismatch_makes_backup_stale(tmp_path):
    make_memory(tmp_path / "memory")
    live = tmp_path / "RECOVERY.md"
    live.write_text("live", encoding="utf-8")
    nodes = evaluate_memory(
        tmp_path,
        {
            "id": "memory",
            "directory": "memory",
            "recovery_files": [{"live": "RECOVERY.md", "backup": "RECOVERY.md"}],
        },
    )
    states = {node["id"]: node["state"] for node in nodes}
    assert states["memory:backup"] == "STALE"


def test_broken_event_digest_is_invalid(tmp_path):
    db = make_memory(tmp_path / "memory")
    import sqlite3

    conn = sqlite3.connect(db)
    conn.execute("DROP TRIGGER events_no_update")
    conn.execute("UPDATE events SET digest=? WHERE seq=1", ("f" * 64,))
    conn.commit()
    conn.close()
    assert verify_chain(db)["state"] == "INVALID"


def test_symlinked_database_outside_memory_is_invalid(tmp_path):
    external = make_memory(tmp_path / "external")
    memory = tmp_path / "memory"
    memory.mkdir()
    os.symlink(external, memory / "program.sqlite")

    result = evaluate_memory(
        tmp_path,
        {"id": "memory", "directory": "memory", "expected_heads": {}},
    )
    nodes = node_map({"nodes": result})

    assert nodes["memory:chains"]["state"] == "INVALID"
    assert nodes["memory:chains"]["databases"][0]["state"] == "INVALID"


def test_declared_hold_cannot_self_promote(tmp_path, basic_spec):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("yes", encoding="utf-8")
    basic_spec["artifacts"] = [
        {"id": "e", "path": "evidence.txt", "sha256": file_sha(evidence), "authority": "EMPIRICAL"}
    ]
    basic_spec["claims"] = [
        {
            "id": "c",
            "claim_kind": "SOFTWARE_INTEGRITY",
            "domain": "SOFTWARE",
            "declared_state": "HOLD",
            "evidence": ["e"],
            "required_authority": "SOFTWARE",
        }
    ]
    assert node_map(evaluate_spec(basic_spec, tmp_path))["c"]["state"] == "HOLD"


def test_biological_authority_requires_review_even_with_empirical_artifact(tmp_path, basic_spec):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("yes", encoding="utf-8")
    basic_spec["claim_ceiling"] = "OWNER"
    basic_spec["artifacts"] = [
        {"id": "e", "path": "evidence.txt", "sha256": file_sha(evidence), "authority": "EMPIRICAL"}
    ]
    basic_spec["claims"] = [
        {
            "id": "c",
            "claim_kind": "BIOLOGICAL_RESULT",
            "domain": "BIOLOGICAL",
            "declared_state": "VERIFIED",
            "evidence": ["e"],
            "required_authority": "EMPIRICAL",
        }
    ]
    node = node_map(evaluate_spec(basic_spec, tmp_path))["c"]
    assert node["state"] == "HOLD"
    assert node["disposition"] == "ABSTAIN_UNCALIBRATED"


def test_missing_dependency_propagates_hold(tmp_path, basic_spec):
    basic_spec["artifacts"] = [{"id": "e", "path": "absent.txt", "authority": "SOFTWARE"}]
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
    nodes = node_map(evaluate_spec(basic_spec, tmp_path))
    assert nodes["e"]["state"] == "MISSING"
    assert nodes["c"]["state"] == "HOLD"


def test_verified_contradiction_wins(tmp_path, basic_spec):
    positive = tmp_path / "positive.txt"
    contradiction = tmp_path / "contradiction.txt"
    positive.write_text("yes", encoding="utf-8")
    contradiction.write_text("no", encoding="utf-8")
    basic_spec["artifacts"] = [
        {
            "id": "yes",
            "path": "positive.txt",
            "sha256": file_sha(positive),
            "authority": "SOFTWARE",
        },
        {
            "id": "no",
            "path": "contradiction.txt",
            "sha256": file_sha(contradiction),
            "authority": "SOFTWARE",
        },
    ]
    basic_spec["claims"] = [
        {
            "id": "c",
            "claim_kind": "SOFTWARE_INTEGRITY",
            "domain": "SOFTWARE",
            "declared_state": "VERIFIED",
            "evidence": ["yes"],
            "contradictions": ["no"],
            "required_authority": "SOFTWARE",
        }
    ]
    assert node_map(evaluate_spec(basic_spec, tmp_path))["c"]["state"] == "CONFLICTING"


def test_forward_claim_evidence_reference_is_topologically_evaluated(tmp_path, basic_spec):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("yes", encoding="utf-8")
    basic_spec["artifacts"] = [
        {"id": "e", "path": "evidence.txt", "sha256": file_sha(evidence), "authority": "SOFTWARE"}
    ]
    basic_spec["claims"] = [
        {
            "id": "a",
            "claim_kind": "SOFTWARE_INTEGRITY",
            "domain": "SOFTWARE",
            "declared_state": "VERIFIED",
            "evidence": ["b"],
        },
        {
            "id": "b",
            "claim_kind": "SOFTWARE_INTEGRITY",
            "domain": "SOFTWARE",
            "declared_state": "VERIFIED",
            "evidence": ["e"],
        },
    ]
    nodes = node_map(evaluate_spec(basic_spec, tmp_path))
    assert nodes["a"]["state"] == "VERIFIED"
    assert nodes["b"]["state"] == "VERIFIED"


def test_action_frontier_blocks_unmet_prerequisite(tmp_path, basic_spec):
    basic_spec["artifacts"] = [
        {"id": "target", "path": "missing.txt", "authority": "SOFTWARE"},
        {"id": "prerequisite", "path": "also-missing.txt", "authority": "SOFTWARE"},
    ]
    basic_spec["actions"] = [
        {
            "id": "fix",
            "resolves": ["target"],
            "requires": ["prerequisite"],
            "effort": 1,
            "time": 1,
            "risk": 1,
        }
    ]
    frontier = evaluate_spec(basic_spec, tmp_path)["frontier"]
    assert frontier[0]["state"] == "BLOCKED"
    assert frontier[0]["score"] == 0


def test_action_ranking_is_deterministic_and_impact_weighted(tmp_path, basic_spec):
    basic_spec["artifacts"] = [
        {"id": "a", "path": "a.missing", "authority": "SOFTWARE"},
        {"id": "b", "path": "b.missing", "authority": "SOFTWARE"},
    ]
    basic_spec["claims"] = [
        {
            "id": "dependent",
            "claim_kind": "SOFTWARE_INTEGRITY",
            "domain": "SOFTWARE",
            "declared_state": "VERIFIED",
            "requires": ["a"],
            "evidence": ["a"],
            "required_authority": "SOFTWARE",
        }
    ]
    basic_spec["actions"] = [
        {"id": "fix-b", "resolves": ["b"], "effort": 1, "time": 1, "risk": 1},
        {"id": "fix-a", "resolves": ["a"], "effort": 1, "time": 1, "risk": 1},
    ]
    first = evaluate_spec(basic_spec, tmp_path)["frontier"]
    second = evaluate_spec(basic_spec, tmp_path)["frontier"]
    assert first == second
    assert first[0]["id"] == "fix-a"
    assert "not a proof of optimality" in first[0]["note"]
