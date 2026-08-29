from __future__ import annotations

import json

import pytest

from gracegraph.canonical import GraceGraphError, canonical_bytes, project_path
from gracegraph.graph import evaluate_spec
from gracegraph.models import load_spec


def write_spec(path, spec):
    path.write_text(json.dumps(spec), encoding="utf-8")


def test_canonical_json_is_order_independent():
    assert canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonical_json_rejects_nan():
    with pytest.raises(GraceGraphError, match="canonical-JSON"):
        canonical_bytes({"score": float("nan")})


def test_project_path_rejects_parent_escape(tmp_path):
    with pytest.raises(GraceGraphError, match="inside"):
        project_path(tmp_path, "../secret", "field")


def test_project_path_rejects_symlink(tmp_path):
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(GraceGraphError, match="symlink"):
        project_path(tmp_path, "link/value", "field")


def test_spec_rejects_unknown_top_level_field(tmp_path, basic_spec):
    basic_spec["mystery"] = True
    path = tmp_path / "spec.json"
    write_spec(path, basic_spec)
    with pytest.raises(GraceGraphError, match="unknown top-level"):
        load_spec(path)


def test_spec_rejects_string_false_as_numeric(tmp_path, basic_spec):
    basic_spec["actions"] = [
        {"id": "a", "resolves": [], "requires": [], "effort": False, "time": 1, "risk": 1}
    ]
    path = tmp_path / "spec.json"
    write_spec(path, basic_spec)
    with pytest.raises(GraceGraphError, match="effort"):
        load_spec(path)


def test_spec_rejects_unknown_reference(tmp_path, basic_spec):
    basic_spec["claims"] = [
        {
            "id": "claim",
            "claim_kind": "SOFTWARE_INTEGRITY",
            "domain": "SOFTWARE",
            "declared_state": "VERIFIED",
            "evidence": ["ghost"],
        }
    ]
    path = tmp_path / "spec.json"
    write_spec(path, basic_spec)
    with pytest.raises(GraceGraphError, match="unknown node"):
        load_spec(path)


def test_spec_allows_derived_memory_references(tmp_path, basic_spec):
    basic_spec["memory_sources"] = [{"id": "memory", "directory": "_MEMORY"}]
    basic_spec["claims"] = [
        {
            "id": "claim",
            "claim_kind": "SOFTWARE_INTEGRITY",
            "domain": "SOFTWARE",
            "declared_state": "VERIFIED",
            "evidence": ["memory:backup"],
            "required_authority": "SOFTWARE",
        }
    ]
    path = tmp_path / "spec.json"
    write_spec(path, basic_spec)
    assert load_spec(path)["claims"][0]["id"] == "claim"


def test_claim_cycle_is_rejected_at_evaluation(tmp_path, basic_spec):
    basic_spec["claims"] = [
        {
            "id": "a",
            "claim_kind": "SOFTWARE_INTEGRITY",
            "domain": "SOFTWARE",
            "declared_state": "HOLD",
            "requires": ["b"],
        },
        {
            "id": "b",
            "claim_kind": "SOFTWARE_INTEGRITY",
            "domain": "SOFTWARE",
            "declared_state": "HOLD",
            "requires": ["a"],
        },
    ]
    with pytest.raises(GraceGraphError, match="cycle"):
        evaluate_spec(basic_spec, tmp_path)


def test_duplicate_json_key_is_rejected(tmp_path, basic_spec):
    path = tmp_path / "spec.json"
    raw = json.dumps(basic_spec)
    path.write_text(raw[:-1] + ',"project_id":"shadow"}', encoding="utf-8")
    with pytest.raises(GraceGraphError, match="duplicate JSON key"):
        load_spec(path)


def test_nested_unknown_field_is_rejected(tmp_path, basic_spec):
    basic_spec["artifacts"] = [{"id": "a", "path": "a", "secret": "value"}]
    path = tmp_path / "spec.json"
    write_spec(path, basic_spec)
    with pytest.raises(GraceGraphError, match="unknown field"):
        load_spec(path)


def test_artifact_cannot_self_declare_empirical_authority(tmp_path, basic_spec):
    basic_spec["artifacts"] = [
        {"id": "a", "path": "a", "sha256": "0" * 64, "authority": "EMPIRICAL"}
    ]
    path = tmp_path / "spec.json"
    write_spec(path, basic_spec)
    with pytest.raises(GraceGraphError, match="v1 artifacts"):
        load_spec(path)


def test_claim_domain_and_authority_must_match(tmp_path, basic_spec):
    basic_spec["claims"] = [
        {
            "id": "claim",
            "claim_kind": "BIOLOGICAL_RESULT",
            "domain": "BIOLOGICAL",
            "required_authority": "SOFTWARE",
            "declared_state": "HOLD",
        }
    ]
    path = tmp_path / "spec.json"
    write_spec(path, basic_spec)
    with pytest.raises(GraceGraphError, match="does not match domain"):
        load_spec(path)


def test_claim_kind_and_domain_must_match(tmp_path, basic_spec):
    basic_spec["claims"] = [
        {
            "id": "claim",
            "claim_kind": "SOFTWARE_INTEGRITY",
            "domain": "BIOLOGICAL",
            "declared_state": "HOLD",
        }
    ]
    path = tmp_path / "spec.json"
    write_spec(path, basic_spec)
    with pytest.raises(GraceGraphError, match="does not match domain"):
        load_spec(path)


def test_logical_input_order_normalizes_to_same_spec(tmp_path, basic_spec):
    import copy

    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("a", encoding="utf-8")
    b.write_text("b", encoding="utf-8")
    basic_spec["artifacts"] = [
        {"id": "a", "path": "a.txt", "sha256": __import__("hashlib").sha256(b"a").hexdigest()},
        {"id": "b", "path": "b.txt", "sha256": __import__("hashlib").sha256(b"b").hexdigest()},
    ]
    basic_spec["actions"] = [
        {"id": "z", "resolves": ["b", "a"]},
        {"id": "a", "resolves": ["a"]},
    ]
    reversed_spec = copy.deepcopy(basic_spec)
    reversed_spec["artifacts"].reverse()
    reversed_spec["actions"].reverse()
    write_spec(first, basic_spec)
    write_spec(second, reversed_spec)
    assert canonical_bytes(load_spec(first)) == canonical_bytes(load_spec(second))


def test_nonclaims_cannot_be_empty(tmp_path, basic_spec):
    basic_spec["nonclaims"] = []
    path = tmp_path / "spec.json"
    write_spec(path, basic_spec)
    with pytest.raises(GraceGraphError, match="nonempty"):
        load_spec(path)


@pytest.mark.parametrize(
    "private_text",
    [
        "/" + "Users/example/private/file.txt",
        "C:\\private\\file.txt",
        "gh" + "p_abcdefghijklmnopqrstuvwxyz123456",
        "sk-" + "proj-abcdefghijklmnopqrstuvwxyz123456",
        "xo" + "xb-abcdefghijklmnopqrstuvwxyz123456",
        "-----BEGIN " + "PRIVATE KEY-----",
    ],
)
def test_private_or_credential_text_is_rejected(tmp_path, basic_spec, private_text):
    basic_spec["nonclaims"] = [private_text]
    path = tmp_path / "spec.json"
    write_spec(path, basic_spec)
    with pytest.raises(GraceGraphError, match="forbidden"):
        load_spec(path)
