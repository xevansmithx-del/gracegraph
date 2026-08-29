"""Deterministic, exact-member GraceGraph capsule compiler and verifier."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .canonical import GraceGraphError, canonical_bytes, read_json, sha256_file, write_canonical
from .graph import ALPHA_CLAIM_BOUNDARY, evaluate_spec
from .models import COMPILER_VERSION, load_spec

PAYLOAD_FILES = ("spec_lock.json", "evaluation.json", "frontier.json", "report.md")
CAPSULE_FILES = set(PAYLOAD_FILES) | {"manifest.json"}


def _report(evaluation: dict[str, Any]) -> str:
    lines = [
        "# GraceGraph evidence report",
        "",
        f"- Project: `{evaluation['project_id']}`",
        f"- Run: `{evaluation['run_id']}`",
        f"- Claim ceiling: `{evaluation['claim_ceiling']}`",
        f"- Verification scope: `{evaluation['verification_scope']}`",
        f"- Capsule scope: `{evaluation['capsule_scope']}`",
        f"- Empirical N: `{evaluation['claim_boundary']['empirical_n']}`",
        f"- Nodes: `{evaluation['summary']['total_nodes']}`",
        "",
        "## Node dispositions",
        "",
        "| Node | Type | Domain | Authority | State |",
        "|---|---|---|---|---|",
    ]
    for node in evaluation["nodes"]:
        lines.append(
            f"| `{node['id']}` | `{node['node_type']}` | `{node.get('domain', 'N/A')}` | "
            f"`{node['authority']}` | `{node['state']}` |"
        )
    lines.extend(["", "## Action frontier", ""])
    if evaluation["frontier"]:
        lines.extend(["| Rank | Action | State | Score |", "|---:|---|---|---:|"])
        for action in evaluation["frontier"]:
            lines.append(
                f"| {action['rank']} | `{action['id']}` | `{action['state']}` | {action['score']:.6f} |"
            )
        lines.extend(
            ["", "Scores are deterministic prioritization heuristics, not proofs of optimality."]
        )
    else:
        lines.append("No actions were declared.")
    lines.extend(["", "## Nonclaims", ""])
    for nonclaim in evaluation["nonclaims"]:
        lines.append(f"- {nonclaim}")
    lines.extend(["", "## Disposition reasons", ""])
    for node in evaluation["nodes"]:
        for reason in node.get("reasons", []):
            lines.append(f"- `{node['id']}`: {reason}")
    lines.append("")
    return "\n".join(lines)


def _write_capsule(stage: Path, spec: dict[str, Any], evaluation: dict[str, Any]) -> None:
    write_canonical(stage / "spec_lock.json", spec)
    write_canonical(stage / "evaluation.json", evaluation)
    write_canonical(
        stage / "frontier.json",
        {
            "schema_version": "gracegraph.frontier.v1",
            "run_id": evaluation["run_id"],
            "actions": evaluation["frontier"],
        },
    )
    (stage / "report.md").write_text(_report(evaluation), encoding="utf-8")
    manifest = {
        "schema_version": "gracegraph.manifest.v1",
        "run_id": evaluation["run_id"],
        "members": {name: sha256_file(stage / name) for name in sorted(PAYLOAD_FILES)},
    }
    write_canonical(stage / "manifest.json", manifest)


def _fsync_tree(directory: Path) -> None:
    """Make staged bytes durable before the single-directory rename."""

    for path in sorted(directory.iterdir()):
        with path.open("rb") as handle:
            os.fsync(handle.fileno())
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def compile_capsule(spec_path: Path, project_root: Path, output: Path) -> dict[str, Any]:
    root = project_root.resolve(strict=True)
    spec = load_spec(spec_path)
    evaluation = evaluate_spec(spec, root)
    output = output.resolve(strict=False)
    if output.exists() or output.is_symlink():
        raise GraceGraphError(f"refusing to overwrite capsule destination: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.stage-", dir=output.parent))
    try:
        _write_capsule(stage, spec, evaluation)
        verify_capsule(stage, root)
        _fsync_tree(stage)
        os.rename(stage, output)
        parent_descriptor = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except BaseException:
        if (
            stage.exists()
            and stage.parent == output.parent
            and stage.name.startswith(f".{output.name}.stage-")
        ):
            shutil.rmtree(stage)
        raise
    return evaluation


def verify_capsule(capsule: Path, project_root: Path | None = None) -> dict[str, Any]:
    capsule = capsule.resolve(strict=True)
    if not capsule.is_dir():
        raise GraceGraphError("capsule must be a directory")
    actual = {path.name for path in capsule.iterdir()}
    if actual != CAPSULE_FILES:
        raise GraceGraphError(
            f"capsule inventory mismatch: unmanifested={sorted(actual - CAPSULE_FILES)}; "
            f"missing={sorted(CAPSULE_FILES - actual)}"
        )
    if any(path.is_symlink() or not path.is_file() for path in capsule.iterdir()):
        raise GraceGraphError("capsule members must be regular non-symlink files")
    if any(path.stat().st_nlink != 1 for path in capsule.iterdir()):
        raise GraceGraphError("capsule members must not be hard-linked")
    manifest = read_json(capsule / "manifest.json")
    if not isinstance(manifest, dict):
        raise GraceGraphError("manifest must be a JSON object")
    if canonical_bytes(manifest) + b"\n" != (capsule / "manifest.json").read_bytes():
        raise GraceGraphError("manifest is not canonical JSON")
    members = manifest.get("members")
    if not isinstance(members, dict) or any(
        not isinstance(name, str) or not isinstance(digest, str) for name, digest in members.items()
    ):
        raise GraceGraphError("manifest members must be a digest object")
    if set(members) != set(PAYLOAD_FILES):
        raise GraceGraphError("manifest member set is not exact")
    for name, expected in members.items():
        if sha256_file(capsule / name) != expected:
            raise GraceGraphError(f"checksum mismatch: {name}")
    for name in ("spec_lock.json", "evaluation.json", "frontier.json"):
        value = read_json(capsule / name)
        if canonical_bytes(value) + b"\n" != (capsule / name).read_bytes():
            raise GraceGraphError(f"{name} is not canonical JSON")
    evaluation = read_json(capsule / "evaluation.json")
    if not isinstance(evaluation, dict):
        raise GraceGraphError("evaluation must be a JSON object")
    if manifest.get("run_id") != evaluation.get("run_id"):
        raise GraceGraphError("run_id mismatch")
    spec = load_spec(capsule / "spec_lock.json")
    expected_spec_sha = hashlib.sha256(canonical_bytes(spec)).hexdigest()
    identity_material = {
        "spec_sha256": expected_spec_sha,
        "nodes": evaluation.get("nodes"),
        "edges": evaluation.get("edges"),
        "claim_boundary": evaluation.get("claim_boundary"),
    }
    expected_evidence_sha = hashlib.sha256(canonical_bytes(identity_material)).hexdigest()
    if (
        evaluation.get("spec_sha256") != expected_spec_sha
        or evaluation.get("evidence_sha256") != expected_evidence_sha
        or evaluation.get("run_id") != expected_evidence_sha[:16]
        or evaluation.get("project_id") != spec["project_id"]
        or evaluation.get("claim_ceiling") != spec["claim_ceiling"]
        or evaluation.get("claim_boundary") != ALPHA_CLAIM_BOUNDARY
        or evaluation.get("verification_scope") != "STRUCTURAL_EVIDENCE_BINDING_ONLY"
        or evaluation.get("capsule_scope") != "PRIVATE_LOCAL_REPLAY"
        or evaluation.get("compiler") != {"name": "gracegraph", "version": COMPILER_VERSION}
    ):
        raise GraceGraphError("evaluation is not bound to the locked specification")
    expected_frontier = {
        "schema_version": "gracegraph.frontier.v1",
        "run_id": evaluation["run_id"],
        "actions": evaluation["frontier"],
    }
    if canonical_bytes(read_json(capsule / "frontier.json")) != canonical_bytes(expected_frontier):
        raise GraceGraphError("frontier is not derived from the evaluation")
    if (capsule / "report.md").read_text(encoding="utf-8") != _report(evaluation):
        raise GraceGraphError("report is not derived from the evaluation")
    live_match: bool | None = None
    if project_root is not None:
        live = evaluate_spec(spec, project_root.resolve(strict=True))
        live_match = canonical_bytes(live) == canonical_bytes(evaluation)
        if not live_match:
            raise GraceGraphError("live project no longer matches the sealed evaluation")
    return {
        "status": "PASS_LIVE_REPLAY" if live_match else "PASS_SEALED_BYTES_ONLY",
        "run_id": evaluation["run_id"],
        "members": sorted(actual),
        "live_match": live_match,
        "semantic_replay_performed": live_match is not None,
    }


def diff_capsules(old: Path, new: Path) -> dict[str, Any]:
    verify_capsule(old)
    verify_capsule(new)
    old_eval = read_json(old / "evaluation.json")
    new_eval = read_json(new / "evaluation.json")
    old_nodes = {node["id"]: node for node in old_eval["nodes"]}
    new_nodes = {node["id"]: node for node in new_eval["nodes"]}
    changes = []
    for identity in sorted(set(old_nodes) | set(new_nodes)):
        before = old_nodes.get(identity, {}).get("state", "ABSENT")
        after = new_nodes.get(identity, {}).get("state", "ABSENT")
        if before != after:
            changes.append({"id": identity, "before": before, "after": after})
    return {
        "schema_version": "gracegraph.diff.v1",
        "old_run_id": old_eval["run_id"],
        "new_run_id": new_eval["run_id"],
        "state_changes": changes,
    }


def explain_node(capsule: Path, node_id: str) -> dict[str, Any]:
    verification = verify_capsule(capsule)
    evaluation = read_json(capsule / "evaluation.json")
    nodes = {node["id"]: node for node in evaluation["nodes"]}
    if node_id not in nodes:
        raise GraceGraphError(f"unknown node: {node_id}")
    inbound = [edge for edge in evaluation["edges"] if edge["to"] == node_id]
    outbound = [edge for edge in evaluation["edges"] if edge["from"] == node_id]
    return {
        "schema_version": "gracegraph.explanation.v1",
        "verification": verification["status"],
        "run_id": evaluation["run_id"],
        "node": nodes[node_id],
        "inbound_edges": inbound,
        "outbound_edges": outbound,
    }
