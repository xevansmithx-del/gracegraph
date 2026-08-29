"""Strict GraceGraph specification validation and authority semantics."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .canonical import GraceGraphError, read_json, unique_ids

SCHEMA_VERSION = "gracegraph.spec.v1"
COMPILER_VERSION = "0.1.0a2"
STATES = {
    "VERIFIED",
    "HOLD",
    "CONFLICTING",
    "REFUTED",
    "STALE",
    "MISSING",
    "REVIEW_REQUIRED",
    "INVALID",
}
AUTHORITIES = {
    "SOFTWARE": 0,
    "DOCUMENTARY": 1,
    "COMPUTATIONAL": 2,
    "EMPIRICAL": 3,
    "HUMAN": 4,
    "OWNER": 5,
}
AUTO_CLOSABLE = {"SOFTWARE", "DOCUMENTARY", "COMPUTATIONAL"}
CLAIM_DOMAINS = {
    "SOFTWARE": "SOFTWARE",
    "DOCUMENTARY": "DOCUMENTARY",
    "COMPUTATIONAL": "COMPUTATIONAL",
    "BIOLOGICAL": "EMPIRICAL",
    "HUMAN": "HUMAN",
    "OWNER": "OWNER",
}
CLAIM_KINDS = {
    "SOFTWARE_INTEGRITY": "SOFTWARE",
    "DOCUMENTARY_RECORD": "DOCUMENTARY",
    "COMPUTATIONAL_RESULT": "COMPUTATIONAL",
    "BIOLOGICAL_RESULT": "BIOLOGICAL",
    "BIOLOGICAL_GATE": "BIOLOGICAL",
    "HUMAN_DECISION": "HUMAN",
    "OWNER_AUTHORIZATION": "OWNER",
}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]*$")
PRIVATE_TEXT_PATTERNS = (
    re.compile(r"/(?:Users|home|Volumes|private|tmp|var)/"),
    re.compile(r"[A-Za-z]:[\\/]"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp_|sk-proj-|xox[baprs]-)[A-Za-z0-9_-]{8,}"),
)


def _only_keys(item: dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(set(item) - allowed)
    if unknown:
        raise GraceGraphError(f"{field} contains unknown field(s): {unknown}")


def _reject_private_text(value: Any, field: str = "spec") -> None:
    if isinstance(value, str):
        if any(ord(character) < 32 for character in value) or any(
            pattern.search(value) for pattern in PRIVATE_TEXT_PATTERNS
        ):
            raise GraceGraphError(f"{field} contains forbidden private/path material")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_private_text(item, f"{field}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_private_text(item, f"{field}.{key}")


def _list_of_dicts(spec: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = spec.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise GraceGraphError(f"{key} must be a list of objects")
    unique_ids(value, key)
    for item in value:
        if not ID_RE.fullmatch(item["id"]):
            raise GraceGraphError(f"invalid {key} id: {item['id']}")
    return value


def _string_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise GraceGraphError(f"{field} must be a list of strings")
    if len(value) != len(set(value)):
        raise GraceGraphError(f"{field} contains duplicates")
    return value


def load_spec(path: Path) -> dict[str, Any]:
    spec = read_json(path)
    if not isinstance(spec, dict):
        raise GraceGraphError("specification must be a JSON object")
    allowed = {
        "schema_version",
        "project_id",
        "claim_ceiling",
        "artifacts",
        "memory_sources",
        "claims",
        "actions",
        "nonclaims",
    }
    unknown = sorted(set(spec) - allowed)
    if unknown:
        raise GraceGraphError(f"unknown top-level field(s): {unknown}")
    if spec.get("schema_version") != SCHEMA_VERSION:
        raise GraceGraphError(f"schema_version must be {SCHEMA_VERSION}")
    if not isinstance(spec.get("project_id"), str) or not ID_RE.fullmatch(spec["project_id"]):
        raise GraceGraphError("project_id must be a lowercase stable identifier")
    ceiling = spec.get("claim_ceiling")
    if ceiling not in AUTO_CLOSABLE:
        raise GraceGraphError(f"unknown claim_ceiling: {ceiling}")

    artifacts = _list_of_dicts(spec, "artifacts")
    memories = _list_of_dicts(spec, "memory_sources")
    claims = _list_of_dicts(spec, "claims")
    actions = _list_of_dicts(spec, "actions")
    all_ids = [item["id"] for group in (artifacts, memories, claims) for item in group]
    if len(all_ids) != len(set(all_ids)):
        raise GraceGraphError("artifact, memory, and claim ids share one namespace")
    derived_memory_ids = {
        f"{item['id']}:{suffix}"
        for item in memories
        for suffix in ("chains", "anchor", "backup", "projection")
    }
    collision = sorted(derived_memory_ids & set(all_ids))
    if collision:
        raise GraceGraphError(f"node id collides with a derived memory node: {collision}")

    for item in artifacts:
        _only_keys(
            item, {"id", "path", "sha256", "authority", "inventory"}, f"artifact {item['id']}"
        )
        if not isinstance(item.get("path"), str):
            raise GraceGraphError(f"artifact {item['id']} requires path")
        digest = item.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise GraceGraphError(f"artifact {item['id']} requires a valid sha256")
        authority = item.get("authority", "SOFTWARE")
        if authority not in AUTO_CLOSABLE:
            raise GraceGraphError(
                f"artifact {item['id']} requests {authority} authority, but v1 artifacts "
                "may carry only software, documentary, or computational authority"
            )
        inventory = item.get("inventory")
        if inventory is not None and not isinstance(inventory, dict):
            raise GraceGraphError(f"artifact {item['id']}.inventory must be an object")
        if inventory is not None:
            _only_keys(
                inventory, {"root", "manifest", "exclude"}, f"artifact {item['id']}.inventory"
            )
            exclude = inventory.get("exclude", [])
            if not isinstance(exclude, list) or any(
                not isinstance(pattern, str) for pattern in exclude
            ):
                raise GraceGraphError(f"artifact {item['id']}.inventory.exclude must be strings")

    for item in memories:
        _only_keys(
            item,
            {"id", "directory", "backup", "recovery_files", "expected_heads"},
            f"memory source {item['id']}",
        )
        if not isinstance(item.get("directory"), str):
            raise GraceGraphError(f"memory source {item['id']} requires directory")
        if item.get("backup", "latest") != "latest":
            raise GraceGraphError("the v1 compiler only accepts backup='latest'")
        recovery_files = item.get("recovery_files", [])
        if not isinstance(recovery_files, list) or any(
            not isinstance(entry, dict) for entry in recovery_files
        ):
            raise GraceGraphError(f"memory source {item['id']}.recovery_files must be objects")
        for index, entry in enumerate(recovery_files):
            _only_keys(
                entry, {"live", "backup"}, f"memory source {item['id']}.recovery_files[{index}]"
            )
            if not isinstance(entry.get("live"), str) or not isinstance(entry.get("backup"), str):
                raise GraceGraphError("recovery file mappings require live and backup strings")
        expected_heads = item.get("expected_heads", {})
        if not isinstance(expected_heads, dict):
            raise GraceGraphError(f"memory source {item['id']}.expected_heads must be an object")
        for database, checkpoint in expected_heads.items():
            if not isinstance(database, str) or Path(database).name != database:
                raise GraceGraphError("expected-head database names must be flat")
            if not isinstance(checkpoint, dict):
                raise GraceGraphError("expected-head checkpoints must be objects")
            _only_keys(
                checkpoint,
                {"identity", "events", "head_digest"},
                f"memory source {item['id']}.expected_heads.{database}",
            )
            if (
                not isinstance(checkpoint.get("identity"), str)
                or isinstance(checkpoint.get("events"), bool)
                or not isinstance(checkpoint.get("events"), int)
                or checkpoint["events"] < 0
                or not isinstance(checkpoint.get("head_digest"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", checkpoint["head_digest"])
            ):
                raise GraceGraphError(f"invalid expected-head checkpoint for {database}")

    known_nodes = set(all_ids) | derived_memory_ids
    for item in claims:
        _only_keys(
            item,
            {
                "id",
                "claim_kind",
                "domain",
                "declared_state",
                "required_authority",
                "requires",
                "evidence",
                "contradictions",
            },
            f"claim {item['id']}",
        )
        claim_kind = item.get("claim_kind")
        if claim_kind not in CLAIM_KINDS:
            raise GraceGraphError(f"claim {item['id']} requires a closed claim_kind")
        domain = item.get("domain")
        if domain not in CLAIM_DOMAINS:
            raise GraceGraphError(f"claim {item['id']} requires a closed domain")
        if domain != CLAIM_KINDS[claim_kind]:
            raise GraceGraphError(
                f"claim {item['id']} kind {claim_kind} does not match domain {domain}"
            )
        declared = item.get("declared_state", "HOLD")
        if declared not in STATES:
            raise GraceGraphError(f"claim {item['id']} has unknown declared_state")
        authority = item.get("required_authority", CLAIM_DOMAINS[domain])
        if authority != CLAIM_DOMAINS[domain]:
            raise GraceGraphError(
                f"claim {item['id']} authority {authority} does not match domain {domain}"
            )
        dependencies = _string_list(item.get("requires"), f"claim {item['id']}.requires")
        evidence = _string_list(item.get("evidence"), f"claim {item['id']}.evidence")
        contradictions = _string_list(
            item.get("contradictions"), f"claim {item['id']}.contradictions"
        )
        for reference in dependencies + evidence + contradictions:
            if reference not in known_nodes:
                raise GraceGraphError(f"claim {item['id']} references unknown node {reference}")
        if item["id"] in dependencies:
            raise GraceGraphError(f"claim {item['id']} depends on itself")

    for item in actions:
        _only_keys(
            item,
            {"id", "title", "resolves", "requires", "effort", "time", "risk"},
            f"action {item['id']}",
        )
        _string_list(item.get("resolves"), f"action {item['id']}.resolves")
        if "title" in item and (not isinstance(item["title"], str) or not item["title"].strip()):
            raise GraceGraphError(f"action {item['id']}.title must be a nonempty string")
        requirements = _string_list(item.get("requires"), f"action {item['id']}.requires")
        for reference in item.get("resolves", []) + requirements:
            if reference not in known_nodes:
                raise GraceGraphError(f"action {item['id']} references unknown node {reference}")
        for field in ("effort", "time", "risk"):
            value = item.get(field, 1)
            if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
                raise GraceGraphError(f"action {item['id']}.{field} must be nonnegative")

    nonclaims = spec.get("nonclaims", [])
    if (
        not isinstance(nonclaims, list)
        or not nonclaims
        or any(not isinstance(item, str) or not item.strip() for item in nonclaims)
    ):
        raise GraceGraphError("nonclaims must be a nonempty list of nonempty strings")
    _reject_private_text(spec)
    for item in artifacts:
        inventory = item.get("inventory")
        if inventory is not None and "exclude" in inventory:
            inventory["exclude"] = sorted(inventory["exclude"])
    for item in memories:
        item["recovery_files"] = sorted(
            item.get("recovery_files", []), key=lambda value: (value["backup"], value["live"])
        )
    for item in claims:
        for field in ("requires", "evidence", "contradictions"):
            item[field] = sorted(item.get(field, []))
    for item in actions:
        for field in ("requires", "resolves"):
            item[field] = sorted(item.get(field, []))
    spec["artifacts"] = sorted(artifacts, key=lambda item: item["id"])
    spec["memory_sources"] = sorted(memories, key=lambda item: item["id"])
    spec["claims"] = sorted(claims, key=lambda item: item["id"])
    spec["actions"] = sorted(actions, key=lambda item: item["id"])
    spec["nonclaims"] = sorted(nonclaims)
    return spec


def authority_sufficient(observed: str, required: str) -> bool:
    return AUTHORITIES[observed] >= AUTHORITIES[required]
