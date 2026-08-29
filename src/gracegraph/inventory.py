"""Content-addressed artifact and exact-inventory verification."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

from .canonical import GraceGraphError, project_path, sha256_file

HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _excluded(relative: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns)


def _read_manifest(path: Path) -> dict[str, str]:
    listed: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise GraceGraphError(f"cannot read inventory manifest: {exc}") from exc
    for number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        parts = raw.split(maxsplit=1)
        if len(parts) != 2:
            raise GraceGraphError(f"manifest line {number} is malformed")
        expected, name = parts
        name = name.lstrip("*")
        if name.startswith("./"):
            name = name[2:]
        relative = Path(name)
        if not HASH_RE.fullmatch(expected) or relative.is_absolute() or ".." in relative.parts:
            raise GraceGraphError(f"manifest line {number} is unsafe")
        normalized = relative.as_posix()
        if normalized in listed:
            raise GraceGraphError(f"manifest line {number} duplicates {normalized}")
        listed[normalized] = expected
    if not listed:
        raise GraceGraphError("inventory manifest is empty")
    return listed


def verify_inventory(root: Path, manifest: Path, patterns: list[str]) -> dict[str, Any]:
    if not root.is_dir() or not manifest.is_file():
        raise GraceGraphError("inventory root or manifest is missing")
    try:
        manifest_relative = manifest.relative_to(root).as_posix()
    except ValueError as exc:
        raise GraceGraphError("inventory manifest must be inside its inventory root") from exc
    listed = _read_manifest(manifest)
    actual: set[str] = set()
    for candidate in sorted(root.rglob("*")):
        relative = candidate.relative_to(root).as_posix()
        if _excluded(relative, patterns) or relative == manifest_relative:
            continue
        if candidate.is_symlink():
            raise GraceGraphError(f"inventory contains symlink: {relative}")
        if candidate.is_file():
            if candidate.stat().st_nlink != 1:
                raise GraceGraphError(f"inventory contains hard-linked file: {relative}")
            actual.add(relative)
    listed_names = set(listed)
    unmanifested = sorted(actual - listed_names)
    missing = sorted(listed_names - actual)
    mismatched: list[str] = []
    for name in sorted(actual & listed_names):
        if sha256_file(root / name) != listed[name]:
            mismatched.append(name)
    state = "VERIFIED" if not (unmanifested or missing or mismatched) else "INVALID"
    return {
        "state": state,
        "listed_files": len(listed_names),
        "actual_files": len(actual),
        "unmanifested": unmanifested,
        "listed_but_missing": missing,
        "checksum_mismatches": mismatched,
    }


def evaluate_artifact(root: Path, item: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": item["id"],
        "node_type": "artifact",
        "authority": item.get("authority", "SOFTWARE"),
        "state": "MISSING",
        "reasons": [],
        "path": item["path"],
    }
    try:
        path = project_path(root, item["path"], f"artifact {item['id']}.path")
        if not path.is_file():
            result["reasons"].append("artifact file is missing")
            return result
        if path.stat().st_nlink != 1:
            result["state"] = "INVALID"
            result["reasons"].append("artifact is hard-linked")
            return result
        observed = sha256_file(path)
        result["sha256"] = observed
        expected = item.get("sha256")
        if expected is not None and observed != expected:
            result["state"] = "INVALID"
            result["reasons"].append("artifact checksum mismatch")
            return result
        inventory = item.get("inventory")
        if inventory is not None:
            inv_root = project_path(
                root, inventory.get("root", ""), f"artifact {item['id']}.inventory.root"
            )
            manifest = project_path(
                root,
                inventory.get("manifest", item["path"]),
                f"artifact {item['id']}.inventory.manifest",
            )
            patterns = inventory.get("exclude", [])
            if not isinstance(patterns, list) or any(not isinstance(p, str) for p in patterns):
                raise GraceGraphError("inventory.exclude must be a list of strings")
            result["inventory"] = verify_inventory(inv_root, manifest, patterns)
            if result["inventory"]["state"] != "VERIFIED":
                result["state"] = "INVALID"
                result["reasons"].append("inventory is not exact")
                return result
        result["state"] = "VERIFIED"
        result["reasons"].append("content digest verified")
        return result
    except GraceGraphError as exc:
        result["state"] = "INVALID"
        result["reasons"].append(str(exc))
        return result
