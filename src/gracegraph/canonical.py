"""Canonical serialization, hashing, and safe project-path helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 4 * 1024 * 1024


class GraceGraphError(ValueError):
    """A fail-closed validation error."""


def canonical_bytes(value: Any) -> bytes:
    """Return strict, deterministic UTF-8 JSON with no insignificant bytes."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise GraceGraphError(f"value is not canonical-JSON serializable: {exc}") from exc


def write_canonical(path: Path, value: Any) -> None:
    path.write_bytes(canonical_bytes(value) + b"\n")


def read_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise GraceGraphError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        if path.is_symlink() or not path.is_file():
            raise GraceGraphError(f"JSON input must be a regular non-symlink file: {path.name}")
        information = path.stat()
        if information.st_nlink != 1:
            raise GraceGraphError(f"JSON input must not be hard-linked: {path.name}")
        if information.st_size > MAX_JSON_BYTES:
            raise GraceGraphError(f"JSON input exceeds {MAX_JSON_BYTES} bytes: {path.name}")
        raw = path.read_bytes()
        if len(raw) != information.st_size:
            raise GraceGraphError(f"JSON input changed while reading: {path.name}")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except GraceGraphError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GraceGraphError(f"cannot read JSON {path.name}: {exc}") from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise GraceGraphError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def require_relative(value: str, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise GraceGraphError(f"{field} must be a nonempty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise GraceGraphError(f"{field} must stay inside the project root")
    return path


def project_path(root: Path, value: str, field: str) -> Path:
    """Resolve a relative path inside root and reject every symlink component."""

    relative = require_relative(value, field)
    candidate = root / relative
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise GraceGraphError(f"{field} traverses a symlink: {relative.as_posix()}")
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise GraceGraphError(f"{field} escapes the project root") from exc
    return candidate


def unique_ids(items: list[dict[str, Any]], field: str) -> None:
    seen: set[str] = set()
    for index, item in enumerate(items):
        identity = item.get("id")
        if not isinstance(identity, str) or not identity:
            raise GraceGraphError(f"{field}[{index}].id must be a nonempty string")
        if identity in seen:
            raise GraceGraphError(f"duplicate {field} id: {identity}")
        seen.add(identity)
