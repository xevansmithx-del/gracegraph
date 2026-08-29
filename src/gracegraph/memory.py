"""Verification of append-only memory, recovery coverage, and replayability."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from .canonical import GraceGraphError, project_path, sha256_file

GENESIS = "0" * 64
STATE_TABLES = ("decisions", "lineages", "gates", "provenance", "corrections", "chats")
EVENT_REQUIRED_FIELDS = {
    "decision": {"id", "topic", "status", "detail", "source"},
    "lineage": {
        "id",
        "lane",
        "locus",
        "direction",
        "event",
        "status",
        "priority",
        "designed_count",
        "note",
    },
    "gate": {"lane", "gate", "state", "blocker"},
    "provenance": {"path", "sha256", "bytes", "source", "note"},
    "correction": {"id", "title", "verdict", "summary", "source"},
    "chat": {"id", "title", "purpose", "db_path"},
}


def _connect(path: Path, *, immutable: bool = False) -> sqlite3.Connection:
    uri = path.resolve().as_uri() + "?mode=ro"
    if immutable:
        uri += "&immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def verify_chain(path: Path, *, immutable: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "database": path.name,
        "state": "INVALID",
        "events": 0,
        "head_digest": GENESIS,
        "state_digest": None,
        "identity": path.name,
        "projection_gaps": [],
    }
    try:
        if path.is_symlink() or not path.is_file():
            raise GraceGraphError("memory database must be a regular non-symlink file")
        if path.stat().st_nlink != 1:
            raise GraceGraphError("memory database must not be hard-linked")
        conn = _connect(path, immutable=immutable)
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise GraceGraphError(f"integrity_check={integrity}")
            triggers = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
            }
            missing_triggers = {"events_no_update", "events_no_delete"} - triggers
            if missing_triggers:
                raise GraceGraphError(f"missing append-only triggers: {sorted(missing_triggers)}")
            tables = {
                row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            missing_tables = (set(STATE_TABLES) | {"events", "metadata"}) - tables
            if missing_tables:
                raise GraceGraphError(f"missing table(s): {sorted(missing_tables)}")
            previous = GENESIS
            identity_row = conn.execute("SELECT value FROM metadata WHERE key='chat_id'").fetchone()
            result["identity"] = identity_row[0] if identity_row else path.name
            projected_types: set[str] = set()
            projections: dict[str, dict[tuple[Any, ...], dict[str, Any]]] = {
                table: {} for table in STATE_TABLES
            }
            projection_contracts = {
                "decision": ("decisions", ("id",), ("id", "topic", "status", "detail", "source")),
                "lineage": (
                    "lineages",
                    ("id",),
                    (
                        "id",
                        "lane",
                        "locus",
                        "direction",
                        "event",
                        "status",
                        "priority",
                        "designed_count",
                        "note",
                    ),
                ),
                "gate": ("gates", ("lane", "gate"), ("lane", "gate", "state", "blocker")),
                "provenance": (
                    "provenance",
                    ("path", "sha256"),
                    ("path", "sha256", "bytes", "source", "note"),
                ),
                "correction": (
                    "corrections",
                    ("id",),
                    ("id", "title", "verdict", "summary", "source"),
                ),
                "chat": ("chats", ("id",), ("id", "title", "purpose", "db_path")),
            }
            expected_seq = 1
            for row in conn.execute("SELECT * FROM events ORDER BY seq"):
                if row["seq"] != expected_seq:
                    raise GraceGraphError(
                        f"event sequence is not contiguous: expected {expected_seq}, got {row['seq']}"
                    )
                payload = json.loads(row["payload_json"])
                canonical = json.dumps(
                    payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                )
                if canonical != row["payload_json"]:
                    raise GraceGraphError(f"event {row['seq']} has noncanonical payload")
                material = "\n".join(
                    [
                        previous,
                        row["ts"],
                        row["chat"] or "",
                        row["type"],
                        row["subject"] or "",
                        canonical,
                    ]
                )
                digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
                if row["prev_digest"] != previous or row["digest"] != digest:
                    raise GraceGraphError(f"event {row['seq']} breaks the digest chain")
                if row["event_id"] != digest[:16]:
                    raise GraceGraphError(f"event {row['seq']} has invalid event_id")
                required = EVENT_REQUIRED_FIELDS.get(row["type"])
                if required is not None:
                    projected_types.add(row["type"])
                    missing = sorted(required - set(payload))
                    if missing:
                        result["projection_gaps"].append(
                            {"seq": row["seq"], "type": row["type"], "missing": missing}
                        )
                    else:
                        table, keys, fields = projection_contracts[row["type"]]
                        identity = tuple(payload[key] for key in keys)
                        projections[table][identity] = {field: payload[field] for field in fields}
                previous = digest
                result["events"] += 1
                expected_seq += 1
            logical_state: dict[str, Any] = {
                "metadata": [
                    dict(row) for row in conn.execute("SELECT key,value FROM metadata ORDER BY key")
                ],
                "application_id": conn.execute("PRAGMA application_id").fetchone()[0],
                "user_version": conn.execute("PRAGMA user_version").fetchone()[0],
            }
            for table in STATE_TABLES:
                count = conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                event_type = table[:-1] if table.endswith("s") else table
                if count and event_type not in projected_types:
                    result["projection_gaps"].append(
                        {"table": table, "rows": count, "reason": "no replayable event type"}
                    )
                contract = next(
                    value for value in projection_contracts.values() if value[0] == table
                )
                _table_name, keys, fields = contract
                actual: dict[tuple[Any, ...], dict[str, Any]] = {}
                for current in conn.execute(f"SELECT {','.join(fields)} FROM {table}"):
                    current_dict = dict(current)
                    actual[tuple(current_dict[key] for key in keys)] = current_dict
                logical_state[table] = sorted(
                    actual.values(),
                    key=lambda value: json.dumps(
                        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                    ),
                )
                if projections[table] != actual:
                    result["projection_gaps"].append(
                        {
                            "table": table,
                            "reason": "event replay differs from materialized state",
                            "projected_rows": len(projections[table]),
                            "materialized_rows": len(actual),
                        }
                    )
            result["head_digest"] = previous
            result["state_digest"] = hashlib.sha256(
                json.dumps(
                    logical_state, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode("utf-8")
            ).hexdigest()
            result["state"] = "VERIFIED"
        finally:
            conn.close()
    except (sqlite3.Error, json.JSONDecodeError, GraceGraphError, OSError) as exc:
        result["error"] = str(exc)
    return result


def _verify_backup_manifest(backup: Path) -> dict[str, Any]:
    manifest = backup / "SHA256SUMS.txt"
    if not manifest.is_file() or manifest.is_symlink() or manifest.stat().st_nlink != 1:
        return {"state": "MISSING", "reason": "backup manifest missing", "files": []}
    listed: dict[str, str] = {}
    try:
        for number, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
            if not raw.strip():
                continue
            parts = raw.split(maxsplit=1)
            if len(parts) != 2:
                raise GraceGraphError(f"manifest line {number} malformed")
            digest, name = parts
            name = name.lstrip("*")
            if name.startswith("./"):
                name = name[2:]
            if Path(name).name != name or len(digest) != 64:
                raise GraceGraphError(f"manifest line {number} unsafe")
            if name in listed:
                raise GraceGraphError(f"manifest line {number} duplicate")
            listed[name] = digest
        candidates = [path for path in backup.iterdir() if path.name != manifest.name]
        if any(path.is_symlink() or not path.is_file() for path in candidates):
            raise GraceGraphError("backup members must be regular non-symlink files")
        if any(path.stat().st_nlink != 1 for path in candidates):
            raise GraceGraphError("backup members must not be hard-linked")
        actual = {path.name for path in candidates}
        if set(listed) != actual:
            raise GraceGraphError(
                f"backup inventory mismatch: unmanifested={sorted(actual - set(listed))}; "
                f"missing={sorted(set(listed) - actual)}"
            )
        mismatches = [
            name for name, digest in sorted(listed.items()) if sha256_file(backup / name) != digest
        ]
        if mismatches:
            raise GraceGraphError(f"backup checksum mismatch: {mismatches}")
        return {"state": "VERIFIED", "files": sorted(actual)}
    except (OSError, UnicodeError, GraceGraphError) as exc:
        return {"state": "INVALID", "reason": str(exc), "files": sorted(listed)}


def evaluate_memory(root: Path, item: dict[str, Any]) -> list[dict[str, Any]]:
    base_id = item["id"]
    directory = project_path(root, item["directory"], f"memory {base_id}.directory")
    chain_node: dict[str, Any] = {
        "id": f"{base_id}:chains",
        "node_type": "memory_chains",
        "authority": "SOFTWARE",
        "state": "MISSING",
        "reasons": [],
        "databases": [],
    }
    backup_node: dict[str, Any] = {
        "id": f"{base_id}:backup",
        "node_type": "memory_backup",
        "authority": "SOFTWARE",
        "state": "MISSING",
        "reasons": [],
    }
    anchor_node: dict[str, Any] = {
        "id": f"{base_id}:anchor",
        "node_type": "memory_external_checkpoint",
        "authority": "SOFTWARE",
        "state": "HOLD",
        "reasons": [],
    }
    projection_node: dict[str, Any] = {
        "id": f"{base_id}:projection",
        "node_type": "memory_projection",
        "authority": "SOFTWARE",
        "state": "HOLD",
        "reasons": [],
        "gaps": [],
    }
    summary_node: dict[str, Any] = {
        "id": base_id,
        "node_type": "memory",
        "authority": "SOFTWARE",
        "state": "HOLD",
        "reasons": [],
        "requires": [
            f"{base_id}:chains",
            f"{base_id}:anchor",
            f"{base_id}:backup",
            f"{base_id}:projection",
        ],
    }
    if not directory.is_dir():
        for node in (chain_node, anchor_node, backup_node, projection_node, summary_node):
            node["reasons"].append("memory directory is missing")
        return [chain_node, anchor_node, backup_node, projection_node, summary_node]

    databases = sorted(directory.glob("*.sqlite"))
    chain_results = [verify_chain(path) for path in databases]
    chain_node["databases"] = chain_results
    if databases and all(result["state"] == "VERIFIED" for result in chain_results):
        chain_node["state"] = "VERIFIED"
        chain_node["reasons"].append("all live database chains are valid")
    else:
        chain_node["state"] = "INVALID" if databases else "MISSING"
        chain_node["reasons"].append("one or more live database chains are unavailable")

    expected_heads = item.get("expected_heads", {})
    observed_heads = {
        result["database"]: {
            "identity": result["identity"],
            "events": result["events"],
            "head_digest": result["head_digest"],
        }
        for result in chain_results
        if result["state"] == "VERIFIED"
    }
    anchor_node["expected_databases"] = sorted(expected_heads)
    anchor_node["observed_databases"] = sorted(observed_heads)
    if expected_heads and expected_heads == observed_heads:
        anchor_node["state"] = "VERIFIED"
        anchor_node["reasons"].append("live memory exactly matches the external checkpoint")
    else:
        anchor_node["reasons"].append(
            "external expected heads are absent, stale, or do not cover the exact database inventory"
        )

    gaps = [
        {"database": result["database"], **gap}
        for result in chain_results
        for gap in result.get("projection_gaps", [])
    ]
    projection_node["gaps"] = gaps
    if not gaps and databases:
        projection_node["state"] = "VERIFIED"
        projection_node["reasons"].append("all materialized state has replay-complete events")
    else:
        projection_node["state"] = "HOLD"
        projection_node["reasons"].append(
            "event chains do not fully prove reconstruction of materialized state"
        )

    backup_root = directory / "backups"
    candidates = (
        sorted(
            path
            for path in backup_root.iterdir()
            if path.is_dir() and (path / "SHA256SUMS.txt").is_file()
        )
        if backup_root.is_dir()
        else []
    )
    if candidates:
        backup = candidates[-1]
        backup_result = _verify_backup_manifest(backup)
        backup_node["backup_id"] = backup.name
        backup_node["manifest"] = backup_result
        live_names = {path.name for path in databases}
        backup_names = {path.name for path in backup.glob("*.sqlite")}
        backup_node["live_databases"] = sorted(live_names)
        backup_node["backed_up_databases"] = sorted(backup_names)
        exact = backup_result["state"] == "VERIFIED" and live_names == backup_names
        if exact:
            for path in databases:
                live = verify_chain(path)
                sealed = verify_chain(backup / path.name, immutable=True)
                if (
                    live["state"] != "VERIFIED"
                    or sealed["state"] != "VERIFIED"
                    or live["events"] != sealed["events"]
                    or live["head_digest"] != sealed["head_digest"]
                    or live["identity"] != sealed["identity"]
                    or live["state_digest"] != sealed["state_digest"]
                ):
                    exact = False
                    break
            if exact:
                recovery_checks: list[dict[str, Any]] = []
                for mapping in item.get("recovery_files", []):
                    live_file = project_path(
                        root, mapping["live"], f"memory {base_id}.recovery_files.live"
                    )
                    backup_name = Path(mapping["backup"])
                    if backup_name.name != mapping["backup"] or backup_name.is_absolute():
                        raise GraceGraphError("backup recovery-file name must be flat")
                    sealed_file = backup / backup_name
                    matched = (
                        live_file.is_file()
                        and sealed_file.is_file()
                        and sha256_file(live_file) == sha256_file(sealed_file)
                    )
                    recovery_checks.append({"backup": mapping["backup"], "matched": matched})
                    if not matched:
                        exact = False
                backup_node["recovery_files"] = recovery_checks
        backup_node["state"] = "VERIFIED" if exact else "STALE"
        backup_node["reasons"].append(
            "latest backup exactly covers live memory"
            if exact
            else "latest backup is stale or incomplete"
        )
    else:
        backup_node["reasons"].append("no sealed backup found")

    component_states = {
        chain_node["state"],
        anchor_node["state"],
        backup_node["state"],
        projection_node["state"],
    }
    summary_node["state"] = "VERIFIED" if component_states == {"VERIFIED"} else "HOLD"
    summary_node["reasons"].append(
        "memory is chain-valid, recovery-complete, and replay-complete"
        if summary_node["state"] == "VERIFIED"
        else "memory remains bounded by at least one unresolved integrity dimension"
    )
    return [chain_node, anchor_node, backup_node, projection_node, summary_node]
