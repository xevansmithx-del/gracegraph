from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path

import pytest

DDL = """
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  ts TEXT NOT NULL,
  chat TEXT,
  type TEXT NOT NULL,
  subject TEXT,
  payload_json TEXT NOT NULL,
  prev_digest TEXT NOT NULL,
  digest TEXT NOT NULL UNIQUE
);
CREATE TRIGGER events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TABLE decisions (id TEXT PRIMARY KEY, topic TEXT, status TEXT, detail TEXT, source TEXT, updated_at TEXT);
CREATE TABLE lineages (id TEXT PRIMARY KEY, lane TEXT, locus TEXT, direction TEXT, event TEXT, status TEXT, priority TEXT, designed_count INTEGER, note TEXT, updated_at TEXT);
CREATE TABLE gates (lane TEXT, gate TEXT, state TEXT, blocker TEXT, updated_at TEXT, PRIMARY KEY(lane, gate));
CREATE TABLE provenance (path TEXT, sha256 TEXT, bytes INTEGER, source TEXT, note TEXT, recorded_at TEXT, PRIMARY KEY(path, sha256));
CREATE TABLE corrections (id TEXT PRIMARY KEY, title TEXT, verdict TEXT, summary TEXT, source TEXT, recorded_at TEXT);
CREATE TABLE chats (id TEXT PRIMARY KEY, title TEXT, purpose TEXT, db_path TEXT, registered_at TEXT);
"""


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def add_event(
    conn: sqlite3.Connection,
    event_type: str,
    subject: str,
    payload: dict,
    *,
    chat: str = "test",
) -> str:
    previous_row = conn.execute("SELECT digest FROM events ORDER BY seq DESC LIMIT 1").fetchone()
    previous = previous_row[0] if previous_row else "0" * 64
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    timestamp = (
        f"2026-01-01T00:00:{conn.execute('SELECT count(*) FROM events').fetchone()[0]:02d}.000000Z"
    )
    material = "\n".join([previous, timestamp, chat, event_type, subject, body])
    digest = hashlib.sha256(material.encode()).hexdigest()
    conn.execute(
        "INSERT INTO events(event_id,ts,chat,type,subject,payload_json,prev_digest,digest) VALUES(?,?,?,?,?,?,?,?)",
        (digest[:16], timestamp, chat, event_type, subject, body, previous, digest),
    )
    return digest


def make_memory(
    directory: Path, *, projection_gap: bool = False, stale_backup: bool = False
) -> Path:
    directory.mkdir(parents=True)
    db = directory / "program.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript(DDL)
    conn.execute("INSERT INTO metadata VALUES('chat_id','program')")
    if projection_gap:
        conn.execute(
            "INSERT INTO decisions VALUES(?,?,?,?,?,?)",
            ("D1", "topic", "OPEN", "detail", "source", "2026-01-01T00:00:00Z"),
        )
        add_event(conn, "decision", "D1", {"id": "D1", "status": "OPEN"})
    else:
        conn.execute(
            "INSERT INTO decisions VALUES(?,?,?,?,?,?)",
            ("D1", "topic", "OPEN", None, None, "2026-01-01T00:00:00Z"),
        )
        add_event(
            conn,
            "decision",
            "D1",
            {"id": "D1", "topic": "topic", "status": "OPEN", "detail": None, "source": None},
        )
    conn.commit()
    conn.close()
    backup = directory / "backups" / "20260101T000000Z"
    backup.mkdir(parents=True)
    shutil.copy2(db, backup / db.name)
    (backup / "NOTE.txt").write_text("recovery\n", encoding="utf-8")
    manifest_lines = [
        f"{file_sha(backup / 'NOTE.txt')}  NOTE.txt",
        f"{file_sha(backup / db.name)}  {db.name}",
    ]
    (backup / "SHA256SUMS.txt").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    if stale_backup:
        conn = sqlite3.connect(db)
        add_event(conn, "note", "later", {"later": True})
        conn.commit()
        conn.close()
    return db


@pytest.fixture
def basic_spec() -> dict:
    return {
        "schema_version": "gracegraph.spec.v1",
        "project_id": "test-project",
        "claim_ceiling": "COMPUTATIONAL",
        "artifacts": [],
        "memory_sources": [],
        "claims": [],
        "actions": [],
        "nonclaims": ["No biological conclusion."],
    }
