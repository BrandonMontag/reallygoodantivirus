from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from .config import DB_FILE, ensure_dirs
from .models import Detection

class Database:
    def __init__(self, path: Path = DB_FILE):
        ensure_dirs()
        self.path = path
        self._init()

    def _connect(self):
        return sqlite3.connect(self.path)

    def _init(self):
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detected_at TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    path TEXT,
                    verdict TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    sha256 TEXT,
                    size INTEGER,
                    reasons TEXT,
                    pid INTEGER,
                    process_name TEXT,
                    remote TEXT
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    target TEXT,
                    scanned INTEGER NOT NULL DEFAULT 0,
                    malicious INTEGER NOT NULL DEFAULT 0,
                    suspicious INTEGER NOT NULL DEFAULT 0,
                    errors INTEGER NOT NULL DEFAULT 0
                )
            """)

    def add_detection(self, d: Detection) -> None:
        with self._connect() as con:
            con.execute("""
                INSERT INTO detections
                (detected_at, kind, path, verdict, score, sha256, size, reasons, pid, process_name, remote)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                d.detected_at, d.kind, d.path, d.verdict, d.score, d.sha256, d.size,
                json.dumps(d.reasons), d.pid, d.process_name, d.remote
            ))

    def start_scan(self, target: str, started_at: str) -> int:
        with self._connect() as con:
            cur = con.execute(
                "INSERT INTO scan_history(started_at, target) VALUES (?, ?)",
                (started_at, target)
            )
            return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, finished_at: str, scanned: int,
                    malicious: int, suspicious: int, errors: int) -> None:
        with self._connect() as con:
            con.execute("""
                UPDATE scan_history
                SET finished_at=?, scanned=?, malicious=?, suspicious=?, errors=?
                WHERE id=?
            """, (finished_at, scanned, malicious, suspicious, errors, scan_id))

    def recent_detections(self, limit: int = 50) -> list[dict]:
        with self._connect() as con:
            rows = con.execute("""
                SELECT detected_at, kind, path, verdict, score, reasons, pid, process_name, remote
                FROM detections ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
        out = []
        for r in rows:
            out.append({
                "detected_at": r[0], "kind": r[1], "path": r[2], "verdict": r[3],
                "score": r[4], "reasons": json.loads(r[5] or "[]"),
                "pid": r[6], "process_name": r[7], "remote": r[8],
            })
        return out

    def latest_scan(self) -> dict | None:
        with self._connect() as con:
            row = con.execute("""
                SELECT started_at, finished_at, target, scanned, malicious, suspicious, errors
                FROM scan_history ORDER BY id DESC LIMIT 1
            """).fetchone()
        if not row:
            return None
        return {
            "started_at": row[0], "finished_at": row[1], "target": row[2],
            "scanned": row[3], "malicious": row[4], "suspicious": row[5], "errors": row[6],
        }
