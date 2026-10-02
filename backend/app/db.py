from __future__ import annotations
import sqlite3, json
from pathlib import Path
from threading import Lock

DB_PATH = Path("/app/data/aegis.db")
if not DB_PATH.parent.exists():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

class DB:
    def __init__(self):
        self.lock = Lock()
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.init()

    def init(self):
        with self.conn:
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                created_at TEXT,
                scenario TEXT,
                host TEXT,
                status TEXT,
                severity TEXT,
                confidence REAL,
                summary TEXT,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audits (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                actor TEXT,
                action TEXT,
                target TEXT,
                reason TEXT,
                result TEXT,
                incident_id TEXT,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS hosts (
                id TEXT PRIMARY KEY,
                name TEXT,
                ip TEXT,
                os TEXT,
                owner TEXT,
                status TEXT,
                risk REAL,
                last_seen TEXT,
                tags TEXT
            );
            CREATE TABLE IF NOT EXISTS iocs (
                id TEXT PRIMARY KEY,
                type TEXT,
                value TEXT,
                severity TEXT,
                source TEXT,
                confidence REAL,
                status TEXT
            );
            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                name TEXT,
                action TEXT,
                threshold REAL,
                enabled INTEGER,
                approval TEXT,
                description TEXT
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            """)

    def execute(self, sql, params=()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    def one(self, sql, params=()):
        row = self.execute(sql, params).fetchone()
        return dict(row) if row else None

    def all(self, sql, params=()):
        return [dict(x) for x in self.execute(sql, params).fetchall()]

db = DB()
