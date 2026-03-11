"""
SQLite-backed stores implementing storage interfaces.
"""
from __future__ import annotations
import sqlite3
from threading import Lock
from typing import List, Dict, Any, Callable
from cloud.storage.interfaces import EventStore, SignatureStore
from cloud.schemas import SignatureRule


class SQLiteEventStore(EventStore):
    def __init__(self, get_db: Callable[[], sqlite3.Connection], lock: Lock):
        self.get_db = get_db
        self.lock = lock

    def save_event(self, evt: Dict[str, Any]) -> None:
        db = self.get_db()
        with self.lock:
            db.execute("""
                INSERT INTO events(ts, agent_id, host, src_ip, dst_ip, url, protocol,
                                   bytes_sent, bytes_recv, region, category, alert, reason, detection_source)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                evt["ts"], evt["agent_id"], evt["host"], evt["src_ip"], evt["dst_ip"], evt["url"],
                evt["protocol"], evt["bytes_sent"], evt["bytes_recv"], evt["region"], evt["category"],
                evt["alert"], evt["reason"], evt["detection_source"]
            ))
            db.commit()


class SQLiteSignatureStore(SignatureStore):
    def __init__(self, get_db: Callable[[], sqlite3.Connection], lock: Lock):
        self.get_db = get_db
        self.lock = lock

    def fetch_all(self) -> List[SignatureRule]:
        db = self.get_db()
        rows = db.execute("SELECT id, type, pattern, severity, source FROM signatures ORDER BY id DESC").fetchall()
        return [SignatureRule(**dict(r)) for r in rows]

    def save(self, rule: SignatureRule) -> None:
        db = self.get_db()
        with self.lock:
            db.execute(
                "INSERT INTO signatures(type, pattern, severity, source) VALUES(?,?,?,?)",
                (rule.type, rule.pattern, rule.severity, rule.source)
            )
            db.commit()








