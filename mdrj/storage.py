"""SQLite storage backend for MDRJ-DAG."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .models import Envelope, Event, EventClass, PeerInfo
from .utils import canonical_json, ensure_directory


class DAGStorage:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        ensure_directory(str(self.path))
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._initialize()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _initialize(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    cls TEXT NOT NULL,
                    source TEXT NOT NULL,
                    ts_local REAL NOT NULL,
                    vclock TEXT NOT NULL,
                    parents TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    sig TEXT,
                    consensus_ts REAL,
                    lamport_ts INTEGER,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS edges (
                    parent_id TEXT NOT NULL,
                    child_id TEXT NOT NULL,
                    UNIQUE(parent_id, child_id)
                );
                CREATE TABLE IF NOT EXISTS envelopes (
                    event_id TEXT PRIMARY KEY,
                    path_meta TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS peers (
                    address TEXT PRIMARY KEY,
                    last_seen REAL,
                    healthy INTEGER DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_events_consensus ON events(consensus_ts);
                CREATE INDEX IF NOT EXISTS idx_events_cls ON events(cls);
                CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
                CREATE INDEX IF NOT EXISTS idx_edges_parent ON edges(parent_id);
                CREATE INDEX IF NOT EXISTS idx_edges_child ON edges(child_id);
                """
            )

    def clear_events(self) -> None:
        """Remove all events, edges and envelopes from storage."""
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM events")
            self._conn.execute("DELETE FROM envelopes")
            self._conn.execute("DELETE FROM edges")

    def _merge_path_meta(self, event_id: str, new_path: Sequence[Dict]) -> None:
        existing = self._conn.execute(
            "SELECT path_meta FROM envelopes WHERE event_id = ?", (event_id,)
        ).fetchone()
        merged = []
        seen = set()
        if existing:
            for hop in json.loads(existing["path_meta"]):
                key = (hop.get("node"), hop.get("ts"))
                if key not in seen:
                    merged.append(hop)
                    seen.add(key)
        for hop in new_path:
            key = (hop.get("node"), hop.get("ts"))
            if key not in seen:
                merged.append(dict(hop))
                seen.add(key)
        self._conn.execute(
            "INSERT OR REPLACE INTO envelopes(event_id, path_meta) VALUES (?, ?)",
            (event_id, canonical_json(merged)),
        )

    def store_envelope(self, envelope: Envelope, consensus_ts: Optional[float]) -> bool:
        event = envelope.event
        with self._lock:
            cur = self._conn.execute("SELECT 1 FROM events WHERE id = ?", (event.id,))
            exists = cur.fetchone() is not None
            if exists:
                with self._conn:
                    self._merge_path_meta(event.id, envelope.path_meta)
                    if consensus_ts is not None:
                        self._conn.execute(
                            "UPDATE events SET consensus_ts = COALESCE(consensus_ts, ?) WHERE id = ?",
                            (consensus_ts, event.id),
                        )
                return False
            record = event.to_record()
            record["consensus_ts"] = consensus_ts
            record["created_at"] = time.time()
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO events(
                        id, cls, source, ts_local, vclock, parents, payload, sig, consensus_ts, lamport_ts, created_at
                    ) VALUES (:id, :cls, :source, :ts_local, :vclock, :parents, :payload, :sig, :consensus_ts, :lamport_ts, :created_at)
                    """,
                    record,
                )
                for parent in event.parents:
                    self._conn.execute(
                        "INSERT OR IGNORE INTO edges(parent_id, child_id) VALUES (?, ?)",
                        (parent, event.id),
                    )
                self._merge_path_meta(event.id, envelope.path_meta)
            return True

    def update_consensus(self, event_id: str, consensus_ts: float) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE events SET consensus_ts = ? WHERE id = ?",
                (consensus_ts, event_id),
            )

    def get_event(self, event_id: str) -> Optional[Event]:
        cur = self._conn.execute("SELECT * FROM events WHERE id = ?", (event_id,))
        row = cur.fetchone()
        if not row:
            return None
        return Event.from_record(row)

    def latest_event_by_source(self, source: str) -> Optional[Event]:
        row = self._conn.execute(
            "SELECT * FROM events WHERE source = ? ORDER BY created_at DESC LIMIT 1",
            (source,),
        ).fetchone()
        if not row:
            return None
        return Event.from_record(row)

    def list_recent_events(self, limit: int = 256) -> List[Event]:
        rows = self._conn.execute(
            "SELECT * FROM events ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [Event.from_record(row) for row in rows]

    def get_envelope(self, event_id: str) -> Optional[Envelope]:
        event = self.get_event(event_id)
        if not event:
            return None
        meta_row = self._conn.execute(
            "SELECT path_meta FROM envelopes WHERE event_id = ?", (event_id,)
        ).fetchone()
        path_meta = []
        if meta_row:
            path_meta = json.loads(meta_row["path_meta"])
        return Envelope(event=event, path_meta=path_meta)

    def list_events(self, limit: int = 100, newer_than: Optional[float] = None) -> List[Event]:
        query = "SELECT * FROM events"
        params: Tuple = ()
        if newer_than is not None:
            query += " WHERE created_at > ?"
            params = (newer_than,)
        query += " ORDER BY created_at ASC LIMIT ?"
        params = params + (limit,)
        rows = self._conn.execute(query, params).fetchall()
        return [Event.from_record(row) for row in rows]

    def all_events(self) -> List[Event]:
        rows = self._conn.execute("SELECT * FROM events ORDER BY created_at ASC").fetchall()
        return [Event.from_record(row) for row in rows]

    def all_edges(self) -> List[Tuple[str, str]]:
        rows = self._conn.execute("SELECT parent_id, child_id FROM edges").fetchall()
        return [(row["parent_id"], row["child_id"]) for row in rows]

    def get_frontier(self) -> List[Tuple[str, Dict[str, int]]]:
        sql = """
        SELECT e.id, e.vclock FROM events e
        LEFT JOIN edges ed ON e.id = ed.parent_id
        WHERE ed.parent_id IS NULL
        """
        rows = self._conn.execute(sql).fetchall()
        return [(row["id"], json.loads(row["vclock"])) for row in rows]

    def subdag_since(self, ts: float) -> List[Event]:
        rows = self._conn.execute(
            "SELECT * FROM events WHERE COALESCE(consensus_ts, ts_local) >= ?",
            (ts,),
        ).fetchall()
        return [Event.from_record(row) for row in rows]

    def toposort(self) -> List[str]:
        rows = self._conn.execute("SELECT id FROM events").fetchall()
        graph = {row["id"]: [] for row in rows}
        indegree = {node: 0 for node in graph}
        edge_rows = self._conn.execute("SELECT parent_id, child_id FROM edges").fetchall()
        for parent, child in edge_rows:
            if child in graph:
                graph[parent].append(child)
                indegree[child] += 1
        queue = [node for node, deg in indegree.items() if deg == 0]
        order: List[str] = []
        while queue:
            node = queue.pop(0)
            order.append(node)
            for child in graph.get(node, []):
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)
        if len(order) != len(graph):
            raise ValueError("cycle detected in DAG")
        return order

    def gc_by_quota(self, memory_mb: int) -> int:
        """Apply best-effort garbage collection. Returns number of events removed."""
        target_bytes = memory_mb * 1024 * 1024
        cur = self._conn.execute("SELECT SUM(LENGTH(payload)) FROM events")
        current = cur.fetchone()[0] or 0
        if current <= target_bytes:
            return 0
        to_delete = []
        rows = self._conn.execute(
            "SELECT id FROM events ORDER BY created_at ASC"
        ).fetchall()
        total = current
        for row in rows:
            if total <= target_bytes:
                break
            to_delete.append(row["id"])
            payload_len = self._conn.execute(
                "SELECT LENGTH(payload) FROM events WHERE id = ?",
                (row["id"],),
            ).fetchone()[0]
            total -= payload_len
        with self._conn:
            for event_id in to_delete:
                self._conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
                self._conn.execute("DELETE FROM envelopes WHERE event_id = ?", (event_id,))
                self._conn.execute("DELETE FROM edges WHERE child_id = ?", (event_id,))
                self._conn.execute("DELETE FROM edges WHERE parent_id = ?", (event_id,))
        return len(to_delete)

    def storage_usage_bytes(self) -> int:
        cur = self._conn.execute(
            "SELECT SUM(LENGTH(payload) + LENGTH(vclock) + LENGTH(parents)) FROM events"
        )
        return cur.fetchone()[0] or 0

    def event_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return row[0]

    def upsert_peer(self, address: str, last_seen: float, healthy: bool) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO peers(address, last_seen, healthy) VALUES (?, ?, ?)\n                 ON CONFLICT(address) DO UPDATE SET last_seen = excluded.last_seen, healthy = excluded.healthy",
                (address, last_seen, int(healthy)),
            )

    def list_peers(self) -> List[PeerInfo]:
        rows = self._conn.execute("SELECT * FROM peers").fetchall()
        peers: List[PeerInfo] = []
        for row in rows:
            peers.append(PeerInfo(address=row["address"], last_seen=row["last_seen"], healthy=bool(row["healthy"])) )
        return peers
