"""SQLite storage backend for MDRJ-DAG."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime
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
                    healthy INTEGER DEFAULT 1,
                    enabled INTEGER DEFAULT 1,
                    note TEXT DEFAULT '',
                    source TEXT DEFAULT 'runtime'
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_consensus ON events(consensus_ts);
                CREATE INDEX IF NOT EXISTS idx_events_cls ON events(cls);
                CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
                CREATE INDEX IF NOT EXISTS idx_edges_parent ON edges(parent_id);
                CREATE INDEX IF NOT EXISTS idx_edges_child ON edges(child_id);
                CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_at);
                """
            )
        self._ensure_peers_schema()

    def _ensure_peers_schema(self) -> None:
        columns = {
            row["name"] for row in self._conn.execute("PRAGMA table_info(peers)").fetchall()
        }
        with self._conn:
            if "enabled" not in columns:
                self._conn.execute("ALTER TABLE peers ADD COLUMN enabled INTEGER DEFAULT 1")
            if "note" not in columns:
                self._conn.execute("ALTER TABLE peers ADD COLUMN note TEXT DEFAULT ''")
            if "source" not in columns:
                self._conn.execute("ALTER TABLE peers ADD COLUMN source TEXT DEFAULT 'runtime'")

    def clear_events(self) -> None:
        """Remove all events, edges and envelopes from storage."""
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM events")
            self._conn.execute("DELETE FROM envelopes")
            self._conn.execute("DELETE FROM edges")
            self._conn.execute("DELETE FROM incidents")

    def list_incidents(self) -> List[Dict]:
        rows = self._conn.execute(
            "SELECT payload FROM incidents ORDER BY updated_at DESC, created_at DESC"
        ).fetchall()
        items: List[Dict] = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except Exception:
                continue
            if isinstance(payload, dict):
                items.append(payload)
        return items

    def replace_incidents(self, incidents: Sequence[Dict]) -> None:
        now = time.time()

        def _parse_iso(value: object, fallback: float) -> float:
            if not value:
                return fallback
            text = str(value).strip()
            if not text:
                return fallback
            try:
                return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
            except ValueError:
                return fallback

        with self._lock, self._conn:
            self._conn.execute("DELETE FROM incidents")
            for index, incident in enumerate(incidents):
                if not isinstance(incident, dict):
                    continue
                incident_id = str(incident.get("id") or "").strip()
                if not incident_id:
                    continue
                created_at = incident.get("createdAt")
                updated_at = incident.get("updatedAt")
                created_ts = now + index * 0.0001
                updated_ts = created_ts
                created_ts = _parse_iso(created_at, created_ts)
                updated_ts = _parse_iso(updated_at, created_ts)
                self._conn.execute(
                    "INSERT INTO incidents(id, payload, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (incident_id, canonical_json(incident), created_ts, updated_ts),
                )

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
                "INSERT INTO peers(address, last_seen, healthy, enabled, note, source) VALUES (?, ?, ?, 1, '', 'runtime')\n                 ON CONFLICT(address) DO UPDATE SET last_seen = excluded.last_seen, healthy = excluded.healthy",
                (address, last_seen, int(healthy)),
            )

    def ensure_peer(
        self,
        address: str,
        *,
        last_seen: Optional[float],
        healthy: bool,
        enabled: bool = True,
        note: str = "",
        source: str = "runtime",
    ) -> PeerInfo:
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT * FROM peers WHERE address = ?",
                (address,),
            ).fetchone()
            if existing:
                merged_last_seen = last_seen if last_seen is not None else existing["last_seen"]
                merged_healthy = int(healthy)
                merged_enabled = bool(existing["enabled"])
                merged_note = existing["note"] or note or ""
                merged_source = existing["source"] or source
                self._conn.execute(
                    "UPDATE peers SET last_seen = ?, healthy = ?, enabled = ?, note = ?, source = ? WHERE address = ?",
                    (
                        merged_last_seen,
                        merged_healthy,
                        int(merged_enabled),
                        merged_note,
                        merged_source,
                        address,
                    ),
                )
                return PeerInfo(
                    address=address,
                    last_seen=merged_last_seen,
                    healthy=bool(merged_healthy),
                    enabled=merged_enabled,
                    note=merged_note,
                    source=merged_source,
                )
            self._conn.execute(
                "INSERT INTO peers(address, last_seen, healthy, enabled, note, source) VALUES (?, ?, ?, ?, ?, ?)",
                (address, last_seen, int(healthy), int(enabled), note, source),
            )
            return PeerInfo(
                address=address,
                last_seen=last_seen,
                healthy=healthy,
                enabled=enabled,
                note=note,
                source=source,
            )

    def update_peer(
        self,
        address: str,
        *,
        enabled: Optional[bool] = None,
        note: Optional[str] = None,
        last_seen: Optional[float] = None,
        healthy: Optional[bool] = None,
    ) -> Optional[PeerInfo]:
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT * FROM peers WHERE address = ?",
                (address,),
            ).fetchone()
            if not existing:
                return None
            next_last_seen = existing["last_seen"] if last_seen is None else last_seen
            next_healthy = bool(existing["healthy"]) if healthy is None else healthy
            next_enabled = bool(existing["enabled"]) if enabled is None else enabled
            next_note = existing["note"] if note is None else note
            next_source = existing["source"] or "runtime"
            self._conn.execute(
                "UPDATE peers SET last_seen = ?, healthy = ?, enabled = ?, note = ?, source = ? WHERE address = ?",
                (next_last_seen, int(next_healthy), int(next_enabled), next_note, next_source, address),
            )
            return PeerInfo(
                address=address,
                last_seen=next_last_seen,
                healthy=next_healthy,
                enabled=next_enabled,
                note=next_note,
                source=next_source,
            )

    def delete_peer(self, address: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM peers WHERE address = ?", (address,))

    def list_peers(self) -> List[PeerInfo]:
        rows = self._conn.execute("SELECT * FROM peers").fetchall()
        peers: List[PeerInfo] = []
        for row in rows:
            peers.append(
                PeerInfo(
                    address=row["address"],
                    last_seen=row["last_seen"],
                    healthy=bool(row["healthy"]),
                    enabled=bool(row["enabled"]) if "enabled" in row.keys() else True,
                    note=(row["note"] if "note" in row.keys() else "") or "",
                    source=(row["source"] if "source" in row.keys() else "runtime") or "runtime",
                )
            )
        return peers
