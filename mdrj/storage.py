"""SQLite storage backend for MDRJ-DAG."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .models import (
    NODE_ROLE_NODE,
    PEER_APPROVAL_APPROVED,
    Envelope,
    Event,
    EventClass,
    PeerInfo,
    normalize_approval_status,
    normalize_node_role,
)
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
                    creator TEXT,
                    ts_local REAL NOT NULL,
                    vclock TEXT NOT NULL,
                    parents TEXT NOT NULL,
                    self_parent_id TEXT,
                    other_parent_id TEXT,
                    payload TEXT NOT NULL,
                    sig TEXT,
                    consensus_ts REAL,
                    lamport_ts INTEGER,
                    round INTEGER,
                    round_received INTEGER,
                    is_witness INTEGER DEFAULT 0,
                    is_famous_witness INTEGER DEFAULT 0,
                    fame_decided INTEGER DEFAULT 0,
                    fame_decision_round INTEGER,
                    fame_decision_kind TEXT DEFAULT 'pending',
                    fame_needs_coin INTEGER DEFAULT 0,
                    fame_coin_used INTEGER DEFAULT 0,
                    fame_coin_round INTEGER,
                    fame_vote_round INTEGER,
                    fame_vote_yes INTEGER DEFAULT 0,
                    fame_vote_no INTEGER DEFAULT 0,
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
                    node_id TEXT DEFAULT '',
                    last_seen REAL,
                    healthy INTEGER DEFAULT 1,
                    enabled INTEGER DEFAULT 1,
                    note TEXT DEFAULT '',
                    source TEXT DEFAULT 'runtime',
                    role TEXT DEFAULT 'node',
                    approval_status TEXT DEFAULT 'approved'
                );
                CREATE TABLE IF NOT EXISTS consensus_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS metrics_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    snapshot_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS checkpoints (
                    round_received INTEGER PRIMARY KEY,
                    merkle_root TEXT NOT NULL,
                    members_snapshot_hash TEXT NOT NULL,
                    signatures_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    confirmed_at REAL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS event_skeletons (
                    id TEXT PRIMARY KEY,
                    cls TEXT NOT NULL,
                    parent_ids TEXT NOT NULL,
                    round_received INTEGER,
                    payload_hash TEXT NOT NULL,
                    archived_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_consensus ON events(consensus_ts);
                CREATE INDEX IF NOT EXISTS idx_events_cls ON events(cls);
                CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
                CREATE INDEX IF NOT EXISTS idx_edges_parent ON edges(parent_id);
                CREATE INDEX IF NOT EXISTS idx_edges_child ON edges(child_id);
                CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_at);
                CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics_history(ts);
                """
            )
        self._ensure_peers_schema()
        self._ensure_events_schema()

    def _ensure_peers_schema(self) -> None:
        columns = {
            row["name"] for row in self._conn.execute("PRAGMA table_info(peers)").fetchall()
        }
        with self._conn:
            if "node_id" not in columns:
                self._conn.execute("ALTER TABLE peers ADD COLUMN node_id TEXT DEFAULT ''")
            if "enabled" not in columns:
                self._conn.execute("ALTER TABLE peers ADD COLUMN enabled INTEGER DEFAULT 1")
            if "note" not in columns:
                self._conn.execute("ALTER TABLE peers ADD COLUMN note TEXT DEFAULT ''")
            if "source" not in columns:
                self._conn.execute("ALTER TABLE peers ADD COLUMN source TEXT DEFAULT 'runtime'")
            if "role" not in columns:
                self._conn.execute(f"ALTER TABLE peers ADD COLUMN role TEXT DEFAULT '{NODE_ROLE_NODE}'")
            if "approval_status" not in columns:
                self._conn.execute("ALTER TABLE peers ADD COLUMN approval_status TEXT DEFAULT 'approved'")
            self._conn.execute(
                "UPDATE peers SET role = ? WHERE role IS NULL OR TRIM(role) = ''",
                (NODE_ROLE_NODE,),
            )
            self._conn.execute(
                "UPDATE peers SET role = ? WHERE LOWER(TRIM(COALESCE(role, ''))) NOT IN ('node', 'responder')",
                (NODE_ROLE_NODE,),
            )
            self._conn.execute(
                "UPDATE peers SET approval_status = 'approved' WHERE approval_status IS NULL OR TRIM(approval_status) = ''"
            )

    def _ensure_events_schema(self) -> None:
        columns = {
            row["name"] for row in self._conn.execute("PRAGMA table_info(events)").fetchall()
        }
        with self._conn:
            if "creator" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN creator TEXT")
            if "self_parent_id" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN self_parent_id TEXT")
            if "other_parent_id" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN other_parent_id TEXT")
            if "round" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN round INTEGER")
            if "round_received" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN round_received INTEGER")
            if "is_witness" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN is_witness INTEGER DEFAULT 0")
            if "is_famous_witness" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN is_famous_witness INTEGER DEFAULT 0")
            if "fame_decided" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN fame_decided INTEGER DEFAULT 0")
            if "fame_decision_round" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN fame_decision_round INTEGER")
            if "fame_decision_kind" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN fame_decision_kind TEXT DEFAULT 'pending'")
            if "fame_needs_coin" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN fame_needs_coin INTEGER DEFAULT 0")
            if "fame_coin_used" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN fame_coin_used INTEGER DEFAULT 0")
            if "fame_coin_round" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN fame_coin_round INTEGER")
            if "fame_vote_round" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN fame_vote_round INTEGER")
            if "fame_vote_yes" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN fame_vote_yes INTEGER DEFAULT 0")
            if "fame_vote_no" not in columns:
                self._conn.execute("ALTER TABLE events ADD COLUMN fame_vote_no INTEGER DEFAULT 0")
            self._conn.execute(
                "UPDATE events SET fame_decision_kind = 'pending' WHERE fame_decision_kind IS NULL OR TRIM(fame_decision_kind) = ''"
            )
            self._conn.execute(
                "UPDATE events SET fame_decision_kind = 'pending' WHERE LOWER(TRIM(COALESCE(fame_decision_kind, ''))) NOT IN ('pending', 'vote', 'coin_surrogate')"
            )
            self._conn.execute("UPDATE events SET creator = source WHERE creator IS NULL OR TRIM(creator) = ''")
            self._conn.execute(
                "UPDATE events SET self_parent_id = json_extract(parents, '$[0]') WHERE self_parent_id IS NULL"
            )
            self._conn.execute(
                "UPDATE events SET other_parent_id = json_extract(parents, '$[1]') WHERE other_parent_id IS NULL"
            )

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
                            "UPDATE events SET consensus_ts = COALESCE(consensus_ts, ?), creator = COALESCE(creator, ?), self_parent_id = COALESCE(self_parent_id, ?), other_parent_id = COALESCE(other_parent_id, ?) WHERE id = ?",
                            (consensus_ts, event.creator, event.self_parent_id, event.other_parent_id, event.id),
                        )
                return False
            record = event.to_record()
            record["consensus_ts"] = consensus_ts
            record["created_at"] = time.time()
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO events(
                        id, cls, source, creator, ts_local, vclock, parents, self_parent_id, other_parent_id, payload, sig, consensus_ts, lamport_ts, round, round_received, is_witness, created_at
                    ) VALUES (:id, :cls, :source, :creator, :ts_local, :vclock, :parents, :self_parent_id, :other_parent_id, :payload, :sig, :consensus_ts, :lamport_ts, :round, :round_received, :is_witness, :created_at)
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

    def replace_consensus_state(self, states: Sequence[Dict[str, object]]) -> None:
        with self._lock, self._conn:
            for state in states:
                self._conn.execute(
                    """
                    UPDATE events
                    SET consensus_ts = ?,
                        round = ?,
                        round_received = ?,
                        is_witness = ?,
                        is_famous_witness = ?,
                        fame_decided = ?,
                        fame_decision_round = ?,
                        fame_decision_kind = ?,
                        fame_needs_coin = ?,
                        fame_coin_used = ?,
                        fame_coin_round = ?,
                        fame_vote_round = ?,
                        fame_vote_yes = ?,
                        fame_vote_no = ?,
                        creator = COALESCE(creator, ?),
                        self_parent_id = COALESCE(self_parent_id, ?),
                        other_parent_id = COALESCE(other_parent_id, ?)
                    WHERE id = ?
                    """,
                    (
                        state.get("consensus_ts"),
                        state.get("round"),
                        state.get("round_received"),
                        int(bool(state.get("is_witness", False))),
                        int(bool(state.get("is_famous_witness", False))),
                        int(bool(state.get("fame_decided", False))),
                        state.get("fame_decision_round"),
                        str(state.get("fame_decision_kind") or "pending"),
                        int(bool(state.get("fame_needs_coin", False))),
                        int(bool(state.get("fame_coin_used", False))),
                        state.get("fame_coin_round"),
                        state.get("fame_vote_round"),
                        int(state.get("fame_vote_yes", 0) or 0),
                        int(state.get("fame_vote_no", 0) or 0),
                        state.get("creator"),
                        state.get("self_parent_id"),
                        state.get("other_parent_id"),
                        state["event_id"],
                    ),
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
            path_meta = json.loads(meta_row["path_meta"] or "[]")
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
            if parent in graph and child in graph:
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

    def prune_under_checkpoint(
        self,
        *,
        confirmed_round: int,
        max_age_seconds: float,
        keep_class_a: bool,
        now: float,
    ) -> List[Dict[str, object]]:
        """Move events covered by a confirmed checkpoint to event_skeletons.

        Safety contract:
          - Only events with `round_received <= confirmed_round` are eligible.
          - Class A events are kept in hot storage if `keep_class_a` is True.
          - Events younger than `max_age_seconds` are kept (gives operators time
            to inspect recent incidents in full).
          - For every pruned event, an `event_skeleton` is recorded with
            (id, cls, parent_ids, round_received, payload_hash) — causal
            chain remains verifiable.

        Returns a list of pruned-event records (full payload included) so the
        caller can optionally write them to a cold archive file before they
        are removed from hot storage.
        """
        age_threshold = now - max_age_seconds
        rows = self._conn.execute(
            "SELECT id, cls, source, creator, ts_local, vclock, parents, "
            "self_parent_id, other_parent_id, payload, sig, consensus_ts, "
            "lamport_ts, round, round_received, created_at "
            "FROM events "
            "WHERE round_received IS NOT NULL "
            "  AND round_received <= ? "
            "  AND created_at < ? "
            + ("  AND cls != 'A' " if keep_class_a else "")
            + "ORDER BY round_received ASC",
            (int(confirmed_round), float(age_threshold)),
        ).fetchall()
        pruned: List[Dict[str, object]] = []
        with self._lock, self._conn:
            for row in rows:
                payload_text = row["payload"]
                payload_hash = hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
                self._conn.execute(
                    "INSERT OR REPLACE INTO event_skeletons(id, cls, parent_ids, round_received, payload_hash, archived_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        row["id"],
                        row["cls"],
                        row["parents"],
                        row["round_received"],
                        payload_hash,
                        now,
                    ),
                )
                pruned.append(
                    {
                        "id": row["id"],
                        "cls": row["cls"],
                        "source": row["source"],
                        "creator": row["creator"],
                        "ts_local": row["ts_local"],
                        "vclock": json.loads(row["vclock"]),
                        "parents": json.loads(row["parents"]),
                        "self_parent_id": row["self_parent_id"],
                        "other_parent_id": row["other_parent_id"],
                        "payload": json.loads(row["payload"]),
                        "sig": row["sig"],
                        "consensus_ts": row["consensus_ts"],
                        "lamport_ts": row["lamport_ts"],
                        "round": row["round"],
                        "round_received": row["round_received"],
                        "payload_hash": payload_hash,
                    }
                )
                self._conn.execute("DELETE FROM events WHERE id = ?", (row["id"],))
                self._conn.execute("DELETE FROM envelopes WHERE event_id = ?", (row["id"],))
                # NB: edges are intentionally preserved so that surviving
                # children still reference their pruned parents through
                # event_skeletons. This is critical for causal-chain replay.
        return pruned

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

    def db_size_bytes(self) -> int:
        """Return current SQLite database file size including WAL pages."""
        try:
            page_count = self._conn.execute("PRAGMA page_count").fetchone()[0]
            page_size = self._conn.execute("PRAGMA page_size").fetchone()[0]
            return int(page_count) * int(page_size)
        except Exception:
            return 0

    def append_metrics_snapshot(self, ts: float, snapshot_json: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO metrics_history(ts, snapshot_json) VALUES (?, ?)",
                (float(ts), snapshot_json),
            )

    def list_metrics_history(self, *, limit: int = 1000, since_ts: float = 0.0) -> List[dict]:
        rows = self._conn.execute(
            "SELECT ts, snapshot_json FROM metrics_history WHERE ts >= ? ORDER BY ts ASC LIMIT ?",
            (float(since_ts), int(limit)),
        ).fetchall()
        return [{"ts": float(row["ts"]), "snapshot": json.loads(row["snapshot_json"])} for row in rows]

    def prune_metrics_history(self, *, keep_last: int) -> int:
        """Keep only the last `keep_last` rows, drop everything older."""
        if keep_last <= 0:
            return 0
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM metrics_history WHERE id NOT IN ("
                "SELECT id FROM metrics_history ORDER BY ts DESC LIMIT ?)",
                (int(keep_last),),
            )
            return cur.rowcount or 0

    # ------------------------------------------------------------------
    # Users (Этап 5)
    def upsert_user(self, *, username: str, password_hash: str, role: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash, role = excluded.role",
                (username, password_hash, role, time.time()),
            )

    def get_user(self, username: str) -> Optional[Dict[str, object]]:
        row = self._conn.execute(
            "SELECT username, password_hash, role, created_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row:
            return None
        return {
            "username": row["username"],
            "password_hash": row["password_hash"],
            "role": row["role"],
            "created_at": float(row["created_at"]),
        }

    def list_users(self) -> List[Dict[str, object]]:
        rows = self._conn.execute(
            "SELECT username, role, created_at FROM users ORDER BY username"
        ).fetchall()
        return [
            {"username": row["username"], "role": row["role"], "created_at": float(row["created_at"])}
            for row in rows
        ]

    def delete_user(self, username: str) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM users WHERE username = ?", (username,))
            return (cur.rowcount or 0) > 0

    def users_count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    # ------------------------------------------------------------------
    # Checkpoints (Этап 3)
    def upsert_checkpoint(
        self,
        *,
        round_received: int,
        merkle_root: str,
        members_snapshot_hash: str,
        signatures: Dict[str, str],
        status: str,
        confirmed_at: Optional[float] = None,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO checkpoints(round_received, merkle_root, members_snapshot_hash, signatures_json, status, confirmed_at, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(round_received) DO UPDATE SET "
                "merkle_root = excluded.merkle_root, "
                "members_snapshot_hash = excluded.members_snapshot_hash, "
                "signatures_json = excluded.signatures_json, "
                "status = excluded.status, "
                "confirmed_at = excluded.confirmed_at",
                (
                    int(round_received),
                    str(merkle_root),
                    str(members_snapshot_hash),
                    canonical_json(signatures),
                    str(status),
                    confirmed_at,
                    time.time(),
                ),
            )

    def get_checkpoint(self, round_received: int) -> Optional[Dict[str, object]]:
        row = self._conn.execute(
            "SELECT round_received, merkle_root, members_snapshot_hash, signatures_json, status, confirmed_at, created_at "
            "FROM checkpoints WHERE round_received = ?",
            (int(round_received),),
        ).fetchone()
        if not row:
            return None
        return _row_to_checkpoint(row)

    def list_checkpoints(self, *, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, object]]:
        if status is not None:
            rows = self._conn.execute(
                "SELECT round_received, merkle_root, members_snapshot_hash, signatures_json, status, confirmed_at, created_at "
                "FROM checkpoints WHERE status = ? ORDER BY round_received DESC LIMIT ?",
                (status, int(limit)),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT round_received, merkle_root, members_snapshot_hash, signatures_json, status, confirmed_at, created_at "
                "FROM checkpoints ORDER BY round_received DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [_row_to_checkpoint(row) for row in rows]

    def latest_confirmed_checkpoint(self) -> Optional[Dict[str, object]]:
        row = self._conn.execute(
            "SELECT round_received, merkle_root, members_snapshot_hash, signatures_json, status, confirmed_at, created_at "
            "FROM checkpoints WHERE status = 'confirmed' ORDER BY round_received DESC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        return _row_to_checkpoint(row)

    def add_event_skeleton(
        self,
        *,
        event_id: str,
        cls: str,
        parent_ids: List[str],
        round_received: Optional[int],
        payload_hash: str,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO event_skeletons(id, cls, parent_ids, round_received, payload_hash, archived_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    cls,
                    canonical_json(list(parent_ids)),
                    round_received,
                    payload_hash,
                    time.time(),
                ),
            )

    def list_event_skeletons(self, *, limit: int = 1000) -> List[Dict[str, object]]:
        rows = self._conn.execute(
            "SELECT id, cls, parent_ids, round_received, payload_hash, archived_at FROM event_skeletons ORDER BY archived_at ASC LIMIT ?",
            (int(limit),),
        ).fetchall()
        return [
            {
                "id": row["id"],
                "cls": row["cls"],
                "parent_ids": json.loads(row["parent_ids"]),
                "round_received": row["round_received"],
                "payload_hash": row["payload_hash"],
                "archived_at": float(row["archived_at"]),
            }
            for row in rows
        ]

    def event_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return row[0]

    def upsert_peer(self, address: str, last_seen: float, healthy: bool) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO peers(address, node_id, last_seen, healthy, enabled, note, source, role) VALUES (?, '', ?, ?, 1, '', 'runtime', ?)\n                 ON CONFLICT(address) DO UPDATE SET last_seen = excluded.last_seen, healthy = excluded.healthy",
                (address, last_seen, int(healthy), NODE_ROLE_NODE),
            )

    def ensure_peer(
        self,
        address: str,
        *,
        node_id: str = "",
        last_seen: Optional[float],
        healthy: bool,
        enabled: bool = True,
        note: str = "",
        source: str = "runtime",
        role: str = NODE_ROLE_NODE,
        approval_status: str = PEER_APPROVAL_APPROVED,
    ) -> PeerInfo:
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT * FROM peers WHERE address = ?",
                (address,),
            ).fetchone()
            next_role = normalize_node_role(role)
            next_approval = normalize_approval_status(approval_status)
            if existing:
                merged_last_seen = last_seen if last_seen is not None else existing["last_seen"]
                merged_healthy = int(healthy)
                merged_enabled = bool(existing["enabled"])
                merged_note = existing["note"] or note or ""
                merged_source = existing["source"] or source
                merged_role = normalize_node_role(existing["role"] if "role" in existing.keys() else next_role)
                merged_node_id = (existing["node_id"] if "node_id" in existing.keys() else "") or node_id or ""
                merged_approval = normalize_approval_status(
                    existing["approval_status"] if "approval_status" in existing.keys() else next_approval
                )
                self._conn.execute(
                    "UPDATE peers SET node_id = ?, last_seen = ?, healthy = ?, enabled = ?, note = ?, source = ?, role = ?, approval_status = ? WHERE address = ?",
                    (
                        merged_node_id,
                        merged_last_seen,
                        merged_healthy,
                        int(merged_enabled),
                        merged_note,
                        merged_source,
                        merged_role,
                        merged_approval,
                        address,
                    ),
                )
                return PeerInfo(
                    address=address,
                    node_id=merged_node_id,
                    last_seen=merged_last_seen,
                    healthy=bool(merged_healthy),
                    enabled=merged_enabled,
                    note=merged_note,
                    source=merged_source,
                    role=merged_role,
                    is_self=merged_source == "self",
                    approval_status=merged_approval,
                )
            self._conn.execute(
                "INSERT INTO peers(address, node_id, last_seen, healthy, enabled, note, source, role, approval_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (address, node_id, last_seen, int(healthy), int(enabled), note, source, next_role, next_approval),
            )
            return PeerInfo(
                address=address,
                node_id=node_id,
                last_seen=last_seen,
                healthy=healthy,
                enabled=enabled,
                note=note,
                source=source,
                role=next_role,
                is_self=source == "self",
                approval_status=next_approval,
            )

    def update_peer(
        self,
        address: str,
        *,
        enabled: Optional[bool] = None,
        note: Optional[str] = None,
        last_seen: Optional[float] = None,
        healthy: Optional[bool] = None,
        role: Optional[str] = None,
        node_id: Optional[str] = None,
        approval_status: Optional[str] = None,
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
            next_role = normalize_node_role(existing["role"] if role is None else role)
            next_node_id = ((existing["node_id"] if "node_id" in existing.keys() else "") or "") if node_id is None else str(node_id or "")
            current_approval = (
                existing["approval_status"]
                if "approval_status" in existing.keys() and existing["approval_status"]
                else PEER_APPROVAL_APPROVED
            )
            next_approval = normalize_approval_status(current_approval if approval_status is None else approval_status)
            self._conn.execute(
                "UPDATE peers SET node_id = ?, last_seen = ?, healthy = ?, enabled = ?, note = ?, source = ?, role = ?, approval_status = ? WHERE address = ?",
                (next_node_id, next_last_seen, int(next_healthy), int(next_enabled), next_note, next_source, next_role, next_approval, address),
            )
            return PeerInfo(
                address=address,
                node_id=next_node_id,
                last_seen=next_last_seen,
                healthy=next_healthy,
                enabled=next_enabled,
                note=next_note,
                source=next_source,
                role=next_role,
                is_self=next_source == "self",
                approval_status=next_approval,
            )

    def delete_peer(self, address: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM peers WHERE address = ?", (address,))

    def list_peers(self) -> List[PeerInfo]:
        rows = self._conn.execute("SELECT * FROM peers").fetchall()
        peers: List[PeerInfo] = []
        for row in rows:
            source = (row["source"] if "source" in row.keys() else "runtime") or "runtime"
            approval = normalize_approval_status(
                row["approval_status"] if "approval_status" in row.keys() else PEER_APPROVAL_APPROVED
            )
            peers.append(
                PeerInfo(
                    address=row["address"],
                    node_id=(row["node_id"] if "node_id" in row.keys() else "") or "",
                    last_seen=row["last_seen"],
                    healthy=bool(row["healthy"]),
                    enabled=bool(row["enabled"]) if "enabled" in row.keys() else True,
                    note=(row["note"] if "note" in row.keys() else "") or "",
                    source=source,
                    role=normalize_node_role((row["role"] if "role" in row.keys() else NODE_ROLE_NODE) or NODE_ROLE_NODE),
                    is_self=source == "self",
                    approval_status=approval,
                )
            )
        peers.sort(key=lambda peer: (not peer.is_self, peer.address))
        return peers

    def get_consensus_membership_snapshot(self) -> Optional[Dict[str, object]]:
        row = self._conn.execute(
            "SELECT value FROM consensus_state WHERE key = 'membership_snapshot'"
        ).fetchone()
        if not row:
            return None
        try:
            data = json.loads(row["value"])
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        return data

    def save_consensus_membership_snapshot(self, snapshot: Dict[str, object]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO consensus_state(key, value) VALUES ('membership_snapshot', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (canonical_json(snapshot),),
            )


def _row_to_checkpoint(row) -> Dict[str, object]:
    return {
        "round_received": int(row["round_received"]),
        "merkle_root": row["merkle_root"],
        "members_snapshot_hash": row["members_snapshot_hash"],
        "signatures": json.loads(row["signatures_json"]),
        "status": row["status"],
        "confirmed_at": row["confirmed_at"],
        "created_at": float(row["created_at"]),
    }
