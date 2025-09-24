"""Utility helpers for MDRJ-DAG."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, Iterable, Mapping, Sequence

DEFAULT_HASH_ALGO = "sha256"


def utc_timestamp() -> float:
    """Return a high resolution UTC timestamp."""
    return time.time()


def canonical_json(data: Any) -> str:
    """Encode *data* into deterministic JSON suitable for hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def compute_event_id(header: Mapping[str, Any], payload: Mapping[str, Any]) -> str:
    """Compute a deterministic hash of event header and payload."""
    digest = hashlib.new(DEFAULT_HASH_ALGO)
    digest.update(canonical_json(header).encode())
    digest.update(b"::")
    digest.update(canonical_json(payload).encode())
    return digest.hexdigest()


def hmac_signature(key: str, message: Mapping[str, Any]) -> str:
    """Return hex encoded HMAC signature for *message* with *key*."""
    digest = hmac.new(key.encode(), canonical_json(message).encode(), DEFAULT_HASH_ALGO)
    return digest.hexdigest()


def median(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("cannot compute median of empty sequence")
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def chunked(seq: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for idx in range(0, len(seq), max(1, size)):
        yield seq[idx : idx + size]


def random_node_id(prefix: str = "node") -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


def ensure_directory(path: str) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)


def to_thread(func: Any, *args: Any, **kwargs: Any):
    """Wrapper over asyncio.to_thread for Python 3.11 compatibility."""
    return asyncio.to_thread(func, *args, **kwargs)


def sliding_window(values: Sequence[float], window: int) -> Sequence[float]:
    if window <= 0:
        return values
    return values[-window:]


def bytes_cost(obj: Mapping[str, Any]) -> int:
    """Rough estimate of serialized size for quota accounting."""
    return len(canonical_json(obj).encode())

