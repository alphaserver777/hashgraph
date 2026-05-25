"""Typer CLI for MDRJ-DAG."""
from __future__ import annotations

import asyncio
import json
import signal
from pathlib import Path
from typing import Optional

import aiohttp
import typer

from .config import load_config
from .models import EventClass
from .node import Node

app = typer.Typer(help="MDRJ-DAG control plane")
peers_app = typer.Typer(help="Peer management")
demo_app = typer.Typer(help="Scenario helpers")
app.add_typer(peers_app, name="peers")
app.add_typer(demo_app, name="demo")


async def _run_node(node: Node) -> None:
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _signal_handler(*_: object) -> None:
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass

    await node.start()
    typer.echo(f"Node {node.config.node_id} started on {node.config.listen}")
    await stop_event.wait()
    await node.stop()
    typer.echo("Node stopped")


def _base_url(listen: str, override: Optional[str]) -> str:
    target = override or listen
    if target.startswith("http://") or target.startswith("https://"):
        return target.rstrip("/")
    return f"http://{target.rstrip('/')}"


async def _post_json(url: str, payload: dict) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload) as resp:
            resp.raise_for_status()
            return await resp.json()


async def _get_json(url: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            resp.raise_for_status()
            return await resp.json()


@app.command()
def node(config: Path = typer.Option(..., exists=True, help="Path to node YAML config")) -> None:
    cfg = load_config(config)
    node = Node(cfg)
    asyncio.run(_run_node(node))


@app.command()
def emit(
    cls: EventClass = typer.Option(..., "--cls", case_sensitive=False, help="Event class A/B/C"),
    payload: Optional[Path] = typer.Option(None, "--payload", exists=True, help="JSON payload file"),
    config: Path = typer.Option(..., exists=True, help="Path to node YAML config"),
    api: Optional[str] = typer.Option(None, "--api", help="Override API address host:port"),
) -> None:
    cfg = load_config(config)
    data = {}
    if payload:
        data = json.loads(payload.read_text())
    url = f"{_base_url(cfg.listen, api)}/event/emit"
    result = asyncio.run(_post_json(url, {"cls": cls.value, "payload": data}))
    typer.echo(json.dumps(result, indent=2))


@peers_app.command("add")
def add_peer(
    addr: str = typer.Argument(..., help="peer address host:port"),
    config: Path = typer.Option(..., exists=True, help="Path to node YAML config"),
    api: Optional[str] = typer.Option(None, "--api", help="Override API address host:port"),
) -> None:
    cfg = load_config(config)
    url = f"{_base_url(cfg.listen, api)}/peers/register"
    result = asyncio.run(_post_json(url, {"address": addr}))
    typer.echo(json.dumps(result, indent=2))


@peers_app.command("list")
def list_peers(
    config: Path = typer.Option(..., exists=True, help="Path to node YAML config"),
    api: Optional[str] = typer.Option(None, "--api", help="Override API address host:port"),
) -> None:
    cfg = load_config(config)
    url = f"{_base_url(cfg.listen, api)}/peers"
    result = asyncio.run(_get_json(url))
    typer.echo(json.dumps(result, indent=2))


@app.command("metrics")
def metrics_once(
    config: Path = typer.Option(..., exists=True, help="Path to node YAML config"),
    api: Optional[str] = typer.Option(None, "--api", help="Override API address host:port"),
) -> None:
    cfg = load_config(config)
    url = f"{_base_url(cfg.listen, api)}/metrics"
    result = asyncio.run(_get_json(url))
    typer.echo(json.dumps(result, indent=2))


@app.command()
def status(
    config: Path = typer.Option(..., exists=True, help="Path to node YAML config"),
    api: Optional[str] = typer.Option(None, "--api", help="Override API address host:port"),
) -> None:
    cfg = load_config(config)
    url = f"{_base_url(cfg.listen, api)}/status"
    result = asyncio.run(_get_json(url))
    typer.echo(json.dumps(result, indent=2))


@app.command()
def dag(
    config: Path = typer.Option(..., exists=True, help="Path to node YAML config"),
    api: Optional[str] = typer.Option(None, "--api", help="Override API address host:port"),
) -> None:
    cfg = load_config(config)
    url = f"{_base_url(cfg.listen, api)}/dag"
    result = asyncio.run(_get_json(url))
    typer.echo(json.dumps(result, indent=2))


@demo_app.command("partition")
def demo_partition(
    groups: str = typer.Option(..., help="Partition groups notation e.g. '1,2/3'"),
) -> None:
    typer.echo(
        "Partition simulation is cooperative. Use OS firewall (e.g., iptables) or container networks\n"
        "Example: iptables -A OUTPUT -p tcp --dport <port-group> -j DROP"
    )
    typer.echo(f"Target partition groups: {groups}")


@demo_app.command("heal")
def demo_heal() -> None:
    typer.echo("Remove previously applied firewall rules to heal the cluster.")


@app.command("metrics-watch")
def metrics_watch(
    config: Path = typer.Option(..., exists=True, help="Path to node YAML config"),
    interval: float = typer.Option(1.0, help="Polling interval seconds"),
    count: Optional[int] = typer.Option(None, help="Number of samples"),
    api: Optional[str] = typer.Option(None, "--api", help="Override API address host:port"),
) -> None:
    cfg = load_config(config)
    base = _base_url(cfg.listen, api)
    url = f"{base}/metrics"

    async def _watch() -> None:
        samples = 0
        async with aiohttp.ClientSession() as session:
            while count is None or samples < count:
                async with session.get(url) as resp:
                    resp.raise_for_status()
                    metrics = await resp.json()
                typer.echo(json.dumps(metrics, indent=2))
                samples += 1
                await asyncio.sleep(interval)

    asyncio.run(_watch())


checkpoint_app = typer.Typer(help="Checkpoint operations")
app.add_typer(checkpoint_app, name="checkpoint")
archive_app = typer.Typer(help="Cold archive operations")
app.add_typer(archive_app, name="archive")
users_app = typer.Typer(help="User management for Web UI")
app.add_typer(users_app, name="users")


@users_app.command("add")
def users_add(
    username: str = typer.Option(..., help="Username (lowercased)"),
    role: str = typer.Option("viewer", help="Role: viewer or admin"),
    config: Path = typer.Option(..., exists=True, help="Path to node YAML config"),
    password: Optional[str] = typer.Option(None, hide_input=True, help="Password (prompted if omitted)"),
) -> None:
    """Add or update a user directly in the node's SQLite (offline, no HTTP)."""
    from .auth import normalize_role, hash_password as _hash_password
    cfg = load_config(config)
    if password is None:
        password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    from .storage import DAGStorage
    storage = DAGStorage(cfg.storage.sqlite_path)
    storage.upsert_user(
        username=username.strip().lower(),
        password_hash=_hash_password(password),
        role=normalize_role(role),
    )
    storage.close()
    typer.echo(f"User {username} added/updated with role={normalize_role(role)}")


@users_app.command("list")
def users_list(
    config: Path = typer.Option(..., exists=True),
) -> None:
    cfg = load_config(config)
    from .storage import DAGStorage
    storage = DAGStorage(cfg.storage.sqlite_path)
    rows = storage.list_users()
    storage.close()
    typer.echo(json.dumps(rows, indent=2, ensure_ascii=False))


@users_app.command("remove")
def users_remove(
    username: str = typer.Option(..., help="Username to remove"),
    config: Path = typer.Option(..., exists=True),
) -> None:
    cfg = load_config(config)
    from .storage import DAGStorage
    storage = DAGStorage(cfg.storage.sqlite_path)
    removed = storage.delete_user(username.strip().lower())
    storage.close()
    typer.echo("removed" if removed else "not found")


@checkpoint_app.command("propose")
def checkpoint_propose(
    config: Path = typer.Option(..., exists=True),
    round_received: Optional[int] = typer.Option(None, help="Target round_received (defaults to latest available)"),
    api: Optional[str] = typer.Option(None, "--api"),
) -> None:
    cfg = load_config(config)
    base = _base_url(cfg.listen, api)
    payload = {} if round_received is None else {"round_received": int(round_received)}
    result = asyncio.run(_post_json(f"{base}/checkpoint/propose", payload))
    typer.echo(json.dumps(result, indent=2, ensure_ascii=False))


@checkpoint_app.command("list")
def checkpoint_list(
    config: Path = typer.Option(..., exists=True),
    status: Optional[str] = typer.Option(None, help="Filter by status: pending|confirmed"),
    limit: int = typer.Option(20, help="Max items"),
    api: Optional[str] = typer.Option(None, "--api"),
) -> None:
    cfg = load_config(config)
    base = _base_url(cfg.listen, api)
    qs = []
    if status:
        qs.append(f"status={status}")
    qs.append(f"limit={limit}")
    url = f"{base}/checkpoint/list?{'&'.join(qs)}"
    result = asyncio.run(_get_json(url))
    typer.echo(json.dumps(result, indent=2, ensure_ascii=False))


@checkpoint_app.command("verify")
def checkpoint_verify(
    config: Path = typer.Option(..., exists=True),
    round_received: int = typer.Option(..., help="Round to verify"),
    api: Optional[str] = typer.Option(None, "--api"),
) -> None:
    cfg = load_config(config)
    base = _base_url(cfg.listen, api)
    url = f"{base}/checkpoint/verify?round_received={int(round_received)}"
    result = asyncio.run(_get_json(url))
    typer.echo(json.dumps(result, indent=2, ensure_ascii=False))
    if result.get("has_tamper_evidence"):
        raise typer.Exit(code=2)


@archive_app.command("verify")
def archive_verify(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, help="Path to JSONL archive file"),
) -> None:
    """Verify integrity of a cold archive file by recomputing every payload hash."""
    import hashlib
    from .utils import canonical_json as _canonical_json

    ok = 0
    bad = 0
    with path.open("r", encoding="utf-8") as fp:
        for raw_line in fp:
            line = raw_line.strip()
            if not line:
                continue
            record = json.loads(line)
            if "_archive_header" in record:
                continue
            stated = record.get("payload_hash")
            actual = hashlib.sha256(_canonical_json(record["payload"]).encode()).hexdigest()
            if stated == actual:
                ok += 1
            else:
                bad += 1
                typer.echo(f"MISMATCH: event {record.get('id')} stated={stated} actual={actual}")
    typer.echo(json.dumps({"records_ok": ok, "records_bad": bad}, indent=2))
    if bad:
        raise typer.Exit(code=2)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
