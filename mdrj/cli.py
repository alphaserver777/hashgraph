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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
