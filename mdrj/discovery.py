"""Peer discovery backends: mDNS (LAN) and Kubernetes DNS (k3s/k8s)."""
from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass, field
from typing import Awaitable, Callable, List, Optional, Set

logger = logging.getLogger(__name__)

# Callback signature: (address, node_id, source)
PeerCallback = Callable[[str, str, str], Awaitable[None]]

MDNS_SERVICE_TYPE = "_mdrj._tcp.local."


@dataclass
class DiscoveryConfig:
    """Optional discovery section in node config.

    mode:
      - "disabled" — discovery off (default).
      - "mdns"     — Zeroconf-based LAN discovery.
      - "k8s"      — Kubernetes headless-service DNS resolution.

    auto_approve_discovered: when True, newly discovered peers go straight
    to `approved` status without operator confirmation. This is appropriate
    for trusted environments (e.g. a k3s cluster where every pod is ours
    by construction) but should be False in untrusted LANs.
    """
    mode: str = "disabled"
    poll_interval_sec: float = 10.0
    auto_approve_discovered: bool = False
    # mDNS settings
    advertise_port: Optional[int] = None  # if None, derived from node.listen
    # Kubernetes settings
    k8s_service: Optional[str] = None  # e.g. "mdrj-headless.mdrj.svc.cluster.local"
    k8s_target_port: int = 9001


class BaseDiscovery:
    """Base for discovery backends. Subclasses implement _discover_once()."""

    def __init__(
        self,
        *,
        node_id: str,
        on_peer: PeerCallback,
        poll_interval_sec: float = 10.0,
        self_address: Optional[str] = None,
    ) -> None:
        self.node_id = node_id
        self.on_peer = on_peer
        self.poll_interval_sec = max(1.0, float(poll_interval_sec))
        self.self_address = self_address or ""
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._stop.set()
        self._known: Set[str] = set()
        self._logger = logging.getLogger(f"mdrj.discovery.{self.kind}")

    @property
    def kind(self) -> str:
        raise NotImplementedError

    async def _discover_once(self) -> List["DiscoveredPeer"]:
        raise NotImplementedError

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._stop.set()
            try:
                await self._task
            except Exception:
                self._logger.exception("error stopping discovery")
            self._task = None

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                peers = await self._discover_once()
            except Exception:
                self._logger.exception("discovery loop failure")
                peers = []
            for peer in peers:
                if not peer.address or peer.address == self.self_address:
                    continue
                key = f"{peer.address}|{peer.node_id}"
                if key in self._known:
                    continue
                self._known.add(key)
                try:
                    await self.on_peer(peer.address, peer.node_id, self.kind)
                except Exception:
                    self._logger.exception("on_peer callback raised")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval_sec)
            except asyncio.TimeoutError:
                continue


@dataclass
class DiscoveredPeer:
    address: str
    node_id: str = ""


class KubernetesDNSDiscovery(BaseDiscovery):
    """Resolve a Kubernetes headless service to a set of pod IPs.

    Headless service (clusterIP=None) in k8s returns A records for every
    pod backing the service. We resolve once per poll_interval_sec and
    register every non-self IP as a candidate peer. The peer's node_id is
    learned later via /status during normal gossip.
    """

    def __init__(
        self,
        *,
        service: str,
        target_port: int,
        node_id: str,
        on_peer: PeerCallback,
        poll_interval_sec: float = 10.0,
        self_address: Optional[str] = None,
    ) -> None:
        super().__init__(
            node_id=node_id,
            on_peer=on_peer,
            poll_interval_sec=poll_interval_sec,
            self_address=self_address,
        )
        self.service = service
        self.target_port = int(target_port)

    @property
    def kind(self) -> str:
        return "k8s"

    async def _discover_once(self) -> List[DiscoveredPeer]:
        return await asyncio.to_thread(self._resolve_service)

    def _resolve_service(self) -> List[DiscoveredPeer]:
        try:
            infos = socket.getaddrinfo(self.service, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            self._logger.debug("DNS resolution failed for %s: %s", self.service, exc)
            return []
        seen: Set[str] = set()
        peers: List[DiscoveredPeer] = []
        for info in infos:
            sockaddr = info[4]
            ip = sockaddr[0] if isinstance(sockaddr, tuple) else None
            if not ip or ip in seen:
                continue
            seen.add(ip)
            peers.append(DiscoveredPeer(address=f"{ip}:{self.target_port}"))
        return peers


class MDNSDiscovery(BaseDiscovery):
    """LAN discovery via Zeroconf. Requires `zeroconf` package.

    If zeroconf is not installed, the backend logs a warning and degrades
    to no-op. This lets the rest of the system run on bare-metal setups
    without the dependency.
    """

    def __init__(
        self,
        *,
        node_id: str,
        advertise_port: int,
        on_peer: PeerCallback,
        poll_interval_sec: float = 10.0,
        self_address: Optional[str] = None,
    ) -> None:
        super().__init__(
            node_id=node_id,
            on_peer=on_peer,
            poll_interval_sec=poll_interval_sec,
            self_address=self_address,
        )
        self.advertise_port = int(advertise_port)
        self._zeroconf = None
        self._service_info = None
        self._browser = None
        self._discovered: List[DiscoveredPeer] = []
        self._discovered_lock = asyncio.Lock()

    @property
    def kind(self) -> str:
        return "mdns"

    async def start(self) -> None:
        try:
            from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, Zeroconf  # type: ignore[import-untyped]
        except ImportError:
            self._logger.warning("zeroconf package not installed; mDNS discovery disabled")
            return
        self._zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        local_ip = _detect_local_ip()
        if local_ip:
            self._service_info = ServiceInfo(
                MDNS_SERVICE_TYPE,
                f"{self.node_id}.{MDNS_SERVICE_TYPE}",
                addresses=[socket.inet_aton(local_ip)],
                port=self.advertise_port,
                properties={"node_id": self.node_id},
            )
            try:
                self._zeroconf.register_service(self._service_info)
            except Exception:
                self._logger.exception("zeroconf register_service failed")
        listener = _MDNSListener(self)
        self._browser = ServiceBrowser(self._zeroconf, MDNS_SERVICE_TYPE, listener)
        await super().start()

    async def stop(self) -> None:
        await super().stop()
        if self._zeroconf is not None:
            try:
                if self._service_info is not None:
                    self._zeroconf.unregister_service(self._service_info)
                self._zeroconf.close()
            except Exception:
                self._logger.exception("zeroconf shutdown failed")
            self._zeroconf = None

    async def _discover_once(self) -> List[DiscoveredPeer]:
        async with self._discovered_lock:
            peers = list(self._discovered)
            self._discovered.clear()
        return peers

    def _on_zeroconf_add(self, info) -> None:
        addresses = info.parsed_addresses() if hasattr(info, "parsed_addresses") else []
        port = getattr(info, "port", None)
        if not addresses or not port:
            return
        peer_node_id = ""
        props = getattr(info, "properties", {}) or {}
        raw_node_id = props.get(b"node_id") if isinstance(props, dict) else None
        if raw_node_id:
            try:
                peer_node_id = raw_node_id.decode("utf-8") if isinstance(raw_node_id, bytes) else str(raw_node_id)
            except Exception:
                peer_node_id = ""
        for addr in addresses:
            asyncio.run_coroutine_threadsafe(
                self._record_peer(DiscoveredPeer(address=f"{addr}:{port}", node_id=peer_node_id)),
                asyncio.get_event_loop(),
            )

    async def _record_peer(self, peer: DiscoveredPeer) -> None:
        async with self._discovered_lock:
            self._discovered.append(peer)


class _MDNSListener:
    def __init__(self, owner: MDNSDiscovery) -> None:
        self.owner = owner

    def add_service(self, zeroconf, service_type, name) -> None:
        info = zeroconf.get_service_info(service_type, name)
        if info is not None:
            self.owner._on_zeroconf_add(info)

    def update_service(self, zeroconf, service_type, name) -> None:
        self.add_service(zeroconf, service_type, name)

    def remove_service(self, zeroconf, service_type, name) -> None:
        # Removal is handled lazily via peer health probes; not handled here.
        pass


def _detect_local_ip() -> Optional[str]:
    """Best-effort detection of a non-loopback IPv4 address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        return None


def build_discovery(
    *,
    config: DiscoveryConfig,
    node_id: str,
    listen: str,
    on_peer: PeerCallback,
) -> Optional[BaseDiscovery]:
    """Factory: returns a configured discovery backend or None if disabled."""
    mode = (config.mode or "disabled").strip().lower()
    if mode == "disabled":
        return None
    if mode == "k8s":
        if not config.k8s_service:
            logger.warning("discovery.mode=k8s requires k8s_service to be set")
            return None
        return KubernetesDNSDiscovery(
            service=config.k8s_service,
            target_port=config.k8s_target_port,
            node_id=node_id,
            on_peer=on_peer,
            poll_interval_sec=config.poll_interval_sec,
            self_address=listen,
        )
    if mode == "mdns":
        try:
            port = config.advertise_port or int(listen.split(":")[1])
        except (ValueError, IndexError):
            port = config.k8s_target_port
        return MDNSDiscovery(
            node_id=node_id,
            advertise_port=port,
            on_peer=on_peer,
            poll_interval_sec=config.poll_interval_sec,
            self_address=listen,
        )
    logger.warning("unknown discovery.mode=%s; discovery disabled", mode)
    return None
