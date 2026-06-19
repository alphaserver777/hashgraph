"""HTTP API for MDRJ-DAG nodes."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac as hmac_lib
import json
import logging
import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional

from aiohttp import web

from .auth import (
    ROLE_ADMIN,
    SESSION_COOKIE_NAME,
    SESSION_TTL_SECONDS,
    SessionRecord,
    normalize_role,
)
from .event_catalog import event_class_for, is_known_event_kind
from .models import Envelope, EventClass
from .simulation import SCENARIOS, scenario_payload

HMAC_HEADER = "X-MDRJ-Sig"
HMAC_PROTECTED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

_auth_logger = logging.getLogger("mdrj.api.auth")

# Endpoints that ALWAYS bypass session auth (login form itself, static assets,
# inter-node gossip, internal health probes). Everything else requires either
# a valid session cookie OR no users configured (open-access prototype mode).
AUTH_PUBLIC_PATHS = {
    "/auth/login",
    "/auth/logout",  # logout is idempotent — safe to expose
    "/status",  # for k3s liveness/readiness probes
    "/event/batch",  # inter-node gossip, protected by HMAC instead
    "/gossip/frontier",  # inter-node frontier handshake
    "/checkpoint/propose",  # inter-node checkpoint proposal
}
# Methods needed in role checks for write operations.
WRITE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
# Read-only paths that a viewer is allowed to GET even with users configured.
VIEWER_READ_PATHS = {
    "/dag",
    "/dag/frontier",
    "/metrics",
    "/metrics/prometheus",
    "/metrics/history",
    "/peers",
    "/incidents",
    "/viz",
    "/viz/graph",
    "/viz/stream",
    "/checkpoint/list",
    "/checkpoint/verify",
    "/auth/me",
    "/notifier/status",
    "/catalog",
}


@web.middleware
async def hmac_auth_middleware(request: web.Request, handler):
    """Verify HMAC-SHA256 signature of state-changing requests when key is set."""
    hmac_key = request.app.get("hmac_key")
    if not hmac_key or request.method not in HMAC_PROTECTED_METHODS:
        return await handler(request)

    # Login endpoint MUST be reachable without HMAC — user has no shared key.
    # Logout is idempotent and benign without HMAC.
    if request.path in AUTH_PUBLIC_PATHS:
        return await handler(request)

    # If the request carries a valid session cookie, treat the human user as
    # authenticated via UI auth and skip HMAC requirement. HMAC remains the
    # gate for inter-node and CLI traffic (which has no session).
    if _resolve_session(request) is not None:
        return await handler(request)

    # Open-access prototype mode (no users configured): UI buttons can call
    # state-changing endpoints from the browser without knowing the HMAC key.
    # The session middleware running above already let the request through
    # for the same reason. As soon as the operator creates the first user,
    # this fallback disappears and HMAC becomes mandatory again.
    node = request.app.get("node")
    if node is not None and node.storage.users_count() == 0:
        return await handler(request)

    provided = request.headers.get(HMAC_HEADER, "")
    if not provided:
        raise web.HTTPUnauthorized(text=f"missing {HMAC_HEADER} header")

    body = await request.read()
    expected = hmac_lib.new(hmac_key.encode(), body, hashlib.sha256).hexdigest()
    if not hmac_lib.compare_digest(provided, expected):
        _auth_logger.warning("HMAC verification failed for %s %s", request.method, request.path)
        raise web.HTTPUnauthorized(text="invalid signature")
    return await handler(request)


def _resolve_session(request: web.Request) -> Optional["SessionRecord"]:
    """Look up the current session from cookie. Returns None if not present/expired."""
    node = request.app.get("node")
    if node is None:
        return None
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    return node.session_store.get(token)


@web.middleware
async def session_auth_middleware(request: web.Request, handler):
    """Gate UI endpoints behind session auth, but only if users exist."""
    node = request.app.get("node")
    if node is None:
        return await handler(request)
    # Inter-node gossip carries HMAC; static auth endpoints are public.
    if request.path in AUTH_PUBLIC_PATHS:
        return await handler(request)
    # No users in DB → open-access prototype mode (skip session auth).
    if node.storage.users_count() == 0:
        return await handler(request)
    session = _resolve_session(request)
    if session is None:
        # Browser UI expects HTML redirect, API clients expect JSON 401.
        accept = request.headers.get("Accept", "")
        if "text/html" in accept and request.method == "GET":
            return web.HTTPFound("/auth/login")
        raise web.HTTPUnauthorized(text="login required")
    # Role check: viewers cannot do write operations except logout.
    if session.role != ROLE_ADMIN and request.method in WRITE_METHODS:
        if request.path != "/auth/logout":
            raise web.HTTPForbidden(text="admin role required")
    # Viewer + GET: only allowed for VIEWER_READ_PATHS.
    if session.role != ROLE_ADMIN and request.method == "GET":
        is_read_path = (
            request.path in VIEWER_READ_PATHS
            or request.path.startswith("/static/")
            or request.path == "/gossip/frontier"
            or request.path.startswith("/events/")  # /events/{id}/ancestry
        )
        if not is_read_path:
            raise web.HTTPForbidden(text="not permitted for viewer role")
    request["session"] = session
    return await handler(request)

VIZ_HTML = """
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <title>MDRJ-DAG Visualizer</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { margin: 0; font-family: system-ui, sans-serif; background: #08111f; color: #eff3ff; }
    header { padding: 1rem 1.5rem; border-bottom: 1px solid rgba(255,255,255,0.1); display: flex; justify-content: space-between; align-items: center; }
    .header-actions { display: flex; align-items: center; gap: 0.75rem; }
    h1 { font-size: 1.2rem; margin: 0; }
    #metrics { font-family: 'JetBrains Mono', Menlo, monospace; white-space: pre; margin-top: 0.6rem; }
    #consensus-status { font-size: 0.82rem; margin-top: 0.25rem; color: rgba(198, 210, 255, 0.75); }
    #consensus-status.ok { color: rgba(140, 220, 150, 0.95); }
    #consensus-status.alert { color: #ff8080; }
    #consensus-status.pending { color: rgba(233, 196, 122, 0.9); }
    #graph-status { font-size: 0.85rem; margin-top: 0.35rem; color: rgba(198, 210, 255, 0.85); }
    #graph-wrapper { display: flex; flex-direction: row; align-items: stretch; width: 100vw; height: calc(100vh - 88px); background: rgba(6, 12, 20, 0.9); position: relative; }
    #graph { flex: 1 1 auto; min-height: calc(100vh - 88px); display: flex; }
    svg { width: 100%; height: 100%; background: radial-gradient(circle at top, rgba(255,255,255,0.06), transparent 60%); }
    .toolbar { font-size: 0.85rem; opacity: 0.75; }
    #controls, #reset-controls { display: flex; flex-direction: column; gap: 0.6rem; padding: 0.75rem 1.5rem; background: rgba(10, 16, 28, 0.92); border-top: 1px solid rgba(255,255,255,0.08); border-bottom: 1px solid rgba(255,255,255,0.08); }
    #controls .controls-title, #reset-controls .controls-title { font-size: 0.9rem; color: rgba(233, 238, 255, 0.9); }
    #controls .controls-buttons, #reset-controls .controls-buttons { display: flex; flex-wrap: wrap; gap: 0.6rem; }
    #filters { display: flex; flex-direction: column; gap: 0.45rem; background: rgba(9, 14, 24, 0.92); padding: 0.7rem 1.5rem; border-top: 1px solid rgba(255,255,255,0.05); border-bottom: 1px solid rgba(255,255,255,0.05); }
    #filters .filters-title { font-size: 0.88rem; color: rgba(233, 238, 255, 0.85); }
    #filters .filter-group { display: flex; flex-wrap: wrap; gap: 0.4rem; }
    .toggle-button { background: rgba(32, 48, 80, 0.8); color: #f6f8ff; border: 1px solid rgba(148, 178, 255, 0.35); border-radius: 6px; padding: 0.4rem 0.75rem; font-size: 0.82rem; cursor: pointer; transition: background 0.15s ease, transform 0.1s ease, opacity 0.15s ease; }
    .toggle-button:hover { background: rgba(46, 68, 110, 0.9); }
    .toggle-button.active { background: rgba(72, 138, 255, 0.8); border-color: rgba(255,255,255,0.6); color: #fff; }
    .toggle-button.disabled { opacity: 0.35; cursor: default; transform: none; }
    .sim-button { background: #22304a; color: #f1f6ff; border: 1px solid rgba(158, 182, 255, 0.4); border-radius: 6px; padding: 0.5rem 0.9rem; font-size: 0.85rem; cursor: pointer; transition: background 0.15s ease, transform 0.1s ease; }
    .sim-button:hover { background: #2e3e5d; transform: translateY(-1px); }
    .sim-button:disabled { opacity: 0.5; cursor: wait; transform: none; }
    .sim-button.primary { background: rgba(76, 110, 196, 0.9); border-color: rgba(180, 210, 255, 0.65); }
    .sim-button.primary:hover { background: rgba(96, 134, 226, 0.95); }
    .sim-button.running { background: rgba(83, 186, 122, 0.9); border-color: rgba(118, 224, 153, 0.7); }
    .sim-button.running:hover { background: rgba(94, 204, 135, 0.95); }
    .sim-button.danger { background: rgba(110, 36, 52, 0.85); border-color: rgba(255, 146, 146, 0.45); }
    .sim-button.danger:hover { background: rgba(142, 44, 63, 0.92); }
    #controls-status, #reset-controls-status { font-size: 0.8rem; color: rgba(198, 210, 255, 0.85); min-height: 1.1rem; }
    .link { stroke: rgba(150, 190, 255, 0.4); stroke-width: 1.6px; marker-end: url(#arrowhead); }
    .link-parent { stroke: rgba(255, 255, 255, 0.15); stroke-width: 1px; stroke-dasharray: 4 3; }
    .lane-line { stroke: rgba(240, 246, 255, 0.18); stroke-width: 1.6px; }
    .node { stroke: #04080f; stroke-width: 2px; }
    .label { fill: rgba(236, 242, 255, 0.9); font-size: 10px; pointer-events: none; }
    .lane-label { fill: rgba(236, 242, 255, 0.85); font-size: 12px; pointer-events: none; letter-spacing: 0.02em; }
    .node-focus { stroke: #ffffff; stroke-width: 3px; }
    .node-ancestor { stroke: #32c5ff; stroke-width: 2.5px; }
    .node-descendant { stroke: #ffdd6d; stroke-width: 2.5px; }
    .node-faded { opacity: 0.15; }
    .link-highlight { stroke: rgba(255, 255, 255, 0.85); stroke-width: 2px; }
    .link-faded { opacity: 0.12; }
    #timeline { display: flex; flex-direction: column; gap: 0.45rem; padding: 0.75rem 1.5rem; background: rgba(10, 16, 28, 0.92); border-top: 1px solid rgba(255,255,255,0.08); border-bottom: 1px solid rgba(255,255,255,0.08); }
    #timeline .timeline-title { font-size: 0.9rem; color: rgba(233, 238, 255, 0.9); }
    #timeline-items { display: flex; flex-wrap: wrap; gap: 0.45rem; }
    .timeline-item { background: #121c31; border: 1px solid rgba(180, 200, 255, 0.25); color: rgba(233, 238, 255, 0.9); border-radius: 6px; padding: 0.35rem 0.7rem; font-size: 0.8rem; cursor: pointer; transition: background 0.15s ease, transform 0.1s ease; }
    .timeline-item:hover { background: #1b2944; transform: translateY(-1px); }
    .timeline-item.active { background: #3c4f7a; border-color: rgba(255,255,255,0.6); color: #fff; }
    .timeline-item.faded { opacity: 0.4; }
    #legend { display: flex; gap: 1.2rem; padding: 0.75rem 1.5rem; font-size: 0.85rem; background: rgba(12, 20, 35, 0.95); border-top: 1px solid rgba(255,255,255,0.08); align-items: center; }
    .legend-item { display: flex; align-items: center; gap: 0.5rem; color: rgba(233, 238, 255, 0.8); }
    .legend-item .label { line-height: 1.2; }
    .dot { width: 12px; height: 12px; border-radius: 50%; display: inline-block; }
    .dot-a { background: #ff6d6d; }
    .dot-b { background: #ffc971; }
    .dot-c { background: #5aa5ff; }
    .dot-seq { background: #e6ebff; border: 1px solid rgba(255,255,255,0.4); width: 18px; height: 18px; border-radius: 4px; display: inline-flex; align-items: center; justify-content: center; font-size: 0.7rem; color: #08111f; }
    .edge { width: 26px; height: 2px; display: inline-block; background: rgba(150, 190, 255, 0.45); border-radius: 2px; }
    body.modal-open { overflow: hidden; }
    #details-backdrop { position: fixed; inset: 0; background: rgba(6, 10, 22, 0.6); backdrop-filter: blur(2px); opacity: 0; pointer-events: none; transition: opacity 0.2s ease; z-index: 200; }
    #details-backdrop.visible { opacity: 1; pointer-events: auto; }
    #details-panel { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%) scale(0.96); width: min(600px, calc(100vw - 3rem)); max-height: calc(100vh - 4rem); overflow-y: auto; background: rgba(14, 20, 34, 0.97); border: 1px solid rgba(255,255,255,0.1); border-radius: 18px; padding: 1.6rem 1.6rem 1.3rem; color: rgba(233, 238, 255, 0.92); box-shadow: 0 28px 68px rgba(4, 10, 24, 0.55); opacity: 0; pointer-events: none; transition: transform 0.2s ease, opacity 0.18s ease; z-index: 240; }
    #details-panel.is-open { opacity: 1; pointer-events: auto; transform: translate(-50%, -50%) scale(1); }
    #details-panel h2 { margin: 0; font-size: 1.08rem; color: #f7f9ff; padding-right: 2.2rem; }
    #details-panel h3 { margin: 0.9rem 0 0.4rem; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05rem; color: rgba(189, 205, 255, 0.85); }
    #details-context { font-size: 0.78rem; margin-top: 0.25rem; color: rgba(189, 202, 255, 0.75); }
    .details-section { margin-top: 0.8rem; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 0.6rem; }
    .details-section:first-of-type { border-top: none; padding-top: 0; margin-top: 0.6rem; }
    #details-meta { display: grid; grid-template-columns: minmax(0, 1fr); gap: 0.4rem; font-size: 0.82rem; }
    .details-meta-row { display: flex; justify-content: space-between; gap: 0.8rem; }
    .details-meta-key { color: rgba(189, 205, 255, 0.8); }
    .details-meta-value { color: rgba(239, 243, 255, 0.95); text-align: right; word-break: break-all; }
    #details-payload, #details-vclock, #details-sig { background: rgba(6, 12, 24, 0.85); border: 1px solid rgba(130, 158, 232, 0.25); border-radius: 6px; padding: 0.6rem; font-family: 'JetBrains Mono', Menlo, monospace; font-size: 0.75rem; line-height: 1.3; white-space: pre-wrap; word-break: break-word; color: #f1f6ff; }
    .details-list { list-style: none; margin: 0.3rem 0 0; padding: 0; font-size: 0.8rem; }
    .details-list li { padding: 0.15rem 0; color: rgba(229, 235, 255, 0.88); word-break: break-all; }
    .details-hint { font-size: 0.78rem; color: rgba(185, 198, 235, 0.7); margin-top: 0.5rem; }
    #details-panel .empty { opacity: 0.6; font-style: italic; }
    .details-close { position: absolute; top: 1rem; right: 1rem; border: none; background: rgba(36, 50, 78, 0.7); color: rgba(235, 240, 255, 0.9); width: 34px; height: 34px; border-radius: 50%; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; font-size: 1.1rem; line-height: 1; transition: background 0.15s ease, transform 0.1s ease; }
    .details-close:hover { background: rgba(49, 66, 102, 0.9); transform: translateY(-1px); }
    .details-close:focus-visible { outline: 2px solid rgba(120, 150, 220, 0.8); outline-offset: 2px; }
    @media (max-width: 640px) {
      #details-panel { width: calc(100vw - 1.5rem); padding: 1.3rem 1.1rem 1.1rem; }
    }
    :root {
      --bg-0: #071019;
      --bg-1: #0d1823;
      --line-soft: rgba(173, 201, 236, 0.14);
      --text-0: #f4f7fb;
      --text-1: rgba(228, 236, 246, 0.92);
      --text-2: rgba(180, 197, 216, 0.82);
      --shadow-soft: 0 28px 80px rgba(0, 0, 0, 0.28);
    }
    body {
      margin: 0;
      font-family: 'IBM Plex Sans', 'Segoe UI', sans-serif;
      color: var(--text-0);
      background:
        radial-gradient(circle at top left, rgba(66, 116, 196, 0.18), transparent 28%),
        radial-gradient(circle at top right, rgba(79, 209, 163, 0.14), transparent 24%),
        linear-gradient(180deg, #08111a 0%, #0b1620 45%, #071018 100%);
      min-height: 100vh;
    }
    .dashboard-shell {
      width: min(1780px, calc(100vw - 2rem));
      margin: 0 auto;
      padding: 0.95rem 0 1.35rem;
      display: grid;
      grid-template-columns: minmax(248px, 286px) minmax(0, 1fr);
      gap: 0.9rem;
      align-items: start;
    }
    .dashboard-main {
      display: flex;
      flex-direction: column;
      min-width: 0;
    }
    .dashboard-nav {
      position: sticky;
      top: 1rem;
      min-height: calc(100vh - 2rem);
      padding: 0.82rem 0.72rem 0.78rem;
      border-radius: 24px;
      background:
        linear-gradient(180deg, rgba(6, 10, 15, 0.992), rgba(4, 8, 13, 0.992)),
        radial-gradient(circle at top right, rgba(106, 169, 255, 0.06), transparent 32%);
      border: 1px solid rgba(255,255,255,0.04);
      box-shadow: 0 26px 80px rgba(0, 0, 0, 0.24);
      display: flex;
      flex-direction: column;
      gap: 0.72rem;
      overflow: hidden;
    }
    .nav-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 0.6rem;
      padding: 0 0.2rem 0.35rem;
    }
    .nav-brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      min-width: 0;
    }
    .nav-brand-mark {
      width: 34px;
      height: 34px;
      border-radius: 12px;
      display: grid;
      place-items: center;
      font-size: 0.82rem;
      font-weight: 700;
      letter-spacing: 0.06em;
      color: #ffffff;
      background:
        radial-gradient(circle at top, rgba(255, 121, 121, 0.24), transparent 58%),
        linear-gradient(135deg, rgba(189, 95, 95, 0.92), rgba(80, 34, 43, 0.98));
      border: 1px solid rgba(255,255,255,0.08);
    }
    .nav-brand-copy {
      min-width: 0;
    }
    .nav-brand-copy strong {
      display: block;
      color: #ffffff;
      font-size: 0.95rem;
      font-weight: 600;
      letter-spacing: -0.02em;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .nav-brand-copy span {
      display: block;
      margin-top: 0.14rem;
      color: var(--text-2);
      font-size: 0.76rem;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .nav-actions {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      flex: 0 0 auto;
    }
    .nav-action,
    .nav-toggle {
      width: 28px;
      height: 28px;
      padding: 0;
      border-radius: 9px;
      border: 1px solid rgba(255,255,255,0.06);
      background: rgba(255,255,255,0.03);
      color: rgba(224, 234, 244, 0.82);
      font: inherit;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: background 180ms ease, border-color 180ms ease, color 180ms ease, transform 180ms ease;
    }
    .nav-action:hover,
    .nav-toggle:hover {
      background: rgba(21, 36, 54, 0.82);
      border-color: rgba(106, 169, 255, 0.16);
      color: #ffffff;
      transform: translateY(-1px);
    }
    .nav-action:focus-visible,
    .nav-toggle:focus-visible {
      outline: 2px solid rgba(106, 169, 255, 0.5);
      outline-offset: 2px;
    }
    .nav-toggle-icon {
      font-size: 0.92rem;
      line-height: 1;
    }
    .nav-node-meta {
      display: flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0 0.25rem 0.55rem;
      color: var(--text-2);
      font-size: 0.74rem;
      border-bottom: 1px solid rgba(255,255,255,0.06);
    }
    .nav-meta-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #4fd1a3;
      box-shadow: 0 0 0 4px rgba(79, 209, 163, 0.12);
      flex: 0 0 auto;
    }
    .nav-node-meta strong {
      color: #ffffff;
      font-weight: 500;
    }
    .nav-menu {
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      min-height: 0;
      padding-top: 0.1rem;
    }
    .nav-list {
      display: flex;
      flex-direction: column;
      gap: 0.22rem;
    }
    .nav-item {
      display: flex;
      align-items: center;
      gap: 0.72rem;
      min-width: 0;
      padding: 0.62rem 0.68rem;
      border-radius: 12px;
      color: var(--text-1);
      text-decoration: none;
      background: transparent;
      border: 1px solid transparent;
      transition: background 180ms ease, border-color 180ms ease, color 180ms ease;
    }
    .nav-item:hover {
      background: rgba(17, 29, 44, 0.76);
      border-color: rgba(106, 169, 255, 0.1);
      color: #ffffff;
    }
    .nav-item.active {
      background: rgba(255,255,255,0.035);
      border-color: rgba(255,255,255,0.025);
      color: #ffffff;
    }
    .nav-item-group {
      display: flex;
      align-items: center;
      gap: 0.72rem;
      min-width: 0;
      flex: 1 1 auto;
    }
    .nav-icon {
      width: 14px;
      height: 14px;
      display: grid;
      place-items: center;
      color: rgba(216, 227, 239, 0.72);
      flex: 0 0 auto;
      font-size: 0.82rem;
    }
    .nav-copy {
      min-width: 0;
      font-size: 0.9rem;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .nav-branch {
      display: flex;
      flex-direction: column;
      gap: 0.2rem;
      margin: 0.05rem 0 0.18rem;
    }
    .nav-branch-label {
      display: flex;
      align-items: center;
      gap: 0.72rem;
      padding: 0.68rem 0.72rem;
      color: rgba(220, 230, 240, 0.82);
      font-size: 0.9rem;
    }
    .nav-tree {
      position: relative;
      display: flex;
      flex-direction: column;
      gap: 0.2rem;
      margin-left: 0.45rem;
      padding-left: 1.15rem;
    }
    .nav-tree::before {
      content: "";
      position: absolute;
      left: 0.32rem;
      top: 0.2rem;
      bottom: 0.35rem;
      width: 1px;
      background: rgba(255,255,255,0.08);
    }
    .nav-tree .nav-item {
      position: relative;
      padding-left: 0.9rem;
    }
    .nav-tree .nav-item::before {
      content: "";
      position: absolute;
      left: -0.85rem;
      top: 50%;
      width: 0.7rem;
      height: 1px;
      background: rgba(255,255,255,0.08);
    }
    .nav-secondary {
      margin-top: 0.45rem;
      padding-top: 0.55rem;
      border-top: 1px solid rgba(255,255,255,0.05);
    }
    .nav-support {
      margin-top: auto;
      padding: 0.88rem 0.92rem;
      border-radius: 18px;
      background:
        linear-gradient(180deg, rgba(10, 17, 27, 0.96), rgba(7, 13, 21, 0.96)),
        radial-gradient(circle at top right, rgba(244, 179, 99, 0.08), transparent 40%);
      border: 1px solid rgba(255,255,255,0.05);
    }
    .nav-support h3 {
      margin: 0;
      color: #ffffff;
      font-size: 0.95rem;
    }
    .nav-support p {
      margin: 0.4rem 0 0;
      color: var(--text-2);
      font-size: 0.76rem;
      line-height: 1.42;
    }
    .nav-support-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 0.45rem;
      margin-top: 0.8rem;
    }
    .nav-support-pill {
      display: inline-flex;
      align-items: center;
      padding: 0.35rem 0.6rem;
      border-radius: 999px;
      background: rgba(255,255,255,0.05);
      color: var(--text-1);
      font-size: 0.72rem;
    }
    .dashboard-shell.nav-collapsed {
      grid-template-columns: 74px minmax(0, 1fr);
    }
    .dashboard-shell.nav-collapsed .dashboard-nav {
      padding: 0.8rem 0.45rem;
      align-items: center;
    }
    .dashboard-shell.nav-collapsed .nav-brand-copy,
    .dashboard-shell.nav-collapsed .nav-copy,
    .dashboard-shell.nav-collapsed .nav-node-meta,
    .dashboard-shell.nav-collapsed .nav-tree,
    .dashboard-shell.nav-collapsed .nav-secondary,
    .dashboard-shell.nav-collapsed .nav-support,
    .dashboard-shell.nav-collapsed .nav-action {
      display: none;
    }
    .dashboard-shell.nav-collapsed .nav-head {
      width: 100%;
      justify-content: center;
      padding-bottom: 0.25rem;
    }
    .dashboard-shell.nav-collapsed .nav-brand {
      justify-content: center;
    }
    .dashboard-shell.nav-collapsed .nav-head .nav-brand {
      display: none;
    }
    .dashboard-shell.nav-collapsed .nav-menu,
    .dashboard-shell.nav-collapsed .nav-list {
      width: 100%;
      align-items: center;
    }
    .dashboard-shell.nav-collapsed .nav-item {
      width: 48px;
      justify-content: center;
      padding: 0.7rem 0;
    }
    .dashboard-shell.nav-collapsed .nav-item-group {
      justify-content: center;
      flex: 0 0 auto;
    }
    .dashboard-shell.nav-collapsed .nav-icon {
      width: 18px;
      height: 18px;
    }
    header {
      padding: 1rem 1.1rem 1.05rem;
      border: 1px solid rgba(255,255,255,0.05);
      border-radius: 24px;
      background:
        linear-gradient(135deg, rgba(16, 28, 42, 0.95), rgba(10, 20, 31, 0.94)),
        radial-gradient(circle at top right, rgba(106, 169, 255, 0.12), transparent 34%);
      box-shadow: 0 24px 70px rgba(0, 0, 0, 0.2);
      align-items: flex-start;
      gap: 0.85rem;
    }
    h1 {
      font-size: clamp(1.36rem, 2.4vw, 2rem);
      letter-spacing: -0.03em;
      line-height: 1.02;
      margin: 0;
    }
    .header-kicker {
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.16em;
      color: rgba(180, 205, 227, 0.72);
      margin-bottom: 0.42rem;
    }
    .header-subtitle {
      max-width: 56ch;
      margin-top: 0.55rem;
      color: var(--text-2);
      font-size: 0.86rem;
      line-height: 1.45;
    }
    .header-actions {
      flex-direction: column;
      align-items: stretch;
      min-width: min(320px, 100%);
    }
    .pill-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.55rem;
      justify-content: flex-end;
    }
    .hero-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.42rem 0.7rem;
      border-radius: 999px;
      background: rgba(19, 31, 46, 0.82);
      border: 1px solid rgba(158, 191, 225, 0.12);
      color: var(--text-1);
      font-size: 0.76rem;
      white-space: nowrap;
    }
    .hero-pill strong { color: #ffffff; font-weight: 600; }
    .toolbar {
      margin-top: 0.6rem;
      padding: 0.68rem 0.82rem;
      border-radius: 16px;
      background: rgba(10, 19, 30, 0.68);
      border: 1px solid rgba(255,255,255,0.05);
      font-size: 0.78rem;
      opacity: 1;
      color: var(--text-2);
    }
    #hero-analytics-grid {
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(420px, 0.9fr);
      gap: 0.9rem;
      margin-top: 0.85rem;
      align-items: stretch;
    }
    .hero-kpi-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 0.85rem;
      align-content: stretch;
    }
    .hero-kpi-card, .hero-spotlight-card {
      border-radius: 24px;
      border: 1px solid rgba(255,255,255,0.06);
      box-shadow: 0 24px 60px rgba(0, 0, 0, 0.22);
    }
    .hero-kpi-card {
      padding: 1rem 1rem 0.9rem;
      min-height: 172px;
      display: flex;
      flex-direction: column;
      gap: 0.72rem;
      background:
        radial-gradient(circle at top right, rgba(106, 169, 255, 0.12), transparent 38%),
        linear-gradient(180deg, rgba(16, 29, 43, 0.96), rgba(10, 20, 31, 0.96));
    }
    .hero-kpi-head {
      display: flex;
      justify-content: space-between;
      gap: 0.75rem;
      align-items: center;
    }
    .hero-kpi-actions {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
    }
    .hero-kpi-label {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      color: rgba(234, 243, 251, 0.92);
      font-size: 0.88rem;
    }
    .hero-kpi-dot {
      width: 11px;
      height: 11px;
      border-radius: 50%;
      box-shadow: 0 0 0 8px rgba(255,255,255,0.03);
    }
    .hero-kpi-dot.mem { background: #4fd1a3; }
    .hero-kpi-dot.net { background: #6aa9ff; }
    .hero-kpi-dot.events { background: #f4b363; }
    .hero-kpi-dot.intensity { background: #ff6d6d; }
    .hero-kpi-delta {
      padding: 0.34rem 0.6rem;
      border-radius: 999px;
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.05);
      color: var(--text-2);
      font-size: 0.74rem;
      white-space: nowrap;
    }
    .hero-kpi-delta.up { color: #4fd1a3; background: rgba(79, 209, 163, 0.08); border-color: rgba(79, 209, 163, 0.16); }
    .hero-kpi-delta.down { color: #ff8f8f; background: rgba(255, 109, 109, 0.08); border-color: rgba(255, 109, 109, 0.16); }
    .hero-kpi-value { font-size: clamp(1.5rem, 2vw, 2rem); line-height: 0.98; letter-spacing: -0.05em; color: #ffffff; }
    .hero-kpi-value.compact { font-size: clamp(0.98rem, 1.2vw, 1.2rem); line-height: 1.2; letter-spacing: -0.02em; }
    .hero-kpi-caption { color: var(--text-2); font-size: 0.8rem; line-height: 1.45; }
    .hero-kpi-spark { width: 100%; height: 82px; display: block; margin-top: auto; }
    .hero-kpi-axis {
      display: flex;
      justify-content: space-between;
      gap: 0.75rem;
      color: rgba(181, 200, 219, 0.62);
      font-size: 0.68rem;
      margin-top: -0.1rem;
    }
    .hero-kpi-expand {
      width: 32px;
      height: 32px;
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 50%;
      background: rgba(16, 28, 42, 0.82);
      color: rgba(231, 239, 247, 0.82);
      font: inherit;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      transition: background 160ms ease, border-color 160ms ease, color 160ms ease, transform 120ms ease;
    }
    .hero-kpi-expand:hover {
      background: rgba(34, 55, 83, 0.92);
      border-color: rgba(106, 169, 255, 0.18);
      color: #ffffff;
      transform: translateY(-1px);
    }
    .hero-spark-grid { stroke: rgba(181, 200, 219, 0.1); stroke-width: 1; stroke-dasharray: 4 5; }
    .hero-spark-area { opacity: 0.18; }
    .hero-spark-line { fill: none; stroke-width: 3; stroke-linecap: round; stroke-linejoin: round; }
    .hero-spark-line.class-a { stroke: #ff6d6d; }
    .hero-spark-line.class-b { stroke: #ffc971; }
    .hero-spark-line.class-c { stroke: #5aa5ff; }
    .hero-spotlight-card {
      padding: 1rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
      background:
        radial-gradient(circle at 18% 18%, rgba(255, 201, 113, 0.1), transparent 34%),
        radial-gradient(circle at 85% 20%, rgba(106, 169, 255, 0.1), transparent 28%),
        linear-gradient(180deg, rgba(16, 29, 43, 0.97), rgba(10, 20, 31, 0.97));
    }
    .hero-spotlight-top { display: flex; justify-content: space-between; gap: 0.85rem; align-items: flex-start; }
    .hero-spotlight-kicker { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.16em; color: rgba(181, 200, 219, 0.68); margin-bottom: 0.45rem; }
    .hero-spotlight-headline { margin: 0; font-size: 1.08rem; letter-spacing: -0.02em; }
    .hero-spotlight-copy { margin-top: 0.3rem; color: var(--text-2); font-size: 0.82rem; line-height: 1.45; max-width: 44ch; }
    .hero-spotlight-pills { display: flex; flex-wrap: wrap; gap: 0.45rem; justify-content: flex-end; }
    .hero-spot-pill { padding: 0.36rem 0.68rem; border-radius: 999px; border: 1px solid rgba(255,255,255,0.05); background: rgba(10, 19, 30, 0.72); color: var(--text-2); font-size: 0.74rem; white-space: nowrap; }
    .hero-spot-pill.ok { color: #4fd1a3; background: rgba(79, 209, 163, 0.08); border-color: rgba(79, 209, 163, 0.16); }
    .hero-spot-pill.warn { color: #ffc971; background: rgba(255, 201, 113, 0.08); border-color: rgba(255, 201, 113, 0.16); }
    .hero-spot-pill.alert { color: #ff8f8f; background: rgba(255, 109, 109, 0.08); border-color: rgba(255, 109, 109, 0.16); }
    .hero-spotlight-body { display: grid; grid-template-columns: 250px minmax(0, 1fr); gap: 1rem; align-items: center; }
    #hero-class-donut { width: 240px; height: 240px; border-radius: 50%; margin: 0 auto; position: relative; background: conic-gradient(#223344 0deg, #223344 360deg); box-shadow: inset 0 0 0 18px rgba(8, 16, 25, 0.86); }
    #hero-class-donut::after { content: ""; position: absolute; inset: 28px; border-radius: 50%; background: rgba(8, 16, 25, 0.97); border: 1px solid rgba(255,255,255,0.05); }
    .hero-class-breakdown { display: flex; flex-direction: column; gap: 0.75rem; }
    .hero-spotlight-stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.65rem; margin-top: 0.2rem; }
    .hero-spot-stat { padding: 0.78rem 0.82rem; border-radius: 16px; background: rgba(8, 18, 29, 0.76); border: 1px solid rgba(255,255,255,0.05); }
    .hero-spot-stat-label { color: rgba(181, 200, 219, 0.68); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em; }
    .hero-spot-stat-value { margin-top: 0.35rem; color: #ffffff; font-size: 0.98rem; font-weight: 600; }
    .analytics-modal-shell { position: fixed; inset: 0; display: none; align-items: center; justify-content: center; padding: 1.5rem; z-index: 295; }
    .analytics-modal-shell.open { display: flex; }
    .analytics-modal-backdrop { position: absolute; inset: 0; background: rgba(5, 10, 18, 0.72); backdrop-filter: blur(4px); }
    .analytics-modal {
      position: relative;
      width: min(1080px, calc(100vw - 2rem));
      max-height: calc(100vh - 2rem);
      overflow: auto;
      padding: 1.2rem;
      border-radius: 24px;
      background: linear-gradient(180deg, rgba(16, 29, 43, 0.98), rgba(10, 20, 31, 0.97));
      border: 1px solid rgba(255,255,255,0.07);
      box-shadow: 0 28px 80px rgba(0, 0, 0, 0.35);
      z-index: 1;
    }
    .analytics-modal-head { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; margin-bottom: 1rem; }
    .analytics-modal-head h3 { margin: 0; color: #ffffff; font-size: 1.08rem; }
    .analytics-modal-stage {
      border-radius: 18px;
      background: radial-gradient(circle at top, rgba(255,255,255,0.04), transparent 60%), rgba(8, 16, 25, 0.82);
      border: 1px solid rgba(255,255,255,0.05);
      padding: 1rem;
    }
    .analytics-modal-legend { display: flex; flex-wrap: wrap; gap: 0.55rem; margin-bottom: 0.75rem; }
    .analytics-modal-chart { width: 100%; height: 320px; display: block; }
    .analytics-modal-caption { display: flex; justify-content: space-between; gap: 1rem; margin-top: 0.8rem; color: var(--text-2); font-size: 0.78rem; }
    #overview-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 0.85rem;
      margin-top: 0.85rem;
      align-items: start;
    }
    .overview-card,
    .panel-surface {
      background: linear-gradient(180deg, rgba(16, 29, 43, 0.95), rgba(10, 20, 31, 0.94));
      border: 1px solid var(--line-soft);
      border-radius: 24px;
      box-shadow: var(--shadow-soft);
    }
    .overview-card {
      padding: 0.9rem 0.95rem 0.95rem;
      min-height: 0;
      display: flex;
      flex-direction: column;
      gap: 0.72rem;
    }
    .overview-card h2,
    .controls-title,
    .filters-title,
    .timeline-title,
    .panel-heading h3 {
      margin: 0;
      font-size: 0.88rem;
      text-transform: uppercase;
      letter-spacing: 0.11em;
      color: rgba(186, 206, 226, 0.72);
    }
    .hero-value {
      font-size: 1.48rem;
      line-height: 1;
      letter-spacing: -0.04em;
      color: #ffffff;
    }
    .hero-meta, .metrics-strip {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 0.55rem;
    }
    .meta-chip, .metric-box, .peer-summary-item, .activity-item {
      padding: 0.62rem 0.72rem;
      border-radius: 14px;
      background: rgba(9, 20, 31, 0.72);
      border: 1px solid rgba(255,255,255,0.05);
    }
    .meta-chip-label, .metric-box-label {
      display: block;
      font-size: 0.72rem;
      color: rgba(181, 200, 219, 0.72);
      margin-bottom: 0.25rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .meta-chip-value, .metric-box-value {
      display: block;
      font-size: 1rem;
      color: #ffffff;
      font-weight: 600;
    }
    .role-value-link {
      color: #d9e9ff;
      text-decoration: none;
      border-bottom: 1px dashed rgba(106, 169, 255, 0.42);
      padding-bottom: 1px;
    }
    .role-value-link:hover {
      color: #ffffff;
      border-bottom-color: rgba(154, 197, 255, 0.78);
    }
    #metrics {
      margin-top: 0;
      font-family: 'IBM Plex Mono', 'JetBrains Mono', monospace;
      color: var(--text-2);
      background: rgba(9, 18, 28, 0.72);
      border-radius: 16px;
      padding: 0.8rem 0.9rem;
      border: 1px solid rgba(255,255,255,0.04);
      min-height: 96px;
    }
    #consensus-status, #graph-status {
      margin-top: 0;
      padding: 0.75rem 0.85rem;
      border-radius: 16px;
      background: rgba(9, 19, 30, 0.8);
      border: 1px solid rgba(255,255,255,0.05);
      font-size: 0.86rem;
    }
    #consensus-peer-summary, #activity-feed {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      margin: 0;
      padding: 0;
      list-style: none;
    }
    .peer-summary-item strong, .activity-item strong { color: #ffffff; font-weight: 600; }
    .intensity-grid {
      display: flex;
      flex-direction: column;
      gap: 0.55rem;
    }
    .intensity-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 0.75rem;
      align-items: center;
      padding: 0.7rem 0.8rem;
      border-radius: 16px;
      background: rgba(9, 20, 31, 0.86);
      border: 1px solid rgba(255,255,255,0.05);
    }
    .intensity-title {
      color: #ffffff;
      font-size: 0.9rem;
      font-weight: 600;
    }
    .intensity-meta {
      margin-top: 0.2rem;
      color: var(--text-2);
      font-size: 0.76rem;
      line-height: 1.4;
    }
    .intensity-rate {
      text-align: right;
      color: #ffffff;
      font-size: 1rem;
      font-weight: 600;
      white-space: nowrap;
    }
    .intensity-rate small {
      display: block;
      margin-top: 0.2rem;
      color: var(--text-2);
      font-size: 0.72rem;
      font-weight: 400;
    }
    #workspace {
      --workspace-stage-height: clamp(760px, 78vh, 980px);
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr) 320px;
      gap: 0.9rem;
      margin-top: 0.9rem;
      align-items: stretch;
      min-height: var(--workspace-stage-height);
    }
    .rail-stack {
      display: flex;
      flex-direction: column;
      gap: 1rem;
      align-self: stretch;
      min-height: 0;
      height: var(--workspace-stage-height);
    }
    #workspace > .rail-stack > .panel-surface:last-child {
      flex: 1 1 auto;
      min-height: 0;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .panel-surface { padding: 0.92rem; }
    .panel-heading {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      align-items: baseline;
      margin-bottom: 0.85rem;
    }
    .panel-hint { color: var(--text-2); font-size: 0.82rem; }
    #workspace > .rail-stack > .panel-surface,
    #workspace > .rail-stack > section.panel-surface {
      border-radius: 24px;
    }
    #controls, #reset-controls, #filters, #timeline, #legend { padding: 0; background: transparent; border: none; }
    #controls-status, #reset-controls-status {
      margin-top: 0.1rem;
      padding: 0.7rem 0.8rem;
      border-radius: 14px;
      background: rgba(9, 19, 30, 0.82);
      border: 1px solid rgba(255,255,255,0.05);
    }
    .sim-button, .toggle-button, .timeline-item { border-radius: 14px; font-family: inherit; }
    .sim-button { background: rgba(30, 49, 74, 0.92); }
    .toggle-button { background: rgba(19, 34, 52, 0.86); }
    #legend {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      flex: 1 1 auto;
      min-height: 0;
      justify-content: flex-start;
      overflow: auto;
      padding-right: 0.2rem;
    }
    .legend-item {
      padding: 0.58rem 0.7rem;
      border-radius: 14px;
      background: rgba(8, 18, 29, 0.78);
      border: 1px solid rgba(255,255,255,0.05);
      align-items: flex-start;
    }
    .legend-item .label {
      font-size: 0.74rem;
      line-height: 1.32;
    }
    #graph-panel {
      overflow: hidden;
      padding: 0;
      display: flex;
      flex-direction: column;
      align-self: stretch;
      min-height: 0;
      height: var(--workspace-stage-height);
    }
    .graph-panel-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      padding: 1rem 1rem 0.9rem;
    }
    .graph-panel-head h2 { margin: 0; font-size: 1.05rem; letter-spacing: -0.02em; }
    .graph-panel-head p { margin: 0.35rem 0 0; color: var(--text-2); font-size: 0.85rem; }
    .graph-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.55rem 0.8rem;
      border-radius: 999px;
      background: rgba(11, 21, 33, 0.9);
      border: 1px solid rgba(255,255,255,0.06);
      font-size: 0.8rem;
      color: var(--text-1);
    }
    #graph-wrapper {
      width: 100%;
      height: auto;
      flex: 1 1 auto;
      min-height: 560px;
      max-height: 100%;
      overflow: auto;
      border-top: 1px solid rgba(255,255,255,0.05);
      background:
        radial-gradient(circle at top, rgba(255,255,255,0.05), transparent 55%),
        linear-gradient(180deg, rgba(7, 15, 24, 0.96), rgba(5, 11, 18, 0.98));
    }
    #graph {
      width: max-content;
      height: max-content;
      min-width: 100%;
      min-height: 100%;
      overflow: visible;
    }
    #timeline-items { max-height: 72vh; overflow: auto; padding-right: 0.25rem; }
    .timeline-item { width: 100%; text-align: left; background: rgba(12, 23, 36, 0.84); }
    .timeline-item.active { background: rgba(56, 86, 132, 0.95); }
    #analytics-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 1rem;
      margin-top: 1rem;
      align-items: start;
    }
    .analytics-stack {
      display: flex;
      flex-direction: column;
      gap: 1rem;
      align-self: start;
    }
    .chart-card {
      min-height: 0;
    }
    .chart-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      margin-bottom: 0.9rem;
    }
    .chart-head h3 {
      margin: 0;
      font-size: 1.02rem;
      letter-spacing: -0.02em;
    }
    .chart-subtitle {
      color: var(--text-2);
      font-size: 0.82rem;
      margin-top: 0.2rem;
    }
    .chart-stage {
      border-radius: 18px;
      background:
        radial-gradient(circle at top, rgba(255,255,255,0.04), transparent 60%),
        rgba(8, 16, 25, 0.82);
      border: 1px solid rgba(255,255,255,0.05);
      padding: 0.9rem;
    }
    .chart-toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.8rem;
      margin-bottom: 0.75rem;
    }
    .chart-tabs {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      flex-wrap: wrap;
    }
    .chart-tab {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.42rem 0.7rem;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,0.05);
      background: rgba(14, 25, 38, 0.88);
      color: var(--text-2);
      font: inherit;
      font-size: 0.76rem;
      cursor: pointer;
      transition: background 180ms ease, border-color 180ms ease, color 180ms ease;
    }
    .chart-tab:hover {
      color: #ffffff;
      border-color: rgba(106, 169, 255, 0.12);
    }
    .chart-tab.active {
      background: rgba(36, 59, 89, 0.92);
      border-color: rgba(106, 169, 255, 0.18);
      color: #ffffff;
    }
    .trend-legend {
      display: flex;
      flex-wrap: wrap;
      gap: 0.55rem;
    }
    .trend-chip {
      display: inline-flex;
      align-items: center;
      gap: 0.42rem;
      padding: 0.42rem 0.65rem;
      border-radius: 999px;
      background: rgba(14, 25, 38, 0.88);
      border: 1px solid rgba(255,255,255,0.05);
      font-size: 0.76rem;
      color: var(--text-1);
    }
    .trend-dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
    .trend-dot.mem { background: #4fd1a3; }
    .trend-dot.net { background: #6aa9ff; }
    .trend-dot.events { background: #f4b363; }
    .trend-dot.class-a { background: #ff6d6d; }
    .trend-dot.class-b { background: #ffc971; }
    .trend-dot.class-c { background: #5aa5ff; }
    #trend-chart {
      width: 100%;
      height: 220px;
      display: block;
    }
    .chart-axis-notes {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      margin-bottom: 0.65rem;
      color: rgba(181, 200, 219, 0.72);
      font-size: 0.74rem;
    }
    .grid-line {
      stroke: rgba(185, 206, 224, 0.12);
      stroke-width: 1;
      stroke-dasharray: 4 6;
    }
    .trend-line {
      fill: none;
      stroke-width: 3;
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    .trend-line.mem { stroke: #4fd1a3; }
    .trend-line.net { stroke: #6aa9ff; }
    .trend-line.events { stroke: #f4b363; }
    .trend-line.class-a { stroke: #ff6d6d; }
    .trend-line.class-b { stroke: #ffc971; }
    .trend-line.class-c { stroke: #5aa5ff; }
    .trend-caption {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      margin-top: 0.75rem;
      color: var(--text-2);
      font-size: 0.78rem;
    }
    #class-donut {
      width: 230px;
      height: 230px;
      border-radius: 50%;
      margin: 0 auto;
      position: relative;
      background: conic-gradient(#223344 0deg, #223344 360deg);
      box-shadow: inset 0 0 0 18px rgba(8, 16, 25, 0.85);
    }
    #class-donut::after {
      content: "";
      position: absolute;
      inset: 26px;
      border-radius: 50%;
      background: rgba(8, 16, 25, 0.96);
      border: 1px solid rgba(255,255,255,0.05);
    }
    .donut-center {
      position: absolute;
      inset: 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      z-index: 1;
      text-align: center;
      pointer-events: none;
    }
    .donut-total {
      font-size: 2rem;
      line-height: 1;
      letter-spacing: -0.04em;
      color: #ffffff;
    }
    .donut-label { margin-top: 0.35rem; font-size: 0.85rem; color: var(--text-2); }
    .donut-layout {
      display: grid;
      grid-template-columns: 240px minmax(0, 1fr);
      gap: 1rem;
      align-items: center;
    }
    #class-breakdown, #source-summary, #alert-window {
      display: flex;
      flex-direction: column;
      gap: 0.7rem;
    }
    .class-row {
      display: grid;
      grid-template-columns: auto 1fr auto;
      gap: 0.75rem;
      align-items: center;
      font-size: 0.84rem;
      color: var(--text-1);
    }
    .class-row-bar {
      height: 10px;
      border-radius: 999px;
      overflow: hidden;
      background: rgba(255,255,255,0.06);
    }
    .class-row-fill { height: 100%; border-radius: inherit; }
    .class-row-fill.a { background: #ff6d6d; }
    .class-row-fill.b { background: #ffc971; }
    .class-row-fill.c { background: #5aa5ff; }
    .class-row-badge { width: 12px; height: 12px; border-radius: 50%; display: inline-block; }
    .class-row-badge.a { background: #ff6d6d; }
    .class-row-badge.b { background: #ffc971; }
    .class-row-badge.c { background: #5aa5ff; }
    .source-row {
      padding: 0.8rem 0.85rem;
      border-radius: 16px;
      background: rgba(9, 18, 29, 0.78);
      border: 1px solid rgba(255,255,255,0.05);
    }
    .source-row-head {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      align-items: baseline;
      margin-bottom: 0.45rem;
      color: #ffffff;
      font-size: 0.86rem;
    }
    .source-row-bars {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 0.5rem;
    }
    .source-mini {
      padding: 0.55rem 0.6rem;
      border-radius: 12px;
      background: rgba(255,255,255,0.03);
      font-size: 0.76rem;
      color: var(--text-2);
    }
    .source-mini strong {
      display: block;
      color: #ffffff;
      font-size: 1rem;
      margin-top: 0.15rem;
    }
    #alert-window {
      max-height: 500px;
      overflow: auto;
      padding-right: 0.15rem;
      flex: 1 1 auto;
      min-height: 0;
    }
    .alert-item {
      padding: 0.85rem 0.9rem;
      border-radius: 16px;
      border: 1px solid rgba(255,255,255,0.05);
      background: rgba(10, 19, 29, 0.82);
    }
    .alert-item.high { border-color: rgba(255, 109, 109, 0.28); }
    .alert-item.medium { border-color: rgba(255, 201, 113, 0.2); }
    .alert-item.info { border-color: rgba(106, 169, 255, 0.18); }
    .alert-meta {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      align-items: center;
      margin-bottom: 0.45rem;
    }
    .alert-level {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.28rem 0.55rem;
      border-radius: 999px;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      background: rgba(255,255,255,0.05);
    }
    .alert-title { color: #ffffff; font-size: 0.9rem; font-weight: 600; }
    .alert-text { color: var(--text-2); font-size: 0.82rem; line-height: 1.45; }
    #analytics-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 1rem;
      margin-top: 1rem;
      align-items: start;
    }
    .analytics-stack {
      display: flex;
      flex-direction: column;
      gap: 1rem;
      align-self: start;
      width: 100%;
    }
    .chart-card {
      min-height: 0;
    }
    .chart-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      margin-bottom: 0.9rem;
    }
    .chart-head h3 {
      margin: 0;
      font-size: 1.02rem;
      letter-spacing: -0.02em;
    }
    .chart-subtitle {
      color: var(--text-2);
      font-size: 0.82rem;
      margin-top: 0.2rem;
    }
    .chart-stage {
      border-radius: 18px;
      background:
        radial-gradient(circle at top, rgba(255,255,255,0.04), transparent 60%),
        rgba(8, 16, 25, 0.82);
      border: 1px solid rgba(255,255,255,0.05);
      padding: 0.9rem;
    }
    .trend-legend {
      display: flex;
      flex-wrap: wrap;
      gap: 0.55rem;
      margin-bottom: 0.75rem;
    }
    .trend-chip {
      display: inline-flex;
      align-items: center;
      gap: 0.42rem;
      padding: 0.42rem 0.65rem;
      border-radius: 999px;
      background: rgba(14, 25, 38, 0.88);
      border: 1px solid rgba(255,255,255,0.05);
      font-size: 0.76rem;
      color: var(--text-1);
    }
    .trend-dot {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      display: inline-block;
    }
    .trend-dot.mem { background: #4fd1a3; }
    .trend-dot.net { background: #6aa9ff; }
    .trend-dot.events { background: #f4b363; }
    #trend-chart {
      width: 100%;
      height: 220px;
      display: block;
    }
    .grid-line {
      stroke: rgba(185, 206, 224, 0.12);
      stroke-width: 1;
      stroke-dasharray: 4 6;
    }
    .trend-line {
      fill: none;
      stroke-width: 3;
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    .trend-line.mem { stroke: #4fd1a3; }
    .trend-line.net { stroke: #6aa9ff; }
    .trend-line.events { stroke: #f4b363; }
    .trend-caption {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      margin-top: 0.75rem;
      color: var(--text-2);
      font-size: 0.78rem;
    }
    #class-donut {
      width: 230px;
      height: 230px;
      border-radius: 50%;
      margin: 0 auto;
      position: relative;
      background: conic-gradient(#223344 0deg, #223344 360deg);
      box-shadow: inset 0 0 0 18px rgba(8, 16, 25, 0.85);
    }
    #class-donut::after {
      content: "";
      position: absolute;
      inset: 26px;
      border-radius: 50%;
      background: rgba(8, 16, 25, 0.96);
      border: 1px solid rgba(255,255,255,0.05);
    }
    .donut-center {
      position: absolute;
      inset: 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      z-index: 1;
      text-align: center;
      pointer-events: none;
    }
    .donut-total {
      font-size: 2rem;
      line-height: 1;
      letter-spacing: -0.04em;
      color: #ffffff;
    }
    .donut-label {
      margin-top: 0.35rem;
      font-size: 0.85rem;
      color: var(--text-2);
    }
    .donut-layout {
      display: grid;
      grid-template-columns: 240px minmax(0, 1fr);
      gap: 1rem;
      align-items: center;
    }
    #class-breakdown {
      display: flex;
      flex-direction: column;
      gap: 0.65rem;
    }
    .class-row {
      display: grid;
      grid-template-columns: auto 1fr auto;
      gap: 0.75rem;
      align-items: center;
      font-size: 0.84rem;
      color: var(--text-1);
    }
    .class-row-bar {
      height: 10px;
      border-radius: 999px;
      overflow: hidden;
      background: rgba(255,255,255,0.06);
    }
    .class-row-fill {
      height: 100%;
      border-radius: inherit;
    }
    .class-row-fill.a { background: #ff6d6d; }
    .class-row-fill.b { background: #ffc971; }
    .class-row-fill.c { background: #5aa5ff; }
    .class-row-badge {
      width: 12px;
      height: 12px;
      border-radius: 50%;
      display: inline-block;
    }
    .class-row-badge.a { background: #ff6d6d; }
    .class-row-badge.b { background: #ffc971; }
    .class-row-badge.c { background: #5aa5ff; }
    #source-summary {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }
    .source-row {
      padding: 0.8rem 0.85rem;
      border-radius: 16px;
      background: rgba(9, 18, 29, 0.78);
      border: 1px solid rgba(255,255,255,0.05);
    }
    .source-row-head {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      align-items: baseline;
      margin-bottom: 0.45rem;
      color: #ffffff;
      font-size: 0.86rem;
    }
    .source-row-bars {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 0.5rem;
    }
    .source-mini {
      padding: 0.55rem 0.6rem;
      border-radius: 12px;
      background: rgba(255,255,255,0.03);
      font-size: 0.76rem;
      color: var(--text-2);
    }
    .source-mini strong {
      display: block;
      color: #ffffff;
      font-size: 1rem;
      margin-top: 0.15rem;
    }
    #alert-window {
      display: flex;
      flex-direction: column;
      gap: 0.7rem;
      max-height: 500px;
      overflow: auto;
      padding-right: 0.15rem;
    }
    .alert-item {
      padding: 0.85rem 0.9rem;
      border-radius: 16px;
      border: 1px solid rgba(255,255,255,0.05);
      background: rgba(10, 19, 29, 0.82);
    }
    .alert-item.high { border-color: rgba(255, 109, 109, 0.28); }
    .alert-item.medium { border-color: rgba(255, 201, 113, 0.2); }
    .alert-item.info { border-color: rgba(106, 169, 255, 0.18); }
    .alert-meta {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      align-items: center;
      margin-bottom: 0.45rem;
    }
    .alert-level {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.28rem 0.55rem;
      border-radius: 999px;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      background: rgba(255,255,255,0.05);
    }
    .alert-title {
      color: #ffffff;
      font-size: 0.9rem;
      font-weight: 600;
    }
    .alert-text {
      color: var(--text-2);
      font-size: 0.82rem;
      line-height: 1.45;
    }
    #incident-workbench {
      margin-top: 1rem;
    }
    .incident-shell {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    #incident-table-view {
      min-height: 0;
    }
    .incident-toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;
      margin-bottom: 0.9rem;
    }
    .incident-badges, .incident-view-switch, .incident-label-cluster, .incident-card-meta, .incident-filter-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.45rem;
      align-items: center;
    }
    .incident-badge, .incident-status-pill, .incident-priority-pill, .incident-label-chip {
      display: inline-flex;
      align-items: center;
      padding: 0.3rem 0.55rem;
      border-radius: 999px;
      font-size: 0.72rem;
      background: rgba(255,255,255,0.05);
      color: var(--text-1);
      border: 1px solid rgba(255,255,255,0.05);
    }
    .incident-badge.primary { background: rgba(255, 121, 121, 0.12); color: #ffaaaa; }
    .incident-priority-pill.high { background: rgba(255, 109, 109, 0.14); color: #ff9d9d; }
    .incident-priority-pill.medium { background: rgba(255, 201, 113, 0.14); color: #ffd78c; }
    .incident-priority-pill.low { background: rgba(106, 169, 255, 0.12); color: #8ec0ff; }
    .incident-event-class {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      color: #ffffff;
      font-weight: 600;
      white-space: nowrap;
    }
    .incident-event-class::before {
      content: '';
      width: 0.68rem;
      height: 0.68rem;
      border-radius: 50%;
      background: rgba(255,255,255,0.2);
      box-shadow: 0 0 0 1px rgba(255,255,255,0.08);
      flex: 0 0 auto;
    }
    .incident-event-class.a::before { background: #ff6d6d; }
    .incident-event-class.b::before { background: #ffc971; }
    .incident-event-class.c::before { background: #5aa5ff; }
    .incident-view-btn, .incident-action-btn, .incident-save-btn, .incident-cancel-btn, .incident-add-btn, .incident-check-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.55rem 0.85rem;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.07);
      background: rgba(16, 29, 43, 0.9);
      color: #ffffff;
      font: inherit;
      font-size: 0.8rem;
      cursor: pointer;
      transition: background 180ms ease, border-color 180ms ease, transform 180ms ease;
    }
    .incident-view-btn.active, .incident-save-btn { background: rgba(36, 59, 89, 0.92); border-color: rgba(106, 169, 255, 0.18); }
    .incident-view-btn:hover, .incident-action-btn:hover, .incident-save-btn:hover, .incident-cancel-btn:hover, .incident-add-btn:hover, .incident-check-btn:hover { background: rgba(26, 43, 63, 0.94); border-color: rgba(106, 169, 255, 0.16); transform: translateY(-1px); }
    .incident-filter-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 2.5rem;
      padding: 0.45rem 0.72rem;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,0.07);
      background: rgba(16, 29, 43, 0.62);
      color: var(--text-2);
      font: inherit;
      font-size: 0.76rem;
      cursor: pointer;
      transition: background 180ms ease, border-color 180ms ease, color 180ms ease;
    }
    .incident-filter-btn.active {
      background: rgba(36, 59, 89, 0.92);
      border-color: rgba(106, 169, 255, 0.18);
      color: #ffffff;
    }
    .incident-filter-input, .incident-group-select {
      padding: 0.55rem 0.8rem;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.07);
      background: rgba(16, 29, 43, 0.9);
      color: #ffffff;
      font: inherit;
      font-size: 0.8rem;
      box-sizing: border-box;
    }
    .incident-filter-input { min-width: 280px; }
    .incident-group-select { min-width: 220px; }
    .incident-table-wrap {
      width: 100%;
      max-height: clamp(460px, 58vh, 760px);
      overflow-x: auto;
      overflow-y: auto;
      border-radius: 18px;
      background: rgba(8, 16, 25, 0.5);
      border: 1px solid rgba(255,255,255,0.04);
    }
    .incident-table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
    .incident-table { min-width: 1460px; }
    .incident-table thead th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: rgba(13, 24, 36, 0.98);
      backdrop-filter: blur(8px);
    }
    .incident-table th, .incident-table td { padding: 0.9rem 0.8rem; border-bottom: 1px solid rgba(255,255,255,0.06); text-align: left; vertical-align: top; }
    .incident-table th { color: rgba(186, 206, 226, 0.72); font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 500; }
    .incident-table td { color: var(--text-1); }
    .incident-group-row td {
      padding: 0.72rem 0.8rem;
      background: rgba(18, 32, 48, 0.92);
      color: #ffffff;
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      border-bottom: 1px solid rgba(255,255,255,0.06);
    }
    #network-workbench {
      margin-top: 1rem;
    }
    .network-shell {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .network-toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .network-summary {
      display: flex;
      flex-wrap: wrap;
      gap: 0.55rem;
    }
    .network-consensus-card {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      padding: 0.85rem 0.95rem;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,0.05);
      background: rgba(10, 19, 29, 0.72);
    }
    .network-consensus-copy {
      display: flex;
      flex-direction: column;
      gap: 0.2rem;
    }
    .network-stat {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.38rem 0.68rem;
      border-radius: 999px;
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.05);
      color: var(--text-1);
      font-size: 0.76rem;
    }
    .network-add-form {
      display: grid;
      grid-template-columns: minmax(260px, 1.5fr) minmax(220px, 1fr) auto;
      gap: 0.65rem;
      align-items: end;
    }
    .network-field {
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
    }
    .network-field label {
      font-size: 0.72rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--text-3);
    }
    .network-field input {
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,0.08);
      background: rgba(10, 19, 29, 0.82);
      color: #ffffff;
      padding: 0.74rem 0.82rem;
      font-size: 0.88rem;
      outline: none;
    }
    .network-field input:focus {
      border-color: rgba(106, 169, 255, 0.35);
      box-shadow: 0 0 0 1px rgba(106, 169, 255, 0.18);
    }
    .network-action-btn {
      border: 1px solid rgba(255,255,255,0.08);
      background: rgba(255,255,255,0.04);
      color: #ffffff;
      border-radius: 14px;
      padding: 0.74rem 0.95rem;
      cursor: pointer;
      font-size: 0.84rem;
      transition: background 0.18s ease, transform 0.18s ease;
    }
    .network-action-btn.primary {
      background: rgba(90, 165, 255, 0.14);
      border-color: rgba(90, 165, 255, 0.22);
      color: #b6d6ff;
    }
    .network-action-btn.warn {
      background: rgba(255, 201, 113, 0.12);
      border-color: rgba(255, 201, 113, 0.18);
      color: #ffd78c;
    }
    .network-action-btn.danger {
      background: rgba(255, 109, 109, 0.12);
      border-color: rgba(255, 109, 109, 0.18);
      color: #ffaaaa;
    }
    .network-action-btn:hover {
      transform: translateY(-1px);
      background: rgba(255,255,255,0.08);
    }
    .network-action-btn:disabled {
      opacity: 0.55;
      cursor: default;
      transform: none;
    }
    .network-table-wrap {
      overflow: auto;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,0.05);
      background: rgba(9, 18, 29, 0.78);
    }
    .network-table {
      width: 100%;
      min-width: 980px;
      border-collapse: collapse;
    }
    .network-table th,
    .network-table td {
      text-align: left;
      padding: 0.82rem 0.9rem;
      border-bottom: 1px solid rgba(255,255,255,0.05);
      vertical-align: middle;
    }
    .network-table th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: rgba(14, 25, 38, 0.96);
      color: var(--text-3);
      font-size: 0.72rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .network-table td {
      color: var(--text-1);
      font-size: 0.86rem;
    }
    .network-mode-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.28rem 0.56rem;
      border-radius: 999px;
      font-size: 0.72rem;
      border: 1px solid rgba(255,255,255,0.06);
      background: rgba(255,255,255,0.05);
    }
    .network-mode-pill.enabled {
      color: #8cf0b8;
      background: rgba(87, 227, 147, 0.1);
      border-color: rgba(87, 227, 147, 0.18);
    }
    .network-mode-pill.disabled {
      color: #ffd78c;
      background: rgba(255, 201, 113, 0.1);
      border-color: rgba(255, 201, 113, 0.18);
    }
    .network-note-input {
      width: 100%;
      min-width: 180px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.08);
      background: rgba(255,255,255,0.03);
      color: #ffffff;
      padding: 0.55rem 0.65rem;
      font-size: 0.82rem;
    }
    .network-role-select {
      min-width: 150px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.08);
      background: rgba(255,255,255,0.03);
      color: #ffffff;
      padding: 0.55rem 0.65rem;
      font-size: 0.82rem;
    }
    .network-row-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.45rem;
    }
    .incident-row-title, .incident-card-title { color: #ffffff; font-weight: 600; }
    .incident-mini, .incident-card-desc { display: block; margin-top: 0.18rem; color: var(--text-2); font-size: 0.74rem; line-height: 1.45; }
    .incident-table-note { color: var(--text-2); max-width: 220px; line-height: 1.45; }
    .incident-board { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; }
    .incident-column { display: flex; flex-direction: column; gap: 0.75rem; padding: 0.9rem; border-radius: 18px; background: rgba(8, 16, 25, 0.76); border: 1px solid rgba(255,255,255,0.05); min-height: 220px; max-height: calc(100vh - 200px); }
    .incident-column-body { display: flex; flex-direction: column; gap: 0.75rem; overflow-y: auto; overflow-x: hidden; flex: 1 1 auto; min-height: 0; padding-right: 4px; }
    .incident-column-body::-webkit-scrollbar { width: 8px; }
    .incident-column-body::-webkit-scrollbar-thumb { background: rgba(150,190,255,0.25); border-radius: 4px; }
    .incident-column-head { position: sticky; top: 0; }
    .cmap-leg-row { display: flex; align-items: center; gap: 8px; margin-bottom: 0.55rem; color: var(--text-2); }
    .cmap-leg-ic { display: inline-flex; align-items: center; justify-content: center; width: 26px; height: 26px; border-radius: 7px; border: 1.5px solid #888; background: rgba(255,255,255,0.04); font-size: 14px; }
    .incident-column.drag-over { border-color: rgba(106, 169, 255, 0.22); background: rgba(14, 25, 38, 0.92); }
    .incident-column-head { display: flex; justify-content: space-between; gap: 0.6rem; align-items: center; }
    .incident-column-head h4 { margin: 0; color: #ffffff; font-size: 0.9rem; }
    .incident-column-count { color: var(--text-2); font-size: 0.74rem; }
    .incident-card { padding: 0.85rem 0.9rem; border-radius: 16px; background: rgba(17, 29, 44, 0.86); border: 1px solid rgba(255,255,255,0.05); cursor: grab; display: flex; flex-direction: column; gap: 0.55rem; }
    .incident-card:active { cursor: grabbing; }
    .incident-empty { padding: 1rem; border-radius: 16px; border: 1px dashed rgba(255,255,255,0.08); color: var(--text-2); font-size: 0.78rem; text-align: center; }
    .incident-modal-shell { position: fixed; inset: 0; display: none; align-items: center; justify-content: center; padding: 1.5rem; z-index: 280; }
    .incident-modal-shell.open { display: flex; }
    .incident-modal-backdrop { position: absolute; inset: 0; background: rgba(5, 10, 18, 0.72); backdrop-filter: blur(3px); }
    .incident-modal { position: relative; width: min(980px, calc(100vw - 2rem)); max-height: calc(100vh - 2rem); overflow: auto; padding: 1.2rem; border-radius: 24px; background: linear-gradient(180deg, rgba(16, 29, 43, 0.98), rgba(10, 20, 31, 0.97)); border: 1px solid rgba(255,255,255,0.07); box-shadow: 0 28px 80px rgba(0, 0, 0, 0.35); z-index: 1; }
    .incident-modal-head { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; margin-bottom: 1rem; }
    .incident-modal-head h3, .incident-form-card h4 { margin: 0; color: #ffffff; }
    .incident-modal-actions { display: flex; align-items: center; gap: 0.5rem; }
    .incident-modal-grid { display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(280px, 0.85fr); gap: 1rem; }
    .incident-form-card { padding: 1rem; border-radius: 18px; background: rgba(8, 16, 25, 0.78); border: 1px solid rgba(255,255,255,0.05); }
    .incident-form-card h4 { margin-bottom: 0.8rem; font-size: 0.92rem; }
    .incident-field-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.75rem; }
    .incident-field { display: flex; flex-direction: column; gap: 0.35rem; }
    .incident-field.full { grid-column: 1 / -1; }
    .incident-field label { color: rgba(186, 206, 226, 0.72); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em; }
    .incident-field input, .incident-field select, .incident-field textarea { width: 100%; padding: 0.75rem 0.8rem; border-radius: 14px; border: 1px solid rgba(255,255,255,0.07); background: rgba(12, 23, 36, 0.9); color: #ffffff; font: inherit; box-sizing: border-box; }
    .incident-field textarea { min-height: 140px; resize: vertical; }
    .incident-event-body {
      margin-top: 0.65rem;
      padding: 0.9rem 0.95rem;
      border-radius: 16px;
      background: rgba(5, 13, 22, 0.82);
      border: 1px solid rgba(255,255,255,0.05);
      color: #f0f5ff;
      white-space: pre-wrap;
      line-height: 1.55;
      font-size: 0.84rem;
    }
    .incident-event-meta {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 0.65rem;
      margin-top: 0.8rem;
    }
    .incident-event-meta-item {
      padding: 0.72rem 0.78rem;
      border-radius: 14px;
      background: rgba(12, 23, 36, 0.84);
      border: 1px solid rgba(255,255,255,0.05);
    }
    .incident-event-meta-item span {
      display: block;
      color: rgba(186, 206, 226, 0.72);
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 0.28rem;
    }
    .incident-event-meta-item strong {
      color: #ffffff;
      font-size: 0.88rem;
      font-weight: 600;
      word-break: break-word;
    }
    .incident-checklist, .incident-event-list { display: flex; flex-direction: column; gap: 0.55rem; }
    .incident-check-item { display: flex; align-items: center; gap: 0.55rem; }
    .incident-check-item input[type="text"] { flex: 1 1 auto; }
    .incident-event-item { padding: 0.7rem 0.8rem; border-radius: 14px; background: rgba(12, 23, 36, 0.84); border: 1px solid rgba(255,255,255,0.05); color: var(--text-1); font-size: 0.78rem; line-height: 1.45; }
    .incident-footer-actions { display: flex; justify-content: flex-end; gap: 0.6rem; margin-top: 1rem; }
    @media (max-width: 1280px) {
      .dashboard-shell { grid-template-columns: 1fr; }
      .dashboard-nav {
        position: static;
        min-height: auto;
      }
      .dashboard-shell.nav-collapsed { grid-template-columns: 1fr; }
      .dashboard-shell.nav-collapsed .dashboard-nav { display: none; }
      #hero-analytics-grid { grid-template-columns: 1fr; }
      #overview-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      #workspace { grid-template-columns: 300px minmax(0, 1fr); }
      #workspace,
      .rail-stack,
      #graph-panel {
        min-height: 0;
        height: auto;
      }
      #workspace > .rail-stack:last-child { grid-column: 1 / -1; flex-direction: row; align-items: stretch; }
      #workspace > .rail-stack:last-child > .panel-surface { flex: 1 1 0; }
      #analytics-grid { grid-template-columns: 1fr; }
      .incident-board, .incident-modal-grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 900px) {
      .dashboard-shell { width: min(100vw - 1rem, 100%); padding: 0.6rem 0 1rem; }
      .dashboard-nav { padding: 0.85rem; }
      .nav-status-strip { grid-template-columns: 1fr; }
      header { flex-direction: column; }
      .pill-row { justify-content: flex-start; }
      .hero-kpi-grid { grid-template-columns: 1fr; }
      .hero-spotlight-body { grid-template-columns: 1fr; }
      .hero-spotlight-stats { grid-template-columns: 1fr; }
      #hero-class-donut { width: 210px; height: 210px; }
      #overview-grid, #workspace { grid-template-columns: 1fr; }
      .rail-stack, #graph-panel { height: auto; }
      #workspace > .rail-stack:last-child { flex-direction: column; }
      #graph-wrapper {
        min-height: 500px;
        height: min(62vh, 620px);
        max-height: 620px;
      }
      #graph { min-height: 0; height: 100%; }
      .hero-meta, .metrics-strip { grid-template-columns: 1fr; }
      .donut-layout { grid-template-columns: 1fr; }
      #class-donut { width: 200px; height: 200px; }
      .incident-field-grid { grid-template-columns: 1fr; }
      .incident-modal-shell { padding: 0.75rem; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>MDRJ-DAG / Hashgraph Visualizer</h1>
      <div id="metrics">Загрузка графа...</div>
      <div id="consensus-status">Консенсус: ожидание данных...</div>
      <div id="graph-status">Подключение...</div>
    </div>
    <div class="header-actions">
      <div class="toolbar">Поток событий: Server-Sent Events</div>
    </div>
  </header>
  <div id="controls">
    <div class="controls-title">Имитация событий (создаёт новые вершины DAG):</div>
    <div class="controls-buttons">
      <button class="sim-button" data-sim="virus">Обнаружен вирус на узле</button>
      <button class="sim-button" data-sim="admin_login">Удалённый вход администратора</button>
      <button class="sim-button primary" id="simulation-toggle" type="button">СИМУЛЯЦИЯ</button>
      <button class="sim-button" data-sim="mac_spoof">Попытка MAC-spoofing</button>
      <button class="sim-button" data-sim="portscan">Аномальный порт-скан</button>
      <button class="sim-button" data-sim="heartbeat">Тестовый heartbeat</button>
      <button class="sim-button danger" id="clear-graph" type="button">Очистить DAG</button>
    </div>
    <div id="controls-status">Готово к имитации.</div>
  </div>
  <div id="reset-controls">
    <div class="controls-title">Операции журнала:</div>
    <div class="controls-buttons">
      <button class="sim-button danger" id="cluster-reset-graph" type="button">Очистить логи на всех нодах</button>
    </div>
    <div id="reset-controls-status">Сброс очистит граф, события и артефакты консенсуса на кластере.</div>
  </div>
  <div id="filters">
    <div class="filters-title">Фильтры визуализации:</div>
    <div class="filter-group" id="filter-classes">
      <button class="toggle-button active" data-filter-class="A">Класс A</button>
      <button class="toggle-button active" data-filter-class="B">Класс B</button>
      <button class="toggle-button active" data-filter-class="C">Класс C</button>
    </div>
    <div class="filter-group" id="filter-sources">
      <button class="toggle-button active" data-filter-source="__all__">Все источники</button>
    </div>
  </div>
  <div id="graph-wrapper">
    <div id="graph"></div>
    <aside id="details-panel" role="dialog" aria-modal="true" aria-hidden="true" aria-labelledby="details-title" aria-describedby="details-context" tabindex="-1">
      <button id="details-close" class="details-close" type="button" aria-label="Скрыть панель деталей"><span aria-hidden="true">&times;</span></button>
      <h2 id="details-title">Нет выбранного события</h2>
      <div id="details-context">Наведите курсор или нажмите на вершину, чтобы увидеть детали.</div>
      <div class="details-section">
        <h3>Метаданные</h3>
        <div id="details-meta" class="details-meta">
          <div class="details-hint">Событие не выбрано.</div>
        </div>
      </div>
      <div class="details-section">
        <h3>Payload</h3>
        <pre id="details-payload" class="empty">—</pre>
      </div>
      <div class="details-section">
        <h3>Векторные часы</h3>
        <pre id="details-vclock" class="empty">—</pre>
      </div>
      <div class="details-section">
        <h3>Причинный путь</h3>
        <div><strong>Родители</strong>
          <ul id="details-path-parents" class="details-list"></ul>
        </div>
        <div style="margin-top: 0.35rem;"><strong>Потомки</strong>
          <ul id="details-path-children" class="details-list"></ul>
        </div>
      </div>
      <div class="details-section">
        <h3>Подпись</h3>
        <pre id="details-sig" class="empty">—</pre>
      </div>
    </aside>
  </div>
  <div id="details-backdrop" aria-hidden="true"></div>
  <div id="legend">
    <div class="legend-item"><span class="dot dot-a"></span><span class="label">Класс A — критические события, транслируются обязательно</span></div>
    <div class="legend-item"><span class="dot dot-b"></span><span class="label">Класс B — важные события, доставляются по порогу угрозы</span></div>
    <div class="legend-item"><span class="dot dot-c"></span><span class="label">Класс C — вспомогательные/якорные события</span></div>
    <div class="legend-item"><span class="edge"></span><span class="label">Рёбра показывают ссылку ребёнка на родителя (причинная зависимость)</span></div>
    <div class="legend-item"><span class="dot dot-seq">#</span><span class="label">Номер (#) отражает итоговый порядок событий</span></div>
  </div>
  <div id="timeline">
    <div class="timeline-title">Порядок событий (нажмите, чтобы сфокусироваться):</div>
    <div id="timeline-items"></div>
  </div>
  <script>
    (function () {
      function reportVizBootstrapError(stage, error) {
        if (typeof document === 'undefined' || !document.body) {
          return;
        }
        var existing = document.getElementById('viz-bootstrap-error');
        var text = '[viz bootstrap][' + stage + '] ' + (error && (error.message || error.stack || error) ? String(error.message || error.stack || error) : 'unknown error');
        if (existing) {
          existing.textContent = text;
          return;
        }
        var banner = document.createElement('div');
        banner.id = 'viz-bootstrap-error';
        banner.style.position = 'fixed';
        banner.style.left = '16px';
        banner.style.right = '16px';
        banner.style.bottom = '16px';
        banner.style.zIndex = '9999';
        banner.style.padding = '12px 14px';
        banner.style.borderRadius = '14px';
        banner.style.background = 'rgba(109, 20, 20, 0.96)';
        banner.style.border = '1px solid rgba(255, 143, 143, 0.35)';
        banner.style.color = '#ffe4e4';
        banner.style.fontFamily = \"'IBM Plex Mono', 'JetBrains Mono', monospace\";
        banner.style.fontSize = '12px';
        banner.style.whiteSpace = 'pre-wrap';
        banner.style.boxShadow = '0 18px 50px rgba(0, 0, 0, 0.35)';
        banner.textContent = text;
        document.body.appendChild(banner);
      }
      if (typeof window !== 'undefined' && window.addEventListener) {
        window.addEventListener('error', function (event) {
          reportVizBootstrapError('runtime', event && (event.error || event.message));
        });
      }
      document.addEventListener('click', function (event) {
        var expandButton = event.target && event.target.closest ? event.target.closest('[data-hero-expand]') : null;
        if (expandButton) {
          openAnalyticsModal(expandButton.getAttribute('data-hero-expand'));
        }
      });
      var colorByClass = { A: '#ff6d6d', B: '#ffc971', C: '#5aa5ff', default: '#99a9ff' };
      var nodes = {};
      var nodeOrder = [];
      var links = {};
      var linkOrder = [];
      var childrenMap = {};
      var layoutOrder = [];
      var laneOrder = [];
      var lanePositions = {};
      function defaultLayoutDimensions() {
        return {
          width: 800,
          height: 600,
          contentWidth: 800,
          contentHeight: 600,
          top: 200,
          bottom: 200,
          left: 160,
          right: 160,
          rowSpacing: 120,
          colSpacing: 200,
          lastNodeY: 200
        };
      }
      var layoutDimensions = defaultLayoutDimensions();
      var sourceOrder = [];
      var focusNodeId = null;
      var focusAncestors = {};
      var focusDescendants = {};
      var headerEl = document.querySelector('header');
      var graphEl = document.getElementById('graph');
      var metricsEl = document.getElementById('metrics');
      var consensusStatusEl = document.getElementById('consensus-status');
      var statusEl = document.getElementById('graph-status');
      var controlsRoot = document.getElementById('controls');
      var controlsStatus = document.getElementById('controls-status');
      var resetControlsRoot = document.getElementById('reset-controls');
      var resetControlsStatus = document.getElementById('reset-controls-status');
      var clusterResetButton = document.getElementById('cluster-reset-graph');
      var filterClassesRoot = document.getElementById('filter-classes');
      var filterSourcesRoot = document.getElementById('filter-sources');
      var simulationButton = document.getElementById('simulation-toggle');
      var detailsPanel = document.getElementById('details-panel');
      var detailsTitle = document.getElementById('details-title');
      var detailsContext = document.getElementById('details-context');
      var detailsMeta = document.getElementById('details-meta');
      var detailsPayload = document.getElementById('details-payload');
      var detailsVclock = document.getElementById('details-vclock');
      var detailsParents = document.getElementById('details-path-parents');
      var detailsChildren = document.getElementById('details-path-children');
      var detailsSig = document.getElementById('details-sig');
      var detailsClose = document.getElementById('details-close');
      var detailsBackdrop = document.getElementById('details-backdrop');
      var syncTimer = null;
      var classFilterState = { A: true, B: true, C: true };
      var classFilterButtons = {};
      var ALL_SOURCES_TOKEN = '__all__';
      var sourceFilterState = {};
      sourceFilterState[ALL_SOURCES_TOKEN] = true;
      var sourceFilterButtons = {};
      var hoveredNodeId = null;
      var isDetailsOpen = false;
      var shouldOpenDetailsOnFocus = false;
      var simulationActive = false;
      var demoControlsEnabled = true;
      var consensusState = {};
      var lastActiveElement = null;

      function buildDashboardLayout() {
        if (!headerEl || !controlsRoot || !resetControlsRoot || !filterClassesRoot || !graphEl || !statusEl) {
          return;
        }
        var body = document.body;
        if (!body || body.querySelector('.dashboard-shell')) {
          return;
        }

        var shell = document.createElement('div');
        shell.className = 'dashboard-shell';
        body.insertBefore(shell, headerEl);

        var nav = document.createElement('aside');
        nav.className = 'dashboard-nav';
        nav.innerHTML =
          '<div class="nav-head">' +
            '<div class="nav-brand">' +
              '<div class="nav-brand-mark">MD</div>' +
              '<div class="nav-brand-copy"><strong>Журнал РУСИБ</strong><span id="nav-node-caption">ID: —</span></div>' +
            '</div>' +
            '<div class="nav-actions">' +
              '<button class="nav-action" type="button" aria-label="Поиск по панели" title="Поиск по панели">⌕</button>' +
              '<button class="nav-toggle" id="nav-toggle" type="button" aria-label="Свернуть или развернуть панель" aria-expanded="true" title="Свернуть или развернуть панель"><span class="nav-toggle-icon">◧</span></button>' +
            '</div>' +
          '</div>' +
          '<div class="nav-node-meta">' +
            '<span class="nav-meta-dot"></span><span>Узел <strong id="nav-node-id">—</strong></span><span>Поток <strong id="nav-stream-state">онлайн</strong></span>' +
          '</div>' +
          '<nav class="nav-menu" aria-label="Основная навигация">' +
            '<div class="nav-list">' +
              '<a class="nav-item" href="#overview-grid"><span class="nav-item-group"><span class="nav-icon">⌂</span><span class="nav-copy">Главная</span></span></a>' +
              '<div class="nav-branch">' +
                '<div class="nav-branch-label"><span class="nav-icon">◫</span><span class="nav-copy">Панель мониторинга</span></div>' +
                '<div class="nav-tree">' +
                  '<a class="nav-item active" href="#hero-analytics-grid"><span class="nav-item-group"><span class="nav-icon">•</span><span class="nav-copy">Аналитика ИБ</span></span></a>' +
                  '<a class="nav-item" href="#overview-grid"><span class="nav-item-group"><span class="nav-icon">•</span><span class="nav-copy">Обзор узла</span></span></a>' +
                  '<a class="nav-item" href="#graph-panel"><span class="nav-item-group"><span class="nav-icon">•</span><span class="nav-copy">Граф событий</span></span></a>' +
                '</div>' +
              '</div>' +
              '<div class="nav-list nav-secondary">' +
                '<a class="nav-item" href="#alert-window"><span class="nav-item-group"><span class="nav-icon">!</span><span class="nav-copy">Тревоги</span></span></a>' +
                '<a class="nav-item" href="#source-summary"><span class="nav-item-group"><span class="nav-icon">◎</span><span class="nav-copy">Источники</span></span></a>' +
                '<a class="nav-item" href="#controls"><span class="nav-item-group"><span class="nav-icon">▶</span><span class="nav-copy">Сценарии</span></span></a>' +
                '<a class="nav-item" href="#reset-controls"><span class="nav-item-group"><span class="nav-icon">⟲</span><span class="nav-copy">Сброс журнала</span></span></a>' +
                '<a class="nav-item" href="#filters"><span class="nav-item-group"><span class="nav-icon">≡</span><span class="nav-copy">Фильтры</span></span></a>' +
                '<a class="nav-item" href="#cluster-map"><span class="nav-item-group"><span class="nav-icon">🌍</span><span class="nav-copy">Карта кластера</span></span></a>' +
                '<a class="nav-item" href="#network-workbench"><span class="nav-item-group"><span class="nav-icon">☷</span><span class="nav-copy">Участники сети</span></span></a>' +
                '<a class="nav-item" id="incident-nav-item" href="#incident-workbench" style="display:none;"><span class="nav-item-group"><span class="nav-icon">▣</span><span class="nav-copy">Инциденты</span></span></a>' +
                '<a class="nav-item" href="#sib-policy"><span class="nav-item-group"><span class="nav-icon">⚙</span><span class="nav-copy">Настройка множества СИБ</span></span></a>' +
              '</div>' +
            '</div>' +
          '</nav>' +
          '<section class="nav-support">' +
            '<h3>Контур панели</h3>' +
            '<p>Живые данные текущего узла и кластера без перезагрузки.</p>' +
            '<div class="nav-support-meta">' +
              '<span class="nav-support-pill">Без перезагрузки</span>' +
              '<span class="nav-support-pill">Server-Sent Events</span>' +
              '<span class="nav-support-pill">SQLite / Gossip</span>' +
            '</div>' +
          '</section>';
        shell.appendChild(nav);

        var main = document.createElement('div');
        main.className = 'dashboard-main';
        shell.appendChild(main);
        main.appendChild(headerEl);

        var titleHost = headerEl.querySelector('h1');
        if (titleHost && !headerEl.querySelector('.header-kicker')) {
          var titleWrap = titleHost.parentElement;
          var kicker = document.createElement('div');
          kicker.className = 'header-kicker';
          kicker.textContent = 'Распределённый мониторинг событий ИБ';
          titleWrap.insertBefore(kicker, titleHost);

          titleHost.textContent = 'РУСИБ / Единая аналитическая панель';

          var subtitle = document.createElement('div');
          subtitle.className = 'header-subtitle';
          subtitle.textContent = 'Состояние узла, тревоги, синхронность журнала и оперативная активность на одном экране.';
          titleWrap.appendChild(subtitle);
        }

        var headerActions = headerEl.querySelector('.header-actions');
        if (headerActions && !headerEl.querySelector('.pill-row')) {
          var pillRow = document.createElement('div');
          pillRow.className = 'pill-row';
          pillRow.innerHTML =
            '<div class="hero-pill">Узел <strong id="hero-node-id">—</strong></div>' +
            '<div class="hero-pill">Режим <strong id="hero-node-state">—</strong></div>' +
            '<div class="hero-pill">Роль <strong id="hero-node-role">—</strong></div>';
          headerActions.insertBefore(pillRow, headerActions.firstChild);
          var toolbar = headerActions.querySelector('.toolbar');
          if (toolbar) {
            toolbar.textContent = 'Поток событий: Server-Sent Events';
          }
        }

        var heroAnalytics = document.createElement('section');
        heroAnalytics.id = 'hero-analytics-grid';
        heroAnalytics.innerHTML =
          '<div class="hero-kpi-grid">' +
            '<article class="hero-kpi-card"><div class="hero-kpi-head"><div class="hero-kpi-label"><span class="hero-kpi-dot mem"></span>Память журнала</div><div class="hero-kpi-actions"><span class="hero-kpi-delta" id="hero-kpi-mem-delta">—</span><button class="hero-kpi-expand" type="button" data-hero-expand="mem" aria-label="Раскрыть график памяти" title="Раскрыть график памяти">↗</button></div></div><div class="hero-kpi-value" id="hero-kpi-mem-value">—</div><div class="hero-kpi-caption" id="hero-kpi-mem-caption">Использование памяти под распределённый журнал.</div><svg class="hero-kpi-spark" id="hero-kpi-mem-spark" viewBox="0 0 220 82" preserveAspectRatio="none"></svg><div class="hero-kpi-axis"><span>Y: %</span><span>X: обновления</span></div></article>' +
            '<article class="hero-kpi-card"><div class="hero-kpi-head"><div class="hero-kpi-label"><span class="hero-kpi-dot net"></span>Сетевая нагрузка</div><div class="hero-kpi-actions"><span class="hero-kpi-delta" id="hero-kpi-net-delta">—</span><button class="hero-kpi-expand" type="button" data-hero-expand="net" aria-label="Раскрыть график сети" title="Раскрыть график сети">↗</button></div></div><div class="hero-kpi-value" id="hero-kpi-net-value">—</div><div class="hero-kpi-caption" id="hero-kpi-net-caption">Текущий бюджет обмена между узлами.</div><svg class="hero-kpi-spark" id="hero-kpi-net-spark" viewBox="0 0 220 82" preserveAspectRatio="none"></svg><div class="hero-kpi-axis"><span>Y: %</span><span>X: обновления</span></div></article>' +
            '<article class="hero-kpi-card"><div class="hero-kpi-head"><div class="hero-kpi-label"><span class="hero-kpi-dot events"></span>Объём журнала</div><div class="hero-kpi-actions"><span class="hero-kpi-delta" id="hero-kpi-events-delta">—</span><button class="hero-kpi-expand" type="button" data-hero-expand="events" aria-label="Раскрыть график объёма журнала" title="Раскрыть график объёма журнала">↗</button></div></div><div class="hero-kpi-value" id="hero-kpi-events-value">—</div><div class="hero-kpi-caption" id="hero-kpi-events-caption">Количество известных событий на узле.</div><svg class="hero-kpi-spark" id="hero-kpi-events-spark" viewBox="0 0 220 82" preserveAspectRatio="none"></svg><div class="hero-kpi-axis"><span>Y: события</span><span>X: обновления</span></div></article>' +
            '<article class="hero-kpi-card"><div class="hero-kpi-head"><div class="hero-kpi-label"><span class="hero-kpi-dot intensity"></span>Интенсивность потока</div><div class="hero-kpi-actions"><span class="hero-kpi-delta" id="hero-kpi-intensity-delta">—</span><button class="hero-kpi-expand" type="button" data-hero-expand="intensity" aria-label="Раскрыть график интенсивности" title="Раскрыть график интенсивности">↗</button></div></div><div class="hero-kpi-value compact" id="hero-kpi-intensity-value">—</div><div class="hero-kpi-caption" id="hero-kpi-intensity-caption">Три класса A/B/C в одном потоке за окно 5 минут.</div><svg class="hero-kpi-spark" id="hero-kpi-intensity-spark" viewBox="0 0 220 82" preserveAspectRatio="none"></svg><div class="hero-kpi-axis"><span>Y: событий/мин</span><span>X: окна 5 мин</span></div></article>' +
          '</div>' +
          '<article class="hero-spotlight-card"><div class="hero-spotlight-top"><div><div class="hero-spotlight-kicker">Главный обзор</div><h2 class="hero-spotlight-headline">Распределение сигналов и состояние контура</h2><div class="hero-spotlight-copy">Верхний экран собирает визуальную сводку по классам событий, синхронности кластера и текущему давлению на узел.</div></div><div class="hero-spotlight-pills"><span class="hero-spot-pill" id="hero-spot-sync">Синхронность: ожидание</span><span class="hero-spot-pill" id="hero-spot-threat">Угроза: —</span><span class="hero-spot-pill" id="hero-spot-pressure">Нагрузка: —</span></div></div><div class="hero-spotlight-body"><div id="hero-class-donut"><div class="donut-center"><div class="donut-total" id="hero-donut-total">0</div><div class="donut-label">Всего событий</div></div></div><div><div class="hero-class-breakdown" id="hero-class-breakdown"></div><div class="hero-spotlight-stats"><div class="hero-spot-stat"><div class="hero-spot-stat-label">Критичные A</div><div class="hero-spot-stat-value" id="hero-spot-class-a">0</div></div><div class="hero-spot-stat"><div class="hero-spot-stat-label">Важные B</div><div class="hero-spot-stat-value" id="hero-spot-class-b">0</div></div><div class="hero-spot-stat"><div class="hero-spot-stat-label">Источники</div><div class="hero-spot-stat-value" id="hero-spot-sources">0</div></div></div></div></div></article>';
        main.appendChild(heroAnalytics);

        var overview = document.createElement('section');
        overview.id = 'overview-grid';
        overview.innerHTML =
          '<article class="overview-card">' +
            '<h2>Состояние узла</h2>' +
            '<div class="hero-value" id="status-state-value">Ожидание данных</div>' +
            '<div class="hero-meta">' +
              '<div class="meta-chip"><span class="meta-chip-label">Узел</span><span class="meta-chip-value" id="status-node-id">—</span></div>' +
              '<div class="meta-chip"><span class="meta-chip-label">Пиры</span><span class="meta-chip-value" id="status-peer-count">—</span></div>' +
              '<div class="meta-chip"><span class="meta-chip-label">Роль</span><span class="meta-chip-value" id="status-role">—</span></div>' +
              '<div class="meta-chip"><span class="meta-chip-label">Уровень угрозы</span><span class="meta-chip-value" id="status-threat-level">—</span></div>' +
            '</div>' +
          '</article>' +
          '<article class="overview-card">' +
            '<h2>Технические сигналы</h2>' +
            '<div class="hero-meta">' +
              '<div class="meta-chip"><span class="meta-chip-label">Готовность</span><span class="meta-chip-value" id="metric-a-est">—</span></div>' +
              '<div class="meta-chip"><span class="meta-chip-label">Задержка</span><span class="meta-chip-value" id="metric-t-gossip">—</span></div>' +
              '<div class="meta-chip"><span class="meta-chip-label">Целостность</span><span class="meta-chip-value" id="metric-k-r">—</span></div>' +
              '<div class="meta-chip"><span class="meta-chip-label">Событий</span><span class="meta-chip-value" id="metric-event-count">—</span></div>' +
            '</div>' +
          '</article>';
        main.appendChild(overview);
        if (metricsEl) {
          metricsEl.style.display = 'none';
        }
        var timelineEl = document.getElementById('timeline');
        if (timelineEl) {
          timelineEl.style.display = 'none';
        }
        if (consensusStatusEl) {
          consensusStatusEl.style.display = 'none';
        }
        if (statusEl) {
          statusEl.style.display = 'none';
        }

        var workspace = document.createElement('main');
        workspace.id = 'workspace';
        main.appendChild(workspace);

        var leftRail = document.createElement('aside');
        leftRail.className = 'rail-stack';
        workspace.appendChild(leftRail);

        var graphPanel = document.createElement('section');
        graphPanel.className = 'panel-surface';
        graphPanel.id = 'graph-panel';
        graphPanel.innerHTML =
          '<div class="graph-panel-head">' +
            '<div><h2>Граф событий и причинных связей</h2><p>Центральная область показывает, как события распространяются между источниками и в каком порядке они выстраиваются на текущем узле.</p></div>' +
            '<div class="graph-badge">Нажмите на вершину, чтобы открыть полные детали события</div>' +
          '</div>';
        workspace.appendChild(graphPanel);

        var rightRail = document.createElement('aside');
        rightRail.className = 'rail-stack';
        workspace.appendChild(rightRail);

        function wrapPanel(content, title, hint) {
          var panel = document.createElement('section');
          panel.className = 'panel-surface';
          if (title) {
            var head = document.createElement('div');
            head.className = 'panel-heading';
            head.innerHTML = '<h3>' + title + '</h3>' + (hint ? '<div class="panel-hint">' + hint + '</div>' : '');
            panel.appendChild(head);
          }
          panel.appendChild(content);
          return panel;
        }

        leftRail.appendChild(wrapPanel(controlsRoot, null, null));
        leftRail.appendChild(wrapPanel(resetControlsRoot, null, null));
        leftRail.appendChild(wrapPanel(filterClassesRoot.parentElement, null, null));
        leftRail.appendChild(wrapPanel(document.getElementById('legend'), 'Легенда', 'Как читать граф и классы событий'));
        var legendLabels = document.querySelectorAll('#legend .legend-item .label');
        if (legendLabels.length >= 5) {
          legendLabels[1].textContent = 'Класс B — важные события, сейчас регистрируются вместе с критическими';
          legendLabels[2].textContent = 'Класс C — служебные и якорные события для замыкания DAG';
          legendLabels[3].textContent = 'Ребро показывает ссылку ребёнка на родителя и причинную связь';
        }

        graphPanel.appendChild(graphEl.parentElement);

        var sourceSummaryPanel = document.createElement('section');
        sourceSummaryPanel.className = 'panel-surface';
        sourceSummaryPanel.innerHTML =
          '<div class="panel-heading"><h3>Источники и устройства</h3><div class="panel-hint">Где фиксируются события разных классов и какие устройства дают наибольшую нагрузку.</div></div>' +
          '<div id="source-summary"></div>';
        rightRail.appendChild(sourceSummaryPanel);

        var alertWindowPanel = document.createElement('section');
        alertWindowPanel.className = 'panel-surface';
        alertWindowPanel.innerHTML =
          '<div class="panel-heading"><h3>Окно тревог</h3><div class="panel-hint">Критичные события, рассогласование между узлами и признаки давления на ресурсы.</div></div>' +
          '<div id="alert-window"><div class="alert-item info"><div class="alert-meta"><span class="alert-level">НЕТ АКТИВНЫХ</span></div><div class="alert-title">Ожидание сигналов</div><div class="alert-text">Тревожные уведомления появятся здесь по мере поступления событий и изменения состояния кластера.</div></div></div>';
        rightRail.appendChild(alertWindowPanel);

        var analyticsModal = document.createElement('div');
        analyticsModal.id = 'analytics-modal-shell';
        analyticsModal.className = 'analytics-modal-shell';
        analyticsModal.innerHTML =
          '<div class="analytics-modal-backdrop" id="analytics-modal-backdrop"></div>' +
          '<div class="analytics-modal">' +
            '<div class="analytics-modal-head">' +
              '<div><h3 id="analytics-modal-title">Расширенная аналитика</h3><div class="panel-hint" id="analytics-modal-subtitle">Подробный вид выбранной мини-карточки.</div></div>' +
              '<div class="incident-modal-actions"><button class="incident-cancel-btn" id="analytics-modal-close" type="button">Закрыть</button></div>' +
            '</div>' +
            '<div class="analytics-modal-stage">' +
              '<div class="analytics-modal-legend" id="analytics-modal-legend"></div>' +
              '<div class="chart-axis-notes"><span id="analytics-modal-y-axis">Ось Y</span><span id="analytics-modal-x-axis">Ось X</span></div>' +
              '<svg class="analytics-modal-chart" id="analytics-modal-chart" viewBox="0 0 920 320" preserveAspectRatio="none"></svg>' +
              '<div class="analytics-modal-caption"><span id="analytics-modal-caption-left">История строится по реальным данным узла.</span><span id="analytics-modal-caption-right">—</span></div>' +
            '</div>' +
          '</div>';
        body.appendChild(analyticsModal);

        var incidentWorkbench = document.createElement('section');
        incidentWorkbench.id = 'incident-workbench';
        incidentWorkbench.className = 'panel-surface';
        incidentWorkbench.style.display = 'none';
        incidentWorkbench.innerHTML =
          '<div class="incident-shell">' +
            '<div class="incident-toolbar">' +
              '<div>' +
                '<h2 style="margin:0;font-size:1.08rem;">Обработка инцидентов</h2>' +
                '<div class="panel-hint">Операторский demo-layer для работы с инцидентами на выбранном узле.</div>' +
              '</div>' +
              '<div class="incident-badges">' +
                '<span class="incident-badge primary">Только операторский узел</span>' +
                '<span class="incident-badge">Без распределённой синхронизации</span>' +
              '</div>' +
            '</div>' +
            '<div class="incident-toolbar">' +
              '<div class="incident-view-switch">' +
                '<button class="incident-view-btn active" id="incident-view-table" type="button">Таблица</button>' +
                '<button class="incident-view-btn" id="incident-view-board" type="button">Kanban</button>' +
              '</div>' +
              '<div class="incident-filter-row">' +
                '<button class="incident-filter-btn active" id="incident-filter-all" type="button">Все</button>' +
                '<button class="incident-filter-btn active" data-incident-filter-class="A" type="button">A</button>' +
                '<button class="incident-filter-btn active" data-incident-filter-class="B" type="button">B</button>' +
                '<button class="incident-filter-btn active" data-incident-filter-class="C" type="button">C</button>' +
              '</div>' +
              '<input class="incident-filter-input" id="incident-filter-input" type="text" placeholder="Фильтр по событию, статусу, источнику, ответственному..." />' +
              '<select class="incident-group-select" id="incident-group-select">' +
                '<option value="">Без группировки</option>' +
                '<option value="eventClass">Группировать по классу события</option>' +
                '<option value="eventId">Группировать по ID события</option>' +
                '<option value="eventType">Группировать по типу события</option>' +
                '<option value="eventOccurredAt">Группировать по дате/времени</option>' +
                '<option value="incident">Группировать по инциденту</option>' +
                '<option value="status">Группировать по статусу</option>' +
                '<option value="priority">Группировать по приоритету</option>' +
                '<option value="source">Группировать по источнику</option>' +
                '<option value="owner">Группировать по ответственному</option>' +
                '<option value="labels">Группировать по меткам</option>' +
              '</select>' +
              '<button class="incident-action-btn" id="incident-create-btn" type="button">Новая карточка</button>' +
            '</div>' +
            '<div id="incident-table-view"></div>' +
            '<div id="incident-board-view" style="display:none;"></div>' +
          '</div>';
        main.appendChild(incidentWorkbench);

        var sibPolicy = document.createElement('section');
        sibPolicy.id = 'sib-policy';
        sibPolicy.className = 'panel-surface';
        sibPolicy.innerHTML =
          '<div class="incident-shell">' +
            '<div class="incident-toolbar">' +
              '<div>' +
                '<h2 style="margin:0;font-size:1.08rem;">Настройка множества СИБ</h2>' +
                '<div class="panel-hint">Перечень регистрируемых событий ИБ: НПА, класс, источник и тугл сохранения в распределённый реестр. Изменение фиксируется незатираемым событием класса A.</div>' +
              '</div>' +
              '<div class="incident-badges">' +
                '<span class="incident-badge primary" id="sib-count">— событий</span>' +
                '<span class="incident-badge" id="sib-enabled-count">— включено</span>' +
              '</div>' +
            '</div>' +
            '<div style="overflow-x:auto;">' +
              '<table id="sib-table" style="width:100%;border-collapse:collapse;font-size:0.86rem;">' +
                '<thead><tr style="text-align:left;border-bottom:1px solid rgba(255,255,255,0.15);">' +
                  '<th style="padding:8px 10px;">Событие</th>' +
                  '<th style="padding:8px 10px;">Класс</th>' +
                  '<th style="padding:8px 10px;">Источник</th>' +
                  '<th style="padding:8px 10px;">НПА</th>' +
                  '<th style="padding:8px 10px;">Угрозы</th>' +
                  '<th style="padding:8px 10px;">В реестр</th>' +
                '</tr></thead>' +
                '<tbody id="sib-tbody"></tbody>' +
              '</table>' +
            '</div>' +
          '</div>';
        main.appendChild(sibPolicy);

        var clusterMap = document.createElement('section');
        clusterMap.id = 'cluster-map';
        clusterMap.className = 'panel-surface';
        clusterMap.innerHTML =
          '<div class="incident-shell">' +
            '<div class="incident-toolbar">' +
              '<div>' +
                '<h2 style="margin:0;font-size:1.08rem;">Карта сети</h2>' +
                '<div class="panel-hint">Логическая топология защищаемой инфраструктуры: узлы реестра, источники событий и пути атак. Красным — зафиксированные атакующие подключения (класс A).</div>' +
              '</div>' +
              '<div class="incident-badges">' +
                '<span class="incident-badge primary" id="cmap-nodes">— узлов</span>' +
                '<span class="incident-badge" id="cmap-attacks">— атак</span>' +
              '</div>' +
            '</div>' +
            '<div style="display:flex;gap:1rem;align-items:stretch;">' +
              '<div id="cmap-legend" style="flex:0 0 180px;padding:1rem;border-radius:14px;background:rgba(8,16,25,0.6);border:1px solid rgba(255,255,255,0.05);font-size:0.8rem;">' +
                '<div style="font-weight:600;margin-bottom:0.7rem;opacity:0.9;">Легенда</div>' +
                '<div class="cmap-leg-row"><span class="cmap-leg-ic" style="border-color:#ef5350;">👑</span> Домен-контроллер</div>' +
                '<div class="cmap-leg-row"><span class="cmap-leg-ic" style="border-color:#ffa726;">🗄</span> Сервер реестра</div>' +
                '<div class="cmap-leg-row"><span class="cmap-leg-ic" style="border-color:#42a5f5;">💻</span> Рабочая станция</div>' +
                '<div class="cmap-leg-row"><span class="cmap-leg-ic" style="border-color:#ab47bc;">📟</span> Устройство / IoT</div>' +
                '<div class="cmap-leg-row"><span class="cmap-leg-ic" style="border-color:#66bb6a;">🌐</span> Точка входа</div>' +
                '<div style="margin-top:0.9rem;border-top:1px solid rgba(255,255,255,0.08);padding-top:0.7rem;">' +
                  '<div class="cmap-leg-row"><span style="display:inline-block;width:22px;height:0;border-top:2px solid #6aa9ff;margin-right:6px;"></span> Соединение</div>' +
                  '<div class="cmap-leg-row"><span style="display:inline-block;width:22px;height:0;border-top:2px dashed #ef5350;margin-right:6px;"></span> Путь атаки</div>' +
                '</div>' +
              '</div>' +
              '<div id="cmap-wrap" style="position:relative;flex:1 1 auto;height:560px;border-radius:14px;overflow:hidden;background:radial-gradient(ellipse at 50% 35%, #0f1f31 0%, #0a131f 72%);border:1px solid rgba(255,255,255,0.06);">' +
                '<svg id="cmap-svg" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"></svg>' +
              '</div>' +
            '</div>' +
          '</div>';
        main.appendChild(clusterMap);

        var incidentModal = document.createElement('div');
        incidentModal.id = 'incident-modal-shell';
        incidentModal.className = 'incident-modal-shell';
        incidentModal.innerHTML =
          '<div class="incident-modal-backdrop" id="incident-modal-backdrop"></div>' +
          '<div class="incident-modal">' +
            '<div class="incident-modal-head">' +
              '<div><h3 id="incident-modal-title">Карточка инцидента</h3><div class="panel-hint">Первая версия работает как локальный операторский слой.</div></div>' +
              '<div class="incident-modal-actions"><button class="incident-cancel-btn" id="incident-close-btn" type="button">Закрыть</button></div>' +
            '</div>' +
            '<div class="incident-modal-grid">' +
              '<div class="incident-form-card">' +
                '<h4>Поля карточки</h4>' +
                '<div class="incident-field-grid">' +
                  '<div class="incident-field full"><label for="incident-title-input">Название</label><input id="incident-title-input" type="text" /></div>' +
                  '<div class="incident-field"><label for="incident-status-input">Статус</label><select id="incident-status-input"></select></div>' +
                  '<div class="incident-field"><label for="incident-priority-input">Приоритет</label><select id="incident-priority-input"><option value="high">Высокий</option><option value="medium">Средний</option><option value="low">Низкий</option></select></div>' +
                  '<div class="incident-field"><label for="incident-owner-input">Ответственный</label><input id="incident-owner-input" type="text" placeholder="Имя или группа" /></div>' +
                  '<div class="incident-field"><label for="incident-source-input">Источник</label><input id="incident-source-input" type="text" /></div>' +
                  '<div class="incident-field full"><label for="incident-labels-input">Метки</label><input id="incident-labels-input" type="text" placeholder="Через запятую" /></div>' +
                  '<div class="incident-field"><label for="incident-detected-input">Обнаружен</label><input id="incident-detected-input" type="datetime-local" /></div>' +
                  '<div class="incident-field"><label for="incident-due-input">Срок реакции</label><input id="incident-due-input" type="datetime-local" /></div>' +
                  '<div class="incident-field full"><label for="incident-note-input">Примечание</label><textarea id="incident-note-input" placeholder="Короткая операторская заметка"></textarea></div>' +
                  '<div class="incident-field full"><label for="incident-description-input">Описание</label><textarea id="incident-description-input"></textarea></div>' +
                '</div>' +
              '</div>' +
              '<div style="display:flex;flex-direction:column;gap:1rem;">' +
                '<div class="incident-form-card">' +
                  '<h4>Подробности события</h4>' +
                  '<div id="incident-event-meta" class="incident-event-meta"></div>' +
                  '<div id="incident-event-body" class="incident-event-body">Подробности появятся после выбора карточки, созданной из события.</div>' +
                '</div>' +
                '<div class="incident-form-card">' +
                  '<h4>Чек-лист</h4>' +
                  '<div id="incident-checklist" class="incident-checklist"></div>' +
                  '<button class="incident-add-btn" id="incident-add-check-btn" type="button">Добавить пункт</button>' +
                '</div>' +
                '<div class="incident-form-card">' +
                  '<h4>Связанные события</h4>' +
                  '<div id="incident-events" class="incident-event-list"></div>' +
                '</div>' +
              '</div>' +
            '</div>' +
            '<div class="incident-footer-actions">' +
              '<button class="incident-cancel-btn" id="incident-cancel-btn" type="button">Отмена</button>' +
              '<button class="incident-save-btn" id="incident-save-btn" type="button">Сохранить</button>' +
            '</div>' +
          '</div>';
        body.appendChild(incidentModal);

        var networkWorkbench = document.createElement('section');
        networkWorkbench.id = 'network-workbench';
        networkWorkbench.className = 'panel-surface';
        networkWorkbench.innerHTML =
          '<div class="network-shell">' +
            '<div class="network-toolbar">' +
              '<div>' +
                '<h2 style="margin:0;font-size:1.08rem;">Участники сети</h2>' +
                '<div class="panel-hint">Локальный реестр доверенных узлов: добавление, временное исключение и удаление участников из gossip-контура. Активный состав consensus фиксируется отдельно и меняется только после явной пересборки.</div>' +
              '</div>' +
              '<div class="network-summary">' +
                '<span class="network-stat">Всего <strong id="network-peer-total">0</strong></span>' +
                '<span class="network-stat">Активных <strong id="network-peer-enabled">0</strong></span>' +
                '<span class="network-stat">Исключённых <strong id="network-peer-disabled">0</strong></span>' +
              '</div>' +
            '</div>' +
            '<div class="network-consensus-card">' +
              '<div class="network-consensus-copy">' +
                '<strong>Активный consensus snapshot</strong>' +
                '<div class="panel-hint" id="network-consensus-summary">Загружаем epoch и состав участников…</div>' +
              '</div>' +
              '<button class="network-action-btn primary" id="network-reconfigure-btn" type="button">Пересобрать состав консенсуса</button>' +
            '</div>' +
            '<div class="network-add-form">' +
              '<div class="network-field"><label for="network-address-input">Адрес узла</label><input id="network-address-input" type="text" placeholder="host:port" /></div>' +
              '<div class="network-field"><label for="network-role-input">Роль</label><select id="network-role-input"><option value="node">Участник сети</option><option value="responder">Реагирование</option></select></div>' +
              '<div class="network-field"><label for="network-note-input">Заметка</label><input id="network-note-input" type="text" placeholder="Например: seed, резервный, скомпрометирован" /></div>' +
              '<button class="network-action-btn primary" id="network-add-btn" type="button">Добавить участника</button>' +
            '</div>' +
            '<div id="network-status-line" class="panel-hint">Локальный реестр участников сети загружается…</div>' +
            '<div id="network-table-view"></div>' +
          '</div>';
        main.appendChild(networkWorkbench);
      }

      try {
        buildDashboardLayout();
      } catch (err) {
        reportVizBootstrapError('layout', err);
      }
      var dashboardShellEl = document.querySelector('.dashboard-shell');
      var navToggleEl = document.getElementById('nav-toggle');
      var navNodeCaptionEl = document.getElementById('nav-node-caption');
      var navNodeIdEl = document.getElementById('nav-node-id');
      var navStreamStateEl = document.getElementById('nav-stream-state');
      var navItems = Array.prototype.slice.call(document.querySelectorAll('.dashboard-nav .nav-item'));
      var incidentNavItemEl = document.getElementById('incident-nav-item');
      var heroNodeIdEl = document.getElementById('hero-node-id');
      var heroNodeStateEl = document.getElementById('hero-node-state');
      var heroNodeRoleEl = document.getElementById('hero-node-role');
      var heroKpiMemDeltaEl = document.getElementById('hero-kpi-mem-delta');
      var heroKpiMemValueEl = document.getElementById('hero-kpi-mem-value');
      var heroKpiMemCaptionEl = document.getElementById('hero-kpi-mem-caption');
      var heroKpiMemSparkEl = document.getElementById('hero-kpi-mem-spark');
      var heroKpiNetDeltaEl = document.getElementById('hero-kpi-net-delta');
      var heroKpiNetValueEl = document.getElementById('hero-kpi-net-value');
      var heroKpiNetCaptionEl = document.getElementById('hero-kpi-net-caption');
      var heroKpiNetSparkEl = document.getElementById('hero-kpi-net-spark');
      var heroKpiEventsDeltaEl = document.getElementById('hero-kpi-events-delta');
      var heroKpiEventsValueEl = document.getElementById('hero-kpi-events-value');
      var heroKpiEventsCaptionEl = document.getElementById('hero-kpi-events-caption');
      var heroKpiEventsSparkEl = document.getElementById('hero-kpi-events-spark');
      var heroKpiIntensityDeltaEl = document.getElementById('hero-kpi-intensity-delta');
      var heroKpiIntensityValueEl = document.getElementById('hero-kpi-intensity-value');
      var heroKpiIntensityCaptionEl = document.getElementById('hero-kpi-intensity-caption');
      var heroKpiIntensitySparkEl = document.getElementById('hero-kpi-intensity-spark');
      var heroExpandButtons = Array.prototype.slice.call(document.querySelectorAll('[data-hero-expand]'));
      var heroSpotSyncEl = document.getElementById('hero-spot-sync');
      var heroSpotThreatEl = document.getElementById('hero-spot-threat');
      var heroSpotPressureEl = document.getElementById('hero-spot-pressure');
      var heroSpotClassAEl = document.getElementById('hero-spot-class-a');
      var heroSpotClassBEl = document.getElementById('hero-spot-class-b');
      var heroSpotSourcesEl = document.getElementById('hero-spot-sources');
      var heroDonutTotalEl = document.getElementById('hero-donut-total');
      var heroClassBreakdownEl = document.getElementById('hero-class-breakdown');
      var statusStateValueEl = document.getElementById('status-state-value');
      var statusNodeIdEl = document.getElementById('status-node-id');
      var statusPeerCountEl = document.getElementById('status-peer-count');
      var statusRoleEl = document.getElementById('status-role');
      var statusThreatLevelEl = document.getElementById('status-threat-level');
      var metricAEstEl = document.getElementById('metric-a-est');
      var metricTGossipEl = document.getElementById('metric-t-gossip');
      var metricKREl = document.getElementById('metric-k-r');
      var metricEventCountEl = document.getElementById('metric-event-count');
      var activityClassAEl = document.getElementById('activity-class-a');
      var activityClassBEl = document.getElementById('activity-class-b');
      var activityClassCEl = document.getElementById('activity-class-c');
      var activitySourceCountEl = document.getElementById('activity-source-count');
      var activityIntensityEl = document.getElementById('activity-intensity');
      var activityFeedEl = document.getElementById('activity-feed');
      var consensusPeerSummaryEl = document.getElementById('consensus-peer-summary');
      var trendChartEl = document.getElementById('trend-chart');
      var trendLegendEl = document.getElementById('trend-legend');
      var trendYAxisEl = document.getElementById('trend-y-axis');
      var trendXAxisEl = document.getElementById('trend-x-axis');
      var trendCaptionValueEl = document.getElementById('trend-caption-value');
      var trendTabResourcesEl = document.getElementById('trend-tab-resources');
      var trendTabIntensityEl = document.getElementById('trend-tab-intensity');
      var analyticsModalShellEl = document.getElementById('analytics-modal-shell');
      var analyticsModalBackdropEl = document.getElementById('analytics-modal-backdrop');
      var analyticsModalCloseEl = document.getElementById('analytics-modal-close');
      var analyticsModalTitleEl = document.getElementById('analytics-modal-title');
      var analyticsModalSubtitleEl = document.getElementById('analytics-modal-subtitle');
      var analyticsModalLegendEl = document.getElementById('analytics-modal-legend');
      var analyticsModalYAxisEl = document.getElementById('analytics-modal-y-axis');
      var analyticsModalXAxisEl = document.getElementById('analytics-modal-x-axis');
      var analyticsModalChartEl = document.getElementById('analytics-modal-chart');
      var analyticsModalCaptionRightEl = document.getElementById('analytics-modal-caption-right');
      var donutTotalEl = document.getElementById('donut-total');
      var classBreakdownEl = document.getElementById('class-breakdown');
      var sourceSummaryEl = document.getElementById('source-summary');
      var alertWindowEl = document.getElementById('alert-window');
      var incidentWorkbenchEl = document.getElementById('incident-workbench');
      var incidentTableViewEl = document.getElementById('incident-table-view');
      var incidentBoardViewEl = document.getElementById('incident-board-view');
      var incidentViewTableEl = document.getElementById('incident-view-table');
      var incidentViewBoardEl = document.getElementById('incident-view-board');
      var incidentFilterAllEl = document.getElementById('incident-filter-all');
      var incidentFilterButtons = Array.prototype.slice.call(document.querySelectorAll('[data-incident-filter-class]'));
      var incidentFilterInputEl = document.getElementById('incident-filter-input');
      var incidentGroupSelectEl = document.getElementById('incident-group-select');
      var incidentCreateBtnEl = document.getElementById('incident-create-btn');
      var incidentModalShellEl = document.getElementById('incident-modal-shell');
      var incidentModalBackdropEl = document.getElementById('incident-modal-backdrop');
      var incidentModalTitleEl = document.getElementById('incident-modal-title');
      var incidentCloseBtnEl = document.getElementById('incident-close-btn');
      var incidentCancelBtnEl = document.getElementById('incident-cancel-btn');
      var incidentSaveBtnEl = document.getElementById('incident-save-btn');
      var incidentTitleInputEl = document.getElementById('incident-title-input');
      var incidentStatusInputEl = document.getElementById('incident-status-input');
      var incidentPriorityInputEl = document.getElementById('incident-priority-input');
      var incidentOwnerInputEl = document.getElementById('incident-owner-input');
      var incidentSourceInputEl = document.getElementById('incident-source-input');
      var incidentLabelsInputEl = document.getElementById('incident-labels-input');
      var incidentDetectedInputEl = document.getElementById('incident-detected-input');
      var incidentDueInputEl = document.getElementById('incident-due-input');
      var incidentNoteInputEl = document.getElementById('incident-note-input');
      var incidentDescriptionInputEl = document.getElementById('incident-description-input');
      var incidentEventMetaEl = document.getElementById('incident-event-meta');
      var incidentEventBodyEl = document.getElementById('incident-event-body');
      var incidentChecklistEl = document.getElementById('incident-checklist');
      var incidentAddCheckBtnEl = document.getElementById('incident-add-check-btn');
      var incidentEventsEl = document.getElementById('incident-events');
      var metricHistory = [];
      var alertFeed = [];
      var trendView = 'resources';
      var lastOperationalNodes = [];
      var lastMetricsSnapshot = null;
      var lastStatusSnapshot = null;
      var lastClassSummary = { A: 0, B: 0, C: 0 };
      var lastSourceCount = 0;
      var analyticsModalKind = null;
      var incidentView = 'table';
      var incidentEnabled = false;
      var incidentDraftId = null;
      var incidents = [];
      var incidentsLoaded = false;
      var incidentsSyncInFlight = false;
      var incidentStatuses = ['Новые сигналы', 'Проверка', 'Подтверждённый инцидент', 'Сдерживание', 'Восстановление', 'Закрыто'];
      var incidentClassFilterState = { A: true, B: true, C: true };
      var incidentSearchQuery = '';
      var incidentGroupBy = '';
      var networkTableViewEl = document.getElementById('network-table-view');
      var networkPeerTotalEl = document.getElementById('network-peer-total');
      var networkPeerEnabledEl = document.getElementById('network-peer-enabled');
      var networkPeerDisabledEl = document.getElementById('network-peer-disabled');
      var networkAddressInputEl = document.getElementById('network-address-input');
      var networkRoleInputEl = document.getElementById('network-role-input');
      var networkNoteInputEl = document.getElementById('network-note-input');
      var networkAddBtnEl = document.getElementById('network-add-btn');
      var networkStatusLineEl = document.getElementById('network-status-line');
      var networkConsensusSummaryEl = document.getElementById('network-consensus-summary');
      var networkReconfigureBtnEl = document.getElementById('network-reconfigure-btn');
      var peerRegistry = [];
      var navStateStorageKey = 'mdrj-dashboard-nav-collapsed';

      function setNavCollapsed(collapsed) {
        if (!dashboardShellEl || !navToggleEl) {
          return;
        }
        dashboardShellEl.classList.toggle('nav-collapsed', !!collapsed);
        navToggleEl.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
        navToggleEl.setAttribute('title', collapsed ? 'Развернуть панель' : 'Свернуть панель');
        navToggleEl.setAttribute('aria-label', collapsed ? 'Развернуть панель' : 'Свернуть панель');
        try {
          window.localStorage.setItem(navStateStorageKey, collapsed ? '1' : '0');
        } catch (err) {
          console.log('nav state storage unavailable', err);
        }
      }

      if (navToggleEl) {
        navToggleEl.addEventListener('click', function () {
          var collapsed = dashboardShellEl && dashboardShellEl.classList.contains('nav-collapsed');
          setNavCollapsed(!collapsed);
        });
      }

      try {
        if (window.localStorage.getItem(navStateStorageKey) === '1') {
          setNavCollapsed(true);
        }
      } catch (err) {
        console.log('nav state restore unavailable', err);
      }

      navItems.forEach(function (item) {
        item.addEventListener('click', function () {
          navItems.forEach(function (candidate) {
            candidate.classList.remove('active');
          });
          item.classList.add('active');
        });
      });

      function setTrendView(nextView) {
        trendView = nextView === 'intensity' ? 'intensity' : 'resources';
        if (trendTabResourcesEl) {
          trendTabResourcesEl.classList.toggle('active', trendView === 'resources');
        }
        if (trendTabIntensityEl) {
          trendTabIntensityEl.classList.toggle('active', trendView === 'intensity');
        }
        renderTrendChart();
      }

      if (trendTabResourcesEl) {
        trendTabResourcesEl.addEventListener('click', function () {
          setTrendView('resources');
        });
      }
      if (trendTabIntensityEl) {
        trendTabIntensityEl.addEventListener('click', function () {
          setTrendView('intensity');
        });
      }

      function incidentPriorityLabel(priority) {
        if (priority === 'high') {
          return 'Высокий';
        }
        if (priority === 'low') {
          return 'Низкий';
        }
        return 'Средний';
      }

      function incidentClassKey(value) {
        var cls = String(value || 'C').toUpperCase();
        if (cls !== 'A' && cls !== 'B' && cls !== 'C') {
          return 'C';
        }
        return cls;
      }

      function incidentClassCss(value) {
        return incidentClassKey(value).toLowerCase();
      }

      function eventTypeLabelFromPayload(payload) {
        var eventKind = payload && payload.event_kind ? String(payload.event_kind) : '';
        var scenario = payload && payload.scenario ? String(payload.scenario) : '';
        var category = payload && payload.category ? String(payload.category) : '';
        var mapping = {
          admin_ssh_login_success: 'Административный SSH-вход',
          virus: 'Вредоносное ПО',
          admin_login: 'Удалённый вход',
          mac_spoof: 'Подмена сетевого адреса',
          portscan: 'Портовое сканирование',
          heartbeat: 'Диагностическое сообщение',
          malware: 'Вредоносное ПО',
          authentication: 'Аутентификация',
          network: 'Сетевой сигнал',
          diagnostic: 'Диагностика'
        };
        if (eventKind && mapping[eventKind]) {
          return mapping[eventKind];
        }
        if (scenario && mapping[scenario]) {
          return mapping[scenario];
        }
        if (category && mapping[category]) {
          return mapping[category];
        }
        return 'Прочее событие';
      }

      function eventTitleFromPayload(payload, fallbackClass) {
        var eventKind = payload && payload.event_kind ? String(payload.event_kind) : '';
        var scenario = payload && payload.scenario ? String(payload.scenario) : '';
        var titles = {
          admin_ssh_login_success: 'Успешный административный SSH-вход',
          virus: 'Обнаружен вирус',
          admin_login: 'Удалённый вход администратора',
          mac_spoof: 'Попытка подмены сетевого адреса',
          portscan: 'Аномальный порт-скан',
          heartbeat: 'Служебный heartbeat'
        };
        if (eventKind && titles[eventKind]) {
          return titles[eventKind];
        }
        if (scenario && titles[scenario]) {
          return titles[scenario];
        }
        if (payload && payload.description) {
          return String(payload.description);
        }
        return incidentClassKey(fallbackClass) === 'A' ? 'Критичный сигнал' : 'Сигнал безопасности';
      }

      function eventBodyFromPayload(payload, title) {
        var parts = [];
        if (title) {
          parts.push(String(title));
        }
        if (payload && payload.description) {
          parts.push(String(payload.description));
        }
        if (payload && payload.source_ip) {
          parts.push('Источник сети: ' + String(payload.source_ip));
        }
        if (payload && payload.principal) {
          parts.push('Учётная запись: ' + String(payload.principal));
        }
        if (payload && payload.target_service) {
          parts.push('Сервис: ' + String(payload.target_service));
        }
        if (payload && payload.privilege_scope) {
          parts.push('Привилегии: ' + String(payload.privilege_scope));
        }
        if (payload && payload.occurred_at) {
          parts.push('Произошло: ' + String(payload.occurred_at));
        }
        if (payload && payload.confidence !== undefined && payload.confidence !== null) {
          parts.push('Уверенность: ' + String(payload.confidence));
        }
        if (payload && payload.generated_at) {
          parts.push('Сформировано: ' + String(payload.generated_at));
        }
        return parts.join('\\n');
      }

      function buildIncidentEventSnapshot(event) {
        var payload = cloneData(event && event.payload);
        if (payload === undefined || payload === null || typeof payload !== 'object') {
          payload = {};
        }
        var eventClass = incidentClassKey(event && event.cls);
        var eventTitle = eventTitleFromPayload(payload, eventClass);
        var rawTs = Number(valueOr(event && event.consensus_ts, event && event.ts_local));
        return {
          eventClass: eventClass,
          eventId: valueOr(event && event.id, ''),
          eventSequence: Number(valueOr(event && event.sequence, 0)) || null,
          eventType: eventTypeLabelFromPayload(payload),
          eventTitle: eventTitle,
          eventBody: eventBodyFromPayload(payload, eventTitle),
          eventOccurredAt: isNaN(rawTs) ? '' : new Date(rawTs * 1000).toISOString(),
          payload: payload
        };
      }

      function compactEventId(eventId, eventSequence) {
        var sequence = Number(valueOr(eventSequence, 0));
        if (!isNaN(sequence) && sequence > 0) {
          return '#' + sequence;
        }
        var raw = String(valueOr(eventId, ''));
        if (!raw) {
          return '—';
        }
        return raw.slice(0, 8);
      }

      function incidentSummaryLabel(incident) {
        if (!valueOr(incident && incident.eventId, '')) {
          return valueOr(incident && incident.title, 'Инцидент');
        }
        return valueOr(incident.eventTitle, incident.title);
      }

      function renderIncidentEventDetails(incident) {
        if (!incidentEventMetaEl || !incidentEventBodyEl) {
          return;
        }
        var eventClass = incidentClassKey(incident && incident.eventClass);
        incidentEventMetaEl.innerHTML =
          '<div class="incident-event-meta-item"><span>Класс события</span><strong><span class="incident-event-class ' + incidentClassCss(eventClass) + '">Класс ' + escapeHtml(eventClass) + '</span></strong></div>' +
          '<div class="incident-event-meta-item"><span>ID события</span><strong title="' + escapeHtml(valueOr(incident && incident.eventId, '—')) + '">' + escapeHtml(compactEventId(incident && incident.eventId, incident && incident.eventSequence)) + '</strong></div>' +
          '<div class="incident-event-meta-item"><span>Тип события</span><strong>' + escapeHtml(valueOr(incident && incident.eventType, '—')) + '</strong></div>' +
          '<div class="incident-event-meta-item"><span>Дата и время</span><strong>' + escapeHtml(formatIncidentDate(incident && incident.eventOccurredAt)) + '</strong></div>';
        incidentEventBodyEl.textContent = valueOr(incident && incident.eventBody, '') || 'Подробности исходного события отсутствуют.';
      }

      function renderIncidentViewSwitch() {
        if (incidentViewTableEl) {
          incidentViewTableEl.classList.toggle('active', incidentView === 'table');
        }
        if (incidentViewBoardEl) {
          incidentViewBoardEl.classList.toggle('active', incidentView === 'board');
        }
        if (incidentTableViewEl) {
          incidentTableViewEl.style.display = incidentView === 'table' ? '' : 'none';
        }
        if (incidentBoardViewEl) {
          incidentBoardViewEl.style.display = incidentView === 'board' ? '' : 'none';
        }
      }

      function persistIncidents() {
        if (!incidentEnabled || incidentsSyncInFlight) {
          return;
        }
        incidentsSyncInFlight = true;
        var xhr = new XMLHttpRequest();
        xhr.open('PUT', '/incidents', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) {
            return;
          }
          incidentsSyncInFlight = false;
          if (xhr.status >= 200 && xhr.status < 300) {
            try {
              var payload = JSON.parse(xhr.responseText);
              if (payload && Array.isArray(payload.items)) {
                incidents = payload.items;
              }
            } catch (err) {
              console.log('incident persist parse error', err);
            }
            renderIncidentWorkbench();
            return;
          }
          console.log('incident persist failed', xhr.status, xhr.responseText);
        };
        xhr.onerror = function () {
          incidentsSyncInFlight = false;
          console.log('incident persist network error');
        };
        xhr.send(JSON.stringify({ items: incidents }));
      }

      function sibClassCss(cls) {
        if (cls === 'A') { return 'background:rgba(239,83,80,0.18);color:#ef9a9a;'; }
        if (cls === 'B') { return 'background:rgba(255,179,0,0.18);color:#ffcc80;'; }
        return 'background:rgba(79,195,247,0.18);color:#90caf9;';
      }

      function renderSibPolicy(events) {
        var tbody = document.getElementById('sib-tbody');
        if (!tbody) { return; }
        var enabledCount = 0;
        var rows = events.map(function (e) {
          if (e.registry_enabled) { enabledCount += 1; }
          var npa = (e.npa || []).join('; ');
          var threats = (e.linked_threats || []).join(', ');
          var checked = e.registry_enabled ? ' checked' : '';
          var disabled = e.protected ? ' disabled title="Служебное событие реестра — отключить нельзя"' : '';
          var lockNote = e.protected ? ' <span style="opacity:0.6;font-size:0.75rem;">(защищено)</span>' : '';
          return '<tr style="border-bottom:1px solid rgba(255,255,255,0.06);">' +
            '<td style="padding:7px 10px;"><strong>' + escapeHtml(e.title || e.event_kind) + '</strong>' +
              '<div style="opacity:0.55;font-size:0.76rem;">' + escapeHtml(e.event_kind) + '</div></td>' +
            '<td style="padding:7px 10px;"><span style="padding:2px 8px;border-radius:10px;' + sibClassCss(e['class']) + '">' + escapeHtml(e['class']) + '</span></td>' +
            '<td style="padding:7px 10px;opacity:0.85;">' + escapeHtml(e.source || '—') + '</td>' +
            '<td style="padding:7px 10px;opacity:0.85;font-size:0.78rem;">' + escapeHtml(npa || '—') + '</td>' +
            '<td style="padding:7px 10px;opacity:0.75;font-size:0.78rem;">' + escapeHtml(threats || '—') + '</td>' +
            '<td style="padding:7px 10px;"><label style="display:inline-flex;align-items:center;gap:6px;cursor:pointer;">' +
              '<input type="checkbox" data-sib-kind="' + escapeHtml(e.event_kind) + '"' + checked + disabled + ' />' + lockNote +
            '</label></td>' +
          '</tr>';
        }).join('');
        tbody.innerHTML = rows;
        var cntEl = document.getElementById('sib-count');
        var enEl = document.getElementById('sib-enabled-count');
        if (cntEl) { cntEl.textContent = events.length + ' событий'; }
        if (enEl) { enEl.textContent = enabledCount + ' включено'; }
        // Навесить обработчики туглов.
        var checks = tbody.querySelectorAll('input[data-sib-kind]');
        for (var i = 0; i < checks.length; i += 1) {
          checks[i].addEventListener('change', function (ev) {
            var kind = ev.target.getAttribute('data-sib-kind');
            var enabled = ev.target.checked;
            ev.target.disabled = true;
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '/catalog/policy', true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.onreadystatechange = function () {
              if (xhr.readyState !== 4) { return; }
              ev.target.disabled = false;
              if (xhr.status >= 200 && xhr.status < 300) {
                loadSibPolicy();  // перечитать актуальное состояние
              } else {
                ev.target.checked = !enabled;  // откатить визуально
                alert('Не удалось изменить политику: ' + xhr.status + ' ' + xhr.responseText);
              }
            };
            xhr.send(JSON.stringify({ event_kind: kind, enabled: enabled }));
          });
        }
      }

      // ====== Карта сети (логическая топология + пути атак) ======
      var CMAP_VIEW = { w: 1000, h: 560 };
      var CMAP_TYPE_ICON = { server: '🗄', entry: '🌐', dc: '👑', ws: '💻', iot: '📟' };
      var CMAP_TYPE_COLOR = { server: '#ffa726', entry: '#66bb6a', dc: '#ef5350', ws: '#42a5f5', iot: '#ab47bc' };
      var cmapBoxes = {};  // id -> {x, y, type}
      function cmapDrawNode(svg, ns, node) {
        var color = CMAP_TYPE_COLOR[node.type] || '#90caf9';
        var icon = CMAP_TYPE_ICON[node.type] || '🖥';
        var bw = 56, bh = 56;
        var g = ns('g'); g.setAttribute('data-cmap-node', node.id);
        var rect = ns('rect');
        rect.setAttribute('x', node.x - bw / 2); rect.setAttribute('y', node.y - bh / 2);
        rect.setAttribute('width', bw); rect.setAttribute('height', bh); rect.setAttribute('rx', '12');
        rect.setAttribute('fill', 'rgba(12,22,34,0.92)');
        rect.setAttribute('stroke', node.online === false ? 'rgba(150,150,160,0.5)' : color);
        rect.setAttribute('stroke-width', '2');
        g.appendChild(rect);
        var ic = ns('text');
        ic.setAttribute('x', node.x); ic.setAttribute('y', node.y + 7);
        ic.setAttribute('text-anchor', 'middle'); ic.setAttribute('font-size', '26');
        ic.textContent = icon;
        g.appendChild(ic);
        var name = ns('text');
        name.setAttribute('x', node.x); name.setAttribute('y', node.y + bh / 2 + 18);
        name.setAttribute('text-anchor', 'middle'); name.setAttribute('fill', '#eff3ff');
        name.setAttribute('font-size', '13'); name.setAttribute('font-weight', '600');
        name.textContent = node.label || node.id;
        g.appendChild(name);
        if (node.ip) {
          var ip = ns('text');
          ip.setAttribute('x', node.x); ip.setAttribute('y', node.y + bh / 2 + 33);
          ip.setAttribute('text-anchor', 'middle'); ip.setAttribute('fill', 'rgba(200,210,230,0.55)');
          ip.setAttribute('font-size', '11');
          ip.textContent = node.ip;
          g.appendChild(ip);
        }
        svg.appendChild(g);
      }
      function renderNetworkMap(servers, attacks) {
        var svg = document.getElementById('cmap-svg');
        if (!svg) { return; }
        var svgNS2 = 'http://www.w3.org/2000/svg';
        function ns(tag) { return document.createElementNS(svgNS2, tag); }
        svg.setAttribute('viewBox', '0 0 ' + CMAP_VIEW.w + ' ' + CMAP_VIEW.h);
        svg.innerHTML = '';
        cmapBoxes = {};
        // defs: стрелка для пути атаки.
        var defs = ns('defs');
        var marker = ns('marker');
        marker.setAttribute('id', 'cmap-arrow'); marker.setAttribute('markerWidth', '10');
        marker.setAttribute('markerHeight', '8'); marker.setAttribute('refX', '8');
        marker.setAttribute('refY', '4'); marker.setAttribute('orient', 'auto');
        var ap = ns('path'); ap.setAttribute('d', 'M0,0 L10,4 L0,8 z'); ap.setAttribute('fill', '#ef5350');
        marker.appendChild(ap); defs.appendChild(marker); svg.appendChild(defs);
        // Раскладка серверов реестра — ряд по центру.
        var sN = servers.length;
        var sY = 360;
        servers.forEach(function (s, i) {
          var x = sN === 1 ? CMAP_VIEW.w / 2 : (CMAP_VIEW.w * 0.18 + i * (CMAP_VIEW.w * 0.64 / (sN - 1)));
          cmapBoxes[s.id] = { x: x, y: sY, type: 'server' };
        });
        // Точки входа (атакующие IP) — ряд сверху.
        var eN = attacks.length;
        var eY = 110;
        attacks.forEach(function (a, i) {
          var x = eN === 1 ? CMAP_VIEW.w / 2 : (CMAP_VIEW.w * 0.15 + i * (CMAP_VIEW.w * 0.70 / Math.max(1, eN - 1)));
          cmapBoxes['entry:' + a.from] = { x: x, y: eY, type: 'entry' };
        });
        // Соединения gossip (синие) между серверами.
        for (var i = 0; i < servers.length; i += 1) {
          for (var j = i + 1; j < servers.length; j += 1) {
            var a2 = cmapBoxes[servers[i].id], b2 = cmapBoxes[servers[j].id];
            var ln = ns('line');
            ln.setAttribute('x1', a2.x); ln.setAttribute('y1', a2.y);
            ln.setAttribute('x2', b2.x); ln.setAttribute('y2', b2.y);
            var both = servers[i].online !== false && servers[j].online !== false;
            ln.setAttribute('stroke', both ? 'rgba(106,169,255,0.5)' : 'rgba(120,120,140,0.2)');
            ln.setAttribute('stroke-width', '2');
            svg.appendChild(ln);
          }
        }
        // Пути атаки (красный пунктир со стрелкой) — от точки входа к жертве.
        attacks.forEach(function (a) {
          var from = cmapBoxes['entry:' + a.from];
          var to = cmapBoxes[a.to];
          if (!from || !to) { return; }
          var ln = ns('line');
          ln.setAttribute('x1', from.x); ln.setAttribute('y1', from.y + 30);
          ln.setAttribute('x2', to.x); ln.setAttribute('y2', to.y - 30);
          ln.setAttribute('stroke', '#ef5350'); ln.setAttribute('stroke-width', '2');
          ln.setAttribute('stroke-dasharray', '6 4'); ln.setAttribute('marker-end', 'url(#cmap-arrow)');
          svg.appendChild(ln);
        });
        // Рисуем узлы поверх линий.
        servers.forEach(function (s) {
          var box = cmapBoxes[s.id];
          cmapDrawNode(svg, ns, { id: s.id, label: s.id, ip: s.ip, type: 'server', online: s.online, x: box.x, y: box.y });
        });
        attacks.forEach(function (a) {
          var box = cmapBoxes['entry:' + a.from];
          cmapDrawNode(svg, ns, { id: 'entry:' + a.from, label: 'Внешний', ip: a.from, type: 'entry', x: box.x, y: box.y });
        });
        var cntEl = document.getElementById('cmap-nodes');
        var atkEl = document.getElementById('cmap-attacks');
        if (cntEl) { cntEl.textContent = servers.length + ' узлов'; }
        if (atkEl) { atkEl.textContent = attacks.length + ' источн. атак'; }
      }
      function pulseClusterNode(nodeId) {
        var svg = document.getElementById('cmap-svg');
        if (!svg || !cmapBoxes[nodeId]) { return; }
        var box = cmapBoxes[nodeId];
        var ns = function (t) { return document.createElementNS('http://www.w3.org/2000/svg', t); };
        var wave = ns('circle');
        wave.setAttribute('cx', box.x); wave.setAttribute('cy', box.y); wave.setAttribute('r', '30');
        wave.setAttribute('fill', 'none'); wave.setAttribute('stroke', '#ef5350'); wave.setAttribute('stroke-width', '3');
        svg.appendChild(wave);
        var a1 = ns('animate'); a1.setAttribute('attributeName', 'r'); a1.setAttribute('from', '30'); a1.setAttribute('to', '90');
        a1.setAttribute('dur', '1s'); a1.setAttribute('fill', 'freeze'); wave.appendChild(a1);
        var a2 = ns('animate'); a2.setAttribute('attributeName', 'opacity'); a2.setAttribute('from', '0.9'); a2.setAttribute('to', '0');
        a2.setAttribute('dur', '1s'); a2.setAttribute('fill', 'freeze'); wave.appendChild(a2);
        setTimeout(function () { if (wave.parentNode) { wave.parentNode.removeChild(wave); } }, 1100);
      }
      function loadClusterMap() {
        var xhrS = new XMLHttpRequest();
        xhrS.open('GET', '/status', true);
        xhrS.onreadystatechange = function () {
          if (xhrS.readyState !== 4 || xhrS.status < 200 || xhrS.status >= 300) { return; }
          try {
            var d = JSON.parse(xhrS.responseText);
            var servers = [];
            var now = Date.now() / 1000;
            servers.push({ id: d.node_id, ip: '', online: true });
            (d.peers || []).forEach(function (p) {
              if (p.is_self) { return; }
              servers.push({ id: p.node_id || p.address, ip: (p.address || '').split(':')[0], online: !!(p.last_seen && (now - p.last_seen) < 60) });
            });
            // Атаки: события класса A с source_ip за последнее время.
            var xhrG = new XMLHttpRequest();
            xhrG.open('GET', '/viz/graph', true);
            xhrG.onreadystatechange = function () {
              if (xhrG.readyState !== 4) { return; }
              var attacks = [];
              if (xhrG.status >= 200 && xhrG.status < 300) {
                try {
                  var g = JSON.parse(xhrG.responseText);
                  var byIp = {};
                  (g.nodes || []).forEach(function (n) {
                    var p = n.payload || {};
                    if (n.cls === 'A' && p.source_ip) {
                      var key = p.source_ip;
                      if (!byIp[key]) { byIp[key] = { from: key, to: n.creator || n.source, count: 0 }; }
                      byIp[key].count += 1;
                    }
                  });
                  attacks = Object.keys(byIp).map(function (k) { return byIp[k]; })
                    .sort(function (a, b) { return b.count - a.count; }).slice(0, 8);
                } catch (e) {}
              }
              renderNetworkMap(servers, attacks);
            };
            xhrG.send();
          } catch (err) {}
        };
        xhrS.send();
      }

      function loadSibPolicy() {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '/catalog', true);
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) { return; }
          if (xhr.status >= 200 && xhr.status < 300) {
            try {
              var payload = JSON.parse(xhr.responseText);
              renderSibPolicy(payload && Array.isArray(payload.events) ? payload.events : []);
            } catch (err) {}
          }
        };
        xhr.send();
      }

      function loadIncidents() {
        if (!incidentEnabled) {
          incidents = [];
          incidentsLoaded = false;
          renderIncidentWorkbench();
          return;
        }
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '/incidents', true);
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) {
            return;
          }
          if (xhr.status >= 200 && xhr.status < 300) {
            try {
              var payload = JSON.parse(xhr.responseText);
              incidents = payload && Array.isArray(payload.items) ? payload.items : [];
              incidentsLoaded = true;
              lastOperationalNodes.forEach(function (node) {
                ensureIncidentFromEvent(node);
              });
              renderIncidentWorkbench();
            } catch (err) {
              console.log('incident load parse error', err);
            }
            return;
          }
          console.log('incident load failed', xhr.status, xhr.responseText);
        };
        xhr.onerror = function () {
          console.log('incident load network error');
        };
        xhr.send();
      }

      function formatIncidentDate(value) {
        if (!value) {
          return '—';
        }
        var date = new Date(value);
        if (isNaN(date.getTime())) {
          return value;
        }
        return date.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
      }

      function toDateTimeLocalValue(value) {
        if (!value) {
          return '';
        }
        var date = new Date(value);
        if (isNaN(date.getTime())) {
          return '';
        }
        var offset = date.getTimezoneOffset();
        var local = new Date(date.getTime() - offset * 60000);
        return local.toISOString().slice(0, 16);
      }

      function fromDateTimeLocalValue(value) {
        if (!value) {
          return '';
        }
        var date = new Date(value);
        if (isNaN(date.getTime())) {
          return '';
        }
        return date.toISOString();
      }

      function fillIncidentStatusOptions() {
        if (!incidentStatusInputEl || incidentStatusInputEl.options.length) {
          return;
        }
        incidentStatuses.forEach(function (status) {
          var option = document.createElement('option');
          option.value = status;
          option.textContent = status;
          incidentStatusInputEl.appendChild(option);
        });
      }

      function findIncident(id) {
        for (var i = 0; i < incidents.length; i += 1) {
          if (incidents[i].id === id) {
            return incidents[i];
          }
        }
        return null;
      }

      function defaultChecklist() {
        return [
          { id: 'triage', text: 'Проверить исходные события', done: false },
          { id: 'scope', text: 'Оценить затронутые узлы и источник', done: false }
        ];
      }

      function renderIncidentChecklistEditor(items) {
        if (!incidentChecklistEl) {
          return;
        }
        incidentChecklistEl.innerHTML = '';
        (items || []).forEach(function (item, index) {
          var row = document.createElement('div');
          row.className = 'incident-check-item';
          row.innerHTML =
            '<input type="checkbox" data-check-index="' + index + '"' + (item.done ? ' checked' : '') + ' />' +
            '<input type="text" data-check-text-index="' + index + '" value="' + escapeHtml(valueOr(item.text, '')) + '" />';
          incidentChecklistEl.appendChild(row);
        });
      }

      function formatPeerLastSeen(value) {
        var ts = Number(value);
        if (!ts || isNaN(ts)) {
          return '—';
        }
        return new Date(ts * 1000).toLocaleString('ru-RU', {
          day: '2-digit',
          month: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit'
        });
      }

      function setNetworkStatus(message, isError) {
        if (!networkStatusLineEl) {
          return;
        }
        networkStatusLineEl.textContent = message;
        networkStatusLineEl.style.color = isError ? '#ffaaaa' : '';
      }

      function renderConsensusMembershipSummary() {
        if (!networkConsensusSummaryEl) {
          return;
        }
        if (!lastStatusSnapshot) {
          networkConsensusSummaryEl.textContent = 'Загружаем epoch и состав участников…';
          return;
        }
        var epoch = valueOr(lastStatusSnapshot.consensus_epoch, '—');
        var size = valueOr(lastStatusSnapshot.consensus_membership_size, '—');
        var fingerprint = String(valueOr(lastStatusSnapshot.membership_snapshot_hash, '—'));
        networkConsensusSummaryEl.textContent = 'Epoch ' + epoch + ' · участников ' + size + ' · hash ' + fingerprint.slice(0, 12);
      }

      function normalizeNodeRole(role) {
        return role === 'responder' ? 'responder' : 'node';
      }

      function formatNodeRoleLabel(role) {
        return normalizeNodeRole(role) === 'responder' ? 'Реагирование' : 'Участник сети';
      }

      function isResponderRole(role) {
        return normalizeNodeRole(role) === 'responder';
      }

      function renderRoleValue(targetEl, role) {
        if (!targetEl) {
          return;
        }
        targetEl.innerHTML = '<a href="#network-workbench" class="role-value-link">' + escapeHtml(formatNodeRoleLabel(role)) + '</a>';
      }

      function buildRoleSelectMarkup(address, role, disabled) {
        var current = normalizeNodeRole(role);
        return '<select class="network-role-select" data-peer-role="' + escapeHtml(valueOr(address, '')) + '"' + (disabled ? ' disabled' : '') + '>' +
          '<option value="node"' + (current === 'node' ? ' selected' : '') + '>Участник сети</option>' +
          '<option value="responder"' + (current === 'responder' ? ' selected' : '') + '>Реагирование</option>' +
        '</select>';
      }

      function renderPeerRegistry() {
        if (!networkTableViewEl) {
          return;
        }
        var total = peerRegistry.length;
        var enabledCount = peerRegistry.filter(function (item) { return !!item.enabled; }).length;
        var disabledCount = total - enabledCount;
        setText(networkPeerTotalEl, String(total));
        setText(networkPeerEnabledEl, String(enabledCount));
        setText(networkPeerDisabledEl, String(disabledCount));
        if (!total) {
          networkTableViewEl.innerHTML = '<div class="incident-empty">Участники сети ещё не добавлены.</div>';
          return;
        }
        var rows = peerRegistry.map(function (peer, index) {
          var modeClass = peer.enabled ? 'enabled' : 'disabled';
          var modeLabel = peer.is_self ? 'Текущий узел' : (peer.enabled ? 'Включён' : 'Исключён');
          var health = peer.healthy ? 'Доступен' : 'Нет подтверждения';
          var addressLabel = peer.is_self ? ('Текущий узел · ' + valueOr(lastStatusSnapshot && lastStatusSnapshot.node_id, valueOr(peer.address, '—'))) : valueOr(peer.address, '—');
          var addressKey = escapeHtml(valueOr(peer.address, ''));
          var roleSelect = buildRoleSelectMarkup(peer.address, peer.role, false);
          var noteInput = '<input class="network-note-input" data-peer-note="' + addressKey + '" type="text" value="' + escapeHtml(valueOr(peer.note, '')) + '" />';
          var actionButtons = '<div class="network-row-actions">' +
              '<button class="network-action-btn" data-peer-save="' + addressKey + '" type="button">Сохранить</button>';
          if (!peer.is_self) {
            actionButtons +=
              '<button class="network-action-btn ' + (peer.enabled ? 'warn' : 'primary') + '" data-peer-toggle="' + addressKey + '" data-peer-enabled="' + (peer.enabled ? '1' : '0') + '" type="button">' + (peer.enabled ? 'Исключить' : 'Вернуть') + '</button>' +
              '<button class="network-action-btn danger" data-peer-remove="' + addressKey + '" type="button">Удалить</button>';
          }
          actionButtons += '</div>';
          return '<tr data-peer-row="' + index + '">' +
            '<td><strong>' + escapeHtml(addressLabel) + '</strong></td>' +
            '<td>' + escapeHtml(valueOr(peer.node_id, 'не определён')) + '</td>' +
            '<td>' + roleSelect + '</td>' +
            '<td><span class="network-mode-pill ' + modeClass + '">' + modeLabel + '</span></td>' +
            '<td>' + escapeHtml(health) + '</td>' +
            '<td>' + escapeHtml(formatPeerLastSeen(peer.last_seen)) + '</td>' +
            '<td>' + escapeHtml(valueOr(peer.source, 'runtime')) + '</td>' +
            '<td>' + noteInput + '</td>' +
            '<td>' + actionButtons + '</td>' +
          '</tr>';
        }).join('');
        networkTableViewEl.innerHTML =
          '<div class="network-table-wrap">' +
            '<table class="network-table">' +
              '<thead><tr><th>Адрес</th><th>Node ID</th><th>Роль</th><th>Режим</th><th>Состояние</th><th>Последняя связь</th><th>Источник</th><th>Заметка</th><th>Действия</th></tr></thead>' +
              '<tbody>' + rows + '</tbody>' +
            '</table>' +
          '</div>';

        Array.prototype.slice.call(networkTableViewEl.querySelectorAll('[data-peer-save]')).forEach(function (button) {
          button.addEventListener('click', function () {
            var address = button.getAttribute('data-peer-save');
            var noteInput = networkTableViewEl.querySelector('[data-peer-note="' + address + '"]');
            var roleInput = networkTableViewEl.querySelector('[data-peer-role="' + address + '"]');
            updatePeerRegistryEntry(address, { note: noteInput ? noteInput.value : '', role: roleInput ? roleInput.value : 'node' }, 'Сохраняем параметры участника…');
          });
        });
        Array.prototype.slice.call(networkTableViewEl.querySelectorAll('[data-peer-toggle]')).forEach(function (button) {
          button.addEventListener('click', function () {
            var address = button.getAttribute('data-peer-toggle');
            var enabled = button.getAttribute('data-peer-enabled') === '1';
            var noteInput = networkTableViewEl.querySelector('[data-peer-note="' + address + '"]');
            var roleInput = networkTableViewEl.querySelector('[data-peer-role="' + address + '"]');
            updatePeerRegistryEntry(address, { enabled: !enabled, note: noteInput ? noteInput.value : '', role: roleInput ? roleInput.value : 'node' }, enabled ? 'Исключаем участника из сети…' : 'Возвращаем участника в сеть…');
          });
        });
        Array.prototype.slice.call(networkTableViewEl.querySelectorAll('[data-peer-role]')).forEach(function (selectEl) {
          selectEl.addEventListener('change', function () {
            var address = selectEl.getAttribute('data-peer-role');
            var noteInput = networkTableViewEl.querySelector('[data-peer-note="' + address + '"]');
            updatePeerRegistryEntry(address, { role: selectEl.value, note: noteInput ? noteInput.value : '' }, 'Переключаем роль участника…');
          });
        });
        Array.prototype.slice.call(networkTableViewEl.querySelectorAll('[data-peer-remove]')).forEach(function (button) {
          button.addEventListener('click', function () {
            var address = button.getAttribute('data-peer-remove');
            removePeerRegistryEntry(address);
          });
        });
      }

      function loadPeerRegistry() {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '/peers', true);
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) {
            return;
          }
          if (xhr.status >= 200 && xhr.status < 300) {
            try {
              var resp = JSON.parse(xhr.responseText);
              peerRegistry = Array.isArray(resp.peers) ? resp.peers : [];
              setNetworkStatus('Реестр участников сети синхронизирован.', false);
              renderPeerRegistry();
              renderConsensusMembershipSummary();
            } catch (err) {
              setNetworkStatus('Не удалось разобрать ответ реестра участников.', true);
            }
          } else {
            setNetworkStatus('Не удалось загрузить участников сети.', true);
          }
        };
        xhr.onerror = function () {
          setNetworkStatus('Ошибка сети при загрузке участников.', true);
        };
        xhr.send();
      }

      function addPeerRegistryEntry() {
        var address = valueOr(networkAddressInputEl && networkAddressInputEl.value, '').trim();
        var role = normalizeNodeRole(valueOr(networkRoleInputEl && networkRoleInputEl.value, 'node'));
        var note = valueOr(networkNoteInputEl && networkNoteInputEl.value, '').trim();
        if (!address) {
          setNetworkStatus('Укажите адрес узла в формате host:port.', true);
          return;
        }
        setNetworkStatus('Добавляем участника сети…', false);
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/peers/register', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) {
            return;
          }
          if (xhr.status >= 200 && xhr.status < 300) {
            if (networkAddressInputEl) { networkAddressInputEl.value = ''; }
            if (networkRoleInputEl) { networkRoleInputEl.value = 'node'; }
            if (networkNoteInputEl) { networkNoteInputEl.value = ''; }
            setNetworkStatus('Участник добавлен в локальный реестр.', false);
            loadPeerRegistry();
            fetchNodeStatus();
          } else {
            setNetworkStatus('Не удалось добавить участника.', true);
          }
        };
        xhr.onerror = function () {
          setNetworkStatus('Ошибка сети при добавлении участника.', true);
        };
        xhr.send(JSON.stringify({ address: address, note: note, role: role }));
      }

      function updatePeerRegistryEntry(address, payload, pendingText) {
        if (!address) {
          return;
        }
        setNetworkStatus(pendingText || 'Обновляем участника сети…', false);
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/peers/update', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) {
            return;
          }
          if (xhr.status >= 200 && xhr.status < 300) {
            setNetworkStatus('Участник сети обновлён.', false);
            loadPeerRegistry();
            fetchNodeStatus();
          } else {
            setNetworkStatus('Не удалось обновить участника сети.', true);
          }
        };
        xhr.onerror = function () {
          setNetworkStatus('Ошибка сети при обновлении участника.', true);
        };
        var body = cloneData(payload) || {};
        body.address = address;
        xhr.send(JSON.stringify(body));
      }

      function removePeerRegistryEntry(address) {
        if (!address) {
          return;
        }
        setNetworkStatus('Удаляем участника сети…', false);
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/peers/remove', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) {
            return;
          }
          if (xhr.status >= 200 && xhr.status < 300) {
            setNetworkStatus('Участник удалён из локального реестра.', false);
            loadPeerRegistry();
            fetchNodeStatus();
          } else {
            setNetworkStatus('Не удалось удалить участника.', true);
          }
        };
        xhr.onerror = function () {
          setNetworkStatus('Ошибка сети при удалении участника.', true);
        };
        xhr.send(JSON.stringify({ address: address }));
      }

      function reconfigureConsensusMembership() {
        setNetworkStatus('Пересобираем frozen consensus membership…', false);
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/consensus/reconfigure', true);
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) {
            return;
          }
          if (xhr.status >= 200 && xhr.status < 300) {
            setNetworkStatus('Активный состав консенсуса пересобран.', false);
            fetchNodeStatus();
            loadPeerRegistry();
          } else {
            setNetworkStatus('Не удалось пересобрать состав консенсуса.', true);
          }
        };
        xhr.onerror = function () {
          setNetworkStatus('Ошибка сети при пересборке консенсуса.', true);
        };
        xhr.send(JSON.stringify({}));
      }

      function escapeHtml(value) {
        return String(value)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }

      function setIncidentWorkbenchEnabled(enabled) {
        incidentEnabled = !!enabled;
        // Видимостью самой секции управляет роутер страниц (routeToPage):
        // incident-workbench показывается ТОЛЬКО на своей странице, а не
        // на дашборде. Здесь — только доступность раздела (nav-item) и данные.
        if (incidentNavItemEl) {
          incidentNavItemEl.style.display = incidentEnabled ? '' : 'none';
        }
        if (incidentEnabled) {
          if (!incidentsLoaded) {
            loadIncidents();
          }
          renderIncidentWorkbench();
        }
        // Пересинхронизировать видимость страниц (статус узла мог прийти
        // асинхронно уже после первичного роутинга).
        if (typeof window.__mdrjRoute === 'function') {
          window.__mdrjRoute();
        }
        if (!incidentEnabled) {
          incidentsLoaded = false;
          closeIncidentModal();
          if (window.location.hash === '#incident-workbench') {
            window.location.hash = '#network-workbench';
          }
        }
      }

      function updateIncidentFilterButtons() {
        var allActive = incidentClassFilterState.A && incidentClassFilterState.B && incidentClassFilterState.C;
        if (incidentFilterAllEl) {
          incidentFilterAllEl.classList.toggle('active', allActive);
        }
        incidentFilterButtons.forEach(function (button) {
          var cls = button.getAttribute('data-incident-filter-class');
          if (!cls) {
            return;
          }
          button.classList.toggle('active', !!incidentClassFilterState[cls]);
        });
      }

      function incidentVisibleByClass(incident) {
        var cls = incidentClassKey(incident && incident.eventClass);
        return !!incidentClassFilterState[cls];
      }

      function incidentFieldValue(incident, key) {
        if (!incident) {
          return '—';
        }
        if (key === 'eventClass') {
          return 'Класс ' + incidentClassKey(incident.eventClass);
        }
        if (key === 'eventId') {
          return compactEventId(valueOr(incident.eventId, incident.id), incident.eventSequence);
        }
        if (key === 'eventType') {
          return valueOr(incident.eventType, '—');
        }
        if (key === 'eventOccurredAt') {
          return formatIncidentDate(valueOr(incident.eventOccurredAt, incident.detectedAt));
        }
        if (key === 'incident') {
          return incidentSummaryLabel(incident);
        }
        if (key === 'status') {
          return valueOr(incident.status, '—');
        }
        if (key === 'priority') {
          return incidentPriorityLabel(valueOr(incident.priority, 'medium'));
        }
        if (key === 'source') {
          return valueOr(incident.source, '—');
        }
        if (key === 'owner') {
          return valueOr(incident.owner, '—');
        }
        if (key === 'labels') {
          return (incident.labels || []).join(', ') || '—';
        }
        return valueOr(incident[key], '—');
      }

      function incidentMatchesQuery(incident) {
        var query = String(incidentSearchQuery || '').trim().toLowerCase();
        if (!query) {
          return true;
        }
        var values = [
          incidentFieldValue(incident, 'eventClass'),
          valueOr(incident.eventId, incident.id),
          incidentFieldValue(incident, 'eventType'),
          incidentFieldValue(incident, 'eventOccurredAt'),
          incidentFieldValue(incident, 'incident'),
          valueOr(incident.title, ''),
          incidentFieldValue(incident, 'status'),
          incidentFieldValue(incident, 'priority'),
          incidentFieldValue(incident, 'source'),
          incidentFieldValue(incident, 'owner'),
          incidentFieldValue(incident, 'labels'),
          valueOr(incident.description, ''),
          valueOr(incident.eventBody, '')
        ];
        return values.some(function (value) {
          return String(value || '').toLowerCase().indexOf(query) !== -1;
        });
      }

      function setAllIncidentClassFilters(value) {
        incidentClassFilterState.A = !!value;
        incidentClassFilterState.B = !!value;
        incidentClassFilterState.C = !!value;
        updateIncidentFilterButtons();
        renderIncidentWorkbench();
      }

      function toggleIncidentClassFilter(cls) {
        if (!incidentClassFilterState.hasOwnProperty(cls)) {
          return;
        }
        if (incidentClassFilterState[cls] && Object.keys(incidentClassFilterState).filter(function (key) {
          return incidentClassFilterState[key];
        }).length <= 1) {
          return;
        }
        incidentClassFilterState[cls] = !incidentClassFilterState[cls];
        updateIncidentFilterButtons();
        renderIncidentWorkbench();
      }

      function renderIncidentTable() {
        if (!incidentTableViewEl) {
          return;
        }
        if (!incidentEnabled) {
          incidentTableViewEl.innerHTML = '';
          return;
        }
        if (!incidentsLoaded) {
          incidentTableViewEl.innerHTML = '<div class="incident-empty">Загружаем инциденты из сервера…</div>';
          return;
        }
        var visibleIncidents = incidents.filter(function (incident) {
          return incidentVisibleByClass(incident) && incidentMatchesQuery(incident);
        });
        if (visibleIncidents.length === 0) {
          incidentTableViewEl.innerHTML = '<div class="incident-empty">Карточки появятся после критичных или важных событий, либо после ручного создания инцидента.</div>';
          return;
        }
        var rows = [];
        var lastGroupValue = null;
        visibleIncidents.forEach(function (incident) {
          var labels = (incident.labels || []).map(function (label) {
            return '<span class="incident-label-chip">' + escapeHtml(label) + '</span>';
          }).join('');
          var eventClass = incidentClassKey(incident.eventClass);
          var note = valueOr(incident.note, '');
          if (incidentGroupBy) {
            var groupValue = incidentFieldValue(incident, incidentGroupBy);
            if (groupValue !== lastGroupValue) {
              rows.push('<tr class="incident-group-row"><td colspan="11">' + escapeHtml(groupValue) + '</td></tr>');
              lastGroupValue = groupValue;
            }
          }
          rows.push('<tr data-incident-open="' + incident.id + '">' +
            '<td><span class="incident-event-class ' + incidentClassCss(eventClass) + '">Класс ' + escapeHtml(eventClass) + '</span></td>' +
            '<td><span class="incident-row-title" title="' + escapeHtml(valueOr(incident.eventId, incident.id)) + '">' + escapeHtml(compactEventId(valueOr(incident.eventId, incident.id), incident.eventSequence)) + '</span></td>' +
            '<td>' + escapeHtml(valueOr(incident.eventType, '—')) + '</td>' +
            '<td>' + escapeHtml(formatIncidentDate(valueOr(incident.eventOccurredAt, incident.detectedAt))) + '</td>' +
            '<td><span class="incident-row-title">' + escapeHtml(incidentSummaryLabel(incident)) + '</span><span class="incident-mini">' + escapeHtml(valueOr(incident.title, '—')) + '</span></td>' +
            '<td><span class="incident-status-pill">' + escapeHtml(incident.status) + '</span></td>' +
            '<td><span class="incident-priority-pill ' + escapeHtml(incident.priority) + '">' + incidentPriorityLabel(incident.priority) + '</span></td>' +
            '<td>' + escapeHtml(valueOr(incident.source, '—')) + '</td>' +
            '<td>' + escapeHtml(valueOr(incident.owner, '—')) + '</td>' +
            '<td><div class="incident-label-cluster">' + labels + '</div></td>' +
            '<td><div class="incident-table-note">' + escapeHtml(note || '—') + '</div></td>' +
          '</tr>');
        });
        incidentTableViewEl.innerHTML =
          '<div class="incident-table-wrap">' +
            '<table class="incident-table">' +
              '<thead><tr><th>Класс события</th><th>ID события</th><th>Тип события</th><th>Дата/Время</th><th>Инцидент</th><th>Статус</th><th>Приоритет</th><th>Источник</th><th>Ответственный</th><th>Метки</th><th>Примечание</th></tr></thead>' +
              '<tbody>' + rows.join('') + '</tbody>' +
            '</table>' +
          '</div>';
        Array.prototype.slice.call(incidentTableViewEl.querySelectorAll('[data-incident-open]')).forEach(function (row) {
          row.addEventListener('click', function () {
            openIncidentModal(row.getAttribute('data-incident-open'));
          });
        });
      }

      function renderIncidentBoard() {
        if (!incidentBoardViewEl) {
          return;
        }
        if (!incidentEnabled) {
          incidentBoardViewEl.innerHTML = '';
          return;
        }
        if (!incidentsLoaded) {
          incidentBoardViewEl.innerHTML = '<div class="incident-empty">Загружаем инциденты из сервера…</div>';
          return;
        }
        var visibleIncidents = incidents.filter(function (incident) {
          return incidentVisibleByClass(incident) && incidentMatchesQuery(incident);
        });
        if (visibleIncidents.length === 0) {
          incidentBoardViewEl.innerHTML = '<div class="incident-empty">Доска заполнится карточками после появления сигналов или ручного создания инцидента.</div>';
          return;
        }
        var columns = incidentStatuses.map(function (status) {
          var cards = visibleIncidents.filter(function (incident) { return incident.status === status; });
          var cardHtml = cards.map(function (incident) {
            return '<article class="incident-card" draggable="true" data-incident-id="' + incident.id + '">' +
              '<div class="incident-card-title">' + escapeHtml(incident.title) + '</div>' +
              '<div class="incident-card-meta">' +
                '<span class="incident-priority-pill ' + escapeHtml(incident.priority) + '">' + incidentPriorityLabel(incident.priority) + '</span>' +
                '<span class="incident-status-pill">' + escapeHtml(valueOr(incident.owner, 'Без ответственного')) + '</span>' +
              '</div>' +
              '<div class="incident-card-desc">' + escapeHtml(valueOr(incident.description, 'Описание ещё не заполнено.')) + '</div>' +
              '<div class="incident-card-meta"><span>' + escapeHtml(valueOr(incident.source, '—')) + '</span><span>Событий: ' + escapeHtml(String((incident.relatedEvents || []).length)) + '</span></div>' +
            '</article>';
          }).join('');
          return '<section class="incident-column" data-status-column="' + escapeHtml(status) + '">' +
            '<div class="incident-column-head"><h4>' + escapeHtml(status) + '</h4><span class="incident-column-count">' + cards.length + '</span></div>' +
            '<div class="incident-column-body">' + (cardHtml || '<div class="incident-empty">Пусто</div>') + '</div>' +
          '</section>';
        }).join('');
        incidentBoardViewEl.innerHTML = '<div class="incident-board">' + columns + '</div>';
        Array.prototype.slice.call(incidentBoardViewEl.querySelectorAll('.incident-card')).forEach(function (card) {
          card.addEventListener('click', function () {
            openIncidentModal(card.getAttribute('data-incident-id'));
          });
          card.addEventListener('dragstart', function (event) {
            event.dataTransfer.setData('text/plain', card.getAttribute('data-incident-id'));
          });
        });
        Array.prototype.slice.call(incidentBoardViewEl.querySelectorAll('.incident-column')).forEach(function (column) {
          column.addEventListener('dragover', function (event) {
            event.preventDefault();
            column.classList.add('drag-over');
          });
          column.addEventListener('dragleave', function () {
            column.classList.remove('drag-over');
          });
          column.addEventListener('drop', function (event) {
            event.preventDefault();
            column.classList.remove('drag-over');
            var incidentId = event.dataTransfer.getData('text/plain');
            var incident = findIncident(incidentId);
            if (!incident) {
              return;
            }
            incident.status = column.getAttribute('data-status-column');
            incident.updatedAt = new Date().toISOString();
            persistIncidents();
            renderIncidentWorkbench();
          });
        });
      }

      function renderIncidentRelatedEvents(incident) {
        if (!incidentEventsEl) {
          return;
        }
        incidentEventsEl.innerHTML = '';
        var related = (incident && incident.relatedEvents) ? incident.relatedEvents : [];
        if (!related.length) {
          incidentEventsEl.innerHTML = '<div class="incident-empty">Связанные события появятся здесь, если карточка создана из сигналов панели.</div>';
          return;
        }
        related.forEach(function (entry) {
          var item = document.createElement('div');
          item.className = 'incident-event-item';
          item.innerHTML = '<strong>' + escapeHtml(valueOr(entry.cls, '—')) + '</strong> · ' + escapeHtml(valueOr(entry.source, '—')) + '<br>' +
            '<span class="incident-mini" title="' + escapeHtml(valueOr(entry.id, '—')) + '">Событие ' + escapeHtml(compactEventId(entry.id, entry.sequence)) + ' · ' + escapeHtml(formatIncidentDate(entry.ts)) + '</span>';
          incidentEventsEl.appendChild(item);
        });
      }

      function closeIncidentModal() {
        incidentDraftId = null;
        if (incidentModalShellEl) {
          incidentModalShellEl.classList.remove('open');
        }
      }

      function openIncidentModal(id) {
        if (!incidentEnabled || !incidentModalShellEl) {
          return;
        }
        fillIncidentStatusOptions();
        var incident = findIncident(id);
        if (!incident) {
          return;
        }
        incidentDraftId = id;
        if (incidentModalTitleEl) {
          incidentModalTitleEl.textContent = incident.title;
        }
        if (incidentTitleInputEl) { incidentTitleInputEl.value = valueOr(incident.title, ''); }
        if (incidentStatusInputEl) { incidentStatusInputEl.value = valueOr(incident.status, incidentStatuses[0]); }
        if (incidentPriorityInputEl) { incidentPriorityInputEl.value = valueOr(incident.priority, 'medium'); }
        if (incidentOwnerInputEl) { incidentOwnerInputEl.value = valueOr(incident.owner, ''); }
        if (incidentSourceInputEl) { incidentSourceInputEl.value = valueOr(incident.source, ''); }
        if (incidentLabelsInputEl) { incidentLabelsInputEl.value = (incident.labels || []).join(', '); }
        if (incidentDetectedInputEl) { incidentDetectedInputEl.value = toDateTimeLocalValue(incident.detectedAt); }
        if (incidentDueInputEl) { incidentDueInputEl.value = toDateTimeLocalValue(incident.dueAt); }
        if (incidentNoteInputEl) { incidentNoteInputEl.value = valueOr(incident.note, ''); }
        if (incidentDescriptionInputEl) { incidentDescriptionInputEl.value = valueOr(incident.description, ''); }
        renderIncidentEventDetails(incident);
        renderIncidentChecklistEditor(incident.checklist || []);
        renderIncidentRelatedEvents(incident);
        incidentModalShellEl.classList.add('open');
      }

      function createManualIncident() {
        var id = 'incident-' + Date.now();
        incidents.unshift({
          id: id,
          title: 'Новый инцидент',
          status: incidentStatuses[0],
          priority: 'medium',
          eventClass: 'C',
          eventId: '',
          eventSequence: null,
          eventType: 'Ручной инцидент',
          eventTitle: 'Ручная карточка',
          eventBody: '',
          eventOccurredAt: new Date().toISOString(),
          source: valueOr(navNodeIdEl ? navNodeIdEl.textContent : '', ''),
          owner: '',
          labels: ['ручной'],
          note: '',
          description: '',
          detectedAt: new Date().toISOString(),
          dueAt: '',
          checklist: defaultChecklist(),
          relatedEvents: [],
          updatedAt: new Date().toISOString()
        });
        persistIncidents();
        renderIncidentWorkbench();
        openIncidentModal(id);
      }

      function saveIncidentModal() {
        var incident = findIncident(incidentDraftId);
        if (!incident) {
          return;
        }
        incident.title = valueOr(incidentTitleInputEl && incidentTitleInputEl.value, incident.title);
        incident.status = valueOr(incidentStatusInputEl && incidentStatusInputEl.value, incident.status);
        incident.priority = valueOr(incidentPriorityInputEl && incidentPriorityInputEl.value, incident.priority);
        incident.owner = valueOr(incidentOwnerInputEl && incidentOwnerInputEl.value, '');
        incident.source = valueOr(incidentSourceInputEl && incidentSourceInputEl.value, incident.source);
        incident.labels = valueOr(incidentLabelsInputEl && incidentLabelsInputEl.value, '').split(',').map(function (label) {
          return label.trim();
        }).filter(Boolean);
        incident.detectedAt = fromDateTimeLocalValue(incidentDetectedInputEl && incidentDetectedInputEl.value) || incident.detectedAt;
        incident.dueAt = fromDateTimeLocalValue(incidentDueInputEl && incidentDueInputEl.value);
        incident.note = valueOr(incidentNoteInputEl && incidentNoteInputEl.value, '');
        incident.description = valueOr(incidentDescriptionInputEl && incidentDescriptionInputEl.value, '');
        if (incidentChecklistEl) {
          var rows = Array.prototype.slice.call(incidentChecklistEl.querySelectorAll('.incident-check-item'));
          incident.checklist = rows.map(function (row, index) {
            var checkbox = row.querySelector('input[type="checkbox"]');
            var textInput = row.querySelector('input[type="text"]');
            return { id: 'check-' + index, text: valueOr(textInput && textInput.value, ''), done: !!(checkbox && checkbox.checked) };
          }).filter(function (item) { return item.text; });
        }
        incident.updatedAt = new Date().toISOString();
        persistIncidents();
        renderIncidentWorkbench();
        closeIncidentModal();
      }

      function addIncidentChecklistItem() {
        var incident = findIncident(incidentDraftId);
        if (!incident) {
          return;
        }
        incident.checklist = incident.checklist || [];
        incident.checklist.push({ id: 'check-' + Date.now(), text: '', done: false });
        renderIncidentChecklistEditor(incident.checklist);
      }

      function ensureIncidentFromEvent(event) {
        if (!incidentEnabled || !incidentsLoaded || !event || (event.cls !== 'A' && event.cls !== 'B')) {
          return;
        }
        var incidentId = 'event-' + event.id;
        var existing = findIncident(incidentId);
        var snapshot = buildIncidentEventSnapshot(event);
        var relatedEvent = {
          id: valueOr(event.id, ''),
          sequence: Number(valueOr(event.sequence, 0)) || null,
          cls: valueOr(event.cls, ''),
          source: valueOr(event.source, ''),
          ts: valueOr(event.consensus_ts, event.ts_local)
        };
        if (existing) {
          var alreadyLinked = (existing.relatedEvents || []).some(function (item) { return item.id === relatedEvent.id; });
          if (!alreadyLinked) {
            existing.relatedEvents.push(relatedEvent);
            existing.updatedAt = new Date().toISOString();
            existing.eventClass = existing.eventClass || snapshot.eventClass;
            existing.eventId = existing.eventId || snapshot.eventId;
            existing.eventSequence = existing.eventSequence || snapshot.eventSequence;
            existing.eventType = existing.eventType || snapshot.eventType;
            existing.eventTitle = existing.eventTitle || snapshot.eventTitle;
            existing.eventBody = existing.eventBody || snapshot.eventBody;
            existing.eventOccurredAt = existing.eventOccurredAt || snapshot.eventOccurredAt;
            persistIncidents();
          }
          return;
        }
        incidents.unshift({
          id: incidentId,
          title: snapshot.eventTitle,
          status: incidentStatuses[0],
          priority: event.cls === 'A' ? 'high' : 'medium',
          eventClass: snapshot.eventClass,
          eventId: snapshot.eventId,
          eventSequence: snapshot.eventSequence,
          eventType: snapshot.eventType,
          eventTitle: snapshot.eventTitle,
          eventBody: snapshot.eventBody,
          eventOccurredAt: snapshot.eventOccurredAt,
          source: valueOr(event.source, ''),
          owner: '',
          labels: [event.cls, valueOr(event.source, 'узел')],
          note: '',
          description: valueOr(snapshot.payload && snapshot.payload.description, 'Карточка автоматически создана из события распределённого журнала.'),
          detectedAt: new Date(valueOr(event.consensus_ts, event.ts_local) * 1000).toISOString(),
          dueAt: '',
          checklist: defaultChecklist(),
          relatedEvents: [relatedEvent],
          updatedAt: new Date().toISOString()
        });
        persistIncidents();
      }

      function renderIncidentWorkbench() {
        renderIncidentViewSwitch();
        renderIncidentTable();
        renderIncidentBoard();
      }

      if (incidentViewTableEl) {
        incidentViewTableEl.addEventListener('click', function () {
          incidentView = 'table';
          renderIncidentWorkbench();
        });
      }
      if (incidentViewBoardEl) {
        incidentViewBoardEl.addEventListener('click', function () {
          incidentView = 'board';
          renderIncidentWorkbench();
        });
      }
      if (incidentFilterAllEl) {
        incidentFilterAllEl.addEventListener('click', function () {
          setAllIncidentClassFilters(true);
        });
      }
      incidentFilterButtons.forEach(function (button) {
        var cls = button.getAttribute('data-incident-filter-class');
        if (!cls) {
          return;
        }
        button.addEventListener('click', function () {
          toggleIncidentClassFilter(cls);
        });
      });
      if (incidentFilterInputEl) {
        incidentFilterInputEl.addEventListener('input', function () {
          incidentSearchQuery = incidentFilterInputEl.value || '';
          renderIncidentWorkbench();
        });
      }
      if (incidentGroupSelectEl) {
        incidentGroupSelectEl.addEventListener('change', function () {
          incidentGroupBy = incidentGroupSelectEl.value || '';
          renderIncidentWorkbench();
        });
      }
      updateIncidentFilterButtons();
      if (incidentCreateBtnEl) {
        incidentCreateBtnEl.addEventListener('click', createManualIncident);
      }
      if (incidentCloseBtnEl) {
        incidentCloseBtnEl.addEventListener('click', closeIncidentModal);
      }
      if (incidentCancelBtnEl) {
        incidentCancelBtnEl.addEventListener('click', closeIncidentModal);
      }
      if (incidentModalBackdropEl) {
        incidentModalBackdropEl.addEventListener('click', closeIncidentModal);
      }
      if (incidentSaveBtnEl) {
        incidentSaveBtnEl.addEventListener('click', saveIncidentModal);
      }
      if (incidentAddCheckBtnEl) {
        incidentAddCheckBtnEl.addEventListener('click', addIncidentChecklistItem);
      }
      if (networkAddBtnEl) {
        networkAddBtnEl.addEventListener('click', addPeerRegistryEntry);
      }
      if (networkReconfigureBtnEl) {
        networkReconfigureBtnEl.addEventListener('click', reconfigureConsensusMembership);
      }
      if (networkAddressInputEl) {
        networkAddressInputEl.addEventListener('keydown', function (event) {
          if (event.key === 'Enter') {
            event.preventDefault();
            addPeerRegistryEntry();
          }
        });
      }
      if (analyticsModalCloseEl) {
        analyticsModalCloseEl.addEventListener('click', closeAnalyticsModal);
      }
      if (analyticsModalBackdropEl) {
        analyticsModalBackdropEl.addEventListener('click', closeAnalyticsModal);
      }
      renderPeerRegistry();
      loadPeerRegistry();

      function openDetailsPanel() {
        if (!detailsPanel) {
          return;
        }
        if (!isDetailsOpen) {
          if (typeof document !== 'undefined') {
            lastActiveElement = document.activeElement;
          }
          detailsPanel.classList.add('is-open');
          if (detailsBackdrop) {
            detailsBackdrop.classList.add('visible');
          }
          if (typeof document !== 'undefined' && document.body) {
            document.body.classList.add('modal-open');
          }
        }
        isDetailsOpen = true;
        detailsPanel.setAttribute('aria-hidden', 'false');
        if (typeof detailsPanel.focus === 'function') {
          try {
            detailsPanel.focus({ preventScroll: true });
          } catch (err) {
            detailsPanel.focus();
          }
        }
      }

      function closeDetailsPanel(options) {
        var opts = options || {};
        var preserveIntent = !!opts.preserveIntent;
        var shouldRestoreFocus = opts.restoreFocus !== false;
        if (!detailsPanel) {
          return;
        }
        detailsPanel.classList.remove('is-open');
        detailsPanel.classList.remove('has-node');
        detailsPanel.setAttribute('aria-hidden', 'true');
        if (detailsBackdrop) {
          detailsBackdrop.classList.remove('visible');
        }
        if (typeof document !== 'undefined' && document.body) {
          document.body.classList.remove('modal-open');
        }
        isDetailsOpen = false;
        if (!preserveIntent) {
          shouldOpenDetailsOnFocus = false;
        }
        if (lastActiveElement && typeof document !== 'undefined' && document.contains && !document.contains(lastActiveElement)) {
          lastActiveElement = null;
        }
        if (shouldRestoreFocus && lastActiveElement && typeof lastActiveElement.focus === 'function') {
          try {
            lastActiveElement.focus();
          } catch (err) {
            /* ignore focus restore errors */
          }
        }
        lastActiveElement = null;
      }

      if (detailsClose) {
        detailsClose.addEventListener('click', function () {
          closeDetailsPanel();
        });
      }
      if (detailsBackdrop) {
        detailsBackdrop.addEventListener('click', function () {
          closeDetailsPanel();
        });
      }
      if (typeof document !== 'undefined' && document.addEventListener) {
        document.addEventListener('keydown', function (event) {
          if (event.key === 'Escape') {
            closeAnalyticsModal();
            closeIncidentModal();
            closeDetailsPanel();
          }
        });
      }

      function setControlsStatus(message, isError) {
        if (!controlsStatus) {
          return;
        }
        controlsStatus.textContent = message;
        controlsStatus.style.color = isError ? '#ff8080' : 'rgba(198, 210, 255, 0.85)';
      }

      function setResetControlsStatus(message, isError) {
        if (!resetControlsStatus) {
          return;
        }
        resetControlsStatus.textContent = message;
        resetControlsStatus.style.color = isError ? '#ff8080' : 'rgba(198, 210, 255, 0.85)';
      }

      function setControlsDisabled(disabled) {
        if (!controlsRoot) {
          return;
        }
        var buttons = controlsRoot.querySelectorAll('.sim-button');
        buttons.forEach(function (button) {
          button.disabled = disabled;
        });
      }

      function setResetControlsDisabled(disabled) {
        if (clusterResetButton) {
          clusterResetButton.disabled = disabled;
        }
      }

      function setText(el, value) {
        if (!el) {
          return;
        }
        el.textContent = value;
      }

      function describeQuorumHealth(value) {
        var numeric = Number(value || 0);
        if (numeric >= 0.95) {
          return 'Норма';
        }
        if (numeric >= 0.75) {
          return 'Наблюдать';
        }
        return 'Риск';
      }

      function describeGraphIntegrity(value) {
        var numeric = Number(value || 0);
        if (numeric >= 0.97) {
          return 'Цельный';
        }
        if (numeric >= 0.85) {
          return 'Есть разрывы';
        }
        return 'Требует проверки';
      }

      function describeDelta(current, previous) {
        if (previous <= 0 && current <= 0) {
          return 'без изменений';
        }
        if (previous <= 0 && current > 0) {
          return 'рост с нуля';
        }
        var ratio = ((current - previous) / previous) * 100;
        if (Math.abs(ratio) < 10) {
          return 'без заметного сдвига';
        }
        return ratio > 0
          ? 'рост на ' + formatValue(ratio, 0) + '%'
          : 'снижение на ' + formatValue(Math.abs(ratio), 0) + '%';
      }

      function formatRatePerMinute(count, windowSeconds) {
        var rate = Number(count || 0) / Math.max(windowSeconds / 60, 1);
        return formatValue(rate, 1) + ' / мин';
      }

      function eventTimestamp(node) {
        if (!node) {
          return null;
        }
        var primary = Number(valueOr(node.consensus_ts, node.ts_local));
        return isNaN(primary) ? null : primary;
      }

      function renderEventIntensity(realNodes) {
        if (!activityIntensityEl) {
          return;
        }
        activityIntensityEl.innerHTML = '';
        if (!realNodes || realNodes.length === 0) {
          activityIntensityEl.innerHTML = '<div class="intensity-row"><div><div class="intensity-title">Интенсивность ещё не рассчитана</div><div class="intensity-meta">Нужны события с временными отметками.</div></div><div class="intensity-rate">—</div></div>';
          return;
        }

        var timestamps = realNodes.map(eventTimestamp).filter(function (value) {
          return value !== null;
        });
        if (timestamps.length === 0) {
          activityIntensityEl.innerHTML = '<div class="intensity-row"><div><div class="intensity-title">Нет корректных временных отметок</div><div class="intensity-meta">Скорость появления событий пока нельзя оценить.</div></div><div class="intensity-rate">—</div></div>';
          return;
        }

        var now = Math.max(Date.now() / 1000, Math.max.apply(null, timestamps));
        var windowSeconds = 5 * 60;
        var currentStart = now - windowSeconds;
        var previousStart = now - windowSeconds * 2;
        var classes = {
          A: { label: 'Класс A', current: 0, previous: 0, tone: '#ff6d6d' },
          B: { label: 'Класс B', current: 0, previous: 0, tone: '#ffc971' },
          C: { label: 'Класс C', current: 0, previous: 0, tone: '#5aa5ff' }
        };

        realNodes.forEach(function (node) {
          if (!classes[node.cls]) {
            return;
          }
          var ts = eventTimestamp(node);
          if (ts === null) {
            return;
          }
          if (ts >= currentStart) {
            classes[node.cls].current += 1;
          } else if (ts >= previousStart && ts < currentStart) {
            classes[node.cls].previous += 1;
          }
        });

        ['A', 'B', 'C'].forEach(function (cls) {
          var stat = classes[cls];
          var row = document.createElement('div');
          row.className = 'intensity-row';
          row.innerHTML =
            '<div>' +
              '<div class="intensity-title">' + stat.label + '</div>' +
              '<div class="intensity-meta">Окно: последние 5 минут · ' + describeDelta(stat.current, stat.previous) + '</div>' +
            '</div>' +
            '<div class="intensity-rate" style="color:' + stat.tone + ';">' + formatRatePerMinute(stat.current, windowSeconds) +
              '<small>предыдущее окно: ' + formatRatePerMinute(stat.previous, windowSeconds) + '</small>' +
            '</div>';
          activityIntensityEl.appendChild(row);
        });
      }

      function updateNodeStatus(status) {
        if (!status) {
          return;
        }
        lastStatusSnapshot = status;
        var peerCount = Array.isArray(status.peers) ? status.peers.length : 0;
        var profile = status.profile || {};
        var nextNodeId = valueOr(status.node_id, '');
        setText(navNodeCaptionEl, 'ID: ' + valueOr(status.node_id, '—'));
        setText(navNodeIdEl, valueOr(status.node_id, '—'));
        setText(heroNodeIdEl, valueOr(status.node_id, '—'));
        setText(heroNodeStateEl, valueOr(status.state, '—'));
        renderRoleValue(heroNodeRoleEl, valueOr(profile.role, 'node'));
        setText(statusStateValueEl, valueOr(status.state, '—'));
        setText(statusNodeIdEl, valueOr(status.node_id, '—'));
        setText(statusPeerCountEl, String(peerCount));
        renderRoleValue(statusRoleEl, valueOr(profile.role, 'node'));
        setText(statusThreatLevelEl, valueOr(profile.threat_level, '—'));
        renderConsensusMembershipSummary();
        demoControlsEnabled = status.demo_controls_enabled !== false;
        if (controlsRoot) {
          controlsRoot.style.display = demoControlsEnabled ? '' : 'none';
        }
        var shouldEnableIncidents = isResponderRole(profile.role);
        setIncidentWorkbenchEnabled(shouldEnableIncidents);
        updateHeroOverview();
      }

      function fetchNodeStatus() {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '/status', true);
        xhr.onreadystatechange = function () {
          if (xhr.readyState === 4 && xhr.status >= 200 && xhr.status < 300) {
            try {
              updateNodeStatus(JSON.parse(xhr.responseText));
            } catch (err) {
              console.log('status parse error', err);
            }
          }
        };
        xhr.send();
      }

      function activeClassCount() {
        var count = 0;
        Object.keys(classFilterState).forEach(function (cls) {
          if (classFilterState[cls]) {
            count += 1;
          }
        });
        return count;
      }

      function updateClassButtonsUI() {
        Object.keys(classFilterButtons).forEach(function (cls) {
          var button = classFilterButtons[cls];
          if (!button) {
            return;
          }
          if (classFilterState[cls]) {
            button.classList.add('active');
          } else {
            button.classList.remove('active');
          }
        });
      }

      function toggleClassFilter(cls) {
        if (!cls || !classFilterState.hasOwnProperty(cls)) {
          return;
        }
        if (classFilterState[cls] && activeClassCount() <= 1) {
          return;
        }
        classFilterState[cls] = !classFilterState[cls];
        updateClassButtonsUI();
        hoveredNodeId = null;
        renderGraph();
      }

      function countActiveSpecificSources() {
        var count = 0;
        Object.keys(sourceFilterState).forEach(function (key) {
          if (key !== ALL_SOURCES_TOKEN && sourceFilterState[key]) {
            count += 1;
          }
        });
        return count;
      }

      function updateSourceButtonsUI() {
        Object.keys(sourceFilterButtons).forEach(function (key) {
          var button = sourceFilterButtons[key];
          if (!button) {
            return;
          }
          var shouldActivate;
          if (key === ALL_SOURCES_TOKEN) {
            shouldActivate = !!sourceFilterState[ALL_SOURCES_TOKEN];
          } else if (sourceFilterState[ALL_SOURCES_TOKEN]) {
            shouldActivate = false;
          } else {
            shouldActivate = !!sourceFilterState[key];
          }
          if (shouldActivate) {
            button.classList.add('active');
          } else {
            button.classList.remove('active');
          }
        });
      }

      function activateAllSourcesFilter() {
        sourceFilterState[ALL_SOURCES_TOKEN] = true;
        Object.keys(sourceFilterState).forEach(function (key) {
          if (key !== ALL_SOURCES_TOKEN) {
            delete sourceFilterState[key];
          }
        });
        updateSourceButtonsUI();
        hoveredNodeId = null;
        renderGraph();
      }

      function toggleSourceFilter(sourceId) {
        if (!sourceId) {
          return;
        }
        if (sourceId === ALL_SOURCES_TOKEN) {
          activateAllSourcesFilter();
          return;
        }
        if (!sourceFilterButtons[sourceId]) {
          return;
        }
        var isActive = !!sourceFilterState[sourceId];
        if (isActive) {
          delete sourceFilterState[sourceId];
          if (countActiveSpecificSources() === 0) {
            activateAllSourcesFilter();
            return;
          }
        } else {
          sourceFilterState[ALL_SOURCES_TOKEN] = false;
          sourceFilterState[sourceId] = true;
        }
        updateSourceButtonsUI();
        hoveredNodeId = null;
        renderGraph();
      }

      function registerSource(sourceId) {
        var key = sourceId || 'unknown';
        if (key === 'unknown') {
          return;
        }
        if (sourceOrder.indexOf(key) === -1) {
          sourceOrder.push(key);
          sourceOrder.sort();
        }
        if (!filterSourcesRoot) {
          return;
        }
        if (sourceFilterButtons[key]) {
          return;
        }
        var button = document.createElement('button');
        button.className = 'toggle-button';
        button.textContent = key;
        button.setAttribute('data-filter-source', key);
        button.addEventListener('click', function () {
          toggleSourceFilter(key);
        });
        filterSourcesRoot.appendChild(button);
        sourceFilterButtons[key] = button;
        updateSourceButtonsUI();
      }

      function isNodeVisible(node) {
        if (!node) {
          return false;
        }
        var classKey = node.cls || 'C';
        if (classFilterState.hasOwnProperty(classKey) && !classFilterState[classKey]) {
          return false;
        }
        if (!sourceFilterState[ALL_SOURCES_TOKEN]) {
          var sourceKey = node.source || 'unknown';
          if (!sourceFilterState[sourceKey]) {
            return false;
          }
        }
        return true;
      }

      function resetDetailsPanel() {
        if (!detailsPanel) {
          return;
        }
        var preserveIntent = !!focusNodeId;
        if (preserveIntent) {
          shouldOpenDetailsOnFocus = true;
        }
        closeDetailsPanel({ preserveIntent: preserveIntent, restoreFocus: !preserveIntent });
        if (detailsTitle) {
          detailsTitle.textContent = 'Нет выбранного события';
        }
        if (detailsContext) {
          detailsContext.textContent = 'Наведите курсор или нажмите на вершину, чтобы увидеть детали.';
        }
        if (detailsMeta) {
          detailsMeta.innerHTML = '<div class="details-hint">Событие не выбрано.</div>';
        }
        if (detailsPayload) {
          detailsPayload.textContent = '—';
          detailsPayload.classList.add('empty');
        }
        if (detailsVclock) {
          detailsVclock.textContent = '—';
          detailsVclock.classList.add('empty');
        }
        if (detailsSig) {
          detailsSig.textContent = '—';
          detailsSig.classList.add('empty');
        }
        if (detailsParents) {
          detailsParents.innerHTML = '<li class="empty">—</li>';
        }
        if (detailsChildren) {
          detailsChildren.innerHTML = '<li class="empty">—</li>';
        }
      }

      function renderMetaRow(container, label, value) {
        if (!container) {
          return;
        }
        var row = document.createElement('div');
        row.className = 'details-meta-row';
        var keyEl = document.createElement('div');
        keyEl.className = 'details-meta-key';
        keyEl.textContent = label;
        var valueEl = document.createElement('div');
        valueEl.className = 'details-meta-value';
        valueEl.textContent = value;
        row.appendChild(keyEl);
        row.appendChild(valueEl);
        container.appendChild(row);
      }

      function renderIdList(container, ids) {
        if (!container) {
          return;
        }
        container.innerHTML = '';
        if (!ids || !ids.length) {
          var emptyItem = document.createElement('li');
          emptyItem.textContent = '—';
          emptyItem.className = 'empty';
          container.appendChild(emptyItem);
          return;
        }
        var seen = {};
        ids.forEach(function (id) {
          if (!id || seen[id]) {
            return;
          }
          seen[id] = true;
          var li = document.createElement('li');
          var label = id;
          if (!nodes[id]) {
            label += ' (нет локально)';
          } else if (!isNodeVisible(nodes[id])) {
            label += ' (скрыто фильтром)';
          }
          li.textContent = label;
          container.appendChild(li);
        });
        if (!container.hasChildNodes()) {
          var fallback = document.createElement('li');
          fallback.textContent = '—';
          fallback.className = 'empty';
          container.appendChild(fallback);
        }
      }

      function stringifyOrDash(obj) {
        if (obj === null || obj === undefined) {
          return '—';
        }
        try {
          if (typeof obj === 'string') {
            return obj.length ? obj : '—';
          }
          return JSON.stringify(obj, null, 2);
        } catch (err) {
          return String(obj);
        }
      }

      function updateDetailsPanel(node, context) {
        if (!detailsPanel) {
          return;
        }
        if (!node) {
          resetDetailsPanel();
          return;
        }
        if (context !== 'focus' && !isDetailsOpen) {
          return;
        }
        if (context === 'focus') {
          if (!isDetailsOpen && shouldOpenDetailsOnFocus) {
            openDetailsPanel();
          }
          shouldOpenDetailsOnFocus = false;
        }
        if (!isDetailsOpen) {
          return;
        }
        detailsPanel.classList.add('has-node');
        detailsPanel.setAttribute('aria-hidden', 'false');
        if (detailsTitle) {
          detailsTitle.textContent = node.id;
        }
        if (detailsContext) {
          var contextLabel = 'Фокус (выбрано кликом)';
          detailsContext.textContent = contextLabel;
        }
        if (detailsMeta) {
          detailsMeta.innerHTML = '';
          renderMetaRow(detailsMeta, 'Класс', node.cls || '—');
          renderMetaRow(detailsMeta, 'Источник', node.source || '—');
          renderMetaRow(detailsMeta, 'Порядок', node.sequence ? '#' + node.sequence : '—');
          renderMetaRow(detailsMeta, 'Consensus TS', node.consensus_ts !== null && node.consensus_ts !== undefined ? formatValue(node.consensus_ts, 6) : '—');
          renderMetaRow(detailsMeta, 'Локальное время', node.ts_local !== null && node.ts_local !== undefined ? formatValue(node.ts_local, 6) : '—');
          renderMetaRow(detailsMeta, 'Lamport', node.lamport_ts !== null && node.lamport_ts !== undefined ? String(node.lamport_ts) : '—');
          renderMetaRow(detailsMeta, 'Подпись', node.sig ? 'установлена' : 'отсутствует');
        }
        if (detailsPayload) {
          var payloadText = stringifyOrDash(node.payload);
          detailsPayload.textContent = payloadText;
          if (payloadText === '—') {
            detailsPayload.classList.add('empty');
          } else {
            detailsPayload.classList.remove('empty');
          }
        }
        if (detailsVclock) {
          var vclockText = stringifyOrDash(node.vclock);
          detailsVclock.textContent = vclockText;
          if (vclockText === '—') {
            detailsVclock.classList.add('empty');
          } else {
            detailsVclock.classList.remove('empty');
          }
        }
        if (detailsSig) {
          var sigText = node.sig ? String(node.sig) : '—';
          detailsSig.textContent = sigText;
          if (sigText === '—') {
            detailsSig.classList.add('empty');
          } else {
            detailsSig.classList.remove('empty');
          }
        }
        if (detailsParents) {
          renderIdList(detailsParents, node.parents || []);
        }
        if (detailsChildren) {
          var childs = childrenMap[node.id] ? childrenMap[node.id].slice(0) : [];
          renderIdList(detailsChildren, childs);
        }
      }

      function markStable() {
        if (!statusEl) {
          return;
        }
        statusEl.textContent = 'Граф стабилизирован: на этом узле известны все события.';
        statusEl.style.color = 'rgba(140, 220, 150, 0.95)';
        syncTimer = null;
      }

      function markSyncPending(message) {
        if (!statusEl) {
          return;
        }
        statusEl.textContent = message || 'Идёт синхронизация...';
        statusEl.style.color = 'rgba(233, 196, 122, 0.9)';
        if (syncTimer) {
          clearTimeout(syncTimer);
        }
        syncTimer = setTimeout(markStable, 2000);
      }

      function markError(message) {
        if (!statusEl) {
          return;
        }
        statusEl.textContent = message;
        statusEl.style.color = '#ff8080';
        if (syncTimer) {
          clearTimeout(syncTimer);
          syncTimer = null;
        }
      }

      function updateSimulationButton() {
        if (!simulationButton) {
          return;
        }
        if (simulationActive) {
          simulationButton.textContent = 'Остановить симуляцию';
          simulationButton.classList.add('running');
        } else {
          simulationButton.textContent = 'СИМУЛЯЦИЯ';
          simulationButton.classList.remove('running');
        }
      }

      function setSimulationRunning(running) {
        simulationActive = !!running;
        updateSimulationButton();
      }

      function setSimulationButtonDisabled(disabled) {
        if (!simulationButton) {
          return;
        }
        simulationButton.disabled = disabled;
      }

      function updateConsensusStatusDisplay() {
        if (!consensusStatusEl) {
          return;
        }
        var peerKeys = Object.keys(consensusState);
        if (peerKeys.length === 0) {
          consensusStatusEl.textContent = 'Консенсус: ожидание данных...';
          consensusStatusEl.classList.remove('alert');
          consensusStatusEl.classList.remove('ok');
          consensusStatusEl.classList.remove('pending');
          return;
        }
        var mismatched = 0;
        var pendingCount = 0;
        peerKeys.forEach(function (peer) {
          var state = consensusState[peer];
          if (!state) {
            return;
          }
          if (state.pending) {
            pendingCount += 1;
            return;
          }
          if (state.error || !state.match) {
            mismatched += 1;
          }
        });
        consensusStatusEl.classList.remove('alert');
        consensusStatusEl.classList.remove('ok');
        consensusStatusEl.classList.remove('pending');
        if (mismatched === 0 && pendingCount === 0) {
          consensusStatusEl.textContent = 'Консенсус: OK (' + peerKeys.length + ')';
          consensusStatusEl.classList.add('ok');
        } else if (mismatched === 0 && pendingCount > 0) {
          consensusStatusEl.textContent = 'Консенсус: синхронизация (' + pendingCount + '/' + peerKeys.length + ')';
          consensusStatusEl.classList.add('pending');
        } else {
          consensusStatusEl.textContent = 'Консенсус: рассогласование (' + mismatched + '/' + peerKeys.length + ')';
          consensusStatusEl.classList.add('alert');
        }
        renderConsensusPeerSummary();
        updateHeroOverview();
      }

      function recordConsensusStatus(payload) {
        if (!payload || !payload.peer) {
          return;
        }
        consensusState[payload.peer] = {
          match: !!payload.match,
          peerNode: payload.peer_node || payload.peer,
          error: payload.error || null,
          pending: !!payload.pending,
          reasons: Array.isArray(payload.mismatch_reasons) ? payload.mismatch_reasons : [],
          localCount: payload.local && typeof payload.local.event_count === 'number' ? payload.local.event_count : null,
          peerCount: payload.peer_state && typeof payload.peer_state.event_count === 'number' ? payload.peer_state.event_count : null
        };
        updateConsensusStatusDisplay();
      }

      function renderConsensusPeerSummary() {
        if (!consensusPeerSummaryEl) {
          return;
        }
        var peerKeys = Object.keys(consensusState);
        consensusPeerSummaryEl.innerHTML = '';
        if (peerKeys.length === 0) {
          var emptyItem = document.createElement('li');
          emptyItem.className = 'peer-summary-item';
          emptyItem.textContent = 'Пока нет данных о сравнении с соседними узлами.';
          consensusPeerSummaryEl.appendChild(emptyItem);
          return;
        }
        peerKeys.sort();
        for (var i = 0; i < peerKeys.length; i += 1) {
          var peerKey = peerKeys[i];
          var peerState = consensusState[peerKey];
          if (!peerState) {
            continue;
          }
          var item = document.createElement('li');
          item.className = 'peer-summary-item';
          var label = peerState.peerNode || peerKey;
          var stateText;
          if (peerState.error) {
            stateText = 'недоступен';
          } else if (peerState.pending) {
            stateText = 'синхронизация';
          } else if (peerState.match) {
            stateText = 'совпадает';
          } else {
            stateText = 'рассогласован';
          }
          var reasonText = peerState.reasons && peerState.reasons.length
            ? ' · причина: ' + peerState.reasons.join(', ')
            : '';
          item.innerHTML =
            '<strong>' + label + '</strong><br>' +
            'Состояние: ' + stateText +
            ' · локально ' + valueOr(peerState.localCount, '—') +
            ' / у соседа ' + valueOr(peerState.peerCount, '—') +
            reasonText;
          consensusPeerSummaryEl.appendChild(item);
        }
      }

      function resetGraphState() {
        nodes = {};
        nodeOrder = [];
        links = {};
        linkOrder = [];
        childrenMap = {};
        layoutOrder = [];
        laneOrder = [];
        lanePositions = {};
        layoutDimensions = defaultLayoutDimensions();
        focusNodeId = null;
        focusAncestors = {};
        focusDescendants = {};
        hoveredNodeId = null;
        shouldOpenDetailsOnFocus = false;
        closeDetailsPanel();
        renderGraph();
      }

      function renderOperationalSummary() {
        var realNodes = [];
        var classCounts = { A: 0, B: 0, C: 0 };
        var sourceMap = {};
        var sourceStats = {};
        Object.keys(nodes).forEach(function (nodeId) {
          var node = nodes[nodeId];
          if (!node || node.source === 'unknown') {
            return;
          }
          realNodes.push(node);
          if (classCounts.hasOwnProperty(node.cls)) {
            classCounts[node.cls] += 1;
          }
          sourceMap[node.source] = true;
          if (!sourceStats[node.source]) {
            sourceStats[node.source] = { A: 0, B: 0, C: 0, total: 0 };
          }
          if (sourceStats[node.source].hasOwnProperty(node.cls)) {
            sourceStats[node.source][node.cls] += 1;
          }
          sourceStats[node.source].total += 1;
        });
        lastOperationalNodes = realNodes.slice(0);
        lastClassSummary = { A: classCounts.A || 0, B: classCounts.B || 0, C: classCounts.C || 0 };
        lastSourceCount = Object.keys(sourceMap).length;
        if (incidentEnabled) {
          realNodes.forEach(function (node) {
            ensureIncidentFromEvent(node);
          });
        }

        setText(activityClassAEl, String(classCounts.A || 0));
        setText(activityClassBEl, String(classCounts.B || 0));
        setText(activityClassCEl, String(classCounts.C || 0));
        setText(activitySourceCountEl, String(Object.keys(sourceMap).length));
        renderClassDistribution(classCounts, realNodes.length);
        renderSourceSummary(sourceStats);
        renderEventIntensity(realNodes);
        updateHeroOverview();

        if (!activityFeedEl) {
          return;
        }
        activityFeedEl.innerHTML = '';
        if (realNodes.length === 0) {
          var emptyItem = document.createElement('li');
          emptyItem.className = 'activity-item';
          emptyItem.textContent = 'События ещё не поступили.';
          activityFeedEl.appendChild(emptyItem);
          return;
        }

        realNodes.sort(function (a, b) {
          var ta = valueOr(a.consensus_ts, valueOr(a.ts_local, 0));
          var tb = valueOr(b.consensus_ts, valueOr(b.ts_local, 0));
          if (ta === tb) {
            return a.id < b.id ? 1 : -1;
          }
          return ta < tb ? 1 : -1;
        });

        var limit = Math.min(realNodes.length, 5);
        for (var i = 0; i < limit; i += 1) {
          var event = realNodes[i];
          var item = document.createElement('li');
          item.className = 'activity-item';
          item.innerHTML =
            '<strong>' + event.cls + ' · ' + event.source + '</strong><br>' +
            'Порядок: #' + valueOr(event.sequence, '—') +
            ' · Родителей: ' + (event.parents ? event.parents.length : 0) +
            ' · ts: ' + formatValue(valueOr(event.consensus_ts, event.ts_local), 3);
          activityFeedEl.appendChild(item);
        }
      }

      function pushAlert(level, title, text, dedupeKey) {
        var key = dedupeKey || (level + '|' + title + '|' + text);
        var last = alertFeed.length > 0 ? alertFeed[0] : null;
        if (last && last.key === key && last.text === text) {
          return;
        }
        alertFeed.unshift({
          key: key,
          level: level,
          title: title,
          text: text,
          timestamp: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        });
        if (alertFeed.length > 10) {
          alertFeed = alertFeed.slice(0, 10);
        }
        renderAlertWindow();
      }

      function renderAlertWindow() {
        if (!alertWindowEl) {
          return;
        }
        alertWindowEl.innerHTML = '';
        if (alertFeed.length === 0) {
          alertWindowEl.innerHTML = '<div class="alert-item info"><div class="alert-meta"><span class="alert-level">НЕТ АКТИВНЫХ</span></div><div class="alert-title">Ожидание сигналов</div><div class="alert-text">Тревожные уведомления появятся здесь по мере поступления событий и изменения состояния кластера.</div></div>';
          return;
        }
        for (var i = 0; i < alertFeed.length; i += 1) {
          var alertItem = alertFeed[i];
          var item = document.createElement('div');
          item.className = 'alert-item ' + alertItem.level;
          item.innerHTML =
            '<div class="alert-meta"><span class="alert-level">' + alertItem.level + '</span><span>' + alertItem.timestamp + '</span></div>' +
            '<div class="alert-title">' + alertItem.title + '</div>' +
            '<div class="alert-text">' + alertItem.text + '</div>';
          alertWindowEl.appendChild(item);
        }
      }

      function updateMetricHistory(metrics) {
        if (!metrics) {
          return;
        }
        lastMetricsSnapshot = metrics;
        metricHistory.push({
          mem: Number(metrics.C_mem || 0),
          net: Number(metrics.C_net || 0),
          events: Number(metrics.event_count || 0)
        });
        if (metricHistory.length > 24) {
          metricHistory = metricHistory.slice(metricHistory.length - 24);
        }
        renderTrendChart();
        updateHeroOverview();
      }

      function buildPolyline(points, width, height, maxValue) {
        if (!points.length) {
          return '';
        }
        var result = [];
        var denominator = Math.max(points.length - 1, 1);
        for (var i = 0; i < points.length; i += 1) {
          var x = (i / denominator) * width;
          var y = height - ((points[i] / Math.max(maxValue, 1)) * height);
          result.push(x.toFixed(2) + ',' + y.toFixed(2));
        }
        return result.join(' ');
      }

      function buildAreaPath(points, width, height, maxValue) {
        if (!points.length) {
          return '';
        }
        var denominator = Math.max(points.length - 1, 1);
        var commands = ['M0,' + height.toFixed(2)];
        for (var i = 0; i < points.length; i += 1) {
          var x = (i / denominator) * width;
          var y = height - ((points[i] / Math.max(maxValue, 1)) * height);
          commands.push('L' + x.toFixed(2) + ',' + y.toFixed(2));
        }
        commands.push('L' + width.toFixed(2) + ',' + height.toFixed(2));
        commands.push('Z');
        return commands.join(' ');
      }

      function setHeroDelta(el, current, previous, formatter) {
        if (!el) {
          return;
        }
        if (previous === null || previous === undefined || !isFinite(previous)) {
          el.textContent = '—';
          el.className = 'hero-kpi-delta';
          return;
        }
        var delta = current - previous;
        if (Math.abs(delta) < 0.0001) {
          el.textContent = '0';
          el.className = 'hero-kpi-delta';
          return;
        }
        el.textContent = (delta > 0 ? '↑ ' : '↓ ') + formatter(Math.abs(delta));
        el.className = 'hero-kpi-delta ' + (delta > 0 ? 'up' : 'down');
      }

      function heroSparkGrid(svgEl, width) {
        [12, 34, 56].forEach(function (y) {
          var line = document.createElementNS(svgNS, 'line');
          line.setAttribute('class', 'hero-spark-grid');
          line.setAttribute('x1', '0'); line.setAttribute('x2', String(width));
          line.setAttribute('y1', String(y)); line.setAttribute('y2', String(y));
          svgEl.appendChild(line);
        });
      }

      // Одиночная гистограмма. baseline по минимуму: при почти-константных
      // значениях (память/сеть) видны колебания, при растущих (объём) —
      // динамика прироста, а не сплошная стена.
      function renderHeroSparkline(svgEl, points, color, maxValue) {
        if (!svgEl) { return; }
        var width = 220, chartHeight = 66, offsetY = 8;
        svgEl.innerHTML = '';
        if (!points || !points.length) { return; }
        heroSparkGrid(svgEl, width);
        var mn = Math.min.apply(null, points);
        var mx = Math.max.apply(null, points);
        var span = mx - mn;
        var n = points.length;
        var slot = width / n;
        var gap = Math.min(4, slot * 0.25);
        var bw = Math.max(1, slot - gap);
        for (var i = 0; i < n; i += 1) {
          var norm = span > 1e-9 ? (points[i] - mn) / span : 0.5;
          // минимум 12% высоты, чтобы столбец всегда читался
          var h = (0.12 + 0.88 * norm) * chartHeight;
          var x = i * slot + gap / 2;
          var y = offsetY + (chartHeight - h);
          var rect = document.createElementNS(svgNS, 'rect');
          rect.setAttribute('x', x.toFixed(2)); rect.setAttribute('y', y.toFixed(2));
          rect.setAttribute('width', bw.toFixed(2)); rect.setAttribute('height', h.toFixed(2));
          rect.setAttribute('rx', Math.min(2, bw / 2).toFixed(1));
          rect.setAttribute('fill', color);
          rect.setAttribute('opacity', i === n - 1 ? '1' : '0.55');
          svgEl.appendChild(rect);
        }
      }

      // Сгруппированная гистограмма по классам A/B/C от нуля.
      function renderHeroMultiSparkline(svgEl, seriesList, maxValue) {
        if (!svgEl) { return; }
        var width = 220, chartHeight = 66, offsetY = 8;
        svgEl.innerHTML = '';
        if (!seriesList || !seriesList.length) { return; }
        heroSparkGrid(svgEl, width);
        var clsColor = { 'class-a': '#ff6d6d', 'class-b': '#ffc971', 'class-c': '#5aa5ff' };
        var n = seriesList[0].points.length;
        if (!n) { return; }
        var mx = Math.max(maxValue || 1, 1);
        var slot = width / n;
        var groupGap = Math.min(4, slot * 0.2);
        var innerW = slot - groupGap;
        var sub = seriesList.length;
        var bw = Math.max(1, innerW / sub - 1);
        for (var i = 0; i < n; i += 1) {
          for (var s = 0; s < sub; s += 1) {
            var v = seriesList[s].points[i] || 0;
            var h = Math.max(v > 0 ? 2 : 0, (v / mx) * chartHeight);
            var x = i * slot + groupGap / 2 + s * (innerW / sub);
            var y = offsetY + (chartHeight - h);
            var rect = document.createElementNS(svgNS, 'rect');
            rect.setAttribute('x', x.toFixed(2)); rect.setAttribute('y', y.toFixed(2));
            rect.setAttribute('width', bw.toFixed(2)); rect.setAttribute('height', h.toFixed(2));
            rect.setAttribute('rx', '1');
            rect.setAttribute('fill', clsColor[seriesList[s].cls] || '#90caf9');
            svgEl.appendChild(rect);
          }
        }
      }

      function buildIntensitySeries(windowSeconds, bucketCount) {
        if (!lastOperationalNodes || lastOperationalNodes.length === 0) {
          return null;
        }
        var timestamps = lastOperationalNodes.map(eventTimestamp).filter(function (value) {
          return value !== null;
        });
        if (timestamps.length === 0) {
          return null;
        }
        var now = Math.max(Date.now() / 1000, Math.max.apply(null, timestamps));
        var start = now - bucketCount * windowSeconds;
        var series = { A: new Array(bucketCount).fill(0), B: new Array(bucketCount).fill(0), C: new Array(bucketCount).fill(0) };
        lastOperationalNodes.forEach(function (node) {
          if (!series.hasOwnProperty(node.cls)) {
            return;
          }
          var ts = eventTimestamp(node);
          if (ts === null || ts < start) {
            return;
          }
          var bucket = Math.floor((ts - start) / windowSeconds);
          if (bucket >= bucketCount) {
            bucket = bucketCount - 1;
          }
          if (bucket >= 0) {
            series[node.cls][bucket] += 1;
          }
        });
        ['A', 'B', 'C'].forEach(function (cls) {
          series[cls] = series[cls].map(function (count) {
            return count / (windowSeconds / 60);
          });
        });
        return series;
      }

      function drawModalChart(seriesList, yMax) {
        if (!analyticsModalChartEl) {
          return;
        }
        var width = 920;
        var height = 320;
        var padTop = 14;
        var padBottom = 24;
        var chartHeight = height - padTop - padBottom;
        analyticsModalChartEl.innerHTML = '';
        for (var g = 0; g < 5; g += 1) {
          var line = document.createElementNS(svgNS, 'line');
          var y = padTop + (chartHeight / 4) * g;
          line.setAttribute('class', 'grid-line');
          line.setAttribute('x1', '0');
          line.setAttribute('x2', String(width));
          line.setAttribute('y1', String(y));
          line.setAttribute('y2', String(y));
          analyticsModalChartEl.appendChild(line);
        }
        seriesList.forEach(function (entry) {
          if (entry.area) {
            var area = document.createElementNS(svgNS, 'path');
            area.setAttribute('class', 'hero-spark-area');
            area.setAttribute('fill', entry.color);
            area.setAttribute('d', buildAreaPath(entry.points, width, chartHeight, yMax));
            area.setAttribute('transform', 'translate(0 ' + padTop + ')');
            analyticsModalChartEl.appendChild(area);
          }
          var poly = document.createElementNS(svgNS, 'polyline');
          poly.setAttribute('class', 'trend-line ' + entry.cls);
          poly.setAttribute('points', buildPolyline(entry.points, width, chartHeight, yMax));
          poly.setAttribute('transform', 'translate(0 ' + padTop + ')');
          analyticsModalChartEl.appendChild(poly);
        });
      }

      function openAnalyticsModal(kind) {
        if (!analyticsModalShellEl) {
          return;
        }
        analyticsModalKind = kind;
        renderAnalyticsModal(kind);
        analyticsModalShellEl.classList.add('open');
        document.body.classList.add('modal-open');
      }

      function closeAnalyticsModal() {
        if (!analyticsModalShellEl) {
          return;
        }
        analyticsModalShellEl.classList.remove('open');
        document.body.classList.remove('modal-open');
        analyticsModalKind = null;
      }

      function renderAnalyticsModal(kind) {
        if (!analyticsModalChartEl || !analyticsModalLegendEl) {
          return;
        }
        var history = metricHistory.slice(0);
        analyticsModalLegendEl.innerHTML = '';
        if (kind === 'intensity') {
          var intensitySeries = buildIntensitySeries(5 * 60, 6);
          if (!intensitySeries) {
            analyticsModalChartEl.innerHTML = '';
            if (analyticsModalTitleEl) { analyticsModalTitleEl.textContent = 'Интенсивность потока'; }
            if (analyticsModalSubtitleEl) { analyticsModalSubtitleEl.textContent = 'Недостаточно событий для построения расширенного графика.'; }
            if (analyticsModalYAxisEl) { analyticsModalYAxisEl.textContent = 'Ось Y: событий в минуту'; }
            if (analyticsModalXAxisEl) { analyticsModalXAxisEl.textContent = 'Ось X: последовательные окна по 5 минут'; }
            if (analyticsModalCaptionRightEl) { analyticsModalCaptionRightEl.textContent = 'Пока недостаточно данных.'; }
            return;
          }
          if (analyticsModalTitleEl) { analyticsModalTitleEl.textContent = 'Интенсивность потока A/B/C'; }
          if (analyticsModalSubtitleEl) { analyticsModalSubtitleEl.textContent = 'Все три класса событий показаны одновременно в одном временном окне.'; }
          if (analyticsModalYAxisEl) { analyticsModalYAxisEl.textContent = 'Ось Y: событий в минуту'; }
          if (analyticsModalXAxisEl) { analyticsModalXAxisEl.textContent = 'Ось X: последовательные окна по 5 минут'; }
          analyticsModalLegendEl.innerHTML =
            '<span class="trend-chip"><span class="trend-dot class-a"></span>Класс A</span>' +
            '<span class="trend-chip"><span class="trend-dot class-b"></span>Класс B</span>' +
            '<span class="trend-chip"><span class="trend-dot class-c"></span>Класс C</span>';
          var maxRate = 1;
          ['A', 'B', 'C'].forEach(function (cls) {
            intensitySeries[cls].forEach(function (value) { if (value > maxRate) { maxRate = value; } });
          });
          drawModalChart([
            { cls: 'class-a', points: intensitySeries.A, color: '#ff6d6d' },
            { cls: 'class-b', points: intensitySeries.B, color: '#ffc971' },
            { cls: 'class-c', points: intensitySeries.C, color: '#5aa5ff' }
          ], maxRate);
          if (analyticsModalCaptionRightEl) {
            var lastIndex = intensitySeries.A.length - 1;
            analyticsModalCaptionRightEl.textContent =
              'Текущее окно: A ' + formatValue(intensitySeries.A[lastIndex], 1) + ' / мин · B ' + formatValue(intensitySeries.B[lastIndex], 1) + ' / мин · C ' + formatValue(intensitySeries.C[lastIndex], 1) + ' / мин';
          }
          return;
        }

        var map = {
          mem: { title: 'Память журнала', subtitle: 'Использование памяти под распределённый журнал.', yAxis: 'Ось Y: процент использования', xAxis: 'Ось X: последовательность обновлений', cls: 'mem', color: '#4fd1a3', points: history.map(function (item) { return item.mem * 100; }), area: true },
          net: { title: 'Сетевая нагрузка', subtitle: 'Текущий бюджет обмена между узлами.', yAxis: 'Ось Y: процент использования', xAxis: 'Ось X: последовательность обновлений', cls: 'net', color: '#6aa9ff', points: history.map(function (item) { return item.net * 100; }), area: true },
          events: { title: 'Объём журнала', subtitle: 'Количество известных событий на текущем узле.', yAxis: 'Ось Y: количество событий', xAxis: 'Ось X: последовательность обновлений', cls: 'events', color: '#f4b363', points: history.map(function (item) { return item.events; }), area: true }
        };
        var config = map[kind];
        if (!config) {
          return;
        }
        if (analyticsModalTitleEl) { analyticsModalTitleEl.textContent = config.title; }
        if (analyticsModalSubtitleEl) { analyticsModalSubtitleEl.textContent = config.subtitle; }
        if (analyticsModalYAxisEl) { analyticsModalYAxisEl.textContent = config.yAxis; }
        if (analyticsModalXAxisEl) { analyticsModalXAxisEl.textContent = config.xAxis; }
        analyticsModalLegendEl.innerHTML = '<span class="trend-chip"><span class="trend-dot ' + config.cls + '"></span>' + config.title + '</span>';
        var maxValue = 1;
        config.points.forEach(function (value) { if (value > maxValue) { maxValue = value; } });
        drawModalChart([{ cls: config.cls, points: config.points, color: config.color, area: config.area }], maxValue);
        if (analyticsModalCaptionRightEl) {
          var lastPoint = config.points.length ? config.points[config.points.length - 1] : 0;
          analyticsModalCaptionRightEl.textContent = 'Текущее значение: ' + (kind === 'events' ? String(Math.round(lastPoint)) : formatValue(lastPoint, 1) + '%');
        }
      }

      function buildAreaPath(points, width, height, maxValue) {
        if (!points.length) {
          return '';
        }
        var denominator = Math.max(points.length - 1, 1);
        var commands = ['M0,' + height.toFixed(2)];
        for (var i = 0; i < points.length; i += 1) {
          var x = (i / denominator) * width;
          var y = height - ((points[i] / Math.max(maxValue, 1)) * height);
          commands.push('L' + x.toFixed(2) + ',' + y.toFixed(2));
        }
        commands.push('L' + width.toFixed(2) + ',' + height.toFixed(2));
        commands.push('Z');
        return commands.join(' ');
      }

      function setHeroDelta(el, current, previous, formatter) {
        if (!el) {
          return;
        }
        if (previous === null || previous === undefined || !isFinite(previous)) {
          el.textContent = '—';
          el.className = 'hero-kpi-delta';
          return;
        }
        var delta = current - previous;
        if (Math.abs(delta) < 0.0001) {
          el.textContent = '0';
          el.className = 'hero-kpi-delta';
          return;
        }
        el.textContent = (delta > 0 ? '↑ ' : '↓ ') + formatter(Math.abs(delta));
        el.className = 'hero-kpi-delta ' + (delta > 0 ? 'up' : 'down');
      }

      function renderHeroSparkline(svgEl, points, color, maxValue) {
        if (!svgEl) {
          return;
        }
        var width = 220;
        var height = 82;
        var chartHeight = 66;
        var offsetY = 8;
        svgEl.innerHTML = '';
        if (!points || points.length < 2) {
          return;
        }
        [12, 34, 56].forEach(function (y) {
          var line = document.createElementNS(svgNS, 'line');
          line.setAttribute('class', 'hero-spark-grid');
          line.setAttribute('x1', '0');
          line.setAttribute('x2', String(width));
          line.setAttribute('y1', String(y));
          line.setAttribute('y2', String(y));
          svgEl.appendChild(line);
        });
        var area = document.createElementNS(svgNS, 'path');
        area.setAttribute('class', 'hero-spark-area');
        area.setAttribute('fill', color);
        area.setAttribute('d', buildAreaPath(points, width, chartHeight, maxValue));
        area.setAttribute('transform', 'translate(0 ' + offsetY + ')');
        svgEl.appendChild(area);
        var poly = document.createElementNS(svgNS, 'polyline');
        poly.setAttribute('class', 'hero-spark-line');
        poly.setAttribute('stroke', color);
        poly.setAttribute('points', buildPolyline(points, width, chartHeight, maxValue));
        poly.setAttribute('transform', 'translate(0 ' + offsetY + ')');
        svgEl.appendChild(poly);
      }

      function buildIntensitySeries(windowSeconds, bucketCount) {
        if (!lastOperationalNodes || lastOperationalNodes.length === 0) {
          return null;
        }
        var timestamps = lastOperationalNodes.map(eventTimestamp).filter(function (value) {
          return value !== null;
        });
        if (timestamps.length === 0) {
          return null;
        }
        var now = Math.max(Date.now() / 1000, Math.max.apply(null, timestamps));
        var start = now - bucketCount * windowSeconds;
        var series = { A: new Array(bucketCount).fill(0), B: new Array(bucketCount).fill(0), C: new Array(bucketCount).fill(0) };
        lastOperationalNodes.forEach(function (node) {
          if (!series.hasOwnProperty(node.cls)) {
            return;
          }
          var ts = eventTimestamp(node);
          if (ts === null || ts < start) {
            return;
          }
          var bucket = Math.floor((ts - start) / windowSeconds);
          if (bucket >= bucketCount) {
            bucket = bucketCount - 1;
          }
          if (bucket >= 0) {
            series[node.cls][bucket] += 1;
          }
        });
        ['A', 'B', 'C'].forEach(function (cls) {
          series[cls] = series[cls].map(function (count) {
            return count / (windowSeconds / 60);
          });
        });
        return series;
      }

      function renderResourceTrendChart() {
        if (!trendChartEl) {
          return;
        }
        var width = 820;
        var height = 220;
        var padTop = 12;
        var padBottom = 20;
        var chartHeight = height - padTop - padBottom;
        trendChartEl.innerHTML = '';
        if (metricHistory.length < 2) {
          if (trendCaptionValueEl) {
            trendCaptionValueEl.textContent = 'Нужно больше точек для построения графика.';
          }
          return;
        }
        for (var g = 0; g < 4; g += 1) {
          var line = document.createElementNS(svgNS, 'line');
          var y = padTop + (chartHeight / 3) * g;
          line.setAttribute('class', 'grid-line');
          line.setAttribute('x1', '0');
          line.setAttribute('x2', String(width));
          line.setAttribute('y1', String(y));
          line.setAttribute('y2', String(y));
          trendChartEl.appendChild(line);
        }
        var maxEventValue = 1;
        for (var i = 0; i < metricHistory.length; i += 1) {
          if (metricHistory[i].events > maxEventValue) {
            maxEventValue = metricHistory[i].events;
          }
        }
        var memPoints = metricHistory.map(function (item) { return item.mem; });
        var netPoints = metricHistory.map(function (item) { return item.net; });
        var eventPoints = metricHistory.map(function (item) { return item.events; });
        var polylines = [
          { cls: 'mem', points: memPoints, max: 1 },
          { cls: 'net', points: netPoints, max: 1 },
          { cls: 'events', points: eventPoints, max: maxEventValue }
        ];
        for (var p = 0; p < polylines.length; p += 1) {
          var poly = document.createElementNS(svgNS, 'polyline');
          poly.setAttribute('class', 'trend-line ' + polylines[p].cls);
          poly.setAttribute('points', buildPolyline(polylines[p].points, width, chartHeight, polylines[p].max));
          poly.setAttribute('transform', 'translate(0 ' + padTop + ')');
          trendChartEl.appendChild(poly);
        }
        if (trendCaptionValueEl) {
          var last = metricHistory[metricHistory.length - 1];
          trendCaptionValueEl.textContent =
            'Сейчас: память ' + formatValue(last.mem * 100, 1) + '% · сеть ' + formatValue(last.net * 100, 1) + '% · событий ' + last.events;
        }
      }

      function renderIntensityTrendChart() {
        if (!trendChartEl) {
          return;
        }
        var width = 820;
        var height = 220;
        var padTop = 12;
        var padBottom = 20;
        var chartHeight = height - padTop - padBottom;
        trendChartEl.innerHTML = '';
        if (!lastOperationalNodes || lastOperationalNodes.length === 0) {
          if (trendCaptionValueEl) {
            trendCaptionValueEl.textContent = 'Для графика интенсивности пока недостаточно событий.';
          }
          return;
        }

        var timestamps = lastOperationalNodes.map(eventTimestamp).filter(function (value) {
          return value !== null;
        });
        if (timestamps.length === 0) {
          if (trendCaptionValueEl) {
            trendCaptionValueEl.textContent = 'У событий нет пригодных временных отметок для расчёта интенсивности.';
          }
          return;
        }

        var windowSeconds = 5 * 60;
        var bucketCount = 6;
        var now = Math.max(Date.now() / 1000, Math.max.apply(null, timestamps));
        var start = now - bucketCount * windowSeconds;
        var series = {
          A: new Array(bucketCount).fill(0),
          B: new Array(bucketCount).fill(0),
          C: new Array(bucketCount).fill(0)
        };

        lastOperationalNodes.forEach(function (node) {
          if (!series.hasOwnProperty(node.cls)) {
            return;
          }
          var ts = eventTimestamp(node);
          if (ts === null || ts < start) {
            return;
          }
          var bucket = Math.floor((ts - start) / windowSeconds);
          if (bucket < 0) {
            return;
          }
          if (bucket >= bucketCount) {
            bucket = bucketCount - 1;
          }
          series[node.cls][bucket] += 1;
        });

        for (var g = 0; g < 4; g += 1) {
          var line = document.createElementNS(svgNS, 'line');
          var y = padTop + (chartHeight / 3) * g;
          line.setAttribute('class', 'grid-line');
          line.setAttribute('x1', '0');
          line.setAttribute('x2', String(width));
          line.setAttribute('y1', String(y));
          line.setAttribute('y2', String(y));
          trendChartEl.appendChild(line);
        }

        var maxValue = 1;
        ['A', 'B', 'C'].forEach(function (cls) {
          series[cls].forEach(function (count) {
            var rate = count / (windowSeconds / 60);
            if (rate > maxValue) {
              maxValue = rate;
            }
          });
        });

        [
          { cls: 'class-a', points: series.A.map(function (count) { return count / (windowSeconds / 60); }) },
          { cls: 'class-b', points: series.B.map(function (count) { return count / (windowSeconds / 60); }) },
          { cls: 'class-c', points: series.C.map(function (count) { return count / (windowSeconds / 60); }) }
        ].forEach(function (entry) {
          var poly = document.createElementNS(svgNS, 'polyline');
          poly.setAttribute('class', 'trend-line ' + entry.cls);
          poly.setAttribute('points', buildPolyline(entry.points, width, chartHeight, maxValue));
          poly.setAttribute('transform', 'translate(0 ' + padTop + ')');
          trendChartEl.appendChild(poly);
        });

        if (trendCaptionValueEl) {
          var lastIndex = bucketCount - 1;
          var rateA = series.A[lastIndex] / (windowSeconds / 60);
          var rateB = series.B[lastIndex] / (windowSeconds / 60);
          var rateC = series.C[lastIndex] / (windowSeconds / 60);
          trendCaptionValueEl.textContent =
            'Текущее окно 5 минут: A ' + formatValue(rateA, 1) + ' / мин · B ' + formatValue(rateB, 1) + ' / мин · C ' + formatValue(rateC, 1) + ' / мин';
        }
      }

      function renderTrendChart() {
        if (trendLegendEl) {
          if (trendView === 'intensity') {
            trendLegendEl.innerHTML =
              '<span class="trend-chip"><span class="trend-dot class-a"></span>Класс A</span>' +
              '<span class="trend-chip"><span class="trend-dot class-b"></span>Класс B</span>' +
              '<span class="trend-chip"><span class="trend-dot class-c"></span>Класс C</span>';
          } else {
            trendLegendEl.innerHTML =
              '<span class="trend-chip"><span class="trend-dot mem"></span>Память журнала</span>' +
              '<span class="trend-chip"><span class="trend-dot net"></span>Сетевая нагрузка</span>' +
              '<span class="trend-chip"><span class="trend-dot events"></span>Количество событий</span>';
          }
        }
        if (trendYAxisEl) {
          trendYAxisEl.textContent = trendView === 'intensity'
            ? 'Ось Y: событий в минуту'
            : 'Ось Y: относительная загрузка и объём журнала';
        }
        if (trendXAxisEl) {
          trendXAxisEl.textContent = trendView === 'intensity'
            ? 'Ось X: последовательные окна по 5 минут'
            : 'Ось X: последовательность наблюдений во времени';
        }
        if (trendView === 'intensity') {
          renderIntensityTrendChart();
          return;
        }
        renderResourceTrendChart();
      }

      function updateHeroOverview() {
        if (heroKpiMemValueEl && metricHistory.length) {
          var lastMetric = metricHistory[metricHistory.length - 1];
          var prevMetric = metricHistory.length > 1 ? metricHistory[metricHistory.length - 2] : null;
          setText(heroKpiMemValueEl, formatValue(lastMetric.mem * 100, 1) + '%');
          setText(heroKpiMemCaptionEl, 'Использование памяти под распределённый журнал.');
          setHeroDelta(heroKpiMemDeltaEl, lastMetric.mem * 100, prevMetric ? prevMetric.mem * 100 : null, function (value) { return formatValue(value, 1) + ' п.п.'; });
          renderHeroSparkline(heroKpiMemSparkEl, metricHistory.map(function (item) { return item.mem * 100; }), '#4fd1a3', 100);

          setText(heroKpiNetValueEl, formatValue(lastMetric.net * 100, 1) + '%');
          setText(heroKpiNetCaptionEl, 'Текущий сетевой бюджет на gossip и доставку.');
          setHeroDelta(heroKpiNetDeltaEl, lastMetric.net * 100, prevMetric ? prevMetric.net * 100 : null, function (value) { return formatValue(value, 1) + ' п.п.'; });
          renderHeroSparkline(heroKpiNetSparkEl, metricHistory.map(function (item) { return item.net * 100; }), '#6aa9ff', 100);

          setText(heroKpiEventsValueEl, String(lastMetric.events));
          setText(heroKpiEventsCaptionEl, 'Количество известных событий внутри локального журнала.');
          setHeroDelta(heroKpiEventsDeltaEl, lastMetric.events, prevMetric ? prevMetric.events : null, function (value) { return String(Math.round(value)) + ' evt'; });
          var maxEvents = 1;
          metricHistory.forEach(function (item) { if (item.events > maxEvents) { maxEvents = item.events; } });
          renderHeroSparkline(heroKpiEventsSparkEl, metricHistory.map(function (item) { return item.events; }), '#f4b363', maxEvents);
        }

        if (heroKpiIntensityValueEl) {
          var intensitySeries = buildIntensitySeries(5 * 60, 6);
          if (!intensitySeries) {
            setText(heroKpiIntensityValueEl, '—');
            setText(heroKpiIntensityCaptionEl, 'Нужны события с временными отметками.');
            if (heroKpiIntensityDeltaEl) {
              heroKpiIntensityDeltaEl.textContent = '—';
              heroKpiIntensityDeltaEl.className = 'hero-kpi-delta';
            }
            if (heroKpiIntensitySparkEl) {
              heroKpiIntensitySparkEl.innerHTML = '';
            }
          } else {
            var combined = intensitySeries.A.map(function (value, index) { return value + intensitySeries.B[index] + intensitySeries.C[index]; });
            var lastRate = combined[combined.length - 1];
            var prevRate = combined.length > 1 ? combined[combined.length - 2] : null;
            var maxRate = 1;
            ['A', 'B', 'C'].forEach(function (cls) {
              intensitySeries[cls].forEach(function (value) { if (value > maxRate) { maxRate = value; } });
            });
            setText(heroKpiIntensityValueEl, 'A ' + formatValue(intensitySeries.A[intensitySeries.A.length - 1], 1) + ' · B ' + formatValue(intensitySeries.B[intensitySeries.B.length - 1], 1) + ' · C ' + formatValue(intensitySeries.C[intensitySeries.C.length - 1], 1));
            setText(heroKpiIntensityCaptionEl, 'Три класса A/B/C показаны вместе за окно 5 минут.');
            setHeroDelta(heroKpiIntensityDeltaEl, lastRate, prevRate, function (value) { return formatValue(value, 1) + ' / мин'; });
            renderHeroMultiSparkline(heroKpiIntensitySparkEl, [
              { cls: 'class-a', points: intensitySeries.A },
              { cls: 'class-b', points: intensitySeries.B },
              { cls: 'class-c', points: intensitySeries.C }
            ], maxRate);
          }
        }

        if (heroSpotClassAEl) { setText(heroSpotClassAEl, String(lastClassSummary.A || 0)); }
        if (heroSpotClassBEl) { setText(heroSpotClassBEl, String(lastClassSummary.B || 0)); }
        if (heroSpotSourcesEl) { setText(heroSpotSourcesEl, String(lastSourceCount || 0)); }
        if (heroSpotSyncEl) {
          var peerKeys = Object.keys(consensusState);
          var mismatched = 0;
          var pendingCount = 0;
          peerKeys.forEach(function (peer) {
            var state = consensusState[peer];
            if (!state) { return; }
            if (state.pending) { pendingCount += 1; return; }
            if (state.error || !state.match) { mismatched += 1; }
          });
          if (peerKeys.length === 0) {
            heroSpotSyncEl.textContent = 'Согласованность: ожидание';
            heroSpotSyncEl.className = 'hero-spot-pill';
          } else if (mismatched > 0) {
            heroSpotSyncEl.textContent = 'Согласованность: рассогласование';
            heroSpotSyncEl.className = 'hero-spot-pill alert';
          } else if (pendingCount > 0) {
            heroSpotSyncEl.textContent = 'Согласованность: проверка';
            heroSpotSyncEl.className = 'hero-spot-pill warn';
          } else {
            heroSpotSyncEl.textContent = 'Согласованность: стабильно';
            heroSpotSyncEl.className = 'hero-spot-pill ok';
          }
        }
        if (heroSpotThreatEl) {
          var threat = lastStatusSnapshot && lastStatusSnapshot.profile ? valueOr(lastStatusSnapshot.profile.threat_level, '—') : '—';
          heroSpotThreatEl.textContent = 'Угроза: ' + threat;
          heroSpotThreatEl.className = 'hero-spot-pill' + (threat === 'high' ? ' alert' : threat === 'medium' ? ' warn' : threat === 'low' ? ' ok' : '');
        }
        if (heroSpotPressureEl) {
          var mem = lastMetricsSnapshot ? Number(lastMetricsSnapshot.C_mem || 0) : 0;
          var net = lastMetricsSnapshot ? Number(lastMetricsSnapshot.C_net || 0) : 0;
          heroSpotPressureEl.textContent = 'Нагрузка: спокойно';
          heroSpotPressureEl.className = 'hero-spot-pill ok';
          if (mem >= 0.85 || net >= 0.8) {
            heroSpotPressureEl.textContent = 'Нагрузка: высокая';
            heroSpotPressureEl.className = 'hero-spot-pill alert';
          } else if (mem >= 0.65 || net >= 0.55) {
            heroSpotPressureEl.textContent = 'Нагрузка: растёт';
            heroSpotPressureEl.className = 'hero-spot-pill warn';
          }
        }
      }

      function renderClassDistribution(classCounts, total) {
        if (!classBreakdownEl && !heroClassBreakdownEl) {
          return;
        }
        if (donutTotalEl) {
          donutTotalEl.textContent = String(total);
        }
        if (heroDonutTotalEl) {
          heroDonutTotalEl.textContent = String(total);
        }
        var a = classCounts.A || 0;
        var b = classCounts.B || 0;
        var c = classCounts.C || 0;
        var totalSafe = Math.max(total, 1);
        var aDeg = (a / totalSafe) * 360;
        var bDeg = (b / totalSafe) * 360;
        var cDeg = 360 - aDeg - bDeg;
        var donut = document.getElementById('class-donut');
        if (donut) {
          donut.style.background =
            'conic-gradient(' +
            '#ff6d6d 0deg ' + aDeg + 'deg,' +
            '#ffc971 ' + aDeg + 'deg ' + (aDeg + bDeg) + 'deg,' +
            '#5aa5ff ' + (aDeg + bDeg) + 'deg ' + (aDeg + bDeg + cDeg) + 'deg)';
        }
        var heroDonut = document.getElementById('hero-class-donut');
        if (heroDonut) {
          heroDonut.style.background =
            'conic-gradient(' +
            '#ff6d6d 0deg ' + aDeg + 'deg,' +
            '#ffc971 ' + aDeg + 'deg ' + (aDeg + bDeg) + 'deg,' +
            '#5aa5ff ' + (aDeg + bDeg) + 'deg ' + (aDeg + bDeg + cDeg) + 'deg)';
        }
        if (classBreakdownEl) {
          classBreakdownEl.innerHTML = '';
        }
        if (heroClassBreakdownEl) {
          heroClassBreakdownEl.innerHTML = '';
        }
        [
          { cls: 'a', label: 'Класс A', value: a },
          { cls: 'b', label: 'Класс B', value: b },
          { cls: 'c', label: 'Класс C', value: c }
        ].forEach(function (entry) {
          var row = document.createElement('div');
          row.className = 'class-row';
          var percentage = total > 0 ? (entry.value / total) * 100 : 0;
          row.innerHTML =
            '<span class="class-row-badge ' + entry.cls + '"></span>' +
            '<div class="class-row-bar"><div class="class-row-fill ' + entry.cls + '" style="width:' + percentage + '%"></div></div>' +
            '<span>' + entry.label + ' · ' + entry.value + ' · ' + formatValue(percentage, 1) + '%</span>';
          if (classBreakdownEl) {
            classBreakdownEl.appendChild(row);
          }
          if (heroClassBreakdownEl) {
            heroClassBreakdownEl.appendChild(row.cloneNode(true));
          }
        });
      }

      function renderSourceSummary(sourceStats) {
        if (!sourceSummaryEl) {
          return;
        }
        sourceSummaryEl.innerHTML = '';
        var keys = Object.keys(sourceStats || {});
        if (keys.length === 0) {
          sourceSummaryEl.innerHTML = '<div class="source-row"><div class="source-row-head"><span>Нет источников</span><span>—</span></div><div class="source-mini">Статистика появится после поступления событий.</div></div>';
          return;
        }
        keys.sort(function (a, b) {
          return sourceStats[b].total - sourceStats[a].total;
        });
        for (var i = 0; i < Math.min(keys.length, 6); i += 1) {
          var key = keys[i];
          var stat = sourceStats[key];
          var row = document.createElement('div');
          row.className = 'source-row';
          row.innerHTML =
            '<div class="source-row-head"><span>' + key + '</span><span>Всего: ' + stat.total + '</span></div>' +
            '<div class="source-row-bars">' +
              '<div class="source-mini">A<strong>' + stat.A + '</strong></div>' +
              '<div class="source-mini">B<strong>' + stat.B + '</strong></div>' +
              '<div class="source-mini">C<strong>' + stat.C + '</strong></div>' +
            '</div>';
          sourceSummaryEl.appendChild(row);
        }
      }

      function triggerSimulation(key) {
        if (!demoControlsEnabled) {
          return;
        }
        if (!key) {
          return;
        }
        setControlsDisabled(true);
        setControlsStatus('Имитируем сценарий "' + key + '"...', false);
        markSyncPending('Добавляется новое событие (' + key + ')...');
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/viz/simulate', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function () {
          if (xhr.readyState === 4) {
            setControlsDisabled(false);
            if (xhr.status >= 200 && xhr.status < 300) {
              setControlsStatus('Событие добавлено. Ожидайте появления на графе.', false);
              markSyncPending('Идёт синхронизация...');
            } else {
              var msg = 'Ошибка запуска сценария';
              if (xhr.responseText) {
                msg += ': ' + xhr.responseText;
              }
              setControlsStatus(msg, true);
              markError('Ошибка запуска сценария.');
            }
          }
        };
        xhr.onerror = function () {
          setControlsDisabled(false);
          setControlsStatus('Ошибка сети при запуске сценария', true);
          markError('Ошибка сети при запуске сценария.');
        };
        xhr.send(JSON.stringify({ scenario: key }));
      }

      function toggleSimulation() {
        if (!demoControlsEnabled) {
          return;
        }
        if (!simulationButton) {
          return;
        }
        setSimulationButtonDisabled(true);
        var action = simulationActive ? 'stop' : 'start';
        setControlsStatus((action === 'start') ? 'Запуск потоковой симуляции...' : 'Остановка симуляции...', false);
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/viz/simulation/control', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function () {
          if (xhr.readyState === 4) {
            setSimulationButtonDisabled(false);
            if (xhr.status >= 200 && xhr.status < 300) {
              var running = false;
              try {
                var resp = JSON.parse(xhr.responseText);
                running = !!resp.running;
              } catch (err) {}
              setSimulationRunning(running);
              if (running) {
                setControlsStatus('Симуляция событий запущена.', false);
                markSyncPending('Идёт симуляция распределённого потока...');
              } else {
                setControlsStatus('Симуляция остановлена.', false);
                markSyncPending('Синхронизация остановленной симуляции...');
              }
            } else {
              setControlsStatus('Не удалось переключить симуляцию', true);
              markError('Ошибка управления симуляцией.');
            }
          }
        };
        xhr.onerror = function () {
          setSimulationButtonDisabled(false);
          setControlsStatus('Ошибка сети при управлении симуляцией', true);
          markError('Ошибка сети при управлении симуляцией.');
        };
        xhr.send(JSON.stringify({ action: action }));
      }

      function fetchSimulationStatus() {
        if (!demoControlsEnabled) {
          return;
        }
        if (!simulationButton) {
          return;
        }
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/viz/simulation/control', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function () {
          if (xhr.readyState === 4) {
            if (xhr.status >= 200 && xhr.status < 300) {
              try {
                var resp = JSON.parse(xhr.responseText);
                setSimulationRunning(resp.running);
              } catch (err) {}
            }
          }
        };
        xhr.onerror = function () {};
        xhr.send(JSON.stringify({ action: 'status', propagate: false }));
      }

      function triggerGraphClear() {
        var proceed = true;
        if (typeof window !== 'undefined' && typeof window.confirm === 'function') {
          proceed = window.confirm('Очистить логи, граф и артефакты консенсуса на всех нодах кластера? Новые события начнут записываться заново.');
        }
        if (!proceed) {
          return;
        }
        setControlsDisabled(true);
        setResetControlsDisabled(true);
        setControlsStatus('Очищаем журнал на кластере...', false);
        setResetControlsStatus('Выполняется сброс графа и consensus state на всех нодах...', false);
        markSyncPending('Выполняется сброс графа...');
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/viz/clear', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function () {
          if (xhr.readyState === 4) {
            setControlsDisabled(false);
            setResetControlsDisabled(false);
            if (xhr.status >= 200 && xhr.status < 300) {
              var payload = null;
              if (xhr.responseText) {
                try {
                  payload = JSON.parse(xhr.responseText);
                } catch (err) {
                  /* ignore parse errors */
                }
              }
              resetGraphState();
              incidents = [];
              incidentsLoaded = false;
              if (payload && payload.metrics) {
                updateMetrics(payload.metrics);
              }
              setControlsStatus('Граф очищен, ждём новые события.', false);
              setResetControlsStatus('Сброс отправлен на все известные ноды. Журнал принимает новые события.', false);
              markSyncPending('Получаем якорные события...');
              loadGraph(function (err) {
                if (err) {
                  setControlsStatus('Ошибка повторной загрузки данных: ' + err.message, true);
                  markError('Ошибка при повторной загрузке графа.');
                } else {
                  if (incidentEnabled) {
                    loadIncidents();
                  }
                  renderGraph();
                }
              });
            } else {
              var message = 'Не удалось очистить DAG';
              if (xhr.responseText) {
                message += ': ' + xhr.responseText;
              }
              setControlsStatus(message, true);
              setResetControlsStatus(message, true);
              markError('Ошибка при очистке DAG.');
            }
          }
        };
        xhr.onerror = function () {
          setControlsDisabled(false);
          setResetControlsDisabled(false);
          setControlsStatus('Ошибка сети при очистке DAG', true);
          setResetControlsStatus('Ошибка сети при очистке журнала', true);
          markError('Ошибка сети при очистке DAG.');
        };
        xhr.send(JSON.stringify({ propagate: true }));
      }

      function setupControls() {
        if (!controlsRoot) {
          return;
        }
        var buttons = controlsRoot.querySelectorAll('.sim-button');
        buttons.forEach(function (button) {
          var simKey = button.getAttribute('data-sim');
          if (simKey) {
            button.addEventListener('click', function () {
              triggerSimulation(simKey);
            });
          } else if (button.id === 'simulation-toggle') {
            button.addEventListener('click', function () {
              toggleSimulation();
            });
          } else if (button.id === 'clear-graph') {
            button.addEventListener('click', function () {
              triggerGraphClear();
            });
          }
        });
        if (clusterResetButton) {
          clusterResetButton.addEventListener('click', function () {
            triggerGraphClear();
          });
        }
        if (filterClassesRoot) {
          var classButtons = filterClassesRoot.querySelectorAll('[data-filter-class]');
          classButtons.forEach(function (button) {
            var cls = button.getAttribute('data-filter-class');
            if (!cls) {
              return;
            }
            classFilterButtons[cls] = button;
            button.addEventListener('click', function () {
              toggleClassFilter(cls);
            });
          });
        }
        if (filterSourcesRoot) {
          var allButton = filterSourcesRoot.querySelector('[data-filter-source="' + ALL_SOURCES_TOKEN + '"]');
          if (allButton) {
            sourceFilterButtons[ALL_SOURCES_TOKEN] = allButton;
            allButton.addEventListener('click', function () {
              toggleSourceFilter(ALL_SOURCES_TOKEN);
            });
          }
        }
        updateClassButtonsUI();
        updateSourceButtonsUI();
        resetDetailsPanel();
        updateSimulationButton();
        updateConsensusStatusDisplay();
      }

      function valueOr(value, fallback) {
        if (value === undefined || value === null) {
          return fallback;
        }
        return value;
      }

      function cloneData(value) {
        if (value === undefined || value === null) {
          return value;
        }
        if (typeof structuredClone === 'function') {
          try {
            return structuredClone(value);
          } catch (err) {}
        }
        if (typeof value === 'object') {
          try {
            return JSON.parse(JSON.stringify(value));
          } catch (err) {
            return value;
          }
        }
        return value;
      }

      var svgNS = 'http://www.w3.org/2000/svg';
      var svg = document.createElementNS(svgNS, 'svg');
      var laneGroup = document.createElementNS(svgNS, 'g');
      var linkGroup = document.createElementNS(svgNS, 'g');
      var nodeGroup = document.createElementNS(svgNS, 'g');
      var labelGroup = document.createElementNS(svgNS, 'g');
      var viewBoxState = {
        baseWidth: 1200,
        baseHeight: 800,
        width: 1200,
        height: 800,
        x: 0,
        y: 0,
        scale: 1,
        initialized: false
      };
      var MIN_SCALE = 0.4;
      var MAX_SCALE = 4.0;

      function clamp(value, min, max) {
        return Math.min(Math.max(value, min), max);
      }

      function applyViewBox() {
        svg.setAttribute(
          'viewBox',
          viewBoxState.x + ' ' + viewBoxState.y + ' ' + viewBoxState.width + ' ' + viewBoxState.height
        );
      }

      function updateViewBoxBase(width, height) {
        var safeWidth = Math.max(width, 10);
        var safeHeight = Math.max(height, 10);
        var centerX;
        var centerY;
        if (viewBoxState.initialized) {
          centerX = viewBoxState.x + viewBoxState.width / 2;
          centerY = viewBoxState.y + viewBoxState.height / 2;
        } else {
          centerX = safeWidth / 2;
          centerY = safeHeight / 2;
        }
        viewBoxState.baseWidth = safeWidth;
        viewBoxState.baseHeight = safeHeight;
        viewBoxState.width = safeWidth / viewBoxState.scale;
        viewBoxState.height = safeHeight / viewBoxState.scale;
        viewBoxState.x = centerX - viewBoxState.width / 2;
        viewBoxState.y = centerY - viewBoxState.height / 2;
        viewBoxState.initialized = true;
        applyViewBox();
      }

      function setScale(newScale, focusX, focusY) {
        var clamped = clamp(newScale, MIN_SCALE, MAX_SCALE);
        if (!isFinite(clamped) || clamped === viewBoxState.scale) {
          return;
        }
        var prevWidth = viewBoxState.width;
        var prevHeight = viewBoxState.height;
        var pivotX = (typeof focusX === 'number') ? focusX : viewBoxState.x + prevWidth / 2;
        var pivotY = (typeof focusY === 'number') ? focusY : viewBoxState.y + prevHeight / 2;
        viewBoxState.scale = clamped;
        viewBoxState.width = viewBoxState.baseWidth / viewBoxState.scale;
        viewBoxState.height = viewBoxState.baseHeight / viewBoxState.scale;
        var widthRatio = viewBoxState.width / prevWidth;
        var heightRatio = viewBoxState.height / prevHeight;
        viewBoxState.x = pivotX - (pivotX - viewBoxState.x) * widthRatio;
        viewBoxState.y = pivotY - (pivotY - viewBoxState.y) * heightRatio;
        applyViewBox();
      }

      function screenDeltaToViewBox(dx, dy) {
        var rectWidth = svg.clientWidth || graphEl.clientWidth || 1;
        var rectHeight = svg.clientHeight || graphEl.clientHeight || 1;
        return {
          dx: dx * (viewBoxState.width / rectWidth),
          dy: dy * (viewBoxState.height / rectHeight)
        };
      }
      var defs = document.createElementNS(svgNS, 'defs');
      var marker = document.createElementNS(svgNS, 'marker');
      marker.setAttribute('id', 'arrowhead');
      marker.setAttribute('markerWidth', '10');
      marker.setAttribute('markerHeight', '7');
      marker.setAttribute('refX', '13');
      marker.setAttribute('refY', '3.5');
      marker.setAttribute('orient', 'auto');
      marker.setAttribute('markerUnits', 'strokeWidth');
      var arrowPath = document.createElementNS(svgNS, 'path');
      arrowPath.setAttribute('d', 'M0,0 L0,7 L10,3.5 z');
      arrowPath.setAttribute('fill', 'rgba(150, 190, 255, 0.7)');
      marker.appendChild(arrowPath);
      defs.appendChild(marker);
      svg.appendChild(defs);
      svg.appendChild(laneGroup);
      svg.appendChild(linkGroup);
      svg.appendChild(nodeGroup);
      svg.appendChild(labelGroup);
      graphEl.appendChild(svg);
      svg.style.cursor = 'grab';
      applyViewBox();

      var isPanning = false;
      var panPointerId = null;
      var lastPanPoint = { x: 0, y: 0 };

      function endPan(event) {
        if (!isPanning) {
          return;
        }
        if (
          event && typeof event.pointerId === 'number' && panPointerId !== null && event.pointerId !== panPointerId
        ) {
          return;
        }
        if (panPointerId !== null) {
          try {
            svg.releasePointerCapture(panPointerId);
          } catch (err) {}
        }
        isPanning = false;
        panPointerId = null;
        svg.style.cursor = 'grab';
      }

      svg.addEventListener('pointerdown', function (event) {
        if (event.button !== 0) {
          return;
        }
        var target = event.target;
        if (
          target &&
          target.classList &&
          (target.classList.contains('node') || target.classList.contains('label'))
        ) {
          return;
        }
        isPanning = true;
        panPointerId = event.pointerId;
        svg.setPointerCapture(panPointerId);
        lastPanPoint.x = event.clientX;
        lastPanPoint.y = event.clientY;
        svg.style.cursor = 'grabbing';
      });

      svg.addEventListener('pointermove', function (event) {
        if (!isPanning || event.pointerId !== panPointerId) {
          return;
        }
        var deltaX = event.clientX - lastPanPoint.x;
        var deltaY = event.clientY - lastPanPoint.y;
        lastPanPoint.x = event.clientX;
        lastPanPoint.y = event.clientY;
        var delta = screenDeltaToViewBox(deltaX, deltaY);
        viewBoxState.x -= delta.dx;
        viewBoxState.y -= delta.dy;
        applyViewBox();
      });

      svg.addEventListener('pointerup', endPan);
      svg.addEventListener('pointerleave', endPan);
      svg.addEventListener('pointercancel', endPan);

      svg.addEventListener(
        'wheel',
        function (event) {
          event.preventDefault();
          var rect = svg.getBoundingClientRect();
          var pointerX = viewBoxState.x + viewBoxState.width / 2;
          var pointerY = viewBoxState.y + viewBoxState.height / 2;
          if (rect.width > 0 && rect.height > 0) {
            pointerX = viewBoxState.x + ((event.clientX - rect.left) / rect.width) * viewBoxState.width;
            pointerY = viewBoxState.y + ((event.clientY - rect.top) / rect.height) * viewBoxState.height;
          }
          var factor = event.deltaY > 0 ? 0.9 : 1.1;
          setScale(viewBoxState.scale * factor, pointerX, pointerY);
        },
        { passive: false }
      );

      function rememberNode(nodeId) {
        if (nodes.hasOwnProperty(nodeId)) {
          return;
        }
        nodes[nodeId] = null;
        nodeOrder.push(nodeId);
        if (!childrenMap[nodeId]) {
          childrenMap[nodeId] = [];
        }
      }

      function ensureNode(event) {
        if (!event || !event.id) {
          return;
        }
        rememberNode(event.id);
        var existing = nodes[event.id];
        if (!existing) {
          var payloadCopy = cloneData(event.payload);
          if (payloadCopy === undefined || payloadCopy === null) {
            payloadCopy = {};
          }
          var vclockCopy = cloneData(event.vclock);
          if (vclockCopy === undefined || vclockCopy === null) {
            vclockCopy = {};
          }
          existing = {
            id: event.id,
            cls: event.cls || 'C',
            source: event.source || 'unknown',
            consensus_ts: valueOr(event.consensus_ts, null),
            ts_local: valueOr(event.ts_local, null),
            parents: (Array.isArray(event.parents) ? event.parents.slice(0) : []),
            payload: payloadCopy,
            vclock: vclockCopy,
            sig: event.sig || null,
            lamport_ts: valueOr(event.lamport_ts, null)
          };
          nodes[event.id] = existing;
        } else {
          existing.cls = event.cls || existing.cls;
          existing.source = event.source || existing.source;
          var newConsensus = valueOr(event.consensus_ts, existing.consensus_ts);
          var newTsLocal = valueOr(event.ts_local, existing.ts_local);
          existing.consensus_ts = newConsensus;
          existing.ts_local = newTsLocal;
          if (Array.isArray(event.parents)) {
            existing.parents = event.parents.slice(0);
          }
          var updatedPayload = cloneData(event.payload);
          if (updatedPayload !== undefined) {
            if (updatedPayload === null) {
              updatedPayload = {};
            }
            existing.payload = updatedPayload;
          }
          var updatedVclock = cloneData(event.vclock);
          if (updatedVclock !== undefined) {
            if (updatedVclock === null) {
              updatedVclock = {};
            }
            existing.vclock = updatedVclock;
          }
          if (event.sig !== undefined) {
            existing.sig = event.sig || null;
          }
          if (event.lamport_ts !== undefined && event.lamport_ts !== null) {
            existing.lamport_ts = event.lamport_ts;
          }
        }
        registerSource(existing.source);
      }

      function addEvent(event) {
        if (!event) {
          return;
        }
        ensureNode(event);
        var parents = (Array.isArray(event.parents) ? event.parents : []);
        for (var i = 0; i < parents.length; i += 1) {
          var parentId = parents[i];
          if (!nodes[parentId]) {
            ensureNode({ id: parentId, cls: 'C', source: 'unknown', parents: [] });
          }
          rememberNode(parentId);
          var key = parentId + '->' + event.id;
          if (!links[key]) {
            links[key] = { source: parentId, target: event.id };
            linkOrder.push(key);
          }
          var childList = childrenMap[parentId];
          if (!childList) {
            childList = [];
            childrenMap[parentId] = childList;
          }
          if (childList.indexOf(event.id) === -1) {
            childList.push(event.id);
          }
        }
      }

      function computeAncestors(nodeId) {
        var result = {};
        var stack = [nodeId];
        var visited = {};
        while (stack.length > 0) {
          var current = stack.pop();
          var currentNode = nodes[current];
          if (!currentNode) {
            continue;
          }
          var parents = currentNode.parents || [];
          for (var i = 0; i < parents.length; i += 1) {
            var parentId = parents[i];
            if (!parentId || result[parentId]) {
              continue;
            }
            result[parentId] = true;
            if (!visited[parentId]) {
              visited[parentId] = true;
              stack.push(parentId);
            }
          }
        }
        return result;
      }

      function computeDescendants(nodeId) {
        var result = {};
        var stack = [nodeId];
        var visited = {};
        while (stack.length > 0) {
          var current = stack.pop();
          var children = childrenMap[current] || [];
          for (var i = 0; i < children.length; i += 1) {
            var childId = children[i];
            if (!childId || result[childId]) {
              continue;
            }
            result[childId] = true;
            if (!visited[childId]) {
              visited[childId] = true;
              stack.push(childId);
            }
          }
        }
        return result;
      }

      function setFocus(nodeId) {
        if (!nodeId) {
          focusNodeId = null;
          focusAncestors = {};
          focusDescendants = {};
          shouldOpenDetailsOnFocus = false;
          closeDetailsPanel();
          renderGraph();
          return;
        }
        if (nodeId === focusNodeId) {
          if (isDetailsOpen) {
            focusNodeId = null;
            focusAncestors = {};
            focusDescendants = {};
            shouldOpenDetailsOnFocus = false;
            closeDetailsPanel();
          } else {
            shouldOpenDetailsOnFocus = true;
          }
          renderGraph();
          return;
        }
        focusNodeId = nodeId;
        if (nodes[nodeId]) {
          focusAncestors = computeAncestors(nodeId);
          focusDescendants = computeDescendants(nodeId);
        } else {
          focusAncestors = {};
          focusDescendants = {};
        }
        shouldOpenDetailsOnFocus = true;
        renderGraph();
      }

      function renderTimeline() {
        var container = document.getElementById('timeline-items');
        if (!container) {
          return;
        }
        container.innerHTML = '';

        var resetBtn = document.createElement('button');
        resetBtn.className = 'timeline-item';
        resetBtn.textContent = 'Сбросить выделение';
        resetBtn.addEventListener('click', function () {
          setFocus(null);
        });
        if (!focusNodeId) {
          resetBtn.classList.add('active');
        }
        container.appendChild(resetBtn);

        for (var i = 0; i < layoutOrder.length; i += 1) {
          var nodeId = layoutOrder[i];
          var node = nodes[nodeId];
          if (!node) {
            continue;
          }
          var item = document.createElement('button');
          item.className = 'timeline-item';
          item.textContent = '#' + valueOr(node.sequence, '?') + ' · ' + node.cls + ' · ' + node.source;
          if (focusNodeId === nodeId) {
            item.classList.add('active');
          } else if (focusNodeId) {
            var related = focusAncestors[nodeId] || focusDescendants[nodeId];
            if (!related) {
              item.classList.add('faded');
            }
          }
          (function (targetId) {
            item.addEventListener('click', function () {
              setFocus(targetId);
            });
          })(nodeId);
          container.appendChild(item);
        }
      }

      function computeLayout() {
        var ordered = nodeOrder.slice(0);
        ordered.sort(function (aId, bId) {
          var a = nodes[aId];
          var b = nodes[bId];
          if (!a || !b) {
            return 0;
          }
          var ta = valueOr(a.consensus_ts, valueOr(a.ts_local, 9007199254740991));
          var tb = valueOr(b.consensus_ts, valueOr(b.ts_local, 9007199254740991));
          if (ta === tb) {
            if (a.id < b.id) { return -1; }
            if (a.id > b.id) { return 1; }
            return 0;
          }
          return (ta < tb) ? -1 : 1;
        });

        var colSpacing = 200;
        var rowSpacing = 130;
        var marginLeft = 200;
        var marginRight = 200;
        var marginTop = 240;
        var marginBottom = 280;

        for (var resetIdx = 0; resetIdx < ordered.length; resetIdx += 1) {
          var resetNode = nodes[ordered[resetIdx]];
          if (resetNode) {
            resetNode.sequence = null;
          }
        }

        var visibleSources = {};
        for (var i = 0; i < ordered.length; i += 1) {
        var node = nodes[ordered[i]];
        if (!node) { continue; }
        if (node.source === 'unknown') {
          continue;
        }
        if (isNodeVisible(node)) {
            var sourceKey = node.source || 'unknown';
            visibleSources[sourceKey] = true;
          }
        }

        var activeSources = [];
        var seenSources = {};
        for (var so = 0; so < sourceOrder.length; so += 1) {
          var sourceCandidate = sourceOrder[so];
          if (visibleSources[sourceCandidate]) {
            activeSources.push(sourceCandidate);
            seenSources[sourceCandidate] = true;
          }
        }
        var sortedVisible = Object.keys(visibleSources).sort();
        for (var sv = 0; sv < sortedVisible.length; sv += 1) {
          if (!seenSources[sortedVisible[sv]]) {
            activeSources.push(sortedVisible[sv]);
          }
        }
        activeSources.sort();
        if (activeSources.length === 0 && sortedVisible.length > 0) {
          activeSources = sortedVisible;
        }

        var localLanePositions = {};
        for (var laneIdx = 0; laneIdx < activeSources.length; laneIdx += 1) {
          localLanePositions[activeSources[laneIdx]] = marginLeft + laneIdx * colSpacing;
        }
        laneOrder = activeSources;
        lanePositions = localLanePositions;

        var positionedIds = [];
        for (var j = 0; j < ordered.length; j += 1) {
          var candidateNode = nodes[ordered[j]];
          if (!candidateNode || candidateNode.source === 'unknown' || !isNodeVisible(candidateNode)) {
            continue;
          }
          var laneKey = candidateNode.source || 'unknown';
          var laneX = localLanePositions.hasOwnProperty(laneKey)
            ? localLanePositions[laneKey]
            : (activeSources.length ? localLanePositions[activeSources[0]] : marginLeft);
          var idx = positionedIds.length;
          candidateNode.x = laneX;
          candidateNode.y = marginTop + idx * rowSpacing;
          candidateNode.sequence = idx + 1;
          positionedIds.push(candidateNode.id);
        }

        var lastNodeY = positionedIds.length > 0 ? (marginTop + (positionedIds.length - 1) * rowSpacing) : marginTop;
        var contentWidth = marginLeft + marginRight;
        if (activeSources.length > 1) {
          contentWidth += (activeSources.length - 1) * colSpacing;
        }
        var contentHeight = marginTop + marginBottom;
        if (positionedIds.length > 1) {
          contentHeight += (positionedIds.length - 1) * rowSpacing;
        }

        var graphWrapperEl = graphEl ? graphEl.parentElement : null;
        var viewportWidth = (graphWrapperEl && graphWrapperEl.clientWidth) || graphEl.clientWidth || 800;
        var viewportHeight = (graphWrapperEl && graphWrapperEl.clientHeight) || graphEl.clientHeight || 600;
        var width = Math.max(contentWidth, viewportWidth);
        var height = Math.max(contentHeight, viewportHeight);

        layoutDimensions = {
          width: width,
          height: height,
          contentWidth: contentWidth,
          contentHeight: contentHeight,
          top: marginTop,
          bottom: marginBottom,
          left: marginLeft,
          right: marginRight,
          rowSpacing: rowSpacing,
          colSpacing: colSpacing,
          lastNodeY: lastNodeY
        };

        updateViewBoxBase(width, height);
        graphEl.style.width = width + 'px';
        graphEl.style.height = height + 'px';
        svg.style.width = width + 'px';
        svg.style.height = height + 'px';
        layoutOrder = positionedIds;
        return { lanes: activeSources, positions: localLanePositions };
      }

      function renderGraph() {
        var layoutInfo = computeLayout();
        linkGroup.innerHTML = '';
        nodeGroup.innerHTML = '';
        labelGroup.innerHTML = '';
        laneGroup.innerHTML = '';

        var laneTop = layoutDimensions.top - 120;
        var laneBottom = Math.max(layoutDimensions.lastNodeY + 120, layoutDimensions.top + 200);
        if (laneBottom < laneTop + 200) {
          laneBottom = laneTop + 200;
        }

        if (layoutInfo && layoutInfo.lanes) {
          for (var li = 0; li < layoutInfo.lanes.length; li += 1) {
            var sourceName = layoutInfo.lanes[li];
            var laneX = layoutInfo.positions[sourceName];
            if (typeof laneX !== 'number') {
              continue;
            }
            var guide = document.createElementNS(svgNS, 'line');
            guide.setAttribute('class', 'lane-line');
            guide.setAttribute('x1', laneX);
            guide.setAttribute('x2', laneX);
            guide.setAttribute('y1', laneTop);
            guide.setAttribute('y2', laneBottom);
            laneGroup.appendChild(guide);

            var label = document.createElementNS(svgNS, 'text');
            label.setAttribute('class', 'lane-label');
            label.setAttribute('x', laneX);
            label.setAttribute('y', laneTop - 12);
            label.setAttribute('text-anchor', 'middle');
            label.textContent = sourceName;
            laneGroup.appendChild(label);
          }
        }

        if (focusNodeId && (!nodes[focusNodeId] || !isNodeVisible(nodes[focusNodeId]))) {
          focusNodeId = null;
          focusAncestors = {};
          focusDescendants = {};
        }

        var focusActive = !!focusNodeId;
        var focusRelated = {};
        if (focusActive && nodes[focusNodeId]) {
          focusRelated[focusNodeId] = true;
          Object.keys(focusAncestors).forEach(function (key) { focusRelated[key] = true; });
          Object.keys(focusDescendants).forEach(function (key) { focusRelated[key] = true; });
        }

        for (var i = 0; i < linkOrder.length; i += 1) {
          var linkKey = linkOrder[i];
          var link = links[linkKey];
          if (!link) { continue; }
          var parentNode = nodes[link.source];
          var childNode = nodes[link.target];
          if (!parentNode || !childNode) { continue; }
          if (parentNode.source === 'unknown' || childNode.source === 'unknown') { continue; }
          if (!isNodeVisible(parentNode) || !isNodeVisible(childNode)) { continue; }
          var line = document.createElementNS(svgNS, 'line');
          var edgeClass = 'link';
          if (focusActive) {
            var parentIn = focusRelated[parentNode.id];
            var childIn = focusRelated[childNode.id];
            if (parentIn && childIn) {
              edgeClass += ' link-highlight';
            } else {
              edgeClass += ' link-faded';
            }
          }
          line.setAttribute('class', edgeClass);
          line.setAttribute('x1', childNode.x);
          line.setAttribute('y1', childNode.y);
          line.setAttribute('x2', parentNode.x);
          line.setAttribute('y2', parentNode.y);
          linkGroup.appendChild(line);
        }

        for (var j = 0; j < layoutOrder.length; j += 1) {
          var nodeId = layoutOrder[j];
          var node = nodes[nodeId];
          if (!node || node.source === 'unknown' || !isNodeVisible(node)) { continue; }
          var circle = document.createElementNS(svgNS, 'circle');
          var circleClass = 'node';
          var radius = 10;
          if (focusActive) {
            if (nodeId === focusNodeId) {
              circleClass += ' node-focus';
              radius = 12;
            } else if (focusAncestors[nodeId]) {
              circleClass += ' node-ancestor';
              radius = 11;
            } else if (focusDescendants[nodeId]) {
              circleClass += ' node-descendant';
              radius = 11;
            } else {
              circleClass += ' node-faded';
              radius = 9;
            }
          }
          circle.setAttribute('class', circleClass);
          circle.setAttribute('r', String(radius));
          circle.setAttribute('cx', node.x);
          circle.setAttribute('cy', node.y);
          circle.setAttribute('fill', colorByClass[node.cls] || colorByClass.default);
          circle.setAttribute('data-id', node.id);
          (function (n) {
            circle.addEventListener('mouseenter', function () { showTooltip(n); });
            circle.addEventListener('click', function () { setFocus(n.id); });
          })(node);
          circle.addEventListener('mouseleave', function () { hideTooltip(); });
          nodeGroup.appendChild(circle);

          var label = document.createElementNS(svgNS, 'text');
          label.setAttribute('class', 'label');
          label.setAttribute('x', node.x);
          label.setAttribute('y', node.y - 16);
          label.setAttribute('text-anchor', 'middle');
          label.textContent = '#' + valueOr(node.sequence, '?') + ' · ' + node.cls;
          labelGroup.appendChild(label);
        }

        renderTimeline();
        renderOperationalSummary();

        if (focusNodeId && nodes[focusNodeId] && isNodeVisible(nodes[focusNodeId])) {
          updateDetailsPanel(nodes[focusNodeId], 'focus');
        } else {
          resetDetailsPanel();
        }
      }

      var tooltip = document.createElement('div');
      tooltip.style.position = 'fixed';
      tooltip.style.padding = '0.6rem 0.8rem';
      tooltip.style.background = 'rgba(20, 28, 44, 0.94)';
      tooltip.style.color = '#f1f6ff';
      tooltip.style.border = '1px solid rgba(160, 190, 255, 0.4)';
      tooltip.style.borderRadius = '8px';
      tooltip.style.fontSize = '0.75rem';
      tooltip.style.pointerEvents = 'none';
      tooltip.style.opacity = '0';
      tooltip.style.transition = 'opacity 0.15s ease-in-out';
      document.body.appendChild(tooltip);

      function showTooltip(node) {
        var parts = [];
        parts.push('id: ' + node.id);
        parts.push('class: ' + node.cls);
        parts.push('sequence: #' + valueOr(node.sequence, '-'));
        parts.push('source: ' + node.source);
        parts.push('consensus_ts: ' + valueOr(node.consensus_ts, '-'));
        parts.push('parents: ' + (node.parents ? node.parents.length : 0));
        tooltip.textContent = parts.join('\\n');
        tooltip.style.whiteSpace = 'pre';
        tooltip.style.opacity = '1';
        document.addEventListener('mousemove', positionTooltip);
        hoveredNodeId = node.id;
      }

      function hideTooltip() {
        tooltip.style.opacity = '0';
        document.removeEventListener('mousemove', positionTooltip);
        hoveredNodeId = null;
      }

      function positionTooltip(event) {
        tooltip.style.left = (event.clientX + 12) + 'px';
        tooltip.style.top = (event.clientY + 12) + 'px';
      }

      function formatValue(value, digits) {
        if (value === undefined || value === null || isNaN(Number(value))) {
          return '-';
        }
        return Number(value).toFixed(digits);
      }

      function updateMetrics(metrics) {
        if (!metrics) {
          return;
        }
        var info = [];
        info.push('Готовность кворума: ' + describeQuorumHealth(metrics.A_est) + ' (' + formatValue(Number(metrics.A_est) * 100, 1) + ' %)');
        info.push('Задержка обмена: ' + formatValue(metrics.T_gossip, 3) + ' с');
        info.push('Целостность графа: ' + describeGraphIntegrity(metrics.K_r) + ' (' + formatValue(Number(metrics.K_r) * 100, 1) + ' %)');
        info.push('Память журнала: ' + formatValue(Number(metrics.C_mem) * 100, 1) + ' %');
        info.push('Сетевой бюджет: ' + formatValue(Number(metrics.C_net) * 100, 1) + ' %');
        info.push('Известных событий: ' + valueOr(metrics.event_count, '-'));
        metricsEl.textContent = info.join('\\n');
        setText(metricAEstEl, describeQuorumHealth(metrics.A_est));
        setText(metricTGossipEl, formatValue(metrics.T_gossip, 3) + ' с');
        setText(metricKREl, describeGraphIntegrity(metrics.K_r));
        setText(metricEventCountEl, String(valueOr(metrics.event_count, '-')));
        updateMetricHistory(metrics);
        if (Number(metrics.C_mem) >= 0.85) {
          pushAlert('high', 'Память журнала близка к пределу', 'Распределённый реестр занял ' + formatValue(Number(metrics.C_mem) * 100, 1) + '% доступного лимита памяти на узле.', 'mem-high');
        } else if (Number(metrics.C_mem) >= 0.65) {
          pushAlert('medium', 'Растёт использование памяти', 'Текущее заполнение памяти под журнал составляет ' + formatValue(Number(metrics.C_mem) * 100, 1) + '%.', 'mem-medium');
        }
        if (Number(metrics.C_net) >= 0.8) {
          pushAlert('medium', 'Высокая сетевая нагрузка gossip', 'Текущее использование сетевого бюджета достигло ' + formatValue(Number(metrics.C_net) * 100, 1) + '%.', 'net-high');
        }
        markSyncPending('Обновление метрик...');
      }

      function loadGraph(callback) {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '/viz/graph', true);
        xhr.onreadystatechange = function () {
          if (xhr.readyState === 4) {
            if (xhr.status >= 200 && xhr.status < 300) {
              try {
                var graph = JSON.parse(xhr.responseText);
                var graphNodes = graph.nodes || [];
                var graphEdges = graph.edges || [];
                for (var i = 0; i < graphNodes.length; i += 1) {
                  addEvent(graphNodes[i]);
                }
                for (var j = 0; j < graphEdges.length; j += 1) {
                  var edge = graphEdges[j];
                  var key = edge.source + '->' + edge.target;
                  if (!links[key]) {
                    links[key] = { source: edge.source, target: edge.target };
                    linkOrder.push(key);
                  }
                }
                updateMetrics(graph.metrics);
                callback(null);
              } catch (err) {
                callback(err);
              }
            } else {
              callback(new Error('status ' + xhr.status));
            }
          }
        };
        xhr.onerror = function () {
          callback(new Error('network error'));
        };
        xhr.send();
      }

      function connectStream() {
        try {
          var source = new EventSource('/viz/stream');
          source.onopen = function () {
            setText(navStreamStateEl, 'Онлайн');
          };
          source.onmessage = function (event) {
            try {
              var data = JSON.parse(event.data);
              if (data && data.type === 'reset') {
                resetGraphState();
                incidents = [];
                incidentsLoaded = false;
                if (data.metrics) {
                  updateMetrics(data.metrics);
                }
                setControlsStatus('Граф на узле был очищен.', false);
                markSyncPending('Ожидаем якорные события...');
                if (incidentEnabled) {
                  loadIncidents();
                }
                return;
              }
              if (data && data.type === 'consensus_status') {
                recordConsensusStatus(data);
                if (data && (!data.match || data.error) && !data.pending) {
                  var peerLabel = data.peer_node || data.peer || 'пир';
                  setControlsStatus('Внимание: рассогласование с ' + peerLabel, true);
                  pushAlert('high', 'Рассогласование между узлами', 'Узел обнаружил проблему согласованности с ' + peerLabel + '.', 'consensus:' + peerLabel);
                }
                return;
              }
              if (data && data.event) {
                addEvent(data.event);
                ensureIncidentFromEvent(data.event);
                renderGraph();
                if (data.event.cls === 'A') {
                  pushAlert('high', 'Зафиксировано критичное событие класса A', 'Источник: ' + valueOr(data.event.source, 'неизвестно') + '. Событие добавлено в распределённый журнал.', 'event:' + data.event.id);
                  // Пульс на карте сети у узла-жертвы + при наличии source_ip
                  // обновить карту (могла появиться новая точка входа).
                  try {
                    var victim = data.event.creator || data.event.source;
                    if (victim) { pulseClusterNode(victim); }
                    if (data.event.payload && data.event.payload.source_ip) {
                      loadClusterMap();
                    }
                  } catch (e) {}
                } else if (data.event.cls === 'B') {
                  pushAlert('medium', 'Поступило важное событие класса B', 'Источник: ' + valueOr(data.event.source, 'неизвестно') + '. Проверьте контекст и соседние записи.', 'event:' + data.event.id);
                }
                markSyncPending('Получено новое событие...');
              }
              if (data && data.metrics) {
                updateMetrics(data.metrics);
                markSyncPending('Идёт синхронизация...');
              }
            } catch (err) {
              console.log('SSE parse error', err);
            }
          };
          source.onerror = function () {
            console.log('SSE disconnected, retry in 3s');
            setText(navStreamStateEl, 'Повтор');
            source.close();
            markError('Поток событий временно прерван, перезапуск...');
            setTimeout(connectStream, 3000);
          };
        } catch (err) {
          console.log('EventSource unsupported', err);
          setText(navStreamStateEl, 'Недоступно');
        }
      }

      setupControls();
      renderAlertWindow();
      fetchNodeStatus();
      setInterval(fetchNodeStatus, 5000);
      fetchSimulationStatus();

      loadGraph(function (err) {
        if (err) {
          metricsEl.textContent = 'Ошибка загрузки графа: ' + err.message;
          markError('Не удалось загрузить DAG.');
          return;
        }
        renderGraph();
        connectStream();
        setControlsStatus('Готово к имитации.', false);
        markStable();
      });

      // Политика сбора СИБ: первичная загрузка + периодическое обновление
      // (политика может меняться на других узлах и доходить через gossip,
      // но registry_enabled — локальное runtime-состояние, обновляем по /catalog).
      loadSibPolicy();
      setInterval(loadSibPolicy, 30000);

      // Карта сети: первичная загрузка + периодическое обновление.
      loadClusterMap();
      setInterval(loadClusterMap, 30000);

      // Маршрутизация «отдельных страниц». Тяжёлые разделы (Участники сети,
      // Инциденты, Настройка множества СИБ) показываются как отдельные
      // страницы поверх дашборда, а не скроллом по одной длинной странице.
      // Работаем через getElementById — секции созданы в другом скоупе.
      var PAGE_IDS = ['network-workbench', 'incident-workbench', 'sib-policy', 'cluster-map'];
      var DASHBOARD_IDS = ['hero-analytics-grid', 'overview-grid', 'workspace'];
      function routeToPage() {
        var hash = (window.location.hash || '').replace('#', '');
        var isPage = PAGE_IDS.indexOf(hash) !== -1;
        // incident-workbench доступен только при роли responder.
        if (hash === 'incident-workbench' && typeof incidentEnabled !== 'undefined' && !incidentEnabled) {
          isPage = false;
          if (window.location.hash === '#incident-workbench') { window.location.hash = ''; }
          hash = '';
        }
        if (isPage) {
          DASHBOARD_IDS.forEach(function (id) {
            var el = document.getElementById(id);
            if (el) { el.style.display = 'none'; }
          });
          PAGE_IDS.forEach(function (id) {
            var el = document.getElementById(id);
            if (el) { el.style.display = (id === hash ? 'block' : 'none'); }
          });
          window.scrollTo(0, 0);
        } else {
          DASHBOARD_IDS.forEach(function (id) {
            var el = document.getElementById(id);
            if (el) { el.style.display = ''; }
          });
          PAGE_IDS.forEach(function (id) {
            var el = document.getElementById(id);
            if (el) { el.style.display = 'none'; }
          });
        }
        // Подсветка активного пункта навигации.
        var navItems = document.querySelectorAll('.nav-item');
        for (var i = 0; i < navItems.length; i += 1) {
          var href = navItems[i].getAttribute('href') || '';
          navItems[i].classList.toggle('active', href === '#' + hash && hash !== '');
        }
      }
      window.addEventListener('hashchange', routeToPage);
      window.__mdrjRoute = routeToPage;
      routeToPage();

      window.addEventListener('resize', function () {
        renderGraph();
      });
    })();
  </script>
</body>
</html>
"""

async def handle_event_batch(request: web.Request) -> web.Response:
    node = request.app["node"]
    body = await request.read()
    node.metrics.record_gossip_in_bytes(len(body))
    payload = json.loads(body) if body else None
    if not isinstance(payload, list):
        raise web.HTTPBadRequest(text="payload must be list of envelopes")
    envelopes = [Envelope.from_dict(item) for item in payload]
    new_ids: List[str] = await asyncio.to_thread(node.ingest_envelopes, envelopes)
    return web.json_response({"new": new_ids})


async def handle_emit_local(request: web.Request) -> web.Response:
    node = request.app["node"]
    payload = await request.json()
    body = dict(payload.get("payload") or {})
    event_kind = payload.get("event_kind") or body.get("event_kind")
    cls_raw = payload.get("cls")

    if event_kind:
        if not is_known_event_kind(event_kind):
            raise web.HTTPBadRequest(text=f"unknown event_kind: {event_kind}")
        event_cls = event_class_for(event_kind)
        body["event_kind"] = event_kind
    elif cls_raw:
        event_cls = EventClass.from_str(cls_raw)
    else:
        raise web.HTTPBadRequest(text="missing event_kind or cls")

    emission = await node.emit_event(event_cls, body)
    return web.json_response({"event": emission.event.to_dict(), "stored": emission.stored})


async def handle_viz_simulate(request: web.Request) -> web.Response:
    node = request.app["node"]
    if not node.demo_controls_enabled():
        raise web.HTTPForbidden(text="simulation disabled for linux ingest mode")
    try:
        data = await request.json()
    except json.JSONDecodeError as exc:
        raise web.HTTPBadRequest(text="invalid json") from exc
    scenario = data.get("scenario")
    if scenario not in SCENARIOS:
        raise web.HTTPBadRequest(text="unknown scenario")
    bundle = scenario_payload(scenario)
    emission = await node.emit_event(bundle["class"], bundle["payload"])
    return web.json_response({"event": emission.event.to_dict()})


async def handle_viz_simulation_control(request: web.Request) -> web.Response:
    node = request.app["node"]
    if not node.demo_controls_enabled():
        raise web.HTTPForbidden(text="simulation disabled for linux ingest mode")
    try:
        data = await request.json()
    except json.JSONDecodeError:
        data = {}
    action = data.get("action", "toggle")
    token = data.get("token")
    propagate = bool(data.get("propagate", True))
    interval = float(data.get("interval", 1.8))
    jitter = float(data.get("jitter", 0.6))

    if action == "start":
        started = await node.start_simulation(interval=interval, jitter=jitter, token=token, propagate=propagate)
        return web.json_response({"running": node.simulation_running(), "started": started, "token": node._simulation_token})
    if action == "stop":
        stopped = await node.stop_simulation(token=token, propagate=propagate)
        return web.json_response({"running": node.simulation_running(), "stopped": stopped, "token": node._simulation_token})
    if action == "status":
        return web.json_response({"running": node.simulation_running(), "token": node._simulation_token})

    if node.simulation_running():
        stopped = await node.stop_simulation(token=token, propagate=propagate)
        return web.json_response({"running": node.simulation_running(), "stopped": stopped, "token": node._simulation_token})
    started = await node.start_simulation(interval=interval, jitter=jitter, token=token, propagate=propagate)
    return web.json_response({"running": node.simulation_running(), "started": started, "token": node._simulation_token})


async def handle_viz_clear(request: web.Request) -> web.Response:
    node = request.app["node"]
    try:
        data = await request.json()
    except json.JSONDecodeError:
        data = {}
    token = data.get("token")
    propagate = bool(data.get("propagate", True))
    if not token:
        token = secrets.token_hex(12)
        propagate = True
    metrics = await node.clear_events(token=token, propagate=propagate)
    return web.json_response({"status": "cleared", "metrics": metrics, "token": token})


async def handle_incidents(request: web.Request) -> web.Response:
    node = request.app["node"]
    if request.method == "GET":
        items = await asyncio.to_thread(node.list_incidents)
        return web.json_response({"items": items})
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        payload = {}
    items = payload.get("items")
    if not isinstance(items, list):
        raise web.HTTPBadRequest(text="missing items")
    saved = await asyncio.to_thread(node.replace_incidents, items)
    return web.json_response({"status": "ok", "items": saved})


async def handle_frontier(request: web.Request) -> web.Response:
    node = request.app["node"]
    frontier = await asyncio.to_thread(node.storage.get_frontier)
    return web.json_response({"frontier": frontier})


async def handle_status(request: web.Request) -> web.Response:
    node = request.app["node"]
    return web.json_response(node.status())


async def handle_metrics(request: web.Request) -> web.Response:
    node = request.app["node"]
    return web.json_response(node.metrics_snapshot())


PROMETHEUS_METRIC_TYPES = {
    "A_est": "gauge",
    "T_gossip": "gauge",
    "K_r": "gauge",
    "C_mem": "gauge",
    "C_net": "gauge",
    "event_count": "gauge",
    "rss_bytes": "gauge",
    "cpu_percent": "gauge",
    "db_size_bytes": "gauge",
    "gossip_bytes_in_total": "counter",
    "gossip_bytes_out_total": "counter",
    "bytes_per_event": "gauge",
    "emit_to_consensus_latency_p50_ms": "gauge",
    "emit_to_consensus_latency_p95_ms": "gauge",
}


async def handle_metrics_prometheus(request: web.Request) -> web.Response:
    from .prometheus_extras import build_extras, render_series

    node = request.app["node"]
    snap = node.metrics_snapshot()
    node_id = getattr(getattr(node, "config", None), "node_id", "unknown")
    lines: List[str] = []
    for key, value in snap.items():
        metric_name = f"mdrj_{key.lower()}"
        metric_type = PROMETHEUS_METRIC_TYPES.get(key, "gauge")
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            continue
        lines.append(f"# TYPE {metric_name} {metric_type}")
        lines.append(f'{metric_name}{{node_id="{node_id}"}} {numeric}')
    base = "\n".join(lines) + ("\n" if lines else "")
    extras = render_series(build_extras(node), common_labels={"node_id": node_id})
    return web.Response(text=base + extras, content_type="text/plain")


async def handle_metrics_history(request: web.Request) -> web.Response:
    node = request.app["node"]
    try:
        limit = int(request.query.get("limit", "1000"))
    except ValueError:
        limit = 1000
    try:
        since_ts = float(request.query.get("since", "0"))
    except ValueError:
        since_ts = 0.0
    rows = await asyncio.to_thread(node.list_metrics_history, limit=limit, since_ts=since_ts)
    return web.json_response({"items": rows})


async def handle_checkpoint_propose(request: web.Request) -> web.Response:
    """Either propose a local checkpoint (no body) or accept a peer proposal."""
    node = request.app["node"]
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        payload = {}
    if payload and "merkle_root" in payload:
        try:
            record = await asyncio.to_thread(node.ingest_checkpoint_proposal, payload)
        except ValueError as exc:
            raise web.HTTPBadRequest(text=str(exc)) from exc
        return web.json_response({"status": "ok", "checkpoint": record})
    target_round = payload.get("round_received") if isinstance(payload, dict) else None
    if target_round is None:
        confirmed = await asyncio.to_thread(lambda: node.storage.latest_confirmed_checkpoint())
        next_round_start = (confirmed["round_received"] + 1) if confirmed else 0
        events = await asyncio.to_thread(node.storage.all_events)
        max_round = max(
            (e.round_received for e in events if e.round_received is not None),
            default=-1,
        )
        if max_round < next_round_start:
            raise web.HTTPBadRequest(text="no new events with round_received available for checkpoint")
        target_round = max_round
    try:
        proposal = await asyncio.to_thread(node.propose_local_checkpoint, int(target_round))
    except ValueError as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc
    return web.json_response({"status": "ok", "proposal": proposal})


async def handle_checkpoint_list(request: web.Request) -> web.Response:
    node = request.app["node"]
    status = request.query.get("status")
    try:
        limit = int(request.query.get("limit", "100"))
    except ValueError:
        limit = 100
    items = await asyncio.to_thread(node.list_checkpoints, status=status, limit=limit)
    return web.json_response({"items": items})


LOGIN_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <title>MDRJ-DAG — Вход</title>
  <style>
    body { display:flex; align-items:center; justify-content:center; min-height:100vh;
           font-family:system-ui, sans-serif; background:#0e1320; color:#e6e9ef; margin:0; }
    form { background:#161c2c; padding:32px 36px; border-radius:8px; min-width:320px;
           border:1px solid #243049; }
    h1 { margin:0 0 18px 0; font-size:18px; color:#4fc3f7; }
    label { display:block; font-size:12px; color:#8892a6; margin:14px 0 4px 0; }
    input[type=text], input[type=password] { width:100%; padding:8px 10px; background:#0c1322;
           color:#e6e9ef; border:1px solid #2c3650; border-radius:4px; font-size:14px; }
    button { width:100%; margin-top:20px; padding:9px; background:#4fc3f7; color:#06121f;
           border:none; border-radius:4px; font-weight:600; cursor:pointer; }
    button:hover { background:#7cd3fa; }
    .err { color:#ef5350; font-size:13px; margin-top:14px; min-height:18px; }
  </style>
</head>
<body>
  <form id="login" action="/auth/login" method="post">
    <h1>MDRJ-DAG · Вход</h1>
    <label for="u">Пользователь</label>
    <input id="u" name="username" type="text" autocomplete="username" required />
    <label for="p">Пароль</label>
    <input id="p" name="password" type="password" autocomplete="current-password" required />
    <button type="submit">Войти</button>
    <div class="err" id="err"></div>
  </form>
  <script>
    document.getElementById("login").addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const body = JSON.stringify({username: fd.get("username"), password: fd.get("password")});
      const r = await fetch("/auth/login", {method:"POST", headers:{"Content-Type":"application/json"}, body});
      if (r.ok) { window.location.href = "/viz"; }
      else { document.getElementById("err").textContent = "Неверные логин или пароль"; }
    });
  </script>
</body></html>"""


async def handle_login_page(request: web.Request) -> web.Response:
    return web.Response(text=LOGIN_HTML, content_type="text/html")


async def handle_login(request: web.Request) -> web.Response:
    node = request.app["node"]
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(text="invalid json")
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    if not username or not password:
        raise web.HTTPBadRequest(text="username and password required")
    user = await asyncio.to_thread(node.authenticate, username, password)
    if user is None:
        raise web.HTTPUnauthorized(text="invalid credentials")
    record = node.session_store.create(username=username, role=str(user["role"]))
    response = web.json_response({"status": "ok", "username": username, "role": str(user["role"])})
    response.set_cookie(
        SESSION_COOKIE_NAME,
        record.token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="Lax",
    )
    return response


async def handle_logout(request: web.Request) -> web.Response:
    node = request.app["node"]
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        node.session_store.revoke(token)
    response = web.json_response({"status": "ok"})
    response.del_cookie(SESSION_COOKIE_NAME)
    return response


async def handle_me(request: web.Request) -> web.Response:
    session = _resolve_session(request)
    if session is None:
        raise web.HTTPUnauthorized(text="no session")
    return web.json_response({
        "username": session.username,
        "role": session.role,
        "expires_at": session.expires_at,
    })


async def handle_notifier_status(request: web.Request) -> web.Response:
    node = request.app["node"]
    return web.json_response(node.notifier.status())


async def handle_gossip_frontier(request: web.Request) -> web.Response:
    """Слой 3. Возвращает {creator_node_id: last_event_id} по всем
    известным авторам. Используется для frontier-handshake между узлами:
    receiver сравнивает с локальным и тянет недостающее через
    /events/{id}/ancestry.
    """
    node = request.app["node"]
    return web.json_response({"frontier": node.local_frontier()})


async def handle_event_ancestry(request: web.Request) -> web.Response:
    """Слой 3. Отдаёт предков события (BFS по self_parent / other_parent)
    до глубины ?depth=N (по умолчанию 64). Включая сам event_id если он
    есть локально. Запрашивается /gossip/frontier-получателем для догонки.
    """
    node = request.app["node"]
    event_id = request.match_info["event_id"]
    try:
        depth = max(1, min(int(request.query.get("depth", "64")), 1024))
    except ValueError:
        depth = 64
    visited = set()
    queue = [event_id]
    out: List[Dict[str, object]] = []
    while queue and len(out) < depth:
        eid = queue.pop(0)
        if eid in visited:
            continue
        visited.add(eid)
        envelope = node.storage.get_envelope(eid)
        if envelope is None:
            continue
        ev = envelope.event
        event_dict = ev.to_dict()
        event_dict["consensus_ts"] = ev.consensus_ts
        out.append({"event": event_dict, "path_meta": envelope.path_meta})
        # Parents в очередь
        for parent_id in ev.parents:
            if parent_id and parent_id not in visited:
                queue.append(parent_id)
    return web.json_response({"events": out})


async def handle_catalog(request: web.Request) -> web.Response:
    """Return the full event catalog: классификация + обоснования.

    Безопасно для viewer-роли (read-only справочник). Может фильтроваться
    по классу через ?class=A и по угрозе через ?threat=UBI.124.
    """
    from .event_catalog import all_event_metadata, EVENT_CATALOG

    metadata = all_event_metadata()
    cls_filter = (request.query.get("class") or "").upper().strip() or None
    threat_filter = (request.query.get("threat") or "").strip() or None
    items: List[Dict[str, object]] = []
    # Если расширенных метаданных нет (fallback встроенный каталог) —
    # отдаём то что есть.
    for kind, descriptor in EVENT_CATALOG.items():
        cls_val = descriptor["class"].value if hasattr(descriptor["class"], "value") else str(descriptor["class"])
        meta = metadata.get(kind, {})
        if cls_filter and cls_val != cls_filter:
            continue
        if threat_filter:
            linked = meta.get("linked_threats") or []
            if not any(threat_filter in str(t) for t in linked):
                continue
        node = request.app.get("node")
        protected = kind in getattr(node, "POLICY_PROTECTED_KINDS", frozenset()) if node else False
        item: Dict[str, object] = {
            "event_kind": kind,
            "class": cls_val,
            "title": str(descriptor.get("title", kind)),
            "category": meta.get("category") or descriptor.get("payload", {}).get("category", "other"),
            "rationale": meta.get("rationale", ""),
            "linked_threats": meta.get("linked_threats", []),
            "added_by": meta.get("added_by", ""),
            "npa": meta.get("npa", []),
            "source": meta.get("source", ""),
            "registry_enabled": meta.get("registry_enabled", True),
            "protected": protected,
        }
        items.append(item)
    items.sort(key=lambda i: (str(i["class"]), str(i["event_kind"])))
    return web.json_response({"version": 1, "count": len(items), "events": items})


async def handle_catalog_policy(request: web.Request) -> web.Response:
    """POST /catalog/policy — изменить тугл registry_enabled для event_kind.

    Тело: {"event_kind": "log_cleared", "enabled": false}. Эмитирует
    улику mdrj_collection_policy_changed класса A. Только для admin.
    """
    node = request.app["node"]
    try:
        body = await request.json()
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(text="invalid JSON")
    kind = str(body.get("event_kind", "")).strip()
    if not kind:
        raise web.HTTPBadRequest(text="missing event_kind")
    if "enabled" not in body:
        raise web.HTTPBadRequest(text="missing enabled")
    enabled = bool(body.get("enabled"))
    try:
        result = await node.set_collection_policy(kind, enabled)
    except KeyError as exc:
        raise web.HTTPNotFound(text=str(exc))
    except ValueError as exc:
        raise web.HTTPForbidden(text=str(exc))
    return web.json_response({"status": "ok", **result})


async def handle_users_list(request: web.Request) -> web.Response:
    node = request.app["node"]
    items = await asyncio.to_thread(node.list_users)
    return web.json_response({"items": items})


async def handle_users_add(request: web.Request) -> web.Response:
    node = request.app["node"]
    payload = await request.json()
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    role = str(payload.get("role") or "viewer")
    if not username or not password:
        raise web.HTTPBadRequest(text="username and password required")
    result = await asyncio.to_thread(node.add_user, username=username, password=password, role=role)
    return web.json_response({"status": "ok", "user": result})


async def handle_users_remove(request: web.Request) -> web.Response:
    node = request.app["node"]
    payload = await request.json()
    username = str(payload.get("username") or "").strip()
    if not username:
        raise web.HTTPBadRequest(text="username required")
    removed = await asyncio.to_thread(node.remove_user, username)
    return web.json_response({"status": "ok" if removed else "not_found"})


async def handle_peer_approve(request: web.Request) -> web.Response:
    node = request.app["node"]
    payload = await request.json()
    address = payload.get("address")
    if not address:
        raise web.HTTPBadRequest(text="missing address")
    peer = await asyncio.to_thread(node.approve_peer, str(address))
    if peer is None:
        raise web.HTTPNotFound(text="unknown peer")
    return web.json_response({"status": "ok", "peer": peer.to_dict()})


async def handle_peer_reject(request: web.Request) -> web.Response:
    node = request.app["node"]
    payload = await request.json()
    address = payload.get("address")
    if not address:
        raise web.HTTPBadRequest(text="missing address")
    peer = await asyncio.to_thread(node.reject_peer, str(address))
    if peer is None:
        raise web.HTTPNotFound(text="unknown peer")
    return web.json_response({"status": "ok", "peer": peer.to_dict()})


async def handle_checkpoint_verify(request: web.Request) -> web.Response:
    node = request.app["node"]
    try:
        round_received = int(request.query.get("round_received") or request.match_info.get("round_received", ""))
    except ValueError:
        raise web.HTTPBadRequest(text="round_received must be integer")
    try:
        report = await asyncio.to_thread(node.verify_checkpoint, round_received)
    except KeyError as exc:
        raise web.HTTPNotFound(text=str(exc)) from exc
    return web.json_response(report)


async def handle_consensus_digest(request: web.Request) -> web.Response:
    node = request.app["node"]
    snapshot = await node.get_consensus_snapshot()
    return web.json_response(snapshot)


async def handle_register_peer(request: web.Request) -> web.Response:
    node = request.app["node"]
    payload = await request.json()
    address = payload.get("address")
    note = str(payload.get("note", "") or "")
    role = payload.get("role", "node")
    node_id = str(payload.get("node_id", "") or "")
    if not address:
        raise web.HTTPBadRequest(text="missing address")
    node.register_peer(address, note=note, source="ui", role=str(role), node_id=node_id)
    return web.json_response({"status": "ok", "peers": [peer.to_dict() for peer in node.list_peer_registry()]})


async def handle_update_peer(request: web.Request) -> web.Response:
    node = request.app["node"]
    payload = await request.json()
    address = payload.get("address")
    if not address:
        raise web.HTTPBadRequest(text="missing address")
    enabled_raw = payload.get("enabled")
    enabled = None if enabled_raw is None else bool(enabled_raw)
    note = payload.get("note")
    note_value = None if note is None else str(note)
    role = payload.get("role")
    role_value = None if role is None else str(role)
    node_id = payload.get("node_id")
    node_id_value = None if node_id is None else str(node_id)
    peer = node.update_peer(address, enabled=enabled, note=note_value, role=role_value, node_id=node_id_value)
    if peer is None:
        raise web.HTTPNotFound(text="unknown peer")
    return web.json_response({"status": "ok", "peer": peer.to_dict()})


async def handle_remove_peer(request: web.Request) -> web.Response:
    node = request.app["node"]
    payload = await request.json()
    address = payload.get("address")
    if not address:
        raise web.HTTPBadRequest(text="missing address")
    if str(address).startswith("self:"):
        raise web.HTTPBadRequest(text="cannot remove self peer")
    node.remove_peer(address)
    return web.json_response({"status": "ok"})


async def handle_peers(request: web.Request) -> web.Response:
    node = request.app["node"]
    return web.json_response({"peers": [peer.to_dict() for peer in node.list_peer_registry()]})


async def handle_reconfigure_consensus_membership(request: web.Request) -> web.Response:
    node = request.app["node"]
    snapshot = await node.reconfigure_consensus_membership()
    return web.json_response({"status": "ok", "snapshot": snapshot})


async def handle_dag(request: web.Request) -> web.Response:
    node = request.app["node"]
    order = await asyncio.to_thread(node.storage.toposort)
    return web.json_response({"toposort": order})


async def handle_viz_page(request: web.Request) -> web.Response:
    return web.Response(text=VIZ_HTML, content_type="text/html")


async def handle_viz_graph(request: web.Request) -> web.Response:
    node = request.app["node"]
    events = await asyncio.to_thread(node.storage.all_events)
    edges = await asyncio.to_thread(node.storage.all_edges)
    nodes = [event.to_dict() for event in events]
    links = [
        {"source": source, "target": target, "key": f"{source}->{target}"}
        for source, target in edges
    ]
    return web.json_response({"nodes": nodes, "edges": links, "metrics": node.metrics_snapshot()})


async def handle_viz_stream(request: web.Request) -> web.StreamResponse:
    node = request.app["node"]
    queue = node.subscribe_visualizer()
    response = web.StreamResponse(
        status=200,
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )
    await response.prepare(request)
    try:
        await response.write(b": connected\n\n")
        while True:
            payload = await queue.get()
            data = json.dumps(payload, ensure_ascii=False)
            message = f"data: {data}\n\n".encode()
            await response.write(message)
            await response.drain()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass
    finally:
        node.unsubscribe_visualizer(queue)
        with contextlib.suppress(Exception):
            await response.write_eof()
    return response

def build_app(node) -> web.Application:
    # Order matters: session middleware runs FIRST (outermost). If a valid
    # session is present, hmac middleware skips the HMAC check.
    app = web.Application(middlewares=[session_auth_middleware, hmac_auth_middleware])
    app["node"] = node
    app["hmac_key"] = getattr(getattr(node.config, "security", None), "hmac_key", None) if hasattr(node, "config") else None
    if not app["hmac_key"]:
        _auth_logger.warning(
            "security.hmac_key is not set — HTTP API accepts unauthenticated state changes. "
            "Set security.hmac_key in node config before exposing the API to untrusted networks."
        )
    app.add_routes(
        [
            web.post("/event/batch", handle_event_batch),
            web.post("/event/emit", handle_emit_local),
            web.get("/dag/frontier", handle_frontier),
            web.get("/dag", handle_dag),
            web.get("/status", handle_status),
            web.get("/metrics", handle_metrics),
            web.get("/metrics/prometheus", handle_metrics_prometheus),
            web.get("/metrics/history", handle_metrics_history),
            web.post("/checkpoint/propose", handle_checkpoint_propose),
            web.get("/checkpoint/list", handle_checkpoint_list),
            web.get("/checkpoint/verify", handle_checkpoint_verify),
            web.post("/peers/approve", handle_peer_approve),
            web.post("/peers/reject", handle_peer_reject),
            web.get("/auth/login", handle_login_page),
            web.post("/auth/login", handle_login),
            web.post("/auth/logout", handle_logout),
            web.get("/auth/me", handle_me),
            web.get("/users", handle_users_list),
            web.post("/users/add", handle_users_add),
            web.post("/users/remove", handle_users_remove),
            web.get("/notifier/status", handle_notifier_status),
            web.get("/catalog", handle_catalog),
            web.post("/catalog/policy", handle_catalog_policy),
            web.get("/gossip/frontier", handle_gossip_frontier),
            web.get("/events/{event_id}/ancestry", handle_event_ancestry),
            web.post("/peers/register", handle_register_peer),
            web.post("/peers/update", handle_update_peer),
            web.post("/peers/remove", handle_remove_peer),
            web.get("/peers", handle_peers),
            web.post("/consensus/reconfigure", handle_reconfigure_consensus_membership),
            web.get("/viz", handle_viz_page),
            web.get("/viz/graph", handle_viz_graph),
            web.get("/viz/stream", handle_viz_stream),
            web.post("/viz/simulate", handle_viz_simulate),
            web.post("/viz/simulation/control", handle_viz_simulation_control),
            web.post("/viz/clear", handle_viz_clear),
            web.get("/incidents", handle_incidents),
            web.put("/incidents", handle_incidents),
            web.get("/consensus/digest", handle_consensus_digest),
        ]
    )
    return app
