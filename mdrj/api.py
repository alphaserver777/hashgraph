"""HTTP API for MDRJ-DAG nodes."""
from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any, Dict, List

from aiohttp import web

from .models import Envelope, EventClass

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
    h1 { font-size: 1.2rem; margin: 0; }
    #metrics { font-family: 'JetBrains Mono', Menlo, monospace; white-space: pre; margin-top: 0.6rem; }
    #graph { width: 100vw; height: calc(100vh - 88px); display: flex; }
    svg { width: 100%; height: 100%; background: radial-gradient(circle at top, rgba(255,255,255,0.06), transparent 60%); }
    .toolbar { font-size: 0.85rem; opacity: 0.75; }
    .link { stroke: rgba(150, 190, 255, 0.25); stroke-width: 1.4px; }
    .node { stroke: #04080f; stroke-width: 2px; }
    .label { fill: rgba(236, 242, 255, 0.9); font-size: 10px; pointer-events: none; }
    #legend { display: flex; gap: 1.2rem; padding: 0.75rem 1.5rem; font-size: 0.85rem; background: rgba(12, 20, 35, 0.95); border-top: 1px solid rgba(255,255,255,0.08); align-items: center; }
    .legend-item { display: flex; align-items: center; gap: 0.5rem; color: rgba(233, 238, 255, 0.8); }
    .legend-item .label { line-height: 1.2; }
    .dot { width: 12px; height: 12px; border-radius: 50%; display: inline-block; }
    .dot-a { background: #ff6d6d; }
    .dot-b { background: #ffc971; }
    .dot-c { background: #5aa5ff; }
    .edge { width: 26px; height: 2px; display: inline-block; background: rgba(150, 190, 255, 0.45); border-radius: 2px; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>MDRJ-DAG / Hashgraph Visualizer</h1>
      <div id="metrics">Загрузка графа...</div>
    </div>
    <div class="toolbar">Поток событий: Server-Sent Events</div>
  </header>
  <div id="graph"></div>
  <div id="legend">
    <div class="legend-item"><span class="dot dot-a"></span><span class="label">Класс A — критические события, транслируются обязательно</span></div>
    <div class="legend-item"><span class="dot dot-b"></span><span class="label">Класс B — важные события, доставляются по порогу угрозы</span></div>
    <div class="legend-item"><span class="dot dot-c"></span><span class="label">Класс C — вспомогательные/якорные события</span></div>
    <div class="legend-item"><span class="edge"></span><span class="label">Рёбра показывают ссылку на родителей (причинную зависимость)</span></div>
    <div class="legend-item"><span class="dot dot-seq"></span><span class="label">Номер (#) отражает итоговый порядок событий</span></div>
  </div>
  <script>
    (function () {
      var colorByClass = { A: '#ff6d6d', B: '#ffc971', C: '#5aa5ff', default: '#99a9ff' };
      var rowByClass = { C: 0, A: 1, B: 2 };
      var nodes = {};
      var nodeOrder = [];
      var links = {};
      var linkOrder = [];
      var graphEl = document.getElementById('graph');
      var metricsEl = document.getElementById('metrics');

      function valueOr(value, fallback) {
        if (value === undefined || value === null) {
          return fallback;
        }
        return value;
      }

      var svgNS = 'http://www.w3.org/2000/svg';
      var svg = document.createElementNS(svgNS, 'svg');
      var linkGroup = document.createElementNS(svgNS, 'g');
      var nodeGroup = document.createElementNS(svgNS, 'g');
      var labelGroup = document.createElementNS(svgNS, 'g');
      svg.appendChild(linkGroup);
      svg.appendChild(nodeGroup);
      svg.appendChild(labelGroup);
      graphEl.appendChild(svg);

      function rememberNode(nodeId) {
        if (nodes.hasOwnProperty(nodeId)) {
          return;
        }
        nodes[nodeId] = null;
        nodeOrder.push(nodeId);
      }

      function ensureNode(event) {
        if (!event || !event.id) {
          return;
        }
        rememberNode(event.id);
        var existing = nodes[event.id];
        if (!existing) {
          existing = {
            id: event.id,
            cls: event.cls || 'C',
            source: event.source || 'unknown',
            consensus_ts: valueOr(event.consensus_ts, null),
            ts_local: valueOr(event.ts_local, null),
            parents: (Array.isArray(event.parents) ? event.parents.slice(0) : [])
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
        }
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

        var colSpacing = 150;
        var rowSpacing = 150;
        for (var i = 0; i < ordered.length; i += 1) {
          var node = nodes[ordered[i]];
          if (!node) { continue; }
          var row = valueOr(rowByClass[node.cls], 3);
          node.x = 120 + i * colSpacing;
          node.y = 120 + row * rowSpacing;
          node.sequence = i + 1;
        }

        var width = Math.max(ordered.length * colSpacing + 240, graphEl.clientWidth || 800);
        var height = Math.max(4 * rowSpacing + 200, graphEl.clientHeight || 600);
        svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
        svg.style.width = '100%';
        svg.style.height = '100%';
      }

      function renderGraph() {
        computeLayout();
        linkGroup.innerHTML = '';
        nodeGroup.innerHTML = '';
        labelGroup.innerHTML = '';

        for (var i = 0; i < linkOrder.length; i += 1) {
          var linkKey = linkOrder[i];
          var link = links[linkKey];
          if (!link) { continue; }
          var source = nodes[link.source];
          var target = nodes[link.target];
          if (!source || !target) { continue; }
          var line = document.createElementNS(svgNS, 'line');
          line.setAttribute('class', 'link');
          line.setAttribute('x1', source.x);
          line.setAttribute('y1', source.y);
          line.setAttribute('x2', target.x);
          line.setAttribute('y2', target.y);
          linkGroup.appendChild(line);
        }

        for (var j = 0; j < nodeOrder.length; j += 1) {
          var nodeId = nodeOrder[j];
          var node = nodes[nodeId];
          if (!node) { continue; }
          var circle = document.createElementNS(svgNS, 'circle');
          circle.setAttribute('class', 'node');
          circle.setAttribute('r', '10');
          circle.setAttribute('cx', node.x);
          circle.setAttribute('cy', node.y);
          circle.setAttribute('fill', colorByClass[node.cls] || colorByClass.default);
          circle.setAttribute('data-id', node.id);
          (function (n) {
            circle.addEventListener('mouseenter', function () { showTooltip(n); });
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
      }

      function hideTooltip() {
        tooltip.style.opacity = '0';
        document.removeEventListener('mousemove', positionTooltip);
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
        info.push('A_est : ' + formatValue(metrics.A_est, 3));
        info.push('T_gossip : ' + formatValue(metrics.T_gossip, 4));
        info.push('K_r : ' + formatValue(metrics.K_r, 3));
        info.push('C_mem : ' + formatValue(Number(metrics.C_mem) * 100, 2) + ' %');
        info.push('C_net : ' + formatValue(Number(metrics.C_net) * 100, 2) + ' %');
        info.push('events : ' + valueOr(metrics.event_count, '-'));
        metricsEl.textContent = info.join('\\n');
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
          source.onmessage = function (event) {
            try {
              var data = JSON.parse(event.data);
              if (data && data.event) {
                addEvent(data.event);
                renderGraph();
              }
              if (data && data.metrics) {
                updateMetrics(data.metrics);
              }
            } catch (err) {
              console.log('SSE parse error', err);
            }
          };
          source.onerror = function () {
            console.log('SSE disconnected, retry in 3s');
            source.close();
            setTimeout(connectStream, 3000);
          };
        } catch (err) {
          console.log('EventSource unsupported', err);
        }
      }

      loadGraph(function (err) {
        if (err) {
          metricsEl.textContent = 'Ошибка загрузки графа: ' + err.message;
          return;
        }
        renderGraph();
        connectStream();
      });

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
    payload = await request.json()
    if not isinstance(payload, list):
        raise web.HTTPBadRequest(text="payload must be list of envelopes")
    envelopes = [Envelope.from_dict(item) for item in payload]
    new_ids: List[str] = await asyncio.to_thread(node.ingest_envelopes, envelopes)
    return web.json_response({"new": new_ids})


async def handle_emit_local(request: web.Request) -> web.Response:
    node = request.app["node"]
    payload = await request.json()
    cls_raw = payload.get("cls")
    if not cls_raw:
        raise web.HTTPBadRequest(text="missing cls")
    event_cls = EventClass.from_str(cls_raw)
    body = payload.get("payload", {})
    emission = await node.emit_event(event_cls, body)
    return web.json_response({"event": emission.event.to_dict(), "stored": emission.stored})


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


async def handle_register_peer(request: web.Request) -> web.Response:
    node = request.app["node"]
    payload = await request.json()
    address = payload.get("address")
    if not address:
        raise web.HTTPBadRequest(text="missing address")
    node.register_peer(address)
    return web.json_response({"status": "ok"})


async def handle_peers(request: web.Request) -> web.Response:
    node = request.app["node"]
    return web.json_response({"peers": [peer.to_dict() for peer in node.list_peers()]})


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
    nodes = [
        {
            "id": event.id,
            "cls": event.cls.value,
            "source": event.source,
            "consensus_ts": event.consensus_ts,
            "ts_local": event.ts_local,
            "parents": list(event.parents),
        }
        for event in events
    ]
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
    app = web.Application()
    app["node"] = node
    app.add_routes(
        [
            web.post("/event/batch", handle_event_batch),
            web.post("/event/emit", handle_emit_local),
            web.get("/dag/frontier", handle_frontier),
            web.get("/dag", handle_dag),
            web.get("/status", handle_status),
            web.get("/metrics", handle_metrics),
            web.post("/peers/register", handle_register_peer),
            web.get("/peers", handle_peers),
            web.get("/viz", handle_viz_page),
            web.get("/viz/graph", handle_viz_graph),
            web.get("/viz/stream", handle_viz_stream),
        ]
    )
    return app
