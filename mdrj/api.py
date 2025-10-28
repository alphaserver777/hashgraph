"""HTTP API for MDRJ-DAG nodes."""
from __future__ import annotations

import asyncio
import contextlib
import json
import secrets
from datetime import datetime
from typing import Any, Dict, List

from aiohttp import web

from .models import Envelope, EventClass
from .simulation import SCENARIOS, scenario_payload

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
    #controls { display: flex; flex-direction: column; gap: 0.6rem; padding: 0.75rem 1.5rem; background: rgba(10, 16, 28, 0.92); border-top: 1px solid rgba(255,255,255,0.08); border-bottom: 1px solid rgba(255,255,255,0.08); }
    #controls .controls-title { font-size: 0.9rem; color: rgba(233, 238, 255, 0.9); }
    #controls .controls-buttons { display: flex; flex-wrap: wrap; gap: 0.6rem; }
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
    #controls-status { font-size: 0.8rem; color: rgba(198, 210, 255, 0.85); min-height: 1.1rem; }
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
      var graphEl = document.getElementById('graph');
      var metricsEl = document.getElementById('metrics');
      var consensusStatusEl = document.getElementById('consensus-status');
      var statusEl = document.getElementById('graph-status');
      var controlsRoot = document.getElementById('controls');
      var controlsStatus = document.getElementById('controls-status');
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
      var consensusState = {};
      var lastActiveElement = null;

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

      function setControlsDisabled(disabled) {
        if (!controlsRoot) {
          return;
        }
        var buttons = controlsRoot.querySelectorAll('.sim-button');
        buttons.forEach(function (button) {
          button.disabled = disabled;
        });
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
          localCount: payload.local && typeof payload.local.event_count === 'number' ? payload.local.event_count : null,
          peerCount: payload.peer_state && typeof payload.peer_state.event_count === 'number' ? payload.peer_state.event_count : null
        };
        updateConsensusStatusDisplay();
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

      function triggerSimulation(key) {
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
          proceed = window.confirm('Очистить известные события DAG на этом узле?');
        }
        if (!proceed) {
          return;
        }
        setControlsDisabled(true);
        setControlsStatus('Очищаем DAG...', false);
        markSyncPending('Выполняется очистка графа...');
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/viz/clear', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function () {
          if (xhr.readyState === 4) {
            setControlsDisabled(false);
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
              if (payload && payload.metrics) {
                updateMetrics(payload.metrics);
              }
              setControlsStatus('Граф очищен, ждём новые события.', false);
              markSyncPending('Получаем якорные события...');
              loadGraph(function (err) {
                if (err) {
                  setControlsStatus('Ошибка повторной загрузки данных: ' + err.message, true);
                  markError('Ошибка при повторной загрузке графа.');
                } else {
                  renderGraph();
                }
              });
            } else {
              var message = 'Не удалось очистить DAG';
              if (xhr.responseText) {
                message += ': ' + xhr.responseText;
              }
              setControlsStatus(message, true);
              markError('Ошибка при очистке DAG.');
            }
          }
        };
        xhr.onerror = function () {
          setControlsDisabled(false);
          setControlsStatus('Ошибка сети при очистке DAG', true);
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

        var width = Math.max(contentWidth, graphEl.clientWidth || 800);
        var height = Math.max(contentHeight, graphEl.clientHeight || 600);

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
        svg.style.width = '100%';
        svg.style.height = '100%';
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
        info.push('A_est : ' + formatValue(metrics.A_est, 3));
        info.push('T_gossip : ' + formatValue(metrics.T_gossip, 4));
        info.push('K_r : ' + formatValue(metrics.K_r, 3));
        info.push('C_mem : ' + formatValue(Number(metrics.C_mem) * 100, 2) + ' %');
        info.push('C_net : ' + formatValue(Number(metrics.C_net) * 100, 2) + ' %');
        info.push('events : ' + valueOr(metrics.event_count, '-'));
        metricsEl.textContent = info.join('\\n');
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
          source.onmessage = function (event) {
            try {
              var data = JSON.parse(event.data);
              if (data && data.type === 'reset') {
                resetGraphState();
                if (data.metrics) {
                  updateMetrics(data.metrics);
                }
                setControlsStatus('Граф на узле был очищен.', false);
                markSyncPending('Ожидаем якорные события...');
                return;
              }
              if (data && data.type === 'consensus_status') {
                recordConsensusStatus(data);
                if (data && (!data.match || data.error) && !data.pending) {
                  var peerLabel = data.peer_node || data.peer || 'пир';
                  setControlsStatus('Внимание: рассогласование с ' + peerLabel, true);
                }
                return;
              }
              if (data && data.event) {
                addEvent(data.event);
                renderGraph();
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
        source.close();
        markError('Поток событий временно прерван, перезапуск...');
        setTimeout(connectStream, 3000);
      };
        } catch (err) {
          console.log('EventSource unsupported', err);
        }
      }

      setupControls();
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


async def handle_viz_simulate(request: web.Request) -> web.Response:
    node = request.app["node"]
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


async def handle_consensus_digest(request: web.Request) -> web.Response:
    node = request.app["node"]
    snapshot = await node.get_consensus_snapshot()
    return web.json_response(snapshot)


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
            web.post("/viz/simulate", handle_viz_simulate),
            web.post("/viz/simulation/control", handle_viz_simulation_control),
            web.post("/viz/clear", handle_viz_clear),
            web.get("/consensus/digest", handle_consensus_digest),
        ]
    )
    return app
