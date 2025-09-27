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
    #graph-status { font-size: 0.85rem; margin-top: 0.35rem; color: rgba(198, 210, 255, 0.85); }
    #graph-wrapper { display: flex; flex-direction: row; align-items: stretch; width: 100vw; height: calc(100vh - 88px); background: rgba(6, 12, 20, 0.9); }
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
    #controls-status { font-size: 0.8rem; color: rgba(198, 210, 255, 0.85); min-height: 1.1rem; }
    .link { stroke: rgba(150, 190, 255, 0.4); stroke-width: 1.6px; marker-end: url(#arrowhead); }
    .link-parent { stroke: rgba(255, 255, 255, 0.15); stroke-width: 1px; stroke-dasharray: 4 3; }
    .node { stroke: #04080f; stroke-width: 2px; }
    .label { fill: rgba(236, 242, 255, 0.9); font-size: 10px; pointer-events: none; }
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
    #details-panel { width: 320px; max-width: 360px; background: rgba(14, 20, 34, 0.97); border-left: 1px solid rgba(255,255,255,0.06); padding: 1rem 1.1rem; overflow-y: auto; color: rgba(233, 238, 255, 0.92); height: 100%; box-sizing: border-box; }
    #details-panel h2 { margin: 0; font-size: 1rem; color: #f7f9ff; }
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
  </style>
</head>
<body>
  <header>
    <div>
      <h1>MDRJ-DAG / Hashgraph Visualizer</h1>
      <div id="metrics">Загрузка графа...</div>
      <div id="graph-status">Подключение...</div>
    </div>
    <div class="toolbar">Поток событий: Server-Sent Events</div>
  </header>
  <div id="controls">
    <div class="controls-title">Имитация событий (создаёт новые вершины DAG):</div>
    <div class="controls-buttons">
      <button class="sim-button" data-sim="virus">Обнаружен вирус на узле</button>
      <button class="sim-button" data-sim="admin_login">Удалённый вход администратора</button>
      <button class="sim-button" data-sim="mac_spoof">Попытка MAC-spoofing</button>
      <button class="sim-button" data-sim="portscan">Аномальный порт-скан</button>
      <button class="sim-button" data-sim="heartbeat">Тестовый heartbeat</button>
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
    <aside id="details-panel">
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
      var rowByClass = { C: 0, A: 1, B: 2 };
      var nodes = {};
      var nodeOrder = [];
      var links = {};
      var linkOrder = [];
      var childrenMap = {};
      var layoutOrder = [];
      var focusNodeId = null;
      var focusAncestors = {};
      var focusDescendants = {};
      var graphEl = document.getElementById('graph');
      var metricsEl = document.getElementById('metrics');
      var statusEl = document.getElementById('graph-status');
      var controlsRoot = document.getElementById('controls');
      var controlsStatus = document.getElementById('controls-status');
      var filterClassesRoot = document.getElementById('filter-classes');
      var filterSourcesRoot = document.getElementById('filter-sources');
      var detailsPanel = document.getElementById('details-panel');
      var detailsTitle = document.getElementById('details-title');
      var detailsContext = document.getElementById('details-context');
      var detailsMeta = document.getElementById('details-meta');
      var detailsPayload = document.getElementById('details-payload');
      var detailsVclock = document.getElementById('details-vclock');
      var detailsParents = document.getElementById('details-path-parents');
      var detailsChildren = document.getElementById('details-path-children');
      var detailsSig = document.getElementById('details-sig');
      var syncTimer = null;
      var classFilterState = { A: true, B: true, C: true };
      var classFilterButtons = {};
      var ALL_SOURCES_TOKEN = '__all__';
      var sourceFilterState = {};
      sourceFilterState[ALL_SOURCES_TOKEN] = true;
      var sourceFilterButtons = {};
      var hoveredNodeId = null;

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
        detailsPanel.classList.remove('has-node');
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
        detailsPanel.classList.add('has-node');
        if (detailsTitle) {
          detailsTitle.textContent = node.id;
        }
        if (detailsContext) {
          var contextLabel = context === 'focus' ? 'Фокус (выбрано кликом)' : 'Просмотр (наведение)';
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

      function setupControls() {
        if (!controlsRoot) {
          return;
        }
        var buttons = controlsRoot.querySelectorAll('.sim-button');
        buttons.forEach(function (button) {
          button.addEventListener('click', function () {
            var key = button.getAttribute('data-sim');
            triggerSimulation(key);
          });
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
        if (nodeId === focusNodeId) {
          focusNodeId = null;
          focusAncestors = {};
          focusDescendants = {};
        } else {
          focusNodeId = nodeId;
          if (nodeId && nodes[nodeId]) {
            focusAncestors = computeAncestors(nodeId);
            focusDescendants = computeDescendants(nodeId);
          } else {
            focusAncestors = {};
            focusDescendants = {};
          }
        }
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

        var colSpacing = 150;
        var rowSpacing = 150;
        for (var resetIdx = 0; resetIdx < ordered.length; resetIdx += 1) {
          var resetNode = nodes[ordered[resetIdx]];
          if (resetNode) {
            resetNode.sequence = null;
          }
        }

        var visibleOrdered = [];
        for (var i = 0; i < ordered.length; i += 1) {
          var node = nodes[ordered[i]];
          if (!node) { continue; }
          if (!isNodeVisible(node)) {
            continue;
          }
          var row = valueOr(rowByClass[node.cls], 3);
          node.x = 120 + visibleOrdered.length * colSpacing;
          node.y = 120 + row * rowSpacing;
          node.sequence = visibleOrdered.length + 1;
          visibleOrdered.push(node.id);
        }

        var width = Math.max(visibleOrdered.length * colSpacing + 240, graphEl.clientWidth || 800);
        var height = Math.max(4 * rowSpacing + 200, graphEl.clientHeight || 600);
        updateViewBoxBase(width, height);
        svg.style.width = '100%';
        svg.style.height = '100%';
        layoutOrder = visibleOrdered;
      }

      function renderGraph() {
        computeLayout();
        linkGroup.innerHTML = '';
        nodeGroup.innerHTML = '';
        labelGroup.innerHTML = '';

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
          if (!node || !isNodeVisible(node)) { continue; }
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
        } else if (hoveredNodeId && nodes[hoveredNodeId] && isNodeVisible(nodes[hoveredNodeId])) {
          updateDetailsPanel(nodes[hoveredNodeId], 'hover');
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
        if (focusNodeId && focusNodeId === node.id) {
          updateDetailsPanel(node, 'focus');
        } else {
          updateDetailsPanel(node, 'hover');
        }
      }

      function hideTooltip() {
        tooltip.style.opacity = '0';
        document.removeEventListener('mousemove', positionTooltip);
        hoveredNodeId = null;
        if (focusNodeId && nodes[focusNodeId] && isNodeVisible(nodes[focusNodeId])) {
          updateDetailsPanel(nodes[focusNodeId], 'focus');
        } else {
          resetDetailsPanel();
        }
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

SIMULATION_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "virus": {
        "class": EventClass.A,
        "payload": {
            "category": "malware",
            "description": "Обнаружен подозрительный исполняемый файл",
            "severity": "high",
        },
    },
    "admin_login": {
        "class": EventClass.B,
        "payload": {
            "category": "authentication",
            "description": "Удалённый вход администратора",
            "source_ip": "192.0.2.15",
        },
    },
    "mac_spoof": {
        "class": EventClass.A,
        "payload": {
            "category": "network",
            "description": "Попытка подмены MAC-адреса",
        },
    },
    "portscan": {
        "class": EventClass.B,
        "payload": {
            "category": "network",
            "description": "Аномальный порт-скан внешним узлом",
        },
    },
    "heartbeat": {
        "class": EventClass.C,
        "payload": {
            "category": "diagnostic",
            "description": "Тестовый heartbeat от панели мониторинга",
        },
    },
}


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
    if scenario not in SIMULATION_SCENARIOS:
        raise web.HTTPBadRequest(text="unknown scenario")
    template = SIMULATION_SCENARIOS[scenario]
    payload = dict(template["payload"])
    payload.update(
        {
            "scenario": scenario,
            "generated_at": datetime.utcnow().isoformat(timespec="seconds"),
            "simulation_id": secrets.token_hex(6),
        }
    )
    emission = await node.emit_event(template["class"], payload)
    return web.json_response({"event": emission.event.to_dict()})


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
        ]
    )
    return app
