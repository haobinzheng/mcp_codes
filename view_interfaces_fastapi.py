import os
import json
import re
import glob
from datetime import datetime
from zoneinfo import ZoneInfo
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI(title="GFiber Interface Audit Dashboard")

WEB_HOST = os.environ.get("WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.environ.get("WEB_PORT", "9000"))
ROOT_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "Audit_interfaces_data"))

def get_safe_path(*subpaths: str) -> str:
    """Securely resolve paths to prevent directory traversal attacks."""
    if not os.path.exists(ROOT_DATA_DIR):
        return ""
    canonical_root = os.path.realpath(ROOT_DATA_DIR)
    target = os.path.realpath(os.path.join(canonical_root, *subpaths))
    if not (target == canonical_root or target.startswith(canonical_root + os.sep)):
        raise PermissionError("Security Violation: Path traversal detected.")
    return target

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GFiber Interface Audit Dashboard (FastAPI Engine)</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --bg: #0b0f19;
      --surface: #1e1b4b;
      --surface-card: rgba(30, 27, 75, 0.7);
      --surface-hover: rgba(49, 46, 129, 0.8);
      --border: #312e81;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent-purple: #a855f7;
      --accent-indigo: #6366f1;
      --accent-amber: #f59e0b;
      --accent-rose: #f43f5e;
      --card-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
    }

    body {
      margin: 0;
      font-family: 'Inter', sans-serif;
      background-color: var(--bg);
      background-image: 
        radial-gradient(circle at 0% 0%, rgba(168, 85, 247, 0.16), transparent 40%),
        radial-gradient(circle at 100% 100%, rgba(99, 102, 241, 0.12), transparent 40%);
      background-attachment: fixed;
      color: var(--text-main);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    header {
      background: rgba(11, 15, 25, 0.85);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      padding: 16px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 700;
      font-size: 22px;
      letter-spacing: -0.03em;
      color: var(--text-main);
    }

    .logo-dot {
      width: 12px;
      height: 12px;
      background: linear-gradient(135deg, var(--accent-purple), var(--accent-indigo));
      border-radius: 50%;
      box-shadow: 0 0 16px var(--accent-purple);
    }

    .tabs {
      display: flex;
      gap: 8px;
      background: rgba(0,0,0,0.25);
      padding: 6px;
      border-radius: 12px;
      border: 1px solid var(--border);
      align-items: center;
    }

    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: inherit;
      font-size: 14px;
      font-weight: 600;
      padding: 8px 18px;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .tab-btn:hover {
      color: var(--text-main);
      background: rgba(255,255,255,0.05);
    }

    .tab-btn.active {
      color: white;
      background: linear-gradient(135deg, var(--accent-purple), var(--accent-indigo));
      box-shadow: 0 4px 12px rgba(168, 85, 247, 0.3);
    }

    .container {
      flex: 1;
      padding: 32px;
      max-width: 1600px;
      margin: 0 auto;
      width: 100%;
      box-sizing: border-box;
    }

    .filter-bar {
      background: var(--surface-card);
      backdrop-filter: blur(12px);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 20px 28px;
      margin-bottom: 28px;
      display: flex;
      flex-wrap: wrap;
      gap: 24px;
      align-items: center;
      box-shadow: var(--card-shadow);
    }

    .filter-group {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .filter-label {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    select {
      background: #0f172a;
      color: var(--text-main);
      border: 1px solid var(--border);
      padding: 10px 18px;
      border-radius: 10px;
      font-family: inherit;
      font-size: 15px;
      font-weight: 500;
      cursor: pointer;
      outline: none;
      min-width: 200px;
      transition: border-color 0.2s;
    }

    select:hover, select:focus {
      border-color: var(--accent-purple);
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 20px;
      margin-bottom: 28px;
    }

    .metric-card {
      background: var(--surface-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 22px 26px;
      box-shadow: var(--card-shadow);
      position: relative;
      overflow: hidden;
    }

    .metric-card::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
    }

    .metric-card.total::before { background: var(--accent-purple); }
    .metric-card.upgraded::before { background: var(--accent-indigo); }
    .metric-card.alert::before { background: var(--accent-rose); }

    .metric-title {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 8px;
    }

    .metric-value {
      font-size: 32px;
      font-weight: 700;
      color: var(--text-main);
    }

    .view-section {
      display: none;
    }

    .view-section.active {
      display: block;
    }

    .layout-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 28px;
    }

    .card {
      background: var(--surface-card);
      backdrop-filter: blur(12px);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 28px;
      box-shadow: var(--card-shadow);
    }

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
    }

    .card-title {
      font-size: 18px;
      font-weight: 700;
      margin: 0;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .table-container {
      overflow-x: auto;
      max-height: 520px;
      overflow-y: auto;
      border-radius: 12px;
      border: 1px solid var(--border);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }

    th {
      background: #0f172a;
      color: var(--text-muted);
      font-size: 13px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 16px 20px;
      position: sticky;
      top: 0;
      z-index: 10;
      border-bottom: 1px solid var(--border);
    }

    td {
      padding: 16px 20px;
      border-bottom: 1px solid rgba(51, 65, 85, 0.5);
      font-size: 14px;
      color: var(--text-main);
    }

    tr {
      transition: background-color 0.15s ease;
      cursor: pointer;
    }

    tr:hover {
      background-color: var(--surface-hover);
    }

    tr.selected {
      background-color: rgba(168, 85, 247, 0.12);
      border-left: 4px solid var(--accent-purple);
    }

    .badge {
      padding: 5px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      display: inline-block;
    }

    .badge-ok {
      background: rgba(99, 102, 241, 0.15);
      color: var(--accent-indigo);
      border: 1px solid rgba(99, 102, 241, 0.3);
    }

    .badge-warn {
      background: rgba(245, 158, 11, 0.15);
      color: var(--accent-amber);
      border: 1px solid rgba(245, 158, 11, 0.3);
    }

    .badge-high {
      background: rgba(244, 63, 94, 0.15);
      color: var(--accent-rose);
      border: 1px solid rgba(244, 63, 94, 0.3);
    }

    .chart-panel {
      background: var(--surface-card);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 28px;
      box-shadow: var(--card-shadow);
      min-height: 400px;
    }

    .high-util-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
      gap: 28px;
    }

    .high-util-card {
      background: var(--surface-card);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 24px;
      box-shadow: var(--card-shadow);
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .high-util-card .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 14px;
    }

    .high-util-card .router-name {
      font-size: 18px;
      font-weight: 700;
      color: var(--accent-purple);
    }

    .high-util-card .intf-name {
      font-family: 'JetBrains Mono', monospace;
      font-size: 16px;
      font-weight: 600;
      background: rgba(0,0,0,0.3);
      padding: 4px 10px;
      border-radius: 6px;
      border: 1px solid var(--border);
    }

    .high-util-card .details {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 12px;
      font-size: 14px;
      color: var(--text-muted);
    }

    .high-util-card .details strong {
      color: var(--text-main);
    }

    .mini-chart-wrapper {
      height: 240px;
      position: relative;
      width: 100%;
    }

    .empty-state {
      text-align: center;
      padding: 64px 20px;
      color: var(--text-muted);
      font-size: 16px;
    }

    .spinner {
      display: inline-block;
      width: 32px;
      height: 32px;
      border: 3px solid rgba(255,255,255,0.1);
      border-radius: 50%;
      border-top-color: var(--accent-purple);
      animation: spin 1s ease-in-out infinite;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    #main-chart-container {
      height: 380px;
      position: relative;
    }
  </style>
</head>
<body>
  <header>
    <div class="logo">
      <div class="logo-dot"></div>
      <span>GFiber Network Auditor (FastAPI Engine)</span>
    </div>
    <div class="tabs">
      <button class="tab-btn active" onclick="switchTab('inspector')">Router Inspector</button>
      <button class="tab-btn" onclick="switchTab('overview')">High Utilization (>50%)</button>
      <button class="tab-btn" onclick="switchTab('history')">Utilization History</button>
      <a href="/docs" target="_blank" class="tab-btn" style="text-decoration: none; background: rgba(168, 85, 247, 0.15); border: 1px solid rgba(168, 85, 247, 0.4); color: var(--accent-purple); display: inline-flex; align-items: center;">Interactive API Docs ⚡</a>
    </div>
  </header>

  <div class="container">
    <!-- Filter Bar -->
    <div class="filter-bar">
      <div id="standard-filter-group" class="filter-group">
        <span class="filter-label">Audit Date</span>
        <select id="date-select" onchange="onDateChange()"></select>
      </div>
      <div id="router-filter-group" class="filter-group">
        <span class="filter-label">Router</span>
        <select id="router-select" onchange="onRouterChange()"></select>
      </div>
      
      <!-- History Range Filters -->
      <div id="history-filter-group" class="filter-group" style="display: none; gap: 16px; align-items: center;">
        <span class="filter-label">Start Date</span>
        <select id="start-date-select"></select>
        <span class="filter-label">End Date</span>
        <select id="end-date-select"></select>
        <span class="filter-label">Threshold %</span>
        <input type="number" id="history-threshold-input" value="50" min="1" max="100" style="background: #0f172a; color: var(--text-main); border: 1px solid var(--border); padding: 10px; border-radius: 10px; width: 70px; font-family: inherit; font-size: 15px; outline: none; text-align: center;">
        <button class="tab-btn active" onclick="loadHighUtilizationHistory()" style="padding: 10px 20px; font-size: 14px;">Apply Filters</button>
      </div>

      <div id="loading-indicator" style="display: none; align-items: center; gap: 10px; color: var(--accent-purple);">
        <div class="spinner"></div>
        <span style="font-size: 14px; font-weight: 500;">Loading data...</span>
      </div>
    </div>

    <!-- Section 1: Router Inspector -->
    <div id="section-inspector" class="view-section active">
      <div class="metrics-grid">
        <div class="metric-card total">
          <div class="metric-title">Total Active Interfaces</div>
          <div id="metric-total" class="metric-value">-</div>
        </div>
        <div class="metric-card upgraded">
          <div class="metric-title">400G Upgraded</div>
          <div id="metric-upgraded" class="metric-value">-</div>
        </div>
        <div class="metric-card alert">
          <div class="metric-title">High Utilization (>50%)</div>
          <div id="metric-high" class="metric-value">-</div>
        </div>
      </div>

      <div class="layout-grid" style="margin-bottom: 28px;">
        <div class="card">
          <div class="card-header">
            <h2 class="card-title">Active Interface Inventory</h2>
          </div>
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>Interface</th>
                  <th>Neighbor</th>
                  <th>Circuit</th>
                  <th>Speed</th>
                  <th>Latest (In / Out)</th>
                  <th>Daily Peak (In / Out)</th>
                  <th>Upgrade Status</th>
                </tr>
              </thead>
              <tbody id="interface-table-body">
                <tr><td colspan="7" class="empty-state">Select a date and router above to view interfaces.</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="chart-panel">
        <div class="card-header">
          <h2 id="main-chart-title" class="card-title">Interface Traffic Trend Over Time</h2>
        </div>
        <div id="main-chart-container">
          <canvas id="main-chart"></canvas>
        </div>
      </div>
    </div>

    <!-- Section 2: High Utilization Overview -->
    <div id="section-overview" class="view-section">
      <div id="high-util-container" class="high-util-grid">
        <div class="empty-state" style="grid-column: 1/-1;">Loading high utilization data...</div>
      </div>
    </div>

    <!-- Section 3: High Utilization History -->
    <div id="section-history" class="view-section">
      <div id="history-util-container" class="high-util-grid">
        <div class="empty-state" style="grid-column: 1/-1;">Select a date range and click Apply Filters above to view historical trends.</div>
      </div>
    </div>
  </div>

  <script>
    let activeTab = 'inspector';
    let currentRouterData = null;
    let mainChartInstance = null;
    let miniChartInstances = [];

    document.addEventListener("DOMContentLoaded", () => {
      loadDates();
    });

    function switchTab(tab) {
      activeTab = tab;
      document.querySelectorAll('.tabs .tab-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.view-section').forEach(sec => sec.classList.remove('active'));

      // Clear existing mini charts
      miniChartInstances.forEach(inst => inst.destroy());
      miniChartInstances = [];

      if (tab === 'inspector') {
        document.querySelector('.tabs button:nth-child(1)').classList.add('active');
        document.getElementById('section-inspector').classList.add('active');
        document.getElementById('standard-filter-group').style.display = 'flex';
        document.getElementById('router-filter-group').style.display = 'flex';
        document.getElementById('history-filter-group').style.display = 'none';
        onRouterChange();
      } else if (tab === 'overview') {
        document.querySelector('.tabs button:nth-child(2)').classList.add('active');
        document.getElementById('section-overview').classList.add('active');
        document.getElementById('standard-filter-group').style.display = 'flex';
        document.getElementById('router-filter-group').style.display = 'none';
        document.getElementById('history-filter-group').style.display = 'none';
        loadHighUtilization();
      } else if (tab === 'history') {
        document.querySelector('.tabs button:nth-child(3)').classList.add('active');
        document.getElementById('section-history').classList.add('active');
        document.getElementById('standard-filter-group').style.display = 'none';
        document.getElementById('router-filter-group').style.display = 'none';
        document.getElementById('history-filter-group').style.display = 'flex';
        loadHighUtilizationHistory();
      }
    }

    function showLoading(show) {
      document.getElementById('loading-indicator').style.display = show ? 'flex' : 'none';
    }

    async function loadDates() {
      showLoading(true);
      try {
        const resp = await fetch('/api/dates');
        const data = await resp.json();
        
        const select = document.getElementById('date-select');
        const startSelect = document.getElementById('start-date-select');
        const endSelect = document.getElementById('end-date-select');
        
        select.replaceChildren();
        startSelect.replaceChildren();
        endSelect.replaceChildren();
        
        if (data.dates.length === 0) {
          const opt = document.createElement('option');
          opt.textContent = "No data available";
          select.appendChild(opt);
          showLoading(false);
          return;
        }
        
        // Sort dates chronologically for the history dropdowns
        const chronologicalDates = [...data.dates].reverse();
        
        chronologicalDates.forEach((d, idx) => {
          const optStart = document.createElement('option');
          optStart.value = d;
          optStart.textContent = d;
          startSelect.appendChild(optStart);

          const optEnd = document.createElement('option');
          optEnd.value = d;
          optEnd.textContent = d;
          endSelect.appendChild(optEnd);
        });
        
        if (chronologicalDates.length > 0) {
          startSelect.value = chronologicalDates[0];
          endSelect.value = chronologicalDates[chronologicalDates.length - 1];
        }

        data.dates.forEach(d => {
          const opt = document.createElement('option');
          opt.value = d;
          opt.textContent = d;
          select.appendChild(opt);
        });
        
        await onDateChange();
      } catch (err) {
        console.error("Failed to load dates", err);
      }
      showLoading(false);
    }

    async function onDateChange() {
      const date = document.getElementById('date-select').value;
      if (!date) return;
      showLoading(true);
      try {
        const resp = await fetch(`/api/routers?date=${encodeURIComponent(date)}`);
        const data = await resp.json();
        const select = document.getElementById('router-select');
        select.replaceChildren();
        if (data.routers.length === 0) {
          const opt = document.createElement('option');
          opt.textContent = "No routers found";
          select.appendChild(opt);
        } else {
          data.routers.forEach(r => {
            const opt = document.createElement('option');
            opt.value = r;
            opt.textContent = r;
            select.appendChild(opt);
          });
        }
        if (activeTab === 'inspector') {
          await onRouterChange();
        } else {
          await loadHighUtilization();
        }
      } catch (err) {
        console.error("Failed to load routers", err);
      }
      showLoading(false);
    }

    async function onRouterChange() {
      if (activeTab !== 'inspector') return;
      const date = document.getElementById('date-select').value;
      const router = document.getElementById('router-select').value;
      if (!date || !router) return;

      showLoading(true);
      try {
        const resp = await fetch(`/api/router_data?date=${encodeURIComponent(date)}&router=${encodeURIComponent(router)}`);
        currentRouterData = await resp.json();
        renderInspector();
      } catch (err) {
        console.error("Failed to load router data", err);
      }
      showLoading(false);
    }

    function renderInspector() {
      if (!currentRouterData || !currentRouterData.interfaces) return;
      const intfs = currentRouterData.interfaces;
      const keys = Object.keys(intfs);
      const seriesMap = currentRouterData.series || {};

      // Update metrics
      let upgraded = 0;
      let highUtil = 0;
      keys.forEach(k => {
        const info = intfs[k];
        const s = seriesMap[k] || { input: [0], output: [0] };
        const pIn = s.input.length > 0 ? Math.max(...s.input) : info.input_percent;
        const pOut = s.output.length > 0 ? Math.max(...s.output) : info.output_percent;

        if (info.is_400g_upgraded) upgraded++;
        if (pIn > 50 || pOut > 50) highUtil++;
      });
      document.getElementById('metric-total').textContent = keys.length;
      document.getElementById('metric-upgraded').textContent = upgraded;
      document.getElementById('metric-high').textContent = highUtil;

      // Render Table
      const tbody = document.getElementById('interface-table-body');
      tbody.replaceChildren();

      if (keys.length === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 7;
        td.className = 'empty-state';
        td.textContent = "No active bundle interfaces recorded for this router.";
        tr.appendChild(td);
        tbody.appendChild(tr);
        if (mainChartInstance) mainChartInstance.destroy();
        return;
      }

      keys.forEach((k, index) => {
        const info = intfs[k];
        const s = seriesMap[k] || { input: [0], output: [0] };
        const peakIn = Math.round(s.input.length > 0 ? Math.max(...s.input) : info.input_percent);
        const peakOut = Math.round(s.output.length > 0 ? Math.max(...s.output) : info.output_percent);
        const latestIn = Math.round(info.input_percent);
        const latestOut = Math.round(info.output_percent);

        const tr = document.createElement('tr');
        tr.id = `row-${k}`;
        tr.onclick = () => selectInterface(k);

        const tdIntf = document.createElement('td');
        tdIntf.style.fontFamily = "'JetBrains Mono', monospace";
        tdIntf.style.fontWeight = "600";
        tdIntf.textContent = k;

        const tdNeigh = document.createElement('td');
        tdNeigh.textContent = info.neighbor || 'Unknown';

        const tdCirc = document.createElement('td');
        tdCirc.textContent = info.circuit || 'Unknown';

        const tdSpd = document.createElement('td');
        tdSpd.textContent = info.speed || 'Unknown';

        // Latest In/Out cell
        const tdLatest = document.createElement('td');
        const badgeLatestIn = document.createElement('span');
        badgeLatestIn.className = `badge ${latestIn > 50 ? (latestIn > 80 ? 'badge-high' : 'badge-warn') : 'badge-ok'}`;
        badgeLatestIn.textContent = `${latestIn}%`;
        
        const spanSlash1 = document.createElement('span');
        spanSlash1.style.margin = "0 6px";
        spanSlash1.style.color = "var(--text-muted)";
        spanSlash1.textContent = "/";

        const badgeLatestOut = document.createElement('span');
        badgeLatestOut.className = `badge ${latestOut > 50 ? (latestOut > 80 ? 'badge-high' : 'badge-warn') : 'badge-ok'}`;
        badgeLatestOut.textContent = `${latestOut}%`;
        tdLatest.append(badgeLatestIn, spanSlash1, badgeLatestOut);

        // Daily Peak In/Out cell
        const tdPeak = document.createElement('td');
        const badgePeakIn = document.createElement('span');
        badgePeakIn.className = `badge ${peakIn > 50 ? (peakIn > 80 ? 'badge-high' : 'badge-warn') : 'badge-ok'}`;
        badgePeakIn.textContent = `${peakIn}%`;

        const spanSlash2 = document.createElement('span');
        spanSlash2.style.margin = "0 6px";
        spanSlash2.style.color = "var(--text-muted)";
        spanSlash2.textContent = "/";

        const badgePeakOut = document.createElement('span');
        badgePeakOut.className = `badge ${peakOut > 50 ? (peakOut > 80 ? 'badge-high' : 'badge-warn') : 'badge-ok'}`;
        badgePeakOut.textContent = `${peakOut}%`;
        tdPeak.append(badgePeakIn, spanSlash2, badgePeakOut);

        const tdUpg = document.createElement('td');
        const spanUpg = document.createElement('span');
        spanUpg.className = `badge ${info.is_400g_upgraded ? 'badge-ok' : 'badge-warn'}`;
        spanUpg.textContent = info.upgrade_status || 'Not upgraded';
        tdUpg.appendChild(spanUpg);

        tr.append(tdIntf, tdNeigh, tdCirc, tdSpd, tdLatest, tdPeak, tdUpg);
        tbody.appendChild(tr);
      });

      // Select first interface by default
      selectInterface(keys[0]);
    }

    function selectInterface(intfName) {
      document.querySelectorAll('#interface-table-body tr').forEach(row => row.classList.remove('selected'));
      const activeRow = document.getElementById(`row-${intfName}`);
      if (activeRow) activeRow.classList.add('selected');

      renderMainChart(intfName);
    }

    function renderMainChart(intfName) {
      if (!currentRouterData || !currentRouterData.series[intfName]) return;
      document.getElementById('main-chart-title').textContent = `Traffic Trend: ${intfName} (${currentRouterData.interfaces[intfName].neighbor})`;
      
      const series = currentRouterData.series[intfName];
      const timestamps = currentRouterData.timestamps;

      if (mainChartInstance) mainChartInstance.destroy();

      const ctx = document.getElementById('main-chart').getContext('2d');
      mainChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
          labels: timestamps,
          datasets: [
            {
              label: 'Input %',
              data: series.input,
              borderColor: '#a855f7',
              backgroundColor: 'rgba(168, 85, 247, 0.1)',
              fill: true,
              tension: 0.3,
              borderWidth: 3,
              pointBackgroundColor: '#a855f7',
              pointRadius: 4,
              pointHoverRadius: 6
            },
            {
              label: 'Output %',
              data: series.output,
              borderColor: '#6366f1',
              backgroundColor: 'rgba(99, 102, 241, 0.1)',
              fill: true,
              tension: 0.3,
              borderWidth: 3,
              pointBackgroundColor: '#6366f1',
              pointRadius: 4,
              pointHoverRadius: 6
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              beginAtZero: true,
              max: 100,
              grid: { color: 'rgba(51, 65, 85, 0.4)' },
              ticks: { color: '#94a3b8', callback: val => `${val}%` }
            },
            x: {
              grid: { color: 'rgba(51, 65, 85, 0.4)' },
              ticks: { color: '#94a3b8' }
            }
          },
          plugins: {
            legend: { labels: { color: '#f8fafc', font: { family: 'Inter', weight: 600 } } },
            tooltip: {
              backgroundColor: '#0f172a',
              titleFont: { family: 'Inter', size: 14 },
              bodyFont: { family: 'Inter', size: 13 },
              borderColor: '#334155',
              borderWidth: 1,
              padding: 12
            }
          }
        }
      });
    }

    async function loadHighUtilization() {
      const date = document.getElementById('date-select').value;
      if (!date) return;
      showLoading(true);
      try {
        const resp = await fetch(`/api/high_utilization?date=${encodeURIComponent(date)}`);
        const data = await resp.json();

        const container = document.getElementById('high-util-container');
        container.replaceChildren();

        miniChartInstances.forEach(inst => inst.destroy());
        miniChartInstances = [];

        if (data.high_interfaces.length === 0) {
          const div = document.createElement('div');
          div.className = 'empty-state';
          div.style.gridColumn = '1/-1';
          div.textContent = "🎉 Excellent! No high utilization interfaces (>50%) detected across any router on this date.";
          container.appendChild(div);
          showLoading(false);
          return;
        }

        data.high_interfaces.forEach((item, i) => {
          const card = document.createElement('div');
          card.className = 'high-util-card';
          
          const header = document.createElement('div');
          header.className = 'header';
          const routerSpan = document.createElement('span');
          routerSpan.className = 'router-name';
          routerSpan.textContent = item.router;
          const intfSpan = document.createElement('span');
          intfSpan.className = 'intf-name';
          intfSpan.textContent = item.interface;
          header.append(routerSpan, intfSpan);

          const details = document.createElement('div');
          details.className = 'details';
          const divN = document.createElement('div'); divN.innerHTML = `Neighbor: <strong>${item.neighbor}</strong>`;
          const divS = document.createElement('div'); divS.innerHTML = `Speed: <strong>${item.speed}</strong>`;
          const divI = document.createElement('div'); divI.innerHTML = `Peak Input: <strong style="color: ${item.peak_input > 80 ? '#f43f5e' : '#f59e0b'}">${Math.round(item.peak_input)}%</strong>`;
          const divO = document.createElement('div'); divO.innerHTML = `Peak Output: <strong style="color: ${item.peak_output > 80 ? '#f43f5e' : '#f59e0b'}">${Math.round(item.peak_output)}%</strong>`;
          details.append(divN, divS, divI, divO);

          const chartWrap = document.createElement('div');
          chartWrap.className = 'mini-chart-wrapper';
          const canvas = document.createElement('canvas');
          canvas.id = `mini-chart-${i}`;
          chartWrap.appendChild(canvas);

          card.append(header, details, chartWrap);
          container.appendChild(card);

          const ctx = canvas.getContext('2d');
          const inst = new Chart(ctx, {
            type: 'line',
            data: {
              labels: item.timestamps,
              datasets: [
                {
                  label: 'In %',
                  data: item.series.input,
                  borderColor: '#a855f7',
                  backgroundColor: 'rgba(168, 85, 247, 0.1)',
                  fill: true,
                  tension: 0.3,
                  pointRadius: 3
                },
                {
                  label: 'Out %',
                  data: item.series.output,
                  borderColor: '#6366f1',
                  backgroundColor: 'rgba(99, 102, 241, 0.1)',
                  fill: true,
                  tension: 0.3,
                  pointRadius: 3
                }
              ]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              scales: {
                y: { max: 100, grid: { color: 'rgba(51,65,85,0.2)' }, ticks: { font: { size: 10 }, color: '#94a3b8' } },
                x: { grid: { color: 'rgba(51,65,85,0.2)' }, ticks: { font: { size: 10 }, color: '#94a3b8' } }
              },
              plugins: { legend: { display: false } }
            }
          });
          miniChartInstances.push(inst);
        });
      } catch (err) {
        console.error("Failed to load high utilization data", err);
      }
    async function loadHighUtilizationHistory() {
      if (activeTab !== 'history') return;
      const startDate = document.getElementById('start-date-select').value;
      const endDate = document.getElementById('end-date-select').value;
      const threshold = document.getElementById('history-threshold-input').value || 50;
      
      showLoading(true);
      try {
        const query = `/api/high_utilization_history?start_date=${encodeURIComponent(startDate)}&end_date=${encodeURIComponent(endDate)}&threshold_percent=${encodeURIComponent(threshold)}`;
        const resp = await fetch(query);
        const data = await resp.json();

        const container = document.getElementById('history-util-container');
        container.replaceChildren();

        miniChartInstances.forEach(inst => inst.destroy());
        miniChartInstances = [];

        if (data.high_interfaces_history.length === 0) {
          const div = document.createElement('div');
          div.className = 'empty-state';
          div.style.gridColumn = '1/-1';
          div.textContent = "🎉 Excellent! No interfaces crossed the threshold across this date range.";
          container.appendChild(div);
          showLoading(false);
          return;
        }

        data.high_interfaces_history.forEach((item, i) => {
          const card = document.createElement('div');
          card.className = 'high-util-card';
          
          const header = document.createElement('div');
          header.className = 'header';
          const routerSpan = document.createElement('span');
          routerSpan.className = 'router-name';
          routerSpan.textContent = item.router;
          const intfSpan = document.createElement('span');
          intfSpan.className = 'intf-name';
          intfSpan.textContent = item.interface;
          header.append(routerSpan, intfSpan);

          const details = document.createElement('div');
          details.className = 'details';
          const divN = document.createElement('div'); divN.innerHTML = `Neighbor: <strong>${item.neighbor}</strong>`;
          const divS = document.createElement('div'); divS.innerHTML = `Speed: <strong>${item.speed}</strong>`;
          const divI = document.createElement('div'); divI.innerHTML = `Max In: <strong style="color: ${item.peak_input > 80 ? '#f43f5e' : '#f59e0b'}">${Math.round(item.peak_input)}%</strong>`;
          const divO = document.createElement('div'); divO.innerHTML = `Max Out: <strong style="color: ${item.peak_output > 80 ? '#f43f5e' : '#f59e0b'}">${Math.round(item.peak_output)}%</strong>`;
          details.append(divN, divS, divI, divO);

          const chartWrap = document.createElement('div');
          chartWrap.className = 'mini-chart-wrapper';
          const canvas = document.createElement('canvas');
          canvas.id = `history-chart-${i}`;
          chartWrap.appendChild(canvas);

          card.append(header, details, chartWrap);
          container.appendChild(card);

          const ctx = canvas.getContext('2d');
          const inst = new Chart(ctx, {
            type: 'line',
            data: {
              labels: item.timestamps,
              datasets: [
                {
                  label: 'In %',
                  data: item.series.input,
                  borderColor: '#a855f7',
                  backgroundColor: 'rgba(168, 85, 247, 0.1)',
                  fill: true,
                  tension: 0.3,
                  pointRadius: 3
                },
                {
                  label: 'Out %',
                  data: item.series.output,
                  borderColor: '#6366f1',
                  backgroundColor: 'rgba(99, 102, 241, 0.1)',
                  fill: true,
                  tension: 0.3,
                  pointRadius: 3
                }
              ]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              scales: {
                y: { max: 100, grid: { color: 'rgba(51,65,85,0.2)' }, ticks: { font: { size: 10 }, color: '#94a3b8' } },
                x: { grid: { color: 'rgba(51,65,85,0.2)' }, ticks: { font: { size: 10 }, color: '#94a3b8' } }
              },
              plugins: { legend: { display: false } }
            }
          });
          miniChartInstances.push(inst);
        });
      } catch (err) {
        console.error("Failed to load high utilization history", err);
      }
      showLoading(false);
    }
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def route_index():
    return HTMLResponse(content=HTML_TEMPLATE)

@app.get("/api/dates")
def route_api_dates():
    try:
        safe_root = get_safe_path()
    except PermissionError:
        raise HTTPException(status_code=403, detail="Access Denied")

    if not safe_root or not os.path.exists(safe_root):
        return {"dates": []}
    
    entries = os.listdir(safe_root)
    dates = [d for d in entries if os.path.isdir(os.path.join(safe_root, d)) and re.match(r"^\d{4}-\d{2}-\d{2}$", d)]
    dates.sort(reverse=True)
    return {"dates": dates}

@app.get("/api/routers")
def route_api_routers(date: str = Query("", pattern=r"^\d{4}-\d{2}-\d{2}$")):
    if not date:
        return {"routers": []}
    
    try:
        date_path = get_safe_path(date)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Access Denied")

    if not os.path.exists(date_path):
        return {"routers": []}
    
    entries = os.listdir(date_path)
    routers = [r for r in entries if os.path.isdir(os.path.join(date_path, r))]
    routers.sort()
    return {"routers": routers}

@app.get("/api/router_data")
def route_api_router_data(date: str = Query(...), router: str = Query(...)):
    if not date or not router:
        raise HTTPException(status_code=400, detail="Missing parameters")

    try:
        router_path = get_safe_path(date, router)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Access Denied")

    if not os.path.exists(router_path):
        return {"timestamps": [], "interfaces": {}, "series": {}}

    files = glob.glob(os.path.join(router_path, f"{router}_*.json"))
    files.sort()

    timestamps = []
    series_map = {}
    latest_intfs = {}

    for f in files:
        basename = os.path.basename(f)
        match = re.search(r"_(\d{4}_\d{2}_\d{2}_\d{2}_\d{2})\.json$", basename)
        if not match:
            continue
        ts_raw = match.group(1)
        parts = ts_raw.split("_")
        if len(parts) >= 5:
            ts_label = f"{parts[3]}:{parts[4]}"
        else:
            ts_label = ts_raw

        timestamps.append(ts_label)

        try:
            with open(f, "r") as fh:
                data = json.load(fh)
        except Exception:
            continue

        for k, v in data.items():
            if k in ["role", "year", "audit_timestamp"] or not isinstance(v, dict):
                continue
            if k not in series_map:
                series_map[k] = {"input": [], "output": []}
            
            in_pct = round(v.get("input_bps_percent", 0), 1)
            out_pct = round(v.get("output_bps_percent", 0), 1)
            series_map[k]["input"].append(in_pct)
            series_map[k]["output"].append(out_pct)
            
            latest_intfs[k] = {
                "neighbor": v.get("neighbor", "Unknown"),
                "circuit": v.get("Circuit", "Unknown"),
                "speed": v.get("speed", "Unknown"),
                "input_percent": in_pct,
                "output_percent": out_pct,
                "is_400g_upgraded": v.get("is_400g_upgraded", False),
                "upgrade_status": v.get("upgrade_status", "Not upgraded")
            }

    return {
        "timestamps": timestamps,
        "interfaces": latest_intfs,
        "series": series_map
    }

@app.get("/api/high_utilization")
def route_api_high_utilization(date: str = Query("", pattern=r"^\d{4}-\d{2}-\d{2}$")):
    if not date:
        return {"high_interfaces": []}

    try:
        date_path = get_safe_path(date)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Access Denied")

    if not os.path.exists(date_path):
        return {"high_interfaces": []}

    routers = [r for r in os.listdir(date_path) if os.path.isdir(os.path.join(date_path, r))]
    routers.sort()

    high_items = []

    for r in routers:
        router_path = os.path.join(date_path, r)
        files = glob.glob(os.path.join(router_path, f"{r}_*.json"))
        files.sort()

        timestamps = []
        r_series = {}
        r_meta = {}

        for f in files:
            basename = os.path.basename(f)
            match = re.search(r"_(\d{4}_\d{2}_\d{2}_\d{2}_\d{2})\.json$", basename)
            if not match:
                continue
            ts_raw = match.group(1)
            parts = ts_raw.split("_")
            ts_label = f"{parts[3]}:{parts[4]}" if len(parts) >= 5 else ts_raw
            timestamps.append(ts_label)

            try:
                with open(f, "r") as fh:
                    data = json.load(fh)
            except Exception:
                continue

            for k, v in data.items():
                if k in ["role", "year", "audit_timestamp"] or not isinstance(v, dict):
                    continue
                if k not in r_series:
                    r_series[k] = {"input": [], "output": []}
                
                in_pct = round(v.get("input_bps_percent", 0), 1)
                out_pct = round(v.get("output_bps_percent", 0), 1)
                r_series[k]["input"].append(in_pct)
                r_series[k]["output"].append(out_pct)

                r_meta[k] = {
                    "neighbor": v.get("neighbor", "Unknown"),
                    "speed": v.get("speed", "Unknown")
                }

        for intf, series in r_series.items():
            peak_in = max(series["input"]) if series["input"] else 0
            peak_out = max(series["output"]) if series["output"] else 0

            if peak_in > 50 or peak_out > 50:
                meta = r_meta.get(intf, {})
                high_items.append({
                    "router": r,
                    "interface": intf,
                    "neighbor": meta.get("neighbor", "Unknown"),
                    "speed": meta.get("speed", "Unknown"),
                    "peak_input": peak_in,
                    "peak_output": peak_out,
                    "timestamps": timestamps,
                    "series": series
                })

    return {"high_interfaces": high_items}

@app.get("/api/high_utilization_history")
def route_api_high_utilization_history(
    start_date: str = Query("", pattern=r"^(\d{4}-\d{2}-\d{2})?$"),
    end_date: str = Query("", pattern=r"^(\d{4}-\d{2}-\d{2})?$"),
    threshold_percent: float = Query(50.0)
):
    try:
        safe_root = get_safe_path()
    except PermissionError:
        raise HTTPException(status_code=403, detail="Access Denied")

    if not safe_root or not os.path.exists(safe_root):
        return {"high_interfaces_history": []}

    entries = os.listdir(safe_root)
    date_folders = [d for d in entries if os.path.isdir(os.path.join(safe_root, d)) and re.match(r"^\d{4}-\d{2}-\d{2}$", d)]
    date_folders.sort()

    filtered_dates = []
    for d in date_folders:
        if start_date and d < start_date:
            continue
        if end_date and d > end_date:
            continue
        filtered_dates.append(d)

    interface_map = {}

    for d in filtered_dates:
        date_path = os.path.join(safe_root, d)
        routers = [r for r in os.listdir(date_path) if os.path.isdir(os.path.join(date_path, r))]
        
        for r in routers:
            router_path = os.path.join(date_path, r)
            files = glob.glob(os.path.join(router_path, f"{r}_*.json"))
            files.sort()

            for f in files:
                basename = os.path.basename(f)
                match = re.search(r"_(\d{4}_\d{2}_\d{2}_\d{2}_\d{2})\.json$", basename)
                if not match:
                    continue
                ts_raw = match.group(1)
                parts = ts_raw.split("_")
                ts_label = f"{parts[0]}-{parts[1]}-{parts[2]} {parts[3]}:{parts[4]}"

                try:
                    with open(f, "r") as fh:
                        data = json.load(fh)
                except Exception:
                    continue

                for k, v in data.items():
                    if k in ["role", "year", "audit_timestamp"] or not isinstance(v, dict):
                        continue
                    
                    in_pct = round(v.get("input_bps_percent", 0), 1)
                    out_pct = round(v.get("output_bps_percent", 0), 1)

                    key = (r, k)
                    if key not in interface_map:
                        interface_map[key] = {
                            "router": r,
                            "interface": k,
                            "neighbor": v.get("neighbor", "Unknown"),
                            "speed": v.get("speed", "Unknown"),
                            "timestamps": [],
                            "series": {"input": [], "output": []},
                            "peak_input": 0,
                            "peak_output": 0
                        }

                    interface_map[key]["timestamps"].append(ts_label)
                    interface_map[key]["series"]["input"].append(in_pct)
                    interface_map[key]["series"]["output"].append(out_pct)
                    
                    if in_pct > interface_map[key]["peak_input"]:
                        interface_map[key]["peak_input"] = in_pct
                    if out_pct > interface_map[key]["peak_output"]:
                        interface_map[key]["peak_output"] = out_pct

    high_history = []
    for key, val in interface_map.items():
        if val["peak_input"] > threshold_percent or val["peak_output"] > threshold_percent:
            high_history.append(val)

    high_history.sort(key=lambda x: (x["router"], x["interface"]))
    return {"high_interfaces_history": high_history}


def main() -> None:
    print(f"GFiber Interface Audit Dashboard (FastAPI) running on http://{WEB_HOST}:{WEB_PORT}")
    uvicorn.run(app, host=WEB_HOST, port=WEB_PORT, log_level="warning")

if __name__ == "__main__":
    main()
