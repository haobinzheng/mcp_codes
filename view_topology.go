package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
)

const defaultPort = "9001"

func main() {
	// Setup structured logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	port := os.Getenv("ANTIGRAVITY_SIDECAR_WEB_PORT")
	if port == "" {
		port = defaultPort
	}

	// Determine path of topology_discovery.json
	jsonPath := "topology_discovery.json"
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		// Try locating it in parent folder or workspace
		jsonPath = filepath.Join(".", "topology_discovery.json")
	}

	mux := http.NewServeMux()

	// Endpoint to serve topology JSON
	mux.HandleFunc("GET /api/topology", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		data, err := os.ReadFile(jsonPath)
		if err != nil {
			slog.Error("Failed to read topology JSON file", "path", jsonPath, "error", err)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error": "topology file not found"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	// Serve HTML UI
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(htmlContent))
	})

	slog.Info("GFiber Topology Map running", "url", fmt.Sprintf("http://localhost:%s", port))
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}

const htmlContent = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GFiber Network Topology Map</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #09090b;
      --surface: #18181b;
      --border: rgba(234, 179, 8, 0.2);
      --text-main: #fafafa;
      --text-muted: #a1a1aa;
      
      /* Device Colors matching photo legend */
      --color-rr: #06b6d4;       /* Cyan */
      --color-cr-core: #3b82f6;  /* Backbone Core - Blue */
      --color-cr-metro: #10b981; /* Metro Core - Teal/Green */
      --color-pr: #22c55e;       /* Peering - Green */
      --color-bng: #f97316;      /* BNG - Orange */
      --color-unknown: #a1a1aa;
      
      /* Capacity Colors */
      --cap-100g: #3b82f6;
      --cap-200g: #06b6d4;
      --cap-300g: #8b5cf6;
      --cap-400g: #ec4899;
      --cap-600g: #f97316;
      --cap-high: #eab308;       /* 1.8T/2.4T - Gold */
    }

    body {
      margin: 0;
      font-family: 'Inter', sans-serif;
      background-color: var(--bg);
      color: var(--text-main);
      height: 100vh;
      display: flex;
      overflow: hidden;
    }

    /* Sidebar Styling */
    #sidebar {
      width: 360px;
      background: rgba(24, 24, 27, 0.85);
      backdrop-filter: blur(16px);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      box-shadow: 10px 0 30px rgba(0, 0, 0, 0.5);
      z-index: 10;
    }

    .sidebar-header {
      padding: 24px;
      border-bottom: 1px solid var(--border);
    }

    .sidebar-title {
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.02em;
      margin: 0;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .logo-dot {
      width: 12px;
      height: 12px;
      background: linear-gradient(135deg, #eab308, #06b6d4);
      border-radius: 50%;
      box-shadow: 0 0 12px #eab308;
    }

    .sidebar-content {
      flex: 1;
      overflow-y: auto;
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    .section-title {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 12px;
    }

    .legend-item {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 14px;
      margin-bottom: 8px;
    }

    .legend-color {
      width: 14px;
      height: 14px;
      border-radius: 50%;
    }

    .info-card {
      background: rgba(0,0,0,0.25);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
    }

    .info-field {
      margin-bottom: 12px;
    }

    .info-label {
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-bottom: 4px;
    }

    .info-value {
      font-size: 15px;
      font-weight: 600;
    }

    .info-mono {
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
    }

    /* Map Area Container */
    #map-container {
      flex: 1;
      position: relative;
      cursor: grab;
      background: radial-gradient(circle at 50% 50%, #111318 0%, #09090b 100%);
    }

    #map-container:active {
      cursor: grabbing;
    }

    #viewport {
      position: absolute;
      width: 100%;
      height: 100%;
      transform-origin: 0 0;
    }

    svg {
      width: 100%;
      height: 100%;
      user-select: none;
    }

    /* Map Elements styling */
    .us-outline {
      fill: rgba(24, 24, 27, 0.4);
      stroke: rgba(234, 179, 8, 0.06);
      stroke-width: 1.5;
    }

    .metro-bubble {
      fill: rgba(39, 39, 42, 0.65);
      stroke: rgba(255,255,255,0.1);
      stroke-width: 1;
      transition: all 0.25s ease;
    }

    .metro-label {
      font-size: 10px;
      font-weight: 700;
      fill: var(--text-muted);
      letter-spacing: 0.05em;
      pointer-events: none;
    }

    .topology-link {
      stroke-linecap: round;
      transition: stroke-width 0.2s, stroke 0.2s;
      opacity: 0.85;
    }

    .topology-link:hover {
      stroke-width: 6 !important;
      opacity: 1;
      cursor: pointer;
    }

    .device-node {
      stroke: var(--bg);
      stroke-width: 1.5;
      cursor: pointer;
      transition: r 0.2s, stroke-width 0.2s;
    }

    .device-node:hover {
      stroke: #ffffff;
      stroke-width: 2.5;
    }

    .device-node.active {
      stroke: #ffffff;
      stroke-width: 3;
      box-shadow: 0 0 20px white;
    }

    .badge {
      padding: 3px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 600;
      display: inline-block;
    }

    .tooltip {
      position: absolute;
      background: rgba(3, 7, 18, 0.9);
      backdrop-filter: blur(8px);
      border: 1px solid var(--border);
      padding: 8px 12px;
      border-radius: 8px;
      pointer-events: none;
      font-size: 12px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      display: none;
      z-index: 100;
    }

    /* Custom Grid Overlay */
    .grid-line {
      stroke: rgba(234, 179, 8, 0.03);
      stroke-width: 1;
    }
  </style>
</head>
<body>
  <!-- Sidebar Info Panel -->
  <div id="sidebar">
    <div class="sidebar-header">
      <h1 class="sidebar-title">
        <div class="logo-dot"></div>
        <span>GFiber Metro Topology</span>
      </h1>
    </div>
    <div class="sidebar-content">
      <!-- Legend Section -->
      <div>
        <div class="section-title">Device Class Legend</div>
        <div class="legend-item">
          <div class="legend-color" style="background: var(--color-rr); box-shadow: 0 0 8px var(--color-rr)"></div>
          <span>Route Reflector (RR)</span>
        </div>
        <div class="legend-item">
          <div class="legend-color" style="background: var(--color-cr-core); box-shadow: 0 0 8px var(--color-cr-core)"></div>
          <span>Backbone Core (CR)</span>
        </div>
        <div class="legend-item">
          <div class="legend-color" style="background: var(--color-cr-metro); box-shadow: 0 0 8px var(--color-cr-metro)"></div>
          <span>Metro Core (CR)</span>
        </div>
        <div class="legend-item">
          <div class="legend-color" style="background: var(--color-pr); box-shadow: 0 0 8px var(--color-pr)"></div>
          <span>Peering Router (PR)</span>
        </div>
        <div class="legend-item">
          <div class="legend-color" style="background: var(--color-bng); box-shadow: 0 0 8px var(--color-bng)"></div>
          <span>BNG Edge Gateway</span>
        </div>
      </div>

      <!-- Capacity Legend Section -->
      <div>
        <div class="section-title">Link Capacity Colors</div>
        <div class="legend-item">
          <div class="legend-color" style="background: var(--cap-100g); border-radius: 2px; height: 4px; width: 20px;"></div>
          <span>100G Capacity</span>
        </div>
        <div class="legend-item">
          <div class="legend-color" style="background: var(--cap-200g); border-radius: 2px; height: 4px; width: 20px;"></div>
          <span>200G Capacity</span>
        </div>
        <div class="legend-item">
          <div class="legend-color" style="background: var(--cap-300g); border-radius: 2px; height: 4px; width: 20px;"></div>
          <span>300G Capacity</span>
        </div>
        <div class="legend-item">
          <div class="legend-color" style="background: var(--cap-400g); border-radius: 2px; height: 4px; width: 20px;"></div>
          <span>400G Capacity</span>
        </div>
        <div class="legend-item">
          <div class="legend-color" style="background: var(--cap-600g); border-radius: 2px; height: 4px; width: 20px;"></div>
          <span>600G Capacity</span>
        </div>
        <div class="legend-item">
          <div class="legend-color" style="background: var(--cap-high); border-radius: 2px; height: 4px; width: 20px;"></div>
          <span>1.8T+ Capacity</span>
        </div>
      </div>

      <!-- Selection Details Section -->
      <div id="selection-panel" style="display: none;">
        <div class="section-title">Node Diagnostic Panel</div>
        <div class="info-card">
          <div class="info-field">
            <div class="info-label">Hostname</div>
            <div id="info-hostname" class="info-value" style="color: #eab308;">-</div>
          </div>
          <div class="info-field">
            <div class="info-label">Metro / Site Location</div>
            <div id="info-site" class="info-value">-</div>
          </div>
          <div class="info-field">
            <div class="info-label">Device Role</div>
            <div id="info-role" class="info-value">-</div>
          </div>
          <div class="info-field">
            <div class="info-label">Core Adjacency Interfaces</div>
            <div id="info-interfaces" class="info-value info-mono" style="max-height: 180px; overflow-y: auto; white-space: pre-wrap;">-</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Interactive Map Container -->
  <div id="map-container">
    <div id="viewport">
      <svg id="map-svg" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid meet">
        <!-- Grids -->
        <g id="svg-grid"></g>

        <!-- US Contour Approximation path scaled up by 1.6 for expanded viewbox -->
        <path class="us-outline" transform="scale(1.6)" d="M 100,150 C 150,100 300,110 350,90 C 400,70 500,80 600,70 C 700,60 800,80 850,110 C 890,130 920,110 940,180 C 960,220 950,280 930,300 C 910,320 930,380 910,400 C 890,420 850,400 820,440 C 800,460 820,520 780,530 C 750,540 700,480 680,480 C 660,480 620,500 590,480 C 560,460 510,460 470,480 C 450,490 430,520 400,530 C 380,540 340,520 310,480 C 280,450 250,460 230,420 C 210,400 180,380 160,370 C 140,360 130,320 110,310 C 90,300 60,310 50,270 C 40,230 70,210 80,190 Z" />

        <!-- Metro Bubbles group -->
        <g id="metro-bubbles"></g>

        <!-- Topologies links group -->
        <g id="topology-links"></g>

        <!-- Device Nodes group -->
        <g id="device-nodes"></g>

        <!-- Metro Labels group -->
        <g id="metro-labels"></g>
      </svg>
    </div>

    <!-- Floating Tooltip -->
    <div id="tooltip" class="tooltip"></div>
  </div>

  <script>
    // Geographical center coordinates inside the SVG grid
    const metroCoordinates = {
      "sfo": { x: 80, y: 400, name: "San Francisco, CA" },
      "sjc": { x: 80, y: 430, name: "San Jose, CA" },
      "svl": { x: 80, y: 415, name: "Sunnyvale, CA" },
      "lax": { x: 120, y: 650, name: "Los Angeles, CA" },
      "pih": { x: 320, y: 150, name: "Pocatello, ID" },
      "lgu": { x: 350, y: 240, name: "Logan, UT" },
      "slc": { x: 350, y: 290, name: "Salt Lake City, UT" },
      "las": { x: 280, y: 520, name: "Las Vegas, NV" },
      "phx": { x: 300, y: 680, name: "Phoenix, AZ" },
      "den": { x: 550, y: 360, name: "Denver, CO" },
      "sat": { x: 720, y: 820, name: "San Antonio, TX" },
      "aus": { x: 760, y: 780, name: "Austin, TX" },
      "dfw": { x: 780, y: 640, name: "Dallas-Fort Worth, TX" },
      "oma": { x: 780, y: 280, name: "Omaha, NE" },
      "cbf": { x: 820, y: 280, name: "Council Bluffs, IA" },
      "dsm": { x: 920, y: 260, name: "Des Moines, IA" },
      "mci": { x: 880, y: 380, name: "Kansas City, MO" },
      "jef": { x: 980, y: 420, name: "Jefferson City, MO" },
      "ord": { x: 1100, y: 220, name: "Chicago, IL" },
      "bna": { x: 1180, y: 560, name: "Nashville, TN" },
      "hsv": { x: 1200, y: 660, name: "Huntsville, AL" },
      "atl": { x: 1240, y: 720, name: "Atlanta, GA" },
      "clt": { x: 1360, y: 580, name: "Charlotte, NC" },
      "rdu": { x: 1420, y: 520, name: "Raleigh-Durham, NC" },
      "iad": { x: 1440, y: 340, name: "Washington D.C." },
      "ewr": { x: 1520, y: 200, name: "Newark, NJ" }
    };

    let topologyData = {};
    let deviceCoords = {};

    // Drag & Zoom parameters
    const container = document.getElementById('map-container');
    const viewport = document.getElementById('viewport');
    let isDragging = false;
    let startX = 0, startY = 0;
    let posX = 0, posY = 0;
    let scale = 1.0;

    // SVG zooming handlers
    container.addEventListener('mousedown', (e) => {
      if (e.target.closest('.device-node')) return; // Don't drag if clicking node
      isDragging = true;
      startX = e.clientX - posX;
      startY = e.clientY - posY;
      container.style.cursor = 'grabbing';
    });

    window.addEventListener('mouseup', () => {
      isDragging = false;
      container.style.cursor = 'grab';
    });

    container.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      posX = e.clientX - startX;
      posY = e.clientY - startY;
      updateViewportTransform();
    });

    container.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = 0.1;
      const mouseX = e.clientX - container.getBoundingClientRect().left;
      const mouseY = e.clientY - container.getBoundingClientRect().top;

      // Zoom to mouse position
      const svgX = (mouseX - posX) / scale;
      const svgY = (mouseY - posY) / scale;

      if (e.deltaY < 0) {
        scale += zoomFactor;
      } else {
        scale = Math.max(0.5, scale - zoomFactor);
      }

      posX = mouseX - svgX * scale;
      posY = mouseY - svgY * scale;
      updateViewportTransform();
    });

    function updateViewportTransform() {
      viewport.style.transform = ` + "`" + `translate(${posX}px, ${posY}px) scale(${scale})` + "`" + `;
    }

    // Initialize Background Grids
    function renderGrid() {
      const gridGroup = document.getElementById('svg-grid');
      let gridHTML = '';
      // Vertical Lines
      for (let x = 0; x <= 1600; x += 80) {
        gridHTML += ` + "`" + `<line class="grid-line" x1="${x}" y1="0" x2="${x}" y2="900" />` + "`" + `;
      }
      // Horizontal Lines
      for (let y = 0; y <= 900; y += 80) {
        gridHTML += ` + "`" + `<line class="grid-line" x1="0" y1="${y}" x2="1600" y2="${y}" />` + "`" + `;
      }
      gridGroup.innerHTML = gridHTML;
    }

    // Extract metro code from hostname
    function getMetroOfDevice(device) {
      const parts = device.split('.');
      const host = parts[0].toLowerCase();
      
      // Check for specific formats first like re0-cr01.atl101
      const match = device.match(/\.([a-z]+)\d*/i);
      if (match) return match[1].toLowerCase();

      const match2 = device.match(/^[a-z]+\d*-([a-z]+)/i);
      if (match2) return match2[1].toLowerCase();

      // Fallback to scanning keys
      for (const m of Object.keys(metroCoordinates)) {
        if (device.toLowerCase().includes(m)) return m;
      }
      return "mci"; // Default to Kansas City
    }

    function getDeviceRole(hostname) {
      const name = hostname.toLowerCase();
      if (name.includes("rr01") || name.startsWith("rr")) return "rr";
      if (name.startsWith("cr")) {
        // Backbone vs Metro Core depending on site
        if (name.includes("atl") || name.includes("mci") || name.includes("sjc") || name.includes("ord") || name.includes("slc") || name.includes("dfw") || name.includes("lax")) {
          return "cr-backbone";
        }
        return "cr-metro";
      }
      if (name.startsWith("pr")) return "pr";
      if (name.startsWith("bng")) return "bng";
      return "unknown";
    }

    function getDeviceColor(role) {
      switch(role) {
        case "rr": return "var(--color-rr)";
        case "cr-backbone": return "var(--color-cr-core)";
        case "cr-metro": return "var(--color-cr-metro)";
        case "pr": return "var(--color-pr)";
        case "bng": return "var(--color-bng)";
        default: return "var(--color-unknown)";
      }
    }

    function getCapacityColor(bps) {
      const gbps = bps / 1000000000;
      if (gbps <= 100) return "var(--cap-100g)";
      if (gbps <= 200) return "var(--cap-200g)";
      if (gbps <= 300) return "var(--cap-300g)";
      if (gbps <= 500) return "var(--cap-400g)";
      if (gbps <= 900) return "var(--cap-600g)";
      return "var(--cap-high)";
    }

    function getCapacityWidth(bps) {
      const gbps = bps / 1000000000;
      if (gbps <= 100) return 1.5;
      if (gbps <= 200) return 2.5;
      if (gbps <= 400) return 3.5;
      if (gbps <= 800) return 4.5;
      return 6.0;
    }

    // Fetch & Draw Topology Map
    async function loadTopology() {
      renderGrid();
      try {
        const resp = await fetch('/api/topology');
        topologyData = await resp.json();
        
        // 1. Group devices by metro to compute radial orbits
        const devicesByMetro = {};
        Object.keys(topologyData).forEach(device => {
          const metro = getMetroOfDevice(device);
          devicesByMetro[metro] = devicesByMetro[metro] || [];
          devicesByMetro[metro].push(device);
        });

        // 2. Calculate coordinates for each device node
        deviceCoords = {};
        const metroBubbles = document.getElementById('metro-bubbles');
        const metroLabels = document.getElementById('metro-labels');
        
        let bubblesHTML = '';
        let labelsHTML = '';

        Object.keys(devicesByMetro).forEach(metro => {
          const devices = devicesByMetro[metro];
          const base = metroCoordinates[metro] || { x: 500, y: 300, name: "Unknown Location" };
          
          // Draw Metro Bubble in the background
          const bubbleRadius = 22 + (devices.length * 3.5);
          bubblesHTML += ` + "`" + `<circle class="metro-bubble" cx="${base.x}" cy="${base.y}" r="${bubbleRadius}" />` + "`" + `;
          
          // Draw Metro Label
          labelsHTML += ` + "`" + `<text class="metro-label" x="${base.x}" y="${base.y + bubbleRadius + 14}" text-anchor="middle">${metro.toUpperCase()}</text>` + "`" + `;

          if (devices.length === 1) {
            deviceCoords[devices[0]] = { x: base.x, y: base.y };
          } else {
            const offsetRadius = 13 + (devices.length * 1.5);
            devices.forEach((dev, idx) => {
              const angle = (idx / devices.length) * 2 * Math.PI;
              deviceCoords[dev] = {
                x: base.x + offsetRadius * Math.cos(angle),
                y: base.y + offsetRadius * Math.sin(angle)
              };
            });
          }
        });

        metroBubbles.innerHTML = bubblesHTML;
        metroLabels.innerHTML = labelsHTML;

        // 3. Draw Links between devices (De-duplicate symmetric links)
        const linksGroup = document.getElementById('topology-links');
        let linksHTML = '';
        const drawnLinks = new Set();

        Object.keys(topologyData).forEach(localDev => {
          const intfs = topologyData[localDev];
          Object.keys(intfs).forEach(intf => {
            const linkDetail = intfs[intf];
            const remoteDev = linkDetail.remote_device;

            if (!remoteDev || remoteDev === "unknown") return;

            // Standardize key to de-duplicate links (e.g. A->B and B->A)
            const linkKey = [localDev, remoteDev].sort().join('---');
            if (drawnLinks.has(linkKey)) return;
            drawnLinks.add(linkKey);

            // Get coordinates
            const start = deviceCoords[localDev];
            // Remote device coordinates might be on another cluster
            let end = deviceCoords[remoteDev];
            
            // If remote device has no explicit data, map it to the coordinates of its metro
            if (!end) {
              const remoteMetro = getMetroOfDevice(remoteDev);
              const base = metroCoordinates[remoteMetro] || { x: 500, y: 300 };
              end = { x: base.x, y: base.y };
            }

            const capBps = linkDetail.capacity_bps || 100000000000;
            const color = getCapacityColor(capBps);
            const width = getCapacityWidth(capBps);

            linksHTML += ` + "`" + `
              <line class="topology-link" 
                x1="${start.x}" y1="${start.y}" 
                x2="${end.x}" y2="${end.y}" 
                stroke="${color}" 
                stroke-width="${width}"
                onclick="selectLink('${localDev}', '${intf}')"
                onmouseenter="showLinkTooltip(event, '${localDev}', '${intf}')"
                onmouseleave="hideTooltip()"
              />
            ` + "`" + `;
          });
        });
        linksGroup.innerHTML = linksHTML;

        // 4. Draw Device Nodes
        const nodesGroup = document.getElementById('device-nodes');
        let nodesHTML = '';

        Object.keys(topologyData).forEach(dev => {
          const coord = deviceCoords[dev];
          const role = getDeviceRole(dev);
          const color = getDeviceColor(role);

          nodesHTML += ` + "`" + `
            <circle class="device-node" id="node-${dev}"
              cx="${coord.x}" cy="${coord.y}" r="6.5" 
              fill="${color}"
              onclick="selectNode('${dev}')"
              onmouseenter="showNodeTooltip(event, '${dev}')"
              onmouseleave="hideTooltip()"
            />
          ` + "`" + `;
        });
        nodesGroup.innerHTML = nodesHTML;

      } catch (err) {
        console.error("Failed to load topology", err);
      }
    }

    // Tooltip Logic
    const tooltip = document.getElementById('tooltip');

    function showNodeTooltip(e, device) {
      const role = getDeviceRole(device).toUpperCase().replace('-', ' ');
      tooltip.innerHTML = ` + "`" + `
        <strong style="color:#eab308">${device}</strong><br/>
        <span style="color:#a1a1aa">Class: ${role}</span><br/>
        <span style="color:#a1a1aa">Location: ${getMetroOfDevice(device).toUpperCase()}</span>
      ` + "`" + `;
      tooltip.style.display = 'block';
      positionTooltip(e);
    }

    function showLinkTooltip(e, localDev, intf) {
      const link = topologyData[localDev][intf];
      tooltip.innerHTML = ` + "`" + `
        <strong>Link: ${localDev} (${intf})</strong><br/>
        <span style="color:#a1a1aa">To Peer: ${link.remote_device}</span><br/>
        <span style="color:#a1a1aa">Capacity: ${link.capacity_human}</span>
      ` + "`" + `;
      tooltip.style.display = 'block';
      positionTooltip(e);
    }

    function positionTooltip(e) {
      tooltip.style.left = (e.clientX + 15) + 'px';
      tooltip.style.top = (e.clientY + 15) + 'px';
    }

    function hideTooltip() {
      tooltip.style.display = 'none';
    }

    // Node & Link Selection Panels
    let selectedNode = null;

    function selectNode(device) {
      // Reset node styles
      document.querySelectorAll('.device-node').forEach(node => {
        node.classList.remove('active');
        node.setAttribute('r', '6.5');
      });

      const circle = document.getElementById(` + "`" + `node-${device}` + "`" + `);
      if (circle) {
        circle.classList.add('active');
        circle.setAttribute('r', '9');
      }

      selectedNode = device;
      const details = topologyData[device];
      const role = getDeviceRole(device).toUpperCase().replace('-', ' ');
      const metro = getMetroOfDevice(device).toUpperCase();

      document.getElementById('info-hostname').textContent = device;
      document.getElementById('info-site').textContent = metroCoordinates[metro.toLowerCase()]?.name || metro;
      document.getElementById('info-role').textContent = role;

      let intfsStr = '';
      Object.keys(details).forEach(intf => {
        const link = details[intf];
        intfsStr += ` + "`" + `${intf} -> ${link.remote_device} (${link.capacity_human})\n` + "`" + `;
      });
      document.getElementById('info-interfaces').textContent = intfsStr || 'No active core-facing links recorded.';
      
      document.getElementById('selection-panel').style.display = 'block';
    }

    function selectLink(localDev, intf) {
      // Programmatically select the local device
      selectNode(localDev);
    }

    document.addEventListener('DOMContentLoaded', loadTopology);
  </script>
</body>
</html>
`
