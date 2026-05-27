package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
)

const defaultPort = "9002"

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
      
      /* High-contrast glowing device colors */
      --color-rr: #00f5ff;       /* Neon Electric Cyan */
      --color-cr-core: #2f72ff;  /* Backbone Core - Intense Cobalt Blue */
      --color-cr-metro: #ccff00; /* Metro Core - Electric Lime/Yellow-Green */
      --color-pr: #00ff66;       /* Peering - Vivid Emerald/Spring Green */
      --color-bng: #ff6c00;      /* BNG - Vibrant Edge Orange */
      --color-unknown: #8a8a93;
      
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
      fill: rgba(15, 23, 42, 0.15);
      stroke: rgba(234, 179, 8, 0.08);
      stroke-width: 2;
      stroke-dasharray: 8, 8;
      filter: drop-shadow(0 0 15px rgba(234, 179, 8, 0.05));
    }

    .metro-bubble {
      fill: rgba(39, 39, 42, 0.45);
      stroke: rgba(255,255,255,0.06);
      stroke-width: 1;
      transition: all 0.25s ease;
      cursor: grab;
    }

    .metro-bubble:active {
      cursor: grabbing;
    }

    .metro-bubble:hover {
      fill: rgba(63, 63, 70, 0.45);
      stroke: rgba(255,255,255,0.15);
    }

    .metro-label {
      font-size: 11px;
      font-weight: 700;
      fill: var(--text-muted);
      letter-spacing: 0.08em;
      pointer-events: none;
      text-shadow: 0 2px 4px rgba(0, 0, 0, 0.8), 0 0 10px rgba(0,0,0,0.9);
    }

    .topology-link {
      stroke-linecap: round;
      transition: opacity 0.25s, stroke-width 0.2s;
      opacity: 0.7;
    }

    .topology-link:hover {
      stroke-width: 6 !important;
      opacity: 1 !important;
      cursor: pointer;
    }

    @keyframes flow-anim {
      to {
        stroke-dashoffset: -16;
      }
    }

    .topology-flow {
      stroke-linecap: round;
      pointer-events: none;
      transition: opacity 0.25s;
    }

    .device-node {
      stroke: var(--bg);
      stroke-width: 1.5;
      cursor: pointer;
      transition: r 0.2s, stroke-width 0.2s, opacity 0.25s;
    }

    .device-node:hover {
      stroke: #ffffff;
      stroke-width: 2.5;
    }

    .device-node.active {
      stroke: #ffffff;
      stroke-width: 3;
      box-shadow: 0 0 25px white;
    }

    /* Dimming overlay for inactive focus highlight */
    .device-node.dimmed,
    .topology-link.dimmed,
    .topology-flow.dimmed {
      opacity: 0.12 !important;
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
          <button class="tab-btn" onclick="resetSelection()" style="width: 100%; margin-top: 12px; padding: 8px; font-size: 13px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); color: #ef4444;">Clear Focus Highlight</button>
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
      "sfo": { x: 70, y: 420, name: "San Francisco, CA" },
      "sjc": { x: 70, y: 470, name: "San Jose, CA" },
      "svl": { x: 70, y: 445, name: "Sunnyvale, CA" },
      "lax": { x: 100, y: 690, name: "Los Angeles, CA" },
      "pih": { x: 300, y: 120, name: "Pocatello, ID" },
      "lgu": { x: 340, y: 210, name: "Logan, UT" },
      "slc": { x: 340, y: 280, name: "Salt Lake City, UT" },
      "las": { x: 260, y: 530, name: "Las Vegas, NV" },
      "phx": { x: 280, y: 710, name: "Phoenix, AZ" },
      "den": { x: 530, y: 360, name: "Denver, CO" },
      "sat": { x: 660, y: 870, name: "San Antonio, TX" },
      "aus": { x: 790, y: 770, name: "Austin, TX" },
      "dfw": { x: 740, y: 590, name: "Dallas-Fort Worth, TX" },
      "oma": { x: 740, y: 240, name: "Omaha, NE" },
      "cbf": { x: 800, y: 250, name: "Council Bluffs, IA" },
      "dsm": { x: 940, y: 200, name: "Des Moines, IA" },
      "mci": { x: 860, y: 420, name: "Kansas City, MO" },
      "jef": { x: 1020, y: 460, name: "Jefferson City, MO" },
      "ord": { x: 1140, y: 180, name: "Chicago, IL" },
      "bna": { x: 1200, y: 540, name: "Nashville, TN" },
      "hsv": { x: 1210, y: 680, name: "Huntsville, AL" },
      "atl": { x: 1240, y: 760, name: "Atlanta, GA" },
      "clt": { x: 1340, y: 580, name: "Charlotte, NC" },
      "rdu": { x: 1460, y: 470, name: "Raleigh-Durham, NC" },
      "iad": { x: 1480, y: 280, name: "Washington D.C." },
      "ewr": { x: 1560, y: 120, name: "Newark, NJ" }
    };

    let topologyData = {};
    let deviceCoords = {};
    let devicesByMetro = {};

    // Drag & Zoom & Node Drag parameters
    const container = document.getElementById('map-container');
    const viewport = document.getElementById('viewport');
    let isDragging = false;
    let startX = 0, startY = 0;
    let posX = 0, posY = 0;
    let scale = 1.0;

    let draggedNode = null;
    let dragOffset = { x: 0, y: 0 };

    let draggedMetro = null;
    let dragMetroStart = { x: 0, y: 0 };

    // Convert client coordinates to local SVG coordinate space
    function getSVGCoords(e) {
      const svg = document.getElementById('map-svg');
      const pt = svg.createSVGPoint();
      pt.x = e.clientX;
      pt.y = e.clientY;
      const svgPoint = pt.matrixTransform(svg.getScreenCTM().inverse());
      return { x: svgPoint.x, y: svgPoint.y };
    }

    function startDragNode(e, device) {
      e.stopPropagation();
      e.preventDefault();
      draggedNode = device;
      const coords = getSVGCoords(e);
      const nodeCoords = deviceCoords[device];
      dragOffset = {
        x: coords.x - nodeCoords.x,
        y: coords.y - nodeCoords.y
      };
      container.style.cursor = 'grabbing';
    }

    function startDragMetro(e, metro) {
      e.stopPropagation();
      e.preventDefault();
      draggedMetro = metro;
      const coords = getSVGCoords(e);
      dragMetroStart = {
        x: coords.x,
        y: coords.y
      };
      container.style.cursor = 'grabbing';
    }

    // SVG zooming handlers
    container.addEventListener('mousedown', (e) => {
      if (e.target.closest('.device-node') || e.target.closest('.metro-bubble')) return; // Don't drag if clicking node or bubble
      isDragging = true;
      startX = e.clientX - posX;
      startY = e.clientY - posY;
      container.style.cursor = 'grabbing';
    });

    window.addEventListener('mouseup', () => {
      isDragging = false;
      draggedNode = null;
      draggedMetro = null;
      container.style.cursor = 'grab';
    });

    container.addEventListener('mousemove', (e) => {
      if (draggedNode) {
        e.preventDefault();
        const coords = getSVGCoords(e);
        const newX = coords.x - dragOffset.x;
        const newY = coords.y - dragOffset.y;

        // Update coordinates in database
        deviceCoords[draggedNode] = { x: newX, y: newY };

        // Update Node Position
        const circle = document.getElementById('node-' + draggedNode);
        if (circle) {
          circle.setAttribute('cx', newX);
          circle.setAttribute('cy', newY);
        }

        // Update connected links & flows (Start side)
        document.querySelectorAll('.topology-link[data-start="' + draggedNode + '"]').forEach(link => {
          link.setAttribute('x1', newX);
          link.setAttribute('y1', newY);
          const flowId = link.id.replace('link-', 'flow-');
          const flow = document.getElementById(flowId);
          if (flow) {
            flow.setAttribute('x1', newX);
            flow.setAttribute('y1', newY);
          }
        });

        // Update connected links & flows (End side)
        document.querySelectorAll('.topology-link[data-end="' + draggedNode + '"]').forEach(link => {
          link.setAttribute('x2', newX);
          link.setAttribute('y2', newY);
          const flowId = link.id.replace('link-', 'flow-');
          const flow = document.getElementById(flowId);
          if (flow) {
            flow.setAttribute('x2', newX);
            flow.setAttribute('y2', newY);
          }
        });
      } else if (draggedMetro) {
        e.preventDefault();
        const coords = getSVGCoords(e);
        const dx = coords.x - dragMetroStart.x;
        const dy = coords.y - dragMetroStart.y;

        if (dx !== 0 || dy !== 0) {
          dragMetroStart = { x: coords.x, y: coords.y };

          // Update metro coordinate data
          const base = metroCoordinates[draggedMetro];
          if (base) {
            base.x += dx;
            base.y += dy;
          }

          // Update metro bubble position in DOM
          const bubble = document.getElementById('bubble-' + draggedMetro);
          if (bubble) {
            const cx = parseFloat(bubble.getAttribute('cx')) + dx;
            const cy = parseFloat(bubble.getAttribute('cy')) + dy;
            bubble.setAttribute('cx', cx);
            bubble.setAttribute('cy', cy);
          }

          // Update metro label position in DOM
          const label = document.getElementById('label-' + draggedMetro);
          if (label) {
            const lx = parseFloat(label.getAttribute('x')) + dx;
            const ly = parseFloat(label.getAttribute('y')) + dy;
            label.setAttribute('x', lx);
            label.setAttribute('y', ly);
          }

          // Shift all nested devices and their links
          const devices = devicesByMetro[draggedMetro] || [];
          devices.forEach(dev => {
            const nodeCoords = deviceCoords[dev];
            if (nodeCoords) {
              nodeCoords.x += dx;
              nodeCoords.y += dy;

              const circle = document.getElementById('node-' + dev);
              if (circle) {
                circle.setAttribute('cx', nodeCoords.x);
                circle.setAttribute('cy', nodeCoords.y);
              }

              // Update connected links & flows (Start side)
              document.querySelectorAll('.topology-link[data-start="' + dev + '"]').forEach(link => {
                link.setAttribute('x1', nodeCoords.x);
                link.setAttribute('y1', nodeCoords.y);
                const flowId = link.id.replace('link-', 'flow-');
                const flow = document.getElementById(flowId);
                if (flow) {
                  flow.setAttribute('x1', nodeCoords.x);
                  flow.setAttribute('y1', nodeCoords.y);
                }
              });

              // Update connected links & flows (End side)
              document.querySelectorAll('.topology-link[data-end="' + dev + '"]').forEach(link => {
                link.setAttribute('x2', nodeCoords.x);
                link.setAttribute('y2', nodeCoords.y);
                const flowId = link.id.replace('link-', 'flow-');
                const flow = document.getElementById(flowId);
                if (flow) {
                  flow.setAttribute('x2', nodeCoords.x);
                  flow.setAttribute('y2', nodeCoords.y);
                }
              });
            }
          });
        }
      } else if (isDragging) {
        posX = e.clientX - startX;
        posY = e.clientY - startY;
        updateViewportTransform();
      }
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
        
        // 1. Group ALL unique devices (both local and discovered remote peers!) by metro
        const allDevices = new Set(Object.keys(topologyData));
        Object.keys(topologyData).forEach(localDev => {
          const intfs = topologyData[localDev];
          Object.keys(intfs).forEach(intf => {
            const remoteDev = intfs[intf].remote_device;
            if (remoteDev && remoteDev !== "unknown") {
              allDevices.add(remoteDev);
            }
          });
        });

        devicesByMetro = {};
        allDevices.forEach(device => {
          const metro = getMetroOfDevice(device);
          devicesByMetro[metro] = devicesByMetro[metro] || [];
          devicesByMetro[metro].push(device);
        });

        // 2. Calculate coordinates for ALL device nodes (including peers)
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
          bubblesHTML += ` + "`" + `<circle class="metro-bubble" id="bubble-${metro}" data-metro="${metro}" cx="${base.x}" cy="${base.y}" r="${bubbleRadius}" onmousedown="startDragMetro(event, '${metro}')" />` + "`" + `;
          
          // Draw Metro Label
          labelsHTML += ` + "`" + `<text class="metro-label" id="label-${metro}" x="${base.x}" y="${base.y + bubbleRadius + 14}" text-anchor="middle">${metro.toUpperCase()}</text>` + "`" + `;

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

            const linkKey = [localDev, remoteDev].sort().join('---');
            if (drawnLinks.has(linkKey)) return;
            drawnLinks.add(linkKey);

            const start = deviceCoords[localDev];
            let end = deviceCoords[remoteDev];
            
            if (!end) {
              const remoteMetro = getMetroOfDevice(remoteDev);
              const base = metroCoordinates[remoteMetro] || { x: 500, y: 300 };
              end = { x: base.x, y: base.y };
            }

            const capBps = linkDetail.capacity_bps || 100000000000;
            const color = getCapacityColor(capBps);
            const width = getCapacityWidth(capBps);

            linksHTML += ` + "`" + `
              <line class="topology-link" id="link-${linkKey}"
                data-start="${localDev}" data-end="${remoteDev}"
                x1="${start.x}" y1="${start.y}" 
                x2="${end.x}" y2="${end.y}" 
                stroke="${color}" 
                stroke-width="${width}"
                onclick="selectLink('${localDev}', '${intf}')"
                onmouseenter="showLinkTooltip(event, '${localDev}', '${intf}')"
                onmouseleave="hideTooltip()"
              />
              <line class="topology-flow" id="flow-${linkKey}"
                x1="${start.x}" y1="${start.y}" 
                x2="${end.x}" y2="${end.y}" 
                stroke="rgba(255, 255, 255, 0.5)" 
                stroke-width="${Math.max(1.0, width * 0.25)}"
                stroke-dasharray="6, 10"
                style="animation: flow-anim 1.5s linear infinite; pointer-events: none;"
              />
            ` + "`" + `;
          });
        });
        linksGroup.innerHTML = linksHTML;

        // Helper for sizing nodes hierarchically
        function getNodeRadius(role) {
          if (role === "cr-backbone" || role === "cr-metro" || role === "rr") return 9.5;
          if (role === "pr") return 7.5;
          return 5.5; // BNG
        }

        // 4. Draw Device Nodes (Local + Discovered Peers)
        const nodesGroup = document.getElementById('device-nodes');
        let nodesHTML = '';

        allDevices.forEach(dev => {
          const coord = deviceCoords[dev];
          const role = getDeviceRole(dev);
          const color = getDeviceColor(role);
          const radius = getNodeRadius(role);

          nodesHTML += ` + "`" + `
            <circle class="device-node" id="node-${dev}"
              cx="${coord.x}" cy="${coord.y}" r="${radius}" 
              fill="${color}"
              onmousedown="startDragNode(event, '${dev}')"
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

    // Links Tooltip Logic
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
      // Helper for sizing nodes hierarchically
      function getNodeRadius(role) {
        if (role === "cr-backbone" || role === "cr-metro" || role === "rr") return 9.5;
        if (role === "pr") return 7.5;
        return 5.5; // BNG
      }

      // Reset all dimming and active classes
      document.querySelectorAll('.device-node').forEach(node => {
        node.classList.remove('active', 'dimmed');
        const devName = node.id.replace('node-', '');
        const role = getDeviceRole(devName);
        node.setAttribute('r', getNodeRadius(role));
      });
      document.querySelectorAll('.topology-link, .topology-flow').forEach(el => {
        el.classList.remove('dimmed');
      });

      const circle = document.getElementById(` + "`" + `node-${device}` + "`" + `);
      if (circle) {
        circle.classList.add('active');
        const role = getDeviceRole(device);
        circle.setAttribute('r', getNodeRadius(role) + 3);
      }

      selectedNode = device;
      const details = topologyData[device] || {};
      const role = getDeviceRole(device).toUpperCase().replace('-', ' ');
      const metro = getMetroOfDevice(device).toUpperCase();

      document.getElementById('info-hostname').textContent = device;
      document.getElementById('info-site').textContent = metroCoordinates[metro.toLowerCase()]?.name || metro;
      document.getElementById('info-role').textContent = role;

      const connectedDevices = new Set();
      let intfsStr = '';
      
      // 1. Map outgoing connections if this device responded to audit
      Object.keys(details).forEach(intf => {
        const link = details[intf];
        connectedDevices.add(link.remote_device);
        intfsStr += ` + "`" + `${intf} -> ${link.remote_device} (${link.capacity_human})\n` + "`" + `;
      });

      // 2. Scan other audited devices for incoming connections pointing to this device
      Object.keys(topologyData).forEach(localDev => {
        const intfs = topologyData[localDev];
        Object.keys(intfs).forEach(intf => {
          if (intfs[intf].remote_device === device) {
            connectedDevices.add(localDev);
            intfsStr += ` + "`" + `[Peer] ${localDev} (${intf}) -> This Device (${intfs[intf].capacity_human})\n` + "`" + `;
          }
        });
      });

      document.getElementById('info-interfaces').textContent = intfsStr || 'Device was unreachable during audit cycle.';
      
      // Dim out non-connected nodes
      document.querySelectorAll('.device-node').forEach(node => {
        const devName = node.id.replace('node-', '');
        if (devName !== device && !connectedDevices.has(devName)) {
          node.classList.add('dimmed');
        }
      });

      // Dim out non-connected links and their flows
      document.querySelectorAll('.topology-link').forEach(link => {
        const startDev = link.getAttribute('data-start');
        const endDev = link.getAttribute('data-end');
        if (startDev !== device && endDev !== device) {
          link.classList.add('dimmed');
          const flowId = link.id.replace('link-', 'flow-');
          const flow = document.getElementById(flowId);
          if (flow) flow.classList.add('dimmed');
        }
      });

      document.getElementById('selection-panel').style.display = 'block';
    }

    function selectLink(localDev, intf) {
      selectNode(localDev);
    }

    function resetSelection() {
      function getNodeRadius(role) {
        if (role === "cr-backbone" || role === "cr-metro" || role === "rr") return 9.5;
        if (role === "pr") return 7.5;
        return 5.5; // BNG
      }

      selectedNode = null;
      document.querySelectorAll('.device-node').forEach(node => {
        node.classList.remove('active', 'dimmed');
        const devName = node.id.replace('node-', '');
        const role = getDeviceRole(devName);
        node.setAttribute('r', getNodeRadius(role));
      });
      document.querySelectorAll('.topology-link, .topology-flow').forEach(el => {
        el.classList.remove('dimmed');
      });
      document.getElementById('selection-panel').style.display = 'none';
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
