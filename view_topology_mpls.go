package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Data Structures for Topology
type MplsInterfaceDetails struct {
	LocalInterface  string   `json:"local_interface"`
	LocalIP         string   `json:"local_ip"`
	RemoteDevice    string   `json:"remote_device"`
	RemoteInterface string   `json:"remote_interface"`
	RemoteIP        string   `json:"remote_ip"`
	CapacityBps     int64    `json:"capacity_bps"`
	CapacityHuman   string   `json:"capacity_human"`
	Members         []string `json:"members"`
	LoopbackIP      string   `json:"loopback_ip"`
}

type MplsTopologyNode map[string]MplsInterfaceDetails

type MplsTopologyReport map[string]MplsTopologyNode

// Data Structures for LSP Details
type RawLspDetails struct {
	MaxAvgBwUtil   interface{} `json:"max_avg_bw_util"`
	TraceroutePath []string    `json:"traceroute_path"`
	LspInterfaceIPs interface{} `json:"lsp_interface_ips"`
	IsShortestPath bool        `json:"is_shortest_path"`
	PathType       string      `json:"path_type"`
}

type RawLspEntry struct {
	From          string        `json:"from"`
	To            string        `json:"to"`
	IngressRouter string        `json:"ingress_router"`
	EgressRouter  string        `json:"egress_router"`
	LspNumber     string        `json:"lsp_number"`
	Details       RawLspDetails `json:"details"`
}

type LspSummary struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	From           string   `json:"from"`
	To             string   `json:"to"`
	IngressRouter  string   `json:"ingress_router"`
	EgressRouter   string   `json:"egress_router"`
	LspNumber      string   `json:"lsp_number"`
	BwStr          string   `json:"bw_str"`
	BwGbps         float64  `json:"bw_gbps"`
	IsShortestPath bool     `json:"is_shortest_path"`
	PathType       string   `json:"path_type"`
	LspIps         []string `json:"lsp_ips"`
	TracerouteIps  []string `json:"traceroute_ips"`
	LspHops        []string `json:"lsp_hops"`
	TracerouteHops []string `json:"traceroute_hops"`
}

// In-memory Caches & IP Lookup Table
var (
	mplsTopologyData   MplsTopologyReport
	mplsTopologyDataMu sync.RWMutex

	ipToDeviceMap   map[string]string
	ipToDeviceMapMu sync.RWMutex

	lspCache   map[string][]LspSummary
	lspCacheMu sync.RWMutex
)

// Helper to strip CIDR prefix and clean IP
func defCleanIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if idx := strings.Index(ip, "/"); idx != -1 {
		return ip[:idx]
	}
	return ip
}

// Build IP -> Hostname lookup table from topology_discovery_mpls.json
func buildIpToDeviceMap(topo MplsTopologyReport) map[string]string {
	m := make(map[string]string)

	for devName, node := range topo {
		normDev := strings.ToLower(strings.TrimSpace(devName))
		for _, intf := range node {
			if intf.LoopbackIP != "" {
				m[defCleanIP(intf.LoopbackIP)] = normDev
			}
			if intf.LocalIP != "" {
				m[defCleanIP(intf.LocalIP)] = normDev
			}
			if intf.RemoteIP != "" && intf.RemoteDevice != "" {
				m[defCleanIP(intf.RemoteIP)] = strings.ToLower(strings.TrimSpace(intf.RemoteDevice))
			}
		}
	}
	return m
}

func parseBwGbps(bwStr string) float64 {
	bwStr = strings.TrimSpace(bwStr)
	re := regexp.MustCompile(`(?i)([\d.]+)\s*([GMK]?bps|Gbps|Mbps|Kbps|bps)`)
	match := re.FindStringSubmatch(bwStr)
	if len(match) < 3 {
		return 0
	}
	val, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0
	}
	unit := strings.ToLower(match[2])
	switch unit {
	case "gbps", "gb":
		return val
	case "mbps", "mb":
		return val / 1000.0
	case "kbps", "kb":
		return val / 1000000.0
	case "bps":
		return val / 1000000000.0
	default:
		return val
	}
}

func mapIpsToHops(ips []string, ingressHost string, egressHost string, ipMap map[string]string) []string {
	var hops []string

	normIngress := strings.ToLower(strings.TrimSpace(ingressHost))
	if normIngress != "" {
		hops = append(hops, normIngress)
	}

	for _, rawIp := range ips {
		clean := defCleanIP(rawIp)
		if dev, exists := ipMap[clean]; exists {
			dev = strings.ToLower(dev)
			if len(hops) == 0 || hops[len(hops)-1] != dev {
				hops = append(hops, dev)
			}
		}
	}

	normEgress := strings.ToLower(strings.TrimSpace(egressHost))
	if normEgress != "" {
		if len(hops) == 0 || hops[len(hops)-1] != normEgress {
			hops = append(hops, normEgress)
		}
	}

	return hops
}

func loadLspDataForDate(targetDate string) ([]LspSummary, error) {
	lspCacheMu.RLock()
	if cached, ok := lspCache[targetDate]; ok {
		lspCacheMu.RUnlock()
		return cached, nil
	}
	lspCacheMu.RUnlock()

	baseDir := "Json_lsp_folder"
	dateDir := filepath.Join(baseDir, targetDate)

	if _, err := os.Stat(dateDir); os.IsNotExist(err) {
		// Fallback to checking inside baseDir directly
		dateDir = baseDir
	}

	ipToDeviceMapMu.RLock()
	ipMap := ipToDeviceMap
	ipToDeviceMapMu.RUnlock()

	var summaries []LspSummary

	err := filepath.Walk(dateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		var rawDict map[string]RawLspEntry
		if err := json.Unmarshal(data, &rawDict); err != nil {
			return nil
		}

		for lspName, entry := range rawDict {
			bwStr := ""
			switch v := entry.Details.MaxAvgBwUtil.(type) {
			case []interface{}:
				if len(v) > 0 {
					bwStr = fmt.Sprintf("%v", v[len(v)-1])
				}
			case string:
				bwStr = v
			}

			bwGbps := parseBwGbps(bwStr)

			var lspIps []string
			switch v := entry.Details.LspInterfaceIPs.(type) {
			case []interface{}:
				for _, elem := range v {
					switch sub := elem.(type) {
					case []interface{}:
						for _, ipVal := range sub {
							lspIps = append(lspIps, fmt.Sprintf("%v", ipVal))
						}
					case string:
						lspIps = append(lspIps, sub)
					}
				}
			}

			tracerouteIps := entry.Details.TraceroutePath

			// Map IPs to router hostnames
			lspHops := mapIpsToHops(lspIps, entry.IngressRouter, entry.EgressRouter, ipMap)
			tracerouteHops := mapIpsToHops(tracerouteIps, entry.IngressRouter, entry.EgressRouter, ipMap)

			isShortest := entry.Details.IsShortestPath
			pathType := entry.Details.PathType

			// Additional check: if hop counts differ, mark as non-shortest
			if len(lspHops) > len(tracerouteHops) && len(tracerouteHops) > 1 {
				isShortest = false
				if pathType == "" || pathType == "shortest path" {
					pathType = "longer path"
				}
			}

			summary := LspSummary{
				ID:             lspName,
				Name:           lspName,
				From:           entry.From,
				To:             entry.To,
				IngressRouter:  entry.IngressRouter,
				EgressRouter:   entry.EgressRouter,
				LspNumber:      entry.LspNumber,
				BwStr:          bwStr,
				BwGbps:         bwGbps,
				IsShortestPath: isShortest,
				PathType:       pathType,
				LspIps:         lspIps,
				TracerouteIps:  tracerouteIps,
				LspHops:        lspHops,
				TracerouteHops: tracerouteHops,
			}
			summaries = append(summaries, summary)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Sort descending by bandwidth
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].BwGbps > summaries[j].BwGbps
	})

	lspCacheMu.Lock()
	if lspCache == nil {
		lspCache = make(map[string][]LspSummary)
	}
	lspCache[targetDate] = summaries
	lspCacheMu.Unlock()

	return summaries, nil
}

func getAvailableLspDates() []string {
	baseDir := "Json_lsp_folder"
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return []string{}
	}

	var dates []string
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			dates = append(dates, entry.Name())
		}
	}

	sort.Slice(dates, func(i, j int) bool {
		return dates[i] > dates[j] // Newest date first
	})

	return dates
}

func loadMplsTopology() error {
	jsonPath := "topology_discovery_mpls.json"
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		jsonPath = filepath.Join(".", "topology_discovery_mpls.json")
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", jsonPath, err)
	}

	var report MplsTopologyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("failed to parse %s: %w", jsonPath, err)
	}

	mplsTopologyDataMu.Lock()
	mplsTopologyData = report
	mplsTopologyDataMu.Unlock()

	ipMap := buildIpToDeviceMap(report)
	ipToDeviceMapMu.Lock()
	ipToDeviceMap = ipMap
	ipToDeviceMapMu.Unlock()

	return nil
}

func main() {
	port := flag.Int("port", 9005, "Port to run the MPLS topology web server on")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if err := loadMplsTopology(); err != nil {
		logger.Error("Failed to load MPLS topology JSON", "error", err)
	} else {
		logger.Info("Loaded topology_discovery_mpls.json successfully")
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		tmpl, err := template.New("index").Parse(htmlTemplate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl.Execute(w, nil)
	})

	http.HandleFunc("/api/topology", func(w http.ResponseWriter, r *http.Request) {
		mplsTopologyDataMu.RLock()
		defer mplsTopologyDataMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mplsTopologyData)
	})

	http.HandleFunc("/api/lsp_dates", func(w http.ResponseWriter, r *http.Request) {
		dates := getAvailableLspDates()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"dates": dates})
	})

	http.HandleFunc("/api/lsps", func(w http.ResponseWriter, r *http.Request) {
		targetDate := r.URL.Query().Get("date")
		dates := getAvailableLspDates()
		if targetDate == "" && len(dates) > 0 {
			targetDate = dates[0]
		}

		lsps, err := loadLspDataForDate(targetDate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(lsps)
	})

	addr := fmt.Sprintf(":%d", *port)
	logger.Info("Starting Gfiber MPLS Core Network Topology", "port", *port, "url", fmt.Sprintf("http://localhost:%d", *port))
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gfiber MPLS Core Network Topology</title>
  <meta name="description" content="Gfiber MPLS Core Network Topology Dashboard for LSP path analysis, bandwidth utilization, and IGP shortest path comparison.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #090d16;
      --panel-bg: rgba(15, 23, 42, 0.85);
      --panel-border: rgba(255, 255, 255, 0.08);
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --cyan: #06b6d4;
      --cyan-glow: rgba(6, 182, 212, 0.35);
      --orange: #f97316;
      --orange-glow: rgba(249, 115, 22, 0.35);
      --red: #ef4444;
      --green: #10b981;
      --purple: #8b5cf6;
      --yellow: #eab308;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg-dark);
      color: var(--text-main);
      overflow: hidden;
      height: 100vh;
      width: 100vw;
    }

    #app-container {
      display: flex;
      height: 100vh;
      width: 100vw;
    }

    /* Sidebar Navigation & Controls */
    #sidebar {
      width: 440px;
      background: var(--panel-bg);
      backdrop-filter: blur(16px);
      border-right: 1px solid var(--panel-border);
      display: flex;
      flex-direction: column;
      z-index: 20;
      box-shadow: 10px 0 30px rgba(0,0,0,0.5);
    }

    .sidebar-header {
      padding: 18px 20px;
      border-bottom: 1px solid var(--panel-border);
      background: rgba(0,0,0,0.2);
    }

    .app-title {
      font-size: 16px;
      font-weight: 800;
      letter-spacing: -0.02em;
      background: linear-gradient(135deg, #38bdf8, #818cf8, #c084fc);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .badge-tag {
      font-size: 10px;
      font-family: 'JetBrains Mono', monospace;
      padding: 2px 8px;
      border-radius: 4px;
      background: rgba(6, 182, 212, 0.15);
      color: var(--cyan);
      border: 1px solid rgba(6, 182, 212, 0.3);
      font-weight: 600;
    }

    /* Filter Tabs */
    .tab-container {
      display: flex;
      background: rgba(0,0,0,0.3);
      border-bottom: 1px solid var(--panel-border);
    }

    .tab-btn {
      flex: 1;
      padding: 12px 14px;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }

    .tab-btn:hover {
      color: var(--text-main);
      background: rgba(255,255,255,0.03);
    }

    .tab-btn.active {
      color: #38bdf8;
      border-bottom-color: #38bdf8;
      background: rgba(56, 189, 248, 0.08);
    }

    .tab-count {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      padding: 1px 6px;
      border-radius: 10px;
      background: rgba(255,255,255,0.1);
    }

    .tab-btn.active .tab-count {
      background: rgba(56, 189, 248, 0.25);
      color: #7dd3fc;
    }

    /* Filter Controls Section */
    .filter-controls {
      padding: 14px 20px;
      background: rgba(0,0,0,0.15);
      border-bottom: 1px solid var(--panel-border);
    }

    .control-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
    }

    .control-label {
      font-size: 11px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .slider-container {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    input[type="range"] {
      flex: 1;
      accent-color: var(--cyan);
      cursor: pointer;
    }

    .val-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      font-weight: 700;
      color: var(--cyan);
      min-width: 60px;
      text-align: right;
    }

    .search-box {
      width: 100%;
      background: rgba(0,0,0,0.3);
      border: 1px solid var(--panel-border);
      border-radius: 8px;
      padding: 8px 12px;
      color: var(--text-main);
      font-size: 12px;
      outline: none;
      transition: border 0.2s;
    }

    .search-box:focus {
      border-color: var(--cyan);
    }

    /* LSP Cards List */
    .lsp-list {
      flex: 1;
      overflow-y: auto;
      padding: 12px 16px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .lsp-card {
      background: rgba(255,255,255,0.03);
      border: 1px solid var(--panel-border);
      border-radius: 10px;
      padding: 12px 14px;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .lsp-card:hover {
      background: rgba(255,255,255,0.07);
      border-color: rgba(6, 182, 212, 0.4);
      transform: translateY(-1px);
    }

    .lsp-card.selected {
      background: rgba(6, 182, 212, 0.12);
      border-color: var(--cyan);
      box-shadow: 0 0 15px rgba(6, 182, 212, 0.2);
    }

    .lsp-card.selected-longer {
      background: rgba(249, 115, 22, 0.12);
      border-color: var(--orange);
      box-shadow: 0 0 15px rgba(249, 115, 22, 0.2);
    }

    .card-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }

    .lsp-name {
      font-size: 12px;
      font-weight: 700;
      color: #fafafa;
      font-family: 'JetBrains Mono', monospace;
    }

    .bw-tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      font-weight: 700;
      color: #38bdf8;
      background: rgba(56, 189, 248, 0.15);
      padding: 2px 6px;
      border-radius: 4px;
    }

    .card-path-info {
      font-size: 11px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .status-badge {
      font-size: 10px;
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }

    .status-badge.shortest {
      background: rgba(16, 185, 129, 0.15);
      color: var(--green);
      border: 1px solid rgba(16, 185, 129, 0.3);
    }

    .status-badge.longer {
      background: rgba(249, 115, 22, 0.15);
      color: var(--orange);
      border: 1px solid rgba(249, 115, 22, 0.3);
    }

    /* Main SVG Canvas Area */
    #canvas-container {
      flex: 1;
      position: relative;
      background: radial-gradient(circle at 50% 50%, #111827 0%, #090d16 100%);
      overflow: hidden;
    }

    svg#topology-svg {
      width: 100%;
      height: 100%;
      cursor: grab;
    }

    svg#topology-svg:active { cursor: grabbing; }

    /* Legend Overlay */
    .map-legend {
      position: absolute;
      top: 20px;
      right: 20px;
      background: var(--panel-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--panel-border);
      border-radius: 10px;
      padding: 12px 16px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      z-index: 10;
      font-size: 11px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.4);
    }

    .legend-item {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .legend-line {
      width: 24px;
      height: 3px;
      border-radius: 2px;
    }

    .legend-line.lsp { background: var(--cyan); box-shadow: 0 0 8px var(--cyan); }
    .legend-line.traceroute { background: var(--orange); border-top: 1px dashed var(--orange); }

    /* Floating Diagnostic Panel */
    #lsp-diag-panel {
      position: absolute;
      bottom: 24px;
      right: 24px;
      width: 420px;
      background: var(--panel-bg);
      backdrop-filter: blur(16px);
      border: 1px solid var(--panel-border);
      border-radius: 14px;
      padding: 18px 20px;
      z-index: 15;
      box-shadow: 0 20px 40px rgba(0,0,0,0.6);
      display: none;
      animation: slideUp 0.3s ease-out;
    }

    @keyframes slideUp {
      from { transform: translateY(20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    .diag-title {
      font-size: 14px;
      font-weight: 700;
      color: var(--text-main);
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .hop-pills {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 6px;
    }

    .hop-pill {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 6px;
      background: rgba(255,255,255,0.06);
      border: 1px solid var(--panel-border);
      color: var(--text-main);
    }

    .hop-pill.lsp-hop { background: rgba(6, 182, 212, 0.15); border-color: rgba(6, 182, 212, 0.3); color: #67e8f9; }
    .hop-pill.tr-hop { background: rgba(249, 115, 22, 0.15); border-color: rgba(249, 115, 22, 0.3); color: #fdba74; }

    /* SVG Nodes & Links */
    .link-line { stroke: #334155; stroke-width: 1.5; opacity: 0.4; }
    .node-group { cursor: pointer; transition: transform 0.2s; }
    .node-group:hover { transform: scale(1.15); }
    .node-rect { stroke-width: 2; rx: 6px; ry: 6px; }

    .lsp-path-line {
      stroke: var(--cyan);
      stroke-width: 3.5;
      stroke-linecap: round;
      filter: drop-shadow(0 0 6px var(--cyan-glow));
    }

    .traceroute-path-line {
      stroke: var(--orange);
      stroke-width: 3.5;
      stroke-dasharray: 6, 6;
      stroke-linecap: round;
      filter: drop-shadow(0 0 6px var(--orange-glow));
    }
  </style>
</head>
<body>
  <div id="app-container">
    <!-- Sidebar -->
    <div id="sidebar">
      <div class="sidebar-header">
        <div class="app-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" stroke-width="2.5">
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
          </svg>
          <span>Gfiber MPLS Topology</span>
          <span class="badge-tag">MPLS & IGP</span>
        </div>
      </div>

      <!-- Filter Tabs -->
      <div class="tab-container">
        <button class="tab-btn active" id="tab-bw" onclick="switchTab('bw')">
          <span>⚡ High Bandwidth</span>
          <span class="tab-count" id="count-bw">0</span>
        </button>
        <button class="tab-btn" id="tab-longer" onclick="switchTab('longer')">
          <span>⚠️ Non-Shortest Paths</span>
          <span class="tab-count" id="count-longer">0</span>
        </button>
      </div>

      <!-- Filter Controls -->
      <div class="filter-controls">
        <div class="control-row">
          <span class="control-label">LSP Audit Date</span>
          <select id="lsp-date-select" class="search-box" style="width: 140px; padding: 4px 8px;" onchange="loadLspData(this.value)"></select>
        </div>

        <div id="bw-slider-box">
          <div class="control-row" style="margin-top: 10px;">
            <span class="control-label">Min Bandwidth</span>
            <span class="val-badge" id="bw-val-display">1.0 Gbps</span>
          </div>
          <div class="slider-container">
            <input type="range" id="bw-threshold-slider" min="0" max="80" step="0.5" value="1.0" oninput="onBwSliderChange(this.value)">
          </div>
        </div>

        <div style="margin-top: 10px;">
          <input type="text" class="search-box" id="lsp-search-input" placeholder="Search LSP name, Ingress, Egress..." oninput="onSearchInput(this.value)">
        </div>
      </div>

      <!-- LSP Cards List -->
      <div class="lsp-list" id="lsp-list-container"></div>
    </div>

    <!-- Canvas -->
    <div id="canvas-container">
      <div class="map-legend">
        <div class="legend-item">
          <div class="legend-line lsp"></div>
          <span>LSP Path (MPLS Traffic Engine)</span>
        </div>
        <div class="legend-item">
          <div class="legend-line traceroute"></div>
          <span>Traceroute Path (IGP Shortest Path)</span>
        </div>
      </div>

      <svg id="topology-svg">
        <defs>
          <marker id="arrow-cyan" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#06b6d4" />
          </marker>
          <marker id="arrow-orange" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#f97316" />
          </marker>
        </defs>

        <g id="zoom-group">
          <g id="links-layer"></g>
          <g id="path-layer"></g>
          <g id="nodes-layer"></g>
        </g>
      </svg>

      <!-- Diagnostic Panel -->
      <div id="lsp-diag-panel">
        <div class="diag-title">
          <span id="diag-lsp-name">LSP Details</span>
          <span class="status-badge" id="diag-status-badge"></span>
        </div>
        <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">
          Bandwidth: <span style="color: #38bdf8; font-weight:700;" id="diag-bw-val"></span> | 
          Ingress: <span style="color:#fff;" id="diag-ingress"></span> ➔ Egress: <span style="color:#fff;" id="diag-egress"></span>
        </div>

        <div style="margin-bottom: 10px;">
          <div style="font-size: 11px; font-weight:700; color: var(--cyan); margin-bottom: 4px;">LSP Traversed Hops:</div>
          <div class="hop-pills" id="diag-lsp-hops"></div>
        </div>

        <div id="diag-tr-section">
          <div style="font-size: 11px; font-weight:700; color: var(--orange); margin-bottom: 4px;">IGP Traceroute Shortest Path Hops:</div>
          <div class="hop-pills" id="diag-tr-hops"></div>
        </div>
      </div>
    </div>
  </div>

  <script>
    let topologyData = {};
    let allLsps = [];
    let activeTab = 'bw';
    let minBwGbps = 1.0;
    let searchQuery = '';
    let selectedLsp = null;
    let deviceCoords = {};

    const metroCoordinates = {
      "ATL": { x: 950, y: 480, width: 280, height: 220 },
      "AUS": { x: 550, y: 560, width: 280, height: 220 },
      "MCI": { x: 550, y: 320, width: 280, height: 220 },
      "SJC": { x: 120, y: 300, width: 280, height: 220 },
      "DFW": { x: 550, y: 440, width: 280, height: 220 },
      "ORD": { x: 750, y: 220, width: 280, height: 220 },
      "IAD": { x: 1050, y: 280, width: 280, height: 220 },
      "RDU": { x: 1050, y: 400, width: 280, height: 220 },
      "CLT": { x: 950, y: 360, width: 280, height: 220 },
      "DEN": { x: 360, y: 320, width: 280, height: 220 },
      "SAT": { x: 550, y: 680, width: 280, height: 220 },
      "LAS": { x: 240, y: 420, width: 280, height: 220 },
      "LAX": { x: 120, y: 480, width: 280, height: 220 },
      "PHX": { x: 240, y: 560, width: 280, height: 220 },
      "EWR": { x: 1150, y: 220, width: 280, height: 220 },
      "NUQ": { x: 120, y: 200, width: 280, height: 220 }
    };

    function getMetroOfDevice(device) {
      if (!device) return "OTHER";
      const dev = device.toUpperCase();
      for (const m of Object.keys(metroCoordinates)) {
        if (dev.includes(m)) return m;
      }
      return "OTHER";
    }

    async function initApp() {
      await loadTopology();
      await loadDates();
      await loadLspData();
    }

    async function loadTopology() {
      try {
        const resp = await fetch('/api/topology');
        topologyData = await resp.json();
        renderTopologyMap();
      } catch (err) {
        console.error("Failed to load topology", err);
      }
    }

    async function loadDates() {
      try {
        const resp = await fetch('/api/lsp_dates');
        const data = await resp.json();
        const select = document.getElementById('lsp-date-select');
        select.innerHTML = '';
        if (data.dates && data.dates.length > 0) {
          data.dates.forEach(d => {
            const opt = document.createElement('option');
            opt.value = d;
            opt.textContent = d;
            select.appendChild(opt);
          });
        }
      } catch (err) {
        console.error("Failed to load dates", err);
      }
    }

    async function loadLspData(dateStr) {
      try {
        const url = dateStr ? '/api/lsps?date=' + encodeURIComponent(dateStr) : '/api/lsps';
        const resp = await fetch(url);
        allLsps = await resp.json();
        updateTabCounts();
        renderLspCards();
      } catch (err) {
        console.error("Failed to load LSPs", err);
      }
    }

    function switchTab(tab) {
      activeTab = tab;
      document.getElementById('tab-bw').classList.toggle('active', tab === 'bw');
      document.getElementById('tab-longer').classList.toggle('active', tab === 'longer');
      document.getElementById('bw-slider-box').style.display = (tab === 'bw') ? 'block' : 'none';
      renderLspCards();
    }

    function onBwSliderChange(val) {
      minBwGbps = parseFloat(val);
      document.getElementById('bw-val-display').textContent = minBwGbps.toFixed(1) + ' Gbps';
      renderLspCards();
    }

    function onSearchInput(query) {
      searchQuery = query.toLowerCase().trim();
      renderLspCards();
    }

    function getFilteredLsps() {
      return allLsps.filter(lsp => {
        if (activeTab === 'bw') {
          if (lsp.bw_gbps < minBwGbps) return false;
        } else if (activeTab === 'longer') {
          if (lsp.is_shortest_path) return false;
        }

        if (searchQuery) {
          const nameMatch = lsp.name.toLowerCase().includes(searchQuery);
          const ingMatch = lsp.ingress_router.toLowerCase().includes(searchQuery);
          const egMatch = lsp.egress_router.toLowerCase().includes(searchQuery);
          if (!nameMatch && !ingMatch && !egMatch) return false;
        }
        return true;
      });
    }

    function updateTabCounts() {
      const bwCount = allLsps.filter(l => l.bw_gbps >= minBwGbps).length;
      const longerCount = allLsps.filter(l => !l.is_shortest_path).length;
      document.getElementById('count-bw').textContent = bwCount;
      document.getElementById('count-longer').textContent = longerCount;
    }

    function renderLspCards() {
      const container = document.getElementById('lsp-list-container');
      const filtered = getFilteredLsps();
      container.innerHTML = '';

      if (filtered.length === 0) {
        container.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-muted); font-size:12px;">No LSPs match current filter criteria.</div>';
        return;
      }

      filtered.forEach(lsp => {
        const card = document.createElement('div');
        const isSelected = selectedLsp && selectedLsp.id === lsp.id;
        card.className = 'lsp-card' + (isSelected ? (lsp.is_shortest_path ? ' selected' : ' selected-longer') : '');

        const statusBadge = lsp.is_shortest_path ? 
          '<span class="status-badge shortest">✓ Shortest Path</span>' : 
          '<span class="status-badge longer">⚠️ Non-Shortest</span>';

        card.innerHTML = 
          '<div class="card-top">' +
            '<span class="lsp-name">' + lsp.ingress_router.toUpperCase() + ' ➔ ' + lsp.egress_router.toUpperCase() + '</span>' +
            '<span class="bw-tag">' + lsp.bw_str + '</span>' +
          '</div>' +
          '<div class="card-path-info">' +
            '<span>' + lsp.lsp_number + '</span>' +
            statusBadge +
          '</div>';

        card.onclick = () => selectLsp(lsp);
        container.appendChild(card);
      });
    }

    function selectLsp(lsp) {
      selectedLsp = lsp;
      renderLspCards();
      highlightPathsOnMap(lsp);
      showDiagnosticPanel(lsp);
    }

    function renderTopologyMap() {
      const nodesLayer = document.getElementById('nodes-layer');
      const linksLayer = document.getElementById('links-layer');
      nodesLayer.innerHTML = '';
      linksLayer.innerHTML = '';

      // Compute Node Coordinates
      const devicesByMetro = {};
      Object.keys(topologyData).forEach(dev => {
        const m = getMetroOfDevice(dev);
        devicesByMetro[m] = devicesByMetro[m] || [];
        devicesByMetro[m].push(dev);
      });

      deviceCoords = {};

      Object.keys(devicesByMetro).forEach(metro => {
        const base = metroCoordinates[metro] || { x: 600, y: 400, width: 280, height: 220 };
        const devs = devicesByMetro[metro];
        
        devs.forEach((dev, idx) => {
          const row = Math.floor(idx / 2);
          const col = idx % 2;
          const cx = base.x + 60 + col * 140;
          const cy = base.y + 50 + row * 60;
          deviceCoords[dev.toLowerCase()] = { x: cx, y: cy, name: dev };
        });
      });

      // Render Static Links
      const drawnLinks = new Set();
      Object.keys(topologyData).forEach(dev => {
        const srcCoord = deviceCoords[dev.toLowerCase()];
        if (!srcCoord) return;

        const intfs = topologyData[dev];
        Object.keys(intfs).forEach(intfName => {
          const link = intfs[intfName];
          const remDev = link.remote_device ? link.remote_device.toLowerCase() : '';
          const dstCoord = deviceCoords[remDev];

          if (dstCoord) {
            const pairKey = [dev.toLowerCase(), remDev].sort().join('--');
            if (!drawnLinks.has(pairKey)) {
              drawnLinks.add(pairKey);
              const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
              line.setAttribute('class', 'link-line');
              line.setAttribute('x1', srcCoord.x);
              line.setAttribute('y1', srcCoord.y);
              line.setAttribute('x2', dstCoord.x);
              line.setAttribute('y2', dstCoord.y);
              linksLayer.appendChild(line);
            }
          }
        });
      });

      // Render Nodes
      Object.keys(deviceCoords).forEach(dev => {
        const c = deviceCoords[dev];
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', 'node-group');
        g.setAttribute('transform', 'translate(' + c.x + ',' + c.y + ')');

        const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
        rect.setAttribute('x', -40);
        rect.setAttribute('y', -16);
        rect.setAttribute('width', 80);
        rect.setAttribute('height', 32);
        rect.setAttribute('class', 'node-rect');
        rect.setAttribute('fill', '#0f172a');
        rect.setAttribute('stroke', dev.startsWith('cr') ? '#06b6d4' : (dev.startsWith('pr') ? '#8b5cf6' : '#eab308'));

        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('dy', 4);
        text.setAttribute('fill', '#f8fafc');
        text.setAttribute('font-size', '11px');
        text.setAttribute('font-weight', '600');
        text.textContent = dev.toUpperCase();

        g.appendChild(rect);
        g.appendChild(text);
        nodesLayer.appendChild(g);
      });
    }

    function getOffsetCoords(start, end, offsetDist) {
      const dx = end.x - start.x;
      const dy = end.y - start.y;
      const len = Math.sqrt(dx * dx + dy * dy);
      if (len === 0) return { start, end };
      const nx = -dy / len;
      const ny = dx / len;
      return {
        start: { x: start.x + nx * offsetDist, y: start.y + ny * offsetDist },
        end: { x: end.x + nx * offsetDist, y: end.y + ny * offsetDist }
      };
    }

    function highlightPathsOnMap(lsp) {
      const pathLayer = document.getElementById('path-layer');
      pathLayer.innerHTML = '';

      if (!lsp) return;

      // Render LSP Path (Cyan)
      if (lsp.lsp_hops && lsp.lsp_hops.length > 1) {
        for (let i = 0; i < lsp.lsp_hops.length - 1; i++) {
          const src = deviceCoords[lsp.lsp_hops[i].toLowerCase()];
          const dst = deviceCoords[lsp.lsp_hops[i+1].toLowerCase()];

          if (src && dst) {
            const offset = getOffsetCoords(src, dst, -4);
            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('class', 'lsp-path-line');
            line.setAttribute('x1', offset.start.x);
            line.setAttribute('y1', offset.start.y);
            line.setAttribute('x2', offset.end.x);
            line.setAttribute('y2', offset.end.y);
            line.setAttribute('marker-end', 'url(#arrow-cyan)');
            pathLayer.appendChild(line);
          }
        }
      }

      // Render Traceroute Path (Orange) if non-shortest or selected
      if (lsp.traceroute_hops && lsp.traceroute_hops.length > 1) {
        for (let i = 0; i < lsp.traceroute_hops.length - 1; i++) {
          const src = deviceCoords[lsp.traceroute_hops[i].toLowerCase()];
          const dst = deviceCoords[lsp.traceroute_hops[i+1].toLowerCase()];

          if (src && dst) {
            const offset = getOffsetCoords(src, dst, 6);
            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('class', 'traceroute-path-line');
            line.setAttribute('x1', offset.start.x);
            line.setAttribute('y1', offset.start.y);
            line.setAttribute('x2', offset.end.x);
            line.setAttribute('y2', offset.end.y);
            line.setAttribute('marker-end', 'url(#arrow-orange)');
            pathLayer.appendChild(line);
          }
        }
      }
    }

    function showDiagnosticPanel(lsp) {
      const panel = document.getElementById('lsp-diag-panel');
      panel.style.display = 'block';

      document.getElementById('diag-lsp-name').textContent = lsp.name;
      document.getElementById('diag-bw-val').textContent = lsp.bw_str;
      document.getElementById('diag-ingress').textContent = lsp.ingress_router.toUpperCase();
      document.getElementById('diag-egress').textContent = lsp.egress_router.toUpperCase();

      const badge = document.getElementById('diag-status-badge');
      if (lsp.is_shortest_path) {
        badge.className = 'status-badge shortest';
        badge.textContent = '✓ Optimal Shortest Path';
      } else {
        badge.className = 'status-badge longer';
        badge.textContent = '⚠️ Non-Shortest Path (' + lsp.lsp_hops.length + ' hops vs IGP ' + lsp.traceroute_hops.length + ' hops)';
      }

      const lspHopsContainer = document.getElementById('diag-lsp-hops');
      lspHopsContainer.innerHTML = lsp.lsp_hops.map(h => '<span class="hop-pill lsp-hop">' + h.toUpperCase() + '</span>').join(' ➔ ');

      const trHopsContainer = document.getElementById('diag-tr-hops');
      trHopsContainer.innerHTML = lsp.traceroute_hops.map(h => '<span class="hop-pill tr-hop">' + h.toUpperCase() + '</span>').join(' ➔ ');
    }

    window.onload = initApp;
  </script>
</body>
</html>
`
