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
	MaxAvgBwUtil    interface{} `json:"max_avg_bw_util"`
	TraceroutePath  []string    `json:"traceroute_path"`
	LspInterfaceIPs interface{} `json:"lsp_interface_ips"`
	IsShortestPath  bool        `json:"is_shortest_path"`
	PathType        string      `json:"path_type"`
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

			lspHops := mapIpsToHops(lspIps, entry.IngressRouter, entry.EgressRouter, ipMap)
			tracerouteHops := mapIpsToHops(tracerouteIps, entry.IngressRouter, entry.EgressRouter, ipMap)

			isShortest := entry.Details.IsShortestPath
			pathType := entry.Details.PathType

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
		return dates[i] > dates[j]
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
      --purple: #a855f7;
      --yellow: #eab308;

      --color-rr: #eab308;
      --color-cr-core: #06b6d4;
      --color-cr-metro: #ccff00;
      --color-pr: #a855f7;
      --color-unknown: #64748b;

      --cap-100g: #3b82f6;
      --cap-200g: #06b6d4;
      --cap-300g: #10b981;
      --cap-400g: #10b981;
      --cap-600g: #eab308;
      --cap-high: #f97316;
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

    /* Sidebar Controls */
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

    .tab-btn:hover { color: var(--text-main); background: rgba(255,255,255,0.03); }
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

    .search-box:focus { border-color: var(--cyan); }

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

    /* SVG Canvas Area */
    #map-container {
      flex: 1;
      position: relative;
      background: radial-gradient(circle at 50% 50%, #0f172a 0%, #090d16 100%);
      overflow: hidden;
    }

    svg#map-svg {
      width: 100%;
      height: 100%;
      cursor: grab;
    }

    svg#map-svg:active { cursor: grabbing; }

    .grid-line { stroke: rgba(255,255,255,0.02); stroke-width: 1; }
    .us-outline { fill: none; stroke: rgba(255,255,255,0.03); stroke-width: 1.5; stroke-dasharray: 4, 4; pointer-events: none; }

    .metro-bubble {
      transition: fill 0.3s, stroke 0.3s;
      cursor: move;
    }
    .metro-bubble:hover {
      stroke-width: 2px;
      filter: drop-shadow(0 0 16px rgba(56, 189, 248, 0.35)) !important;
    }

    .metro-label {
      font-family: 'Inter', sans-serif;
      font-size: 11px;
      font-weight: 700;
      fill: #cbd5e1;
      letter-spacing: 0.1em;
      pointer-events: none;
    }

    .topology-link { stroke-linecap: round; opacity: 0.55; transition: stroke-width 0.2s; }
    .topology-link:hover { opacity: 1; stroke-width: 5px !important; }

    .device-node { cursor: pointer; transition: transform 0.2s; }
    .device-node:hover { transform: scale(1.15); }
    .device-pill { rx: 6px; ry: 6px; stroke-width: 1.5px; }

    .lsp-path-line {
      stroke: var(--cyan);
      stroke-width: 4.0;
      stroke-linecap: round;
      filter: drop-shadow(0 0 8px var(--cyan-glow));
    }

    .traceroute-path-line {
      stroke: var(--orange);
      stroke-width: 3.5;
      stroke-dasharray: 6, 6;
      stroke-linecap: round;
      filter: drop-shadow(0 0 8px var(--orange-glow));
    }

    /* Map Legend Overlay */
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

    .legend-item { display: flex; align-items: center; gap: 8px; }
    .legend-line { width: 24px; height: 3px; border-radius: 2px; }
    .legend-line.lsp { background: var(--cyan); box-shadow: 0 0 8px var(--cyan); }
    .legend-line.traceroute { background: var(--orange); border-top: 1px dashed var(--orange); }

    /* Map Controls (Zoom / Fit View) */
    .canvas-controls {
      position: absolute;
      bottom: 24px;
      left: 24px;
      display: flex;
      gap: 8px;
      z-index: 10;
    }

    .canvas-btn {
      background: var(--panel-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--panel-border);
      color: var(--text-main);
      padding: 8px 12px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .canvas-btn:hover { background: rgba(255,255,255,0.1); border-color: var(--cyan); }

    /* Diagnostic Panel */
    #lsp-diag-panel {
      position: absolute;
      bottom: 24px;
      right: 24px;
      width: 440px;
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

    .hop-pills { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
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

    /* Tooltip */
    .tooltip {
      position: absolute;
      background: rgba(15, 23, 42, 0.95);
      border: 1px solid var(--cyan);
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 11px;
      pointer-events: none;
      z-index: 100;
      box-shadow: 0 10px 20px rgba(0,0,0,0.5);
      display: none;
    }
  </style>
</head>
<body>
  <div id="app-container">
    <!-- Sidebar Controls -->
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

    <!-- Map Canvas Area -->
    <div id="map-container">
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

      <!-- Canvas Controls -->
      <div class="canvas-controls">
        <button class="canvas-btn" onclick="fitView()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/>
          </svg>
          <span>Fit View</span>
        </button>
        <button class="canvas-btn" onclick="resetZoom()">
          <span>100% Reset</span>
        </button>
      </div>

      <svg id="map-svg" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid meet">
        <defs>
          <marker id="arrow-cyan" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
            <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#06b6d4" />
          </marker>
          <marker id="arrow-orange" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
            <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#f97316" />
          </marker>
        </defs>

        <g id="viewport">
          <!-- Grids -->
          <g id="svg-grid"></g>

          <!-- US Contour Approximation -->
          <path class="us-outline" transform="scale(1.6)" d="M 100,150 C 150,100 300,110 350,90 C 400,70 500,80 600,70 C 700,60 800,80 850,110 C 890,130 920,110 940,180 C 960,220 950,280 930,300 C 910,320 930,380 910,400 C 890,420 850,400 820,440 C 800,460 820,520 780,530 C 750,540 700,480 680,480 C 660,480 620,500 590,480 C 560,460 510,460 470,480 C 450,490 430,520 400,530 C 380,540 340,520 310,480 C 280,450 250,460 230,420 C 210,400 180,380 160,370 C 140,360 130,320 110,310 C 90,300 60,310 50,270 C 40,230 70,210 80,190 Z" />

          <!-- Metro Bubbles -->
          <g id="metro-bubbles"></g>

          <!-- Topology Links -->
          <g id="topology-links"></g>

          <!-- Path Highlights Layer -->
          <g id="path-layer"></g>

          <!-- Device Nodes -->
          <g id="device-nodes"></g>

          <!-- Metro Labels -->
          <g id="metro-labels"></g>
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

      <div id="tooltip" class="tooltip"></div>
    </div>
  </div>

  <script>
    const metroCoordinates = {
      "sfo": { x: 80, y: 280, name: "San Francisco, CA" },
      "svl": { x: 80, y: 440, name: "Sunnyvale, CA" },
      "sjc": { x: 80, y: 600, name: "San Jose, CA" },
      "lax": { x: 120, y: 780, name: "Los Angeles, CA" },
      "pih": { x: 300, y: 70, name: "Pocatello, ID" },
      "lgu": { x: 310, y: 190, name: "Logan, UT" },
      "slc": { x: 330, y: 330, name: "Salt Lake City, UT" },
      "las": { x: 230, y: 530, name: "Las Vegas, NV" },
      "phx": { x: 260, y: 740, name: "Phoenix, AZ" },
      "den": { x: 520, y: 380, name: "Denver, CO" },
      "sat": { x: 550, y: 870, name: "San Antonio, TX" },
      "aus": { x: 720, y: 830, name: "Austin, TX" },
      "dfw": { x: 700, y: 640, name: "Dallas-Fort Worth, TX" },
      "oma": { x: 680, y: 180, name: "Omaha, NE" },
      "cbf": { x: 840, y: 240, name: "Council Bluffs, IA" },
      "dsm": { x: 980, y: 160, name: "Des Moines, IA" },
      "mci": { x: 890, y: 440, name: "Kansas City, MO" },
      "jef": { x: 1080, y: 460, name: "Jefferson City, MO" },
      "ord": { x: 1180, y: 140, name: "Chicago, IL" },
      "bna": { x: 980, y: 490, name: "Nashville, TN" },
      "hsv": { x: 980, y: 860, name: "Huntsville, AL" },
      "atl": { x: 1280, y: 810, name: "Atlanta, GA" },
      "clt": { x: 1380, y: 590, name: "Charlotte, NC" },
      "rdu": { x: 1490, y: 470, name: "Raleigh-Durham, NC" },
      "iad": { x: 1490, y: 280, name: "Washington D.C." },
      "ewr": { x: 1560, y: 100, name: "Newark, NJ" }
    };

    let topologyData = {};
    let allLsps = [];
    let activeTab = 'bw';
    let minBwGbps = 1.0;
    let searchQuery = '';
    let selectedLsp = null;

    let deviceCoords = {};
    let devicesByMetro = {};

    // Zoom & Drag parameters
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

    function getSVGCoords(e) {
      const svg = document.getElementById('map-svg');
      const pt = svg.createSVGPoint();
      pt.x = e.clientX;
      pt.y = e.clientY;
      const svgPoint = pt.matrixTransform(svg.getScreenCTM().inverse());
      return { x: svgPoint.x, y: svgPoint.y };
    }

    function getOffsetCoords(start, end, offsetStart, offsetEnd) {
      const dx = end.x - start.x;
      const dy = end.y - start.y;
      const len = Math.sqrt(dx * dx + dy * dy);
      if (len === 0) return { start: start, end: end };

      const nx = -dy / len;
      const ny = dx / len;

      return {
        start: { x: start.x + nx * offsetStart, y: start.y + ny * offsetStart },
        end: { x: end.x + nx * offsetEnd, y: end.y + ny * offsetEnd }
      };
    }

    function renderGrid() {
      const gridGroup = document.getElementById('svg-grid');
      let gridHTML = '';
      for (let x = 0; x <= 1600; x += 80) {
        gridHTML += '<line class="grid-line" x1="' + x + '" y1="0" x2="' + x + '" y2="900" />';
      }
      for (let y = 0; y <= 900; y += 80) {
        gridHTML += '<line class="grid-line" x1="0" y1="' + y + '" x2="1600" y2="' + y + '" />';
      }
      gridGroup.innerHTML = gridHTML;
    }

    function getMetroOfDevice(device) {
      if (!device) return "mci";
      const match = device.match(/\.([a-z]+)\d*/i);
      if (match) return match[1].toLowerCase();

      const match2 = device.match(/^[a-z]+\d*-([a-z]+)/i);
      if (match2) return match2[1].toLowerCase();

      for (const m of Object.keys(metroCoordinates)) {
        if (device.toLowerCase().includes(m)) return m;
      }
      return "mci";
    }

    function getDeviceRole(hostname) {
      const name = hostname.toLowerCase();
      if (name.includes("rr01") || name.startsWith("rr")) return "rr";
      if (name.startsWith("cr")) {
        if (name.includes("atl") || name.includes("mci") || name.includes("sjc") || name.includes("ord") || name.includes("slc") || name.includes("dfw") || name.includes("lax")) {
          return "cr-backbone";
        }
        return "cr-metro";
      }
      if (name.startsWith("pr")) return "pr";
      return "unknown";
    }

    function getDeviceColor(role) {
      switch(role) {
        case "rr": return "var(--color-rr)";
        case "cr-backbone": return "var(--color-cr-core)";
        case "cr-metro": return "var(--color-cr-metro)";
        case "pr": return "var(--color-pr)";
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

    async function initApp() {
      await loadTopology();
      await loadDates();
      await loadLspData();
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

    async function loadTopology() {
      renderGrid();
      try {
        const resp = await fetch('/api/topology');
        topologyData = await resp.json();

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

        // Bubble Sizes Calculation
        const bubbleSizes = {};
        Object.keys(devicesByMetro).forEach(metro => {
          const devices = devicesByMetro[metro];
          devices.sort((a, b) => {
            const roleA = getDeviceRole(a);
            const roleB = getDeviceRole(b);
            const order = { "cr-backbone": 1, "cr-metro": 2, "rr": 3, "pr": 4, "unknown": 5 };
            return (order[roleA] || 99) - (order[roleB] || 99);
          });

          let cols = 1;
          if (devices.length > 1) cols = 2;
          if (devices.length > 6) cols = 3;

          const rows = Math.ceil(devices.length / cols);
          const dx = 105;
          const dy = 36;

          const gridWidth = (cols - 1) * dx;
          const gridHeight = (rows - 1) * dy;

          bubbleSizes[metro] = {
            width: gridWidth + 85 + 30,
            height: gridHeight + 22 + 30,
            cols: cols,
            rows: rows,
            dx: dx,
            dy: dy,
            gridWidth: gridWidth,
            gridHeight: gridHeight,
            logicalNodes: devices
          };
        });

        // Adjusted Coordinates via Physics Solver
        const adjustedCoordinates = {};
        Object.keys(devicesByMetro).forEach(metro => {
          const base = metroCoordinates[metro] || { x: 500, y: 300 };
          adjustedCoordinates[metro] = { x: base.x, y: base.y };
        });

        for (let iter = 0; iter < 50; iter++) {
          let shifted = false;
          const metros = Object.keys(devicesByMetro);
          for (let i = 0; i < metros.length; i++) {
            for (let j = i + 1; j < metros.length; j++) {
              const m1 = metros[i];
              const m2 = metros[j];
              const c1 = adjustedCoordinates[m1];
              const c2 = adjustedCoordinates[m2];
              const s1 = bubbleSizes[m1];
              const s2 = bubbleSizes[m2];

              const halfW1 = s1.width / 2;
              const halfH1 = s1.height / 2;
              const halfW2 = s2.width / 2;
              const halfH2 = s2.height / 2;

              const margin = 35;
              const dx = c2.x - c1.x;
              const dy = c2.y - c1.y;

              const minXDist = halfW1 + halfW2 + margin;
              const minYDist = halfH1 + halfH2 + margin;

              const overlapX = minXDist - Math.abs(dx);
              const overlapY = minYDist - Math.abs(dy);

              if (overlapX > 0 && overlapY > 0) {
                if (overlapX < overlapY) {
                  const push = overlapX / 2;
                  const dir = dx >= 0 ? 1 : -1;
                  c1.x -= push * dir;
                  c2.x += push * dir;
                } else {
                  const push = overlapY / 2;
                  const dir = dy >= 0 ? 1 : -1;
                  c1.y -= push * dir;
                  c2.y += push * dir;
                }
                shifted = true;
              }
            }
          }

          metros.forEach(metro => {
            const coord = adjustedCoordinates[metro];
            const size = bubbleSizes[metro];
            const halfW = size.width / 2;
            const halfH = size.height / 2;

            const minX = halfW + 20;
            const maxX = 1600 - halfW - 20;
            const minY = halfH + 20;
            const maxY = 900 - halfH - 20;

            if (coord.x < minX) coord.x = minX;
            if (coord.x > maxX) coord.x = maxX;
            if (coord.y < minY) coord.y = minY;
            if (coord.y > maxY) coord.y = maxY;
          });

          if (!shifted) break;
        }

        deviceCoords = {};
        const metroBubbles = document.getElementById('metro-bubbles');
        const metroLabels = document.getElementById('metro-labels');

        let bubblesHTML = '';
        let labelsHTML = '';

        Object.keys(devicesByMetro).forEach(metro => {
          const devices = devicesByMetro[metro];
          const base = adjustedCoordinates[metro];
          const size = bubbleSizes[metro];

          const bx = base.x - size.width / 2;
          const by = base.y - size.height / 2;

          const bbMetros = new Set(["lax", "sjc", "slc", "cbf", "ord", "iad", "ewr"]);
          const isBB = bbMetros.has(metro.toLowerCase());

          const fill = isBB ? "rgba(69, 45, 10, 0.55)" : "rgba(30, 41, 59, 0.65)";
          const stroke = isBB ? "rgba(234, 179, 8, 0.55)" : "rgba(148, 163, 184, 0.45)";
          const shadowGlow = isBB ? "rgba(234, 179, 8, 0.25)" : "rgba(148, 163, 184, 0.15)";

          bubblesHTML += '<rect class="metro-bubble" id="bubble-' + metro + '" data-metro="' + metro + '" x="' + bx + '" y="' + by + '" width="' + size.width + '" height="' + size.height + '" rx="16" ry="16" fill="' + fill + '" stroke="' + stroke + '" style="filter: drop-shadow(0 4px 12px ' + shadowGlow + ');" onmousedown="startDragMetro(event, \'' + metro + '\')" />';
          labelsHTML += '<text class="metro-label" id="label-' + metro + '" x="' + base.x + '" y="' + (base.y + size.height / 2 + 14) + '" text-anchor="middle">' + metro.toUpperCase() + '</text>';

          const offsetX = -size.gridWidth / 2;
          const offsetY = -size.gridHeight / 2;

          size.logicalNodes.forEach((dev, idx) => {
            const r = Math.floor(idx / size.cols);
            const c = idx % size.cols;
            deviceCoords[dev.toLowerCase()] = {
              x: base.x + offsetX + c * size.dx,
              y: base.y + offsetY + r * size.dy,
              name: dev
            };
          });
        });

        metroBubbles.innerHTML = bubblesHTML;
        metroLabels.innerHTML = labelsHTML;

        // Render Links
        const linksGroup = document.getElementById('topology-links');
        let linksHTML = '';
        const drawnLinks = new Set();

        Object.keys(topologyData).forEach(localDev => {
          const intfs = topologyData[localDev];
          Object.keys(intfs).forEach(intf => {
            const linkDetail = intfs[intf];
            const remoteDev = linkDetail.remote_device;

            if (!remoteDev || remoteDev === "unknown") return;

            const linkKey = [localDev.toLowerCase(), remoteDev.toLowerCase()].sort().join('---');
            if (drawnLinks.has(linkKey)) return;
            drawnLinks.add(linkKey);

            const start = deviceCoords[localDev.toLowerCase()];
            let end = deviceCoords[remoteDev.toLowerCase()];

            if (!end) {
              const remoteMetro = getMetroOfDevice(remoteDev);
              const base = adjustedCoordinates[remoteMetro] || { x: 500, y: 300 };
              end = { x: base.x, y: base.y };
            }

            if (start && end) {
              const capBps = linkDetail.capacity_bps || 100000000000;
              const color = getCapacityColor(capBps);
              const width = getCapacityWidth(capBps);
              const offset = getOffsetCoords(start, end, 36, 36);

              linksHTML += '<line class="topology-link" x1="' + offset.start.x + '" y1="' + offset.start.y + '" x2="' + offset.end.x + '" y2="' + offset.end.y + '" stroke="' + color + '" stroke-width="' + width + '" onmouseenter="showLinkTooltip(event, \'' + localDev + '\', \'' + intf + '\')" onmouseleave="hideTooltip()" />';
            }
          });
        });

        linksGroup.innerHTML = linksHTML;

        // Render Nodes
        const nodesGroup = document.getElementById('device-nodes');
        let nodesHTML = '';

        Object.keys(deviceCoords).forEach(dev => {
          const c = deviceCoords[dev];
          const role = getDeviceRole(dev);
          const strokeColor = getDeviceColor(role);
          const displayTitle = dev.toUpperCase();

          nodesHTML += '<g class="device-node" id="node-' + dev + '" transform="translate(' + c.x + ', ' + c.y + ')" onmousedown="startDragNode(event, \'' + dev + '\')">' +
            '<rect class="device-pill" x="-42" y="-14" width="84" height="28" fill="#0f172a" stroke="' + strokeColor + '" />' +
            '<text text-anchor="middle" dy="4" fill="#f8fafc" font-size="10.5px" font-weight="700" font-family="JetBrains Mono, monospace">' + displayTitle + '</text>' +
          '</g>';
        });

        nodesGroup.innerHTML = nodesHTML;

        fitView();
      } catch (err) {
        console.error("Failed to load topology", err);
      }
    }

    function getOffsetCoords(start, end, offsetStart, offsetEnd) {
      const dx = end.x - start.x;
      const dy = end.y - start.y;
      const len = Math.sqrt(dx * dx + dy * dy);
      if (len === 0) return { start: start, end: end };

      const nx = -dy / len;
      const ny = dx / len;

      return {
        start: { x: start.x + nx * offsetStart, y: start.y + ny * offsetStart },
        end: { x: end.x + nx * offsetEnd, y: end.y + ny * offsetEnd }
      };
    }

    function highlightPathsOnMap(lsp) {
      const pathLayer = document.getElementById('path-layer');
      pathLayer.innerHTML = '';

      if (!lsp) return;

      // Render LSP Path (Cyan)
      if (lsp.lsp_hops && lsp.lsp_hops.length > 1) {
        for (let i = 0; i < lsp.lsp_hops.length - 1; i++) {
          const srcName = lsp.lsp_hops[i].toLowerCase();
          const dstName = lsp.lsp_hops[i+1].toLowerCase();
          const src = deviceCoords[srcName];
          const dst = deviceCoords[dstName];

          if (src && dst) {
            const offset = getOffsetCoords(src, dst, -4, -4);
            pathLayer.innerHTML += '<line class="lsp-path-line" x1="' + offset.start.x + '" y1="' + offset.start.y + '" x2="' + offset.end.x + '" y2="' + offset.end.y + '" marker-end="url(#arrow-cyan)" />';
          }
        }
      }

      // Render Traceroute Path (Orange) if non-shortest
      if (lsp.traceroute_hops && lsp.traceroute_hops.length > 1) {
        for (let i = 0; i < lsp.traceroute_hops.length - 1; i++) {
          const srcName = lsp.traceroute_hops[i].toLowerCase();
          const dstName = lsp.traceroute_hops[i+1].toLowerCase();
          const src = deviceCoords[srcName];
          const dst = deviceCoords[dstName];

          if (src && dst) {
            const offset = getOffsetCoords(src, dst, 6, 6);
            pathLayer.innerHTML += '<line class="traceroute-path-line" x1="' + offset.start.x + '" y1="' + offset.start.y + '" x2="' + offset.end.x + '" y2="' + offset.end.y + '" marker-end="url(#arrow-orange)" />';
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

    // Zoom & Pan Engine
    function updateTransform() {
      viewport.setAttribute('transform', 'translate(' + posX + ',' + posY + ') scale(' + scale + ')');
    }

    function zoom(delta, cx, cy) {
      const oldScale = scale;
      scale *= delta;
      scale = Math.max(0.35, Math.min(3.5, scale));
      posX = cx - (cx - posX) * (scale / oldScale);
      posY = cy - (cy - posY) * (scale / oldScale);
      updateTransform();
    }

    function resetZoom() {
      scale = 1.0;
      posX = 0;
      posY = 0;
      updateTransform();
    }

    function fitView() {
      const nodes = Object.values(deviceCoords);
      if (nodes.length === 0) return;

      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      nodes.forEach(c => {
        if (c.x < minX) minX = c.x;
        if (c.x > maxX) maxX = c.x;
        if (c.y < minY) minY = c.y;
        if (c.y > maxY) maxY = c.y;
      });

      const margin = 80;
      const width = (maxX - minX) + margin * 2;
      const height = (maxY - minY) + margin * 2;

      const svgWidth = 1600;
      const svgHeight = 900;

      scale = Math.min(svgWidth / width, svgHeight / height);
      scale = Math.max(0.45, Math.min(1.2, scale));

      const centerX = (minX + maxX) / 2;
      const centerY = (minY + maxY) / 2;

      posX = (svgWidth / 2) - centerX * scale;
      posY = (svgHeight / 2) - centerY * scale;

      updateTransform();
    }

    // Dragging Handlers
    container.addEventListener('mousedown', e => {
      if (e.target.closest('.device-node') || e.target.closest('.metro-bubble')) return;
      isDragging = true;
      startX = e.clientX - posX;
      startY = e.clientY - posY;
    });

    window.addEventListener('mousemove', e => {
      if (isDragging) {
        posX = e.clientX - startX;
        posY = e.clientY - startY;
        updateTransform();
      } else if (draggedNode) {
        const coords = getSVGCoords(e);
        const newX = coords.x - dragOffset.x;
        const newY = coords.y - dragOffset.y;
        deviceCoords[draggedNode].x = newX;
        deviceCoords[draggedNode].y = newY;
        const elem = document.getElementById('node-' + draggedNode);
        if (elem) elem.setAttribute('transform', 'translate(' + newX + ',' + newY + ')');
        if (selectedLsp) highlightPathsOnMap(selectedLsp);
      }
    });

    window.addEventListener('mouseup', () => {
      isDragging = false;
      draggedNode = null;
      draggedMetro = null;
    });

    container.addEventListener('wheel', e => {
      e.preventDefault();
      const coords = getSVGCoords(e);
      const delta = e.deltaY < 0 ? 1.1 : 0.9;
      zoom(delta, coords.x, coords.y);
    }, { passive: false });

    function startDragNode(e, node) {
      e.stopPropagation();
      draggedNode = node;
      const coords = getSVGCoords(e);
      dragOffset = {
        x: coords.x - deviceCoords[node].x,
        y: coords.y - deviceCoords[node].y
      };
    }

    function startDragMetro(e, metro) {
      e.stopPropagation();
      draggedMetro = metro;
      dragMetroStart = getSVGCoords(e);
    }

    function showLinkTooltip(e, dev, intf) {
      const tooltip = document.getElementById('tooltip');
      const detail = topologyData[dev][intf];
      tooltip.style.display = 'block';
      tooltip.style.left = (e.clientX + 15) + 'px';
      tooltip.style.top = (e.clientY + 15) + 'px';
      tooltip.innerHTML = '<div style="font-weight:700; color:#fff;">' + dev.toUpperCase() + ' ➔ ' + (detail.remote_device ? detail.remote_device.toUpperCase() : 'UNKNOWN') + '</div>' +
        '<div>Interface: ' + intf + ' (' + (detail.capacity_human || 'N/A') + ')</div>' +
        '<div>IP: ' + (detail.local_ip || 'N/A') + '</div>';
    }

    function hideTooltip() {
      document.getElementById('tooltip').style.display = 'none';
    }

    window.onload = initApp;
  </script>
</body>
</html>
`
