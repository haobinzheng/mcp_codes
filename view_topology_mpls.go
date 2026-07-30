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

func mapIpsToHops(ips []string, fromIp string, toIp string, ingressHost string, egressHost string, ipMap map[string]string) []string {
	var hops []string

	cleanFrom := defCleanIP(fromIp)
	startDev := ""
	if dev, ok := ipMap[cleanFrom]; ok {
		startDev = strings.ToLower(dev)
	} else {
		startDev = strings.ToLower(strings.TrimSpace(ingressHost))
	}

	if startDev != "" {
		hops = append(hops, startDev)
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

	cleanTo := defCleanIP(toIp)
	endDev := ""
	if dev, ok := ipMap[cleanTo]; ok {
		endDev = strings.ToLower(dev)
	} else {
		endDev = strings.ToLower(strings.TrimSpace(egressHost))
	}

	if endDev != "" && (len(hops) == 0 || hops[len(hops)-1] != endDev) {
		hops = append(hops, endDev)
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

			lspHops := mapIpsToHops(lspIps, entry.From, entry.To, entry.IngressRouter, entry.EgressRouter, ipMap)
			tracerouteHops := mapIpsToHops(tracerouteIps, entry.From, entry.To, entry.IngressRouter, entry.EgressRouter, ipMap)

			isShortest := true
			pathType := entry.Details.PathType

			if len(lspHops) > len(tracerouteHops) && len(tracerouteHops) > 1 {
				isShortest = false
				if pathType == "" || pathType == "shortest path" {
					pathType = "longer path"
				}
			} else {
				isShortest = true
				if pathType == "" {
					pathType = "shortest path"
				}
			}

			ingressHost := strings.TrimSpace(entry.IngressRouter)
			if fullDev, ok := ipMap[defCleanIP(entry.From)]; ok {
				ingressHost = strings.ToLower(fullDev)
			} else if len(lspHops) > 0 {
				ingressHost = lspHops[0]
			}

			egressHost := strings.TrimSpace(entry.EgressRouter)
			if fullDev, ok := ipMap[defCleanIP(entry.To)]; ok {
				egressHost = strings.ToLower(fullDev)
			} else if len(lspHops) > 0 {
				egressHost = lspHops[len(lspHops)-1]
			}

			summary := LspSummary{
				ID:             lspName,
				Name:           lspName,
				From:           entry.From,
				To:             entry.To,
				IngressRouter:  ingressHost,
				EgressRouter:   egressHost,
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
			dirPath := filepath.Join(baseDir, entry.Name())
			subEntries, err := os.ReadDir(dirPath)
			hasJson := false
			if err == nil {
				for _, sub := range subEntries {
					if !sub.IsDir() && strings.HasSuffix(sub.Name(), ".json") {
						hasJson = true
						break
					}
				}
			}
			if hasJson {
				dates = append(dates, entry.Name())
			}
		}
	}

	sort.Slice(dates, func(i, j int) bool {
		return dates[i] > dates[j]
	})

	return dates
}

func enrichRemoteInterfaces(report MplsTopologyReport) {
	ipToIntfMap := make(map[string]string)

	for devName, node := range report {
		cleanDev := strings.ToLower(strings.TrimSpace(devName))
		for intfKey, intf := range node {
			if intf.LocalIP != "" {
				cleanIp := defCleanIP(intf.LocalIP)
				key := fmt.Sprintf("%s|%s", cleanDev, cleanIp)
				ipToIntfMap[key] = intfKey
			}
		}
	}

	for _, node := range report {
		for intfKey, intf := range node {
			if intf.RemoteDevice != "" && (intf.RemoteInterface == "" || intf.RemoteInterface == "N/A") {
				cleanRemoteDev := strings.ToLower(strings.TrimSpace(intf.RemoteDevice))
				cleanRemoteIp := defCleanIP(intf.RemoteIP)

				key := fmt.Sprintf("%s|%s", cleanRemoteDev, cleanRemoteIp)
				if rIntf, found := ipToIntfMap[key]; found {
					intf.RemoteInterface = rIntf
					node[intfKey] = intf
				} else {
					for remoteDevKey, remoteNode := range report {
						if strings.ToLower(strings.TrimSpace(remoteDevKey)) == cleanRemoteDev {
							for rKey, rDetails := range remoteNode {
								if defCleanIP(rDetails.LocalIP) == cleanRemoteIp || (intf.LocalIP != "" && defCleanIP(rDetails.RemoteIP) == defCleanIP(intf.LocalIP)) {
									intf.RemoteInterface = rKey
									node[intfKey] = intf
									break
								}
							}
						}
					}
				}
				if intf.RemoteInterface == "" {
					intf.RemoteInterface = "N/A"
					node[intfKey] = intf
				}
			}
		}
	}
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

	enrichRemoteInterfaces(report)

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
      gap: 8px;
    }

    .lsp-name {
      font-size: 11.5px;
      font-weight: 700;
      color: #fafafa;
      font-family: 'JetBrains Mono', monospace;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      flex: 1;
      min-width: 0;
    }

    .bw-tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      font-weight: 700;
      color: #38bdf8;
      background: rgba(56, 189, 248, 0.15);
      padding: 2px 6px;
      border-radius: 4px;
      white-space: nowrap;
      flex-shrink: 0;
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

    .topology-link { stroke-linecap: round; opacity: 0.7; transition: stroke-width 0.2s, opacity 0.2s; }
    .topology-link:hover { opacity: 1 !important; stroke-width: 6px !important; cursor: pointer; }

    @keyframes flow-anim {
      to { stroke-dashoffset: -16; }
    }
    .topology-flow {
      stroke-linecap: round;
      pointer-events: none;
      transition: opacity 0.25s;
    }

    .device-node { cursor: pointer; transition: stroke-width 0.2s, fill 0.2s, stroke 0.2s; }
    .device-node:hover {
      stroke: #ffffff !important;
      stroke-width: 2.5px !important;
      fill: #1e1e24 !important;
      cursor: pointer;
    }

    .lsp-path-base {
      stroke: #00f2fe;
      stroke-width: 5.5px;
      stroke-linecap: round;
      filter: drop-shadow(0 0 12px rgba(0, 242, 254, 0.9));
    }

    .lsp-path-flow {
      stroke: #ffffff;
      stroke-width: 2.5px;
      stroke-linecap: round;
      stroke-dasharray: 6, 12;
      pointer-events: none;
    }

    .traceroute-path-base {
      stroke: #ff7a00;
      stroke-width: 5px;
      stroke-dasharray: 10, 8;
      stroke-linecap: round;
      filter: drop-shadow(0 0 12px rgba(255, 122, 0, 0.9));
    }

    .traceroute-path-flow {
      stroke: #fff7ed;
      stroke-width: 2.2px;
      stroke-linecap: round;
      stroke-dasharray: 4, 10;
      pointer-events: none;
    }

    .path-step-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      font-weight: 800;
      fill: #ffffff;
      pointer-events: none;
      text-shadow: 0 1px 3px rgba(0,0,0,0.9);
    }

    .device-node-group.dimmed {
      opacity: 0.22 !important;
      transition: opacity 0.3s;
    }

    .device-node-group.path-highlighted {
      opacity: 1.0 !important;
      filter: drop-shadow(0 0 18px rgba(0, 242, 254, 0.85)) !important;
      transition: opacity 0.3s, filter 0.3s;
    }

    .topology-link.dimmed {
      opacity: 0.10 !important;
      transition: opacity 0.3s;
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
          <div class="control-row" style="margin-top: 10px; display: flex; align-items: center; justify-content: space-between;">
            <span class="control-label">Min Bandwidth</span>
            <div style="display: flex; align-items: center; gap: 4px;">
              <input type="number" id="bw-number-input" class="search-box" style="width: 60px; padding: 2px 4px; font-size: 11px; text-align: right; font-family: 'JetBrains Mono', monospace;" value="1.0" min="0" step="any" oninput="onBwNumberInput(this.value)">
              <select id="bw-unit-select" class="search-box" style="padding: 2px 4px; font-size: 11px; font-family: 'JetBrains Mono', monospace;" onchange="onBwUnitChange(this.value)">
                <option value="Gbps" selected>Gbps</option>
                <option value="Mbps">Mbps</option>
              </select>
              <button class="canvas-btn" style="padding: 3px 8px; font-size: 11px; margin-left: 2px;" onclick="applyBwFilter()" title="Apply Filter">Apply</button>
            </div>
          </div>
          <div class="slider-container" style="margin-top: 6px;">
            <input type="range" id="bw-threshold-slider" min="0" max="100" step="1" value="50" oninput="onBwSliderChange(this.value)">
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

      <!-- Diagnostic Panel (Draggable, Minimizable, Closeable) -->
      <div id="lsp-diag-panel">
        <div class="diag-header" id="diag-panel-header" style="cursor: move; display: flex; align-items: center; justify-content: space-between; padding-bottom: 8px; margin-bottom: 8px; border-bottom: 1px solid var(--panel-border); user-select: none;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" stroke-width="2">
              <path d="M5 9l4-4 4 4M5 15l4 4 4-4"/>
            </svg>
            <span id="diag-lsp-name" style="font-size: 13px; font-weight: 700; color: var(--text-main); font-family: 'JetBrains Mono', monospace;">LSP Details</span>
          </div>
          <div style="display: flex; align-items: center; gap: 6px;">
            <span class="status-badge" id="diag-status-badge"></span>
            <button onclick="toggleDiagPanelCollapse()" title="Minimize / Expand" style="background: rgba(255,255,255,0.08); border: 1px solid var(--panel-border); color: #cbd5e1; border-radius: 4px; width: 22px; height: 22px; cursor: pointer; font-size: 12px; font-weight: bold; display: flex; align-items: center; justify-content: center;">_</button>
            <button onclick="closeDiagPanel()" title="Close Card" style="background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); color: #ef4444; border-radius: 4px; width: 22px; height: 22px; cursor: pointer; font-size: 14px; font-weight: bold; display: flex; align-items: center; justify-content: center;">×</button>
          </div>
        </div>

        <div id="diag-panel-body">
          <div style="font-size: 11.5px; color: var(--text-muted); margin-bottom: 10px;">
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

      <div id="tooltip" class="tooltip"></div>
    </div>
  </div>

  <script>
    const metroCoordinates = {
      "sfo": { x: 100, y: 150, name: "San Francisco, CA" },
      "svl": { x: 100, y: 360, name: "Sunnyvale, CA" },
      "sjc": { x: 100, y: 590, name: "San Jose, CA" },
      "lax": { x: 140, y: 830, name: "Los Angeles, CA" },
      "pih": { x: 380, y: 70, name: "Pocatello, ID" },
      "lgu": { x: 390, y: 200, name: "Logan, UT" },
      "slc": { x: 450, y: 320, name: "Salt Lake City, UT" },
      "las": { x: 400, y: 570, name: "Las Vegas, NV" },
      "phx": { x: 450, y: 830, name: "Phoenix, AZ" },
      "den": { x: 720, y: 380, name: "Denver, CO" },
      "sat": { x: 700, y: 870, name: "San Antonio, TX" },
      "aus": { x: 920, y: 830, name: "Austin, TX" },
      "dfw": { x: 920, y: 640, name: "Dallas-Fort Worth, TX" },
      "oma": { x: 880, y: 180, name: "Omaha, NE" },
      "cbf": { x: 1080, y: 220, name: "Council Bluffs, IA" },
      "dsm": { x: 1240, y: 160, name: "Des Moines, IA" },
      "mci": { x: 1120, y: 440, name: "Kansas City, MO" },
      "jef": { x: 1300, y: 460, name: "Jefferson City, MO" },
      "ord": { x: 1420, y: 140, name: "Chicago, IL" },
      "bna": { x: 1220, y: 640, name: "Nashville, TN" },
      "hsv": { x: 1220, y: 860, name: "Huntsville, AL" },
      "atl": { x: 1480, y: 810, name: "Atlanta, GA" },
      "clt": { x: 1580, y: 590, name: "Charlotte, NC" },
      "rdu": { x: 1700, y: 470, name: "Raleigh-Durham, NC" },
      "iad": { x: 1700, y: 280, name: "Washington D.C." },
      "ewr": { x: 1780, y: 100, name: "Newark, NJ" }
    };

    let topologyData = {};
    let allLsps = [];
    let activeTab = 'bw';
    let minBwGbps = 1.0;
    let searchQuery = '';
    let selectedLsp = null;

    let deviceCoords = {};
    let devicesByMetro = {};
    let adjustedCoordinates = {};

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
      const cleanDev = device.toLowerCase().trim();
      const match = cleanDev.match(/\.([a-z]+)\d*/i);
      if (match) return match[1].toLowerCase();

      const match2 = cleanDev.match(/^[a-z]+\d*-([a-z]+)/i);
      if (match2) return match2[1].toLowerCase();

      for (const m of Object.keys(metroCoordinates)) {
        if (cleanDev.includes(m)) return m;
      }

      if (topologyData) {
        for (const peerDev in topologyData) {
          const peerClean = peerDev.toLowerCase();
          if (peerClean !== cleanDev) {
            const peerMetro = getMetroOfDevice(peerClean);
            if (peerMetro && peerMetro !== "mci") {
              const intfs = topologyData[peerDev] || {};
              for (const intf in intfs) {
                const rDev = (intfs[intf].remote_device || "").toLowerCase();
                if (rDev === cleanDev) {
                  return peerMetro;
                }
              }
            }
          }
        }
      }

      return "mci";
    }

    function getDeviceRole(hostname) {
      const name = hostname.toLowerCase();
      if (name.includes("rr01") || name.startsWith("rr")) return "rr";
      if (name.startsWith("cr")) {
        if (name.includes("atl") || name.includes("mci") || name.includes("sjc") || name.includes("ord") || name.includes("slc") || name.includes("dfw") || name.includes("lax") || name.includes("iad") || name.includes("ewr") || name.includes("cbf")) {
          return "cr-backbone";
        }
        return "cr-metro";
      }
      if (name.startsWith("pr") || name.startsWith("mpr")) return "pr";
      if (name.startsWith("bng")) return "bng";
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

    function sliderToBwGbps(val) {
      const pos = parseFloat(val);
      if (pos === 0) return 0;
      if (pos <= 50) {
        // Sub-1G range (0 to 50): 0.01 Gbps (10M) to 1.0 Gbps (1000M) in 0.02G (20M) steps
        return Math.round((0.01 + (pos - 1) * 0.02) * 100) / 100;
      } else if (pos <= 80) {
        // 1G to 20G range
        return Math.round((1.0 + (pos - 50) * 0.633) * 10) / 10;
      } else {
        // 20G to 150G range
        return Math.round(20.0 + (pos - 80) * 6.5);
      }
    }

    function bwGbpsToSlider(gbps) {
      if (gbps <= 0) return 0;
      if (gbps < 1.0) {
        return Math.round(1 + (gbps - 0.01) / 0.02);
      } else if (gbps <= 20.0) {
        return Math.round(50 + (gbps - 1.0) / 0.633);
      } else {
        return Math.round(80 + (gbps - 20.0) / 6.5);
      }
    }

    function syncBwInputFields(gbps) {
      const numInput = document.getElementById('bw-number-input');
      const unitSelect = document.getElementById('bw-unit-select');
      const slider = document.getElementById('bw-threshold-slider');

      if (slider) slider.value = bwGbpsToSlider(gbps);

      if (numInput && unitSelect) {
        if (gbps < 1.0 && gbps > 0) {
          unitSelect.value = 'Mbps';
          numInput.value = Math.round(gbps * 1000);
        } else {
          unitSelect.value = 'Gbps';
          numInput.value = gbps === 0 ? 0 : gbps.toFixed(1);
        }
      }
    }

    function applyBwFilter() {
      updateTabCounts();
      renderLspCards();
    }

    function onBwSliderChange(val) {
      minBwGbps = sliderToBwGbps(val);
      syncBwInputFields(minBwGbps);
      applyBwFilter();
    }

    function onBwNumberInput(val) {
      const num = parseFloat(val) || 0;
      const unit = document.getElementById('bw-unit-select').value;
      if (unit === 'Mbps') {
        minBwGbps = num / 1000.0;
      } else {
        minBwGbps = num;
      }
      const slider = document.getElementById('bw-threshold-slider');
      if (slider) slider.value = bwGbpsToSlider(minBwGbps);
      applyBwFilter();
    }

    function onBwUnitChange(unit) {
      const numInput = document.getElementById('bw-number-input');
      const val = parseFloat(numInput.value) || 0;
      if (unit === 'Mbps') {
        minBwGbps = val / 1000.0;
      } else {
        minBwGbps = val;
      }
      applyBwFilter();
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
            const diff = (order[roleA] || 99) - (order[roleB] || 99);
            if (diff !== 0) return diff;
            return b.localeCompare(a);
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
            width: gridWidth + 110 + 30,
            height: gridHeight + 40 + 30,
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
        adjustedCoordinates = {};
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
          labelsHTML += '<text class="metro-label" id="label-' + metro + '" x="' + base.x + '" y="' + (base.y + size.height / 2 + 14) + '" text-anchor="middle" style="cursor: move; pointer-events: auto;" onmousedown="startDragMetro(event, \'' + metro + '\')">' + metro.toUpperCase() + '</text>';

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

        // Render Links (supporting multiple parallel links per router pair)
        const linksGroup = document.getElementById('topology-links');
        let linksHTML = '';
        const linkGroups = {};

        Object.keys(topologyData).forEach(localDev => {
          const intfs = topologyData[localDev];
          Object.keys(intfs).forEach(intf => {
            const linkDetail = intfs[intf];
            const remoteDev = linkDetail.remote_device;

            if (!remoteDev || remoteDev === "unknown") return;

            const devPairKey = [localDev.toLowerCase(), remoteDev.toLowerCase()].sort().join('---');

            if (!linkGroups[devPairKey]) {
              linkGroups[devPairKey] = [];
            }

            const exists = linkGroups[devPairKey].some(l => 
              (l.localDev.toLowerCase() === localDev.toLowerCase() && l.intf === intf) ||
              (l.localDev.toLowerCase() === remoteDev.toLowerCase() && l.remoteIntf === intf)
            );

            if (!exists) {
              linkGroups[devPairKey].push({
                localDev: localDev,
                remoteDev: remoteDev,
                intf: intf,
                remoteIntf: linkDetail.remote_interface || '',
                detail: linkDetail
              });
            }
          });
        });

        Object.keys(linkGroups).forEach(devPairKey => {
          const links = linkGroups[devPairKey];
          const totalLinks = links.length;

          links.forEach((linkItem, idx) => {
            const localDev = linkItem.localDev;
            const remoteDev = linkItem.remoteDev;
            const intf = linkItem.intf;
            const linkDetail = linkItem.detail;

            const start = resolveDeviceCoords(localDev);
            let end = resolveDeviceCoords(remoteDev);

            if (!end) {
              const remoteMetro = getMetroOfDevice(remoteDev);
              if (adjustedCoordinates[remoteMetro]) {
                const base = adjustedCoordinates[remoteMetro];
                end = { x: base.x, y: base.y };
              }
            }

            if (start && end) {
              const capBps = linkDetail.capacity_bps || 100000000000;
              const color = getCapacityColor(capBps);
              const width = getCapacityWidth(capBps);

              const roleLocal = getDeviceRole(localDev);
              const roleRemote = getDeviceRole(remoteDev);
              const isCoreLocal = (roleLocal === "cr-backbone" || roleLocal === "cr-metro" || roleLocal === "rr");
              const isCoreRemote = (roleRemote === "cr-backbone" || roleRemote === "cr-metro" || roleRemote === "rr");
              const isCoreLink = isCoreLocal && isCoreRemote;

              let x1 = start.x, y1 = start.y, x2 = end.x, y2 = end.y;
              let pathD = "";

              if (totalLinks > 1) {
                const dx = x2 - x1;
                const dy = y2 - y1;
                const len = Math.sqrt(dx * dx + dy * dy) || 1;
                const nx = -dy / len;
                const ny = dx / len;

                const offsetStep = 12;
                const offset = (idx - (totalLinks - 1) / 2) * offsetStep;

                const cx = (x1 + x2) / 2 + nx * offset * 2.5;
                const cy = (y1 + y2) / 2 + ny * offset * 2.5;

                pathD = 'M ' + x1 + ' ' + y1 + ' Q ' + cx + ' ' + cy + ' ' + x2 + ' ' + y2;
              }

              const dataAttrs = 'data-start="' + localDev + '" data-end="' + remoteDev + '" data-link-index="' + idx + '" data-total-links="' + totalLinks + '"';

              if (isCoreLink) {
                if (pathD) {
                  linksHTML += '<path class="topology-link" ' + dataAttrs + ' d="' + pathD + '" stroke="' + color + '" stroke-width="' + width + '" fill="none" onmouseenter="showLinkTooltip(event, \'' + localDev + '\', \'' + intf + '\')" onmouseleave="hideTooltip()" />';
                  linksHTML += '<path class="topology-flow" ' + dataAttrs + ' d="' + pathD + '" stroke="rgba(255, 255, 255, 0.5)" stroke-width="' + Math.max(1.0, width * 0.25) + '" stroke-dasharray="6, 10" fill="none" style="animation: flow-anim 1.5s linear infinite; pointer-events: none;" />';
                } else {
                  linksHTML += '<line class="topology-link" ' + dataAttrs + ' x1="' + x1 + '" y1="' + y1 + '" x2="' + x2 + '" y2="' + y2 + '" stroke="' + color + '" stroke-width="' + width + '" onmouseenter="showLinkTooltip(event, \'' + localDev + '\', \'' + intf + '\')" onmouseleave="hideTooltip()" />';
                  linksHTML += '<line class="topology-flow" ' + dataAttrs + ' x1="' + x1 + '" y1="' + y1 + '" x2="' + x2 + '" y2="' + y2 + '" stroke="rgba(255, 255, 255, 0.5)" stroke-width="' + Math.max(1.0, width * 0.25) + '" stroke-dasharray="6, 10" style="animation: flow-anim 1.5s linear infinite; pointer-events: none;" />';
                }
              } else {
                if (pathD) {
                  linksHTML += '<path class="topology-link edge-link" ' + dataAttrs + ' d="' + pathD + '" stroke="' + color + '" stroke-width="1.2" stroke-dasharray="4, 4" fill="none" opacity="0.45" onmouseenter="showLinkTooltip(event, \'' + localDev + '\', \'' + intf + '\')" onmouseleave="hideTooltip()" />';
                } else {
                  linksHTML += '<line class="topology-link edge-link" ' + dataAttrs + ' x1="' + x1 + '" y1="' + y1 + '" x2="' + x2 + '" y2="' + y2 + '" stroke="' + color + '" stroke-width="1.2" stroke-dasharray="4, 4" opacity="0.45" onmouseenter="showLinkTooltip(event, \'' + localDev + '\', \'' + intf + '\')" onmouseleave="hideTooltip()" />';
                }
              }
            }
          });
        });

        linksGroup.innerHTML = linksHTML;

        // Render Nodes following view_topology standards (Hexagon for CR, Pill for RR, Rect for PR)
        const nodesGroup = document.getElementById('device-nodes');
        let nodesHTML = '';

        Object.keys(deviceCoords).forEach(dev => {
          const c = deviceCoords[dev];
          const role = getDeviceRole(dev);
          const strokeColor = getDeviceColor(role);
          const displayTitle = dev.toUpperCase();

          const isCR = (role === "cr-backbone" || role === "cr-metro");
          const isRR = (role === "rr");

          nodesHTML += '<g class="device-node-group" id="node-group-' + dev + '" transform="translate(' + c.x + ', ' + c.y + ')">';

          if (isCR) {
            // Core Router: Hexagon shape matching view_topology standard
            nodesHTML += '  <polygon class="device-node-glow" points="-45,0 -33,-12 33,-12 45,0 33,12 -33,12" fill="none" stroke="' + strokeColor + '" stroke-width="4" opacity="0.22" style="pointer-events: none;" />';
            nodesHTML += '  <polygon class="device-node" id="node-' + dev + '" points="-45,0 -33,-12 33,-12 45,0 33,12 -33,12" fill="#121214" stroke="' + strokeColor + '" stroke-width="2" onmousedown="startDragNode(event, \'' + dev + '\')" onmouseenter="showNodeTooltip(event, \'' + dev + '\')" onmouseleave="hideTooltip()" />';
            nodesHTML += '  <text class="device-node-text" x="0" y="0" dy="3.5px" text-anchor="middle" fill="#ffffff" style="font-family: \'JetBrains Mono\', monospace; font-size: 9px; font-weight: 700; pointer-events: none; text-shadow: 0 1px 2px rgba(0,0,0,0.8);">' + displayTitle + '</text>';
          } else if (isRR) {
            // Route Reflector: Pill shape matching view_topology standard
            nodesHTML += '  <rect class="device-node-glow" x="-45" y="-12" width="90" height="24" rx="12" ry="12" fill="none" stroke="' + strokeColor + '" stroke-width="4" opacity="0.22" style="pointer-events: none;" />';
            nodesHTML += '  <rect class="device-node" id="node-' + dev + '" x="-45" y="-12" width="90" height="24" rx="12" ry="12" fill="#121214" stroke="' + strokeColor + '" stroke-width="2" onmousedown="startDragNode(event, \'' + dev + '\')" onmouseenter="showNodeTooltip(event, \'' + dev + '\')" onmouseleave="hideTooltip()" />';
            nodesHTML += '  <text class="device-node-text" x="0" y="0" dy="3.5px" text-anchor="middle" fill="#ffffff" style="font-family: \'JetBrains Mono\', monospace; font-size: 9px; font-weight: 700; pointer-events: none; text-shadow: 0 1px 2px rgba(0,0,0,0.8);">' + displayTitle + '</text>';
          } else {
            // Peering Router: Rounded rectangle matching view_topology standard
            nodesHTML += '  <rect class="device-node-glow" x="-38" y="-9" width="76" height="18" rx="5" ry="5" fill="none" stroke="' + strokeColor + '" stroke-width="4" opacity="0.22" style="pointer-events: none;" />';
            nodesHTML += '  <rect class="device-node" id="node-' + dev + '" x="-38" y="-9" width="76" height="18" rx="5" ry="5" fill="#121214" stroke="' + strokeColor + '" stroke-width="1.2" onmousedown="startDragNode(event, \'' + dev + '\')" onmouseenter="showNodeTooltip(event, \'' + dev + '\')" onmouseleave="hideTooltip()" />';
            nodesHTML += '  <text class="device-node-text" x="0" y="0" dy="2.8px" text-anchor="middle" fill="#ffffff" style="font-family: \'JetBrains Mono\', monospace; font-size: 7.8px; font-weight: 600; pointer-events: none; text-shadow: 0 1px 2px rgba(0,0,0,0.8);">' + displayTitle + '</text>';
          }

          nodesHTML += '</g>';
        });

        nodesGroup.innerHTML = nodesHTML;

        resetZoom();
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

    
    function resolveDeviceCoords(name) {
      if (!name) return null;
      const clean = name.toLowerCase().trim();
      if (deviceCoords[clean]) return deviceCoords[clean];

      for (const devKey in deviceCoords) {
        if (devKey === clean || devKey.startsWith(clean) || clean.startsWith(devKey)) {
          return deviceCoords[devKey];
        }
        const devParts = devKey.split('.');
        const hopParts = clean.split('.');
        if (devParts[0] === hopParts[0]) {
          if (!devParts[1] || !hopParts[1] || devParts[1].startsWith(hopParts[1]) || hopParts[1].startsWith(devParts[1])) {
            return deviceCoords[devKey];
          }
        }
      }
      return null;
    }

    function highlightPathsOnMap(lsp) {
      const pathLayer = document.getElementById('path-layer');
      pathLayer.innerHTML = '';

      // Reset spotlight dimming on all nodes and links
      document.querySelectorAll('.device-node-group').forEach(el => {
        el.classList.remove('dimmed', 'path-highlighted');
      });
      document.querySelectorAll('.topology-link').forEach(el => {
        el.classList.remove('dimmed');
      });

      if (!lsp) return;

      const pathNodes = new Set();
      if (lsp.lsp_hops) {
        lsp.lsp_hops.forEach(h => pathNodes.add(h.toLowerCase()));
      }
      if (lsp.traceroute_hops) {
        lsp.traceroute_hops.forEach(h => pathNodes.add(h.toLowerCase()));
      }

      // Dim uninvolved router nodes
      document.querySelectorAll('.device-node-group').forEach(el => {
        const id = el.id.replace('node-group-', '').toLowerCase();
        if (pathNodes.has(id)) {
          el.classList.add('path-highlighted');
        } else {
          el.classList.add('dimmed');
        }
      });

      // Dim uninvolved topology links
      document.querySelectorAll('.topology-link').forEach(el => {
        const start = (el.getAttribute('data-start') || '').toLowerCase();
        const end = (el.getAttribute('data-end') || '').toLowerCase();
        if (pathNodes.has(start) && pathNodes.has(end)) {
          el.classList.remove('dimmed');
        } else {
          el.classList.add('dimmed');
        }
      });

      let overlayHTML = '';

      // 1. Render LSP Path (Electric Cyan Glow + White Particle Flow)
      if (lsp.lsp_hops && lsp.lsp_hops.length > 1) {
        for (let i = 0; i < lsp.lsp_hops.length - 1; i++) {
          const srcName = lsp.lsp_hops[i];
          const dstName = lsp.lsp_hops[i+1];
          const src = resolveDeviceCoords(srcName);
          const dst = resolveDeviceCoords(dstName);

          if (src && dst) {
            const metroSrc = getMetroOfDevice(srcName);
            const metroDst = getMetroOfDevice(dstName);
            const offset = getOffsetCoords(src, dst, -5, -5);

            if (metroSrc !== metroDst) {
              const dx = offset.end.x - offset.start.x;
              const dy = offset.end.y - offset.start.y;
              const cx = (offset.start.x + offset.end.x) / 2 - dy * 0.15;
              const cy = (offset.start.y + offset.end.y) / 2 + dx * 0.15;
              overlayHTML += '<path class="lsp-path-base" d="M ' + offset.start.x + ' ' + offset.start.y + ' Q ' + cx + ' ' + cy + ' ' + offset.end.x + ' ' + offset.end.y + '" fill="none" marker-end="url(#arrow-cyan)" />';
              overlayHTML += '<path class="lsp-path-flow" d="M ' + offset.start.x + ' ' + offset.start.y + ' Q ' + cx + ' ' + cy + ' ' + offset.end.x + ' ' + offset.end.y + '" fill="none" style="animation: flow-anim 0.8s linear infinite;" />';
            } else {
              overlayHTML += '<line class="lsp-path-base" x1="' + offset.start.x + '" y1="' + offset.start.y + '" x2="' + offset.end.x + '" y2="' + offset.end.y + '" marker-end="url(#arrow-cyan)" />';
              overlayHTML += '<line class="lsp-path-flow" x1="' + offset.start.x + '" y1="' + offset.start.y + '" x2="' + offset.end.x + '" y2="' + offset.end.y + '" style="animation: flow-anim 0.8s linear infinite;" />';
            }
          }
        }
      }

      // 2. Render Traceroute Path (Sunset Orange Glow + Amber Particle Flow)
      if (lsp.traceroute_hops && lsp.traceroute_hops.length > 1) {
        for (let i = 0; i < lsp.traceroute_hops.length - 1; i++) {
          const srcName = lsp.traceroute_hops[i];
          const dstName = lsp.traceroute_hops[i+1];
          const src = resolveDeviceCoords(srcName);
          const dst = resolveDeviceCoords(dstName);

          if (src && dst) {
            const metroSrc = getMetroOfDevice(srcName);
            const metroDst = getMetroOfDevice(dstName);
            const offset = getOffsetCoords(src, dst, 6, 6);

            if (metroSrc !== metroDst) {
              const dx = offset.end.x - offset.start.x;
              const dy = offset.end.y - offset.start.y;
              const cx = (offset.start.x + offset.end.x) / 2 + dy * 0.15;
              const cy = (offset.start.y + offset.end.y) / 2 - dx * 0.15;
              overlayHTML += '<path class="traceroute-path-base" d="M ' + offset.start.x + ' ' + offset.start.y + ' Q ' + cx + ' ' + cy + ' ' + offset.end.x + ' ' + offset.end.y + '" fill="none" marker-end="url(#arrow-orange)" />';
              overlayHTML += '<path class="traceroute-path-flow" d="M ' + offset.start.x + ' ' + offset.start.y + ' Q ' + cx + ' ' + cy + ' ' + offset.end.x + ' ' + offset.end.y + '" fill="none" style="animation: flow-anim 1.0s linear infinite;" />';
            } else {
              overlayHTML += '<line class="traceroute-path-base" x1="' + offset.start.x + '" y1="' + offset.start.y + '" x2="' + offset.end.x + '" y2="' + offset.end.y + '" marker-end="url(#arrow-orange)" />';
              overlayHTML += '<line class="traceroute-path-flow" x1="' + offset.start.x + '" y1="' + offset.start.y + '" x2="' + offset.end.x + '" y2="' + offset.end.y + '" style="animation: flow-anim 1.0s linear infinite;" />';
            }
          }
        }
      }

      // 3. Render Hop Step Badges over traversed nodes
      if (lsp.lsp_hops) {
        lsp.lsp_hops.forEach((hName, idx) => {
          const coords = resolveDeviceCoords(hName);
          if (coords) {
            const label = (idx === 0) ? "IN" : (idx === lsp.lsp_hops.length - 1 ? "OUT" : "H" + (idx + 1));
            const badgeColor = (idx === 0) ? "#10b981" : (idx === lsp.lsp_hops.length - 1 ? "#ef4444" : "#00f2fe");
            overlayHTML += '<g transform="translate(' + coords.x + ', ' + (coords.y - 18) + ')">' +
              '<rect x="-14" y="-8" width="28" height="15" rx="4" fill="' + badgeColor + '" style="filter: drop-shadow(0 2px 6px rgba(0,0,0,0.8));" />' +
              '<text class="path-step-badge" x="0" y="3" text-anchor="middle">' + label + '</text>' +
            '</g>';
          }
        });
      }

      pathLayer.innerHTML = overlayHTML;
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
      if (e.target.closest('.device-node') || e.target.closest('.metro-bubble') || e.target.closest('#lsp-diag-panel') || e.target.closest('.map-legend') || e.target.closest('.canvas-controls')) return;
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
        e.preventDefault();
        const coords = getSVGCoords(e);
        const newX = coords.x - dragOffset.x;
        const newY = coords.y - dragOffset.y;
        deviceCoords[draggedNode] = { x: newX, y: newY, name: draggedNode };

        const group = document.getElementById('node-group-' + draggedNode);
        if (group) group.setAttribute('transform', 'translate(' + newX + ', ' + newY + ')');

        updateNodeLinks(draggedNode);

        if (selectedLsp) highlightPathsOnMap(selectedLsp);
      } else if (draggedMetro) {
        e.preventDefault();
        const coords = getSVGCoords(e);
        const dx = coords.x - dragMetroStart.x;
        const dy = coords.y - dragMetroStart.y;

        if (dx !== 0 || dy !== 0) {
          dragMetroStart = { x: coords.x, y: coords.y };

          const base = adjustedCoordinates[draggedMetro];
          if (base) {
            base.x += dx;
            base.y += dy;
          }

          const bubble = document.getElementById('bubble-' + draggedMetro);
          if (bubble) {
            const bx = parseFloat(bubble.getAttribute('x')) + dx;
            const by = parseFloat(bubble.getAttribute('y')) + dy;
            bubble.setAttribute('x', bx);
            bubble.setAttribute('y', by);
          }

          const label = document.getElementById('label-' + draggedMetro);
          if (label) {
            const lx = parseFloat(label.getAttribute('x')) + dx;
            const ly = parseFloat(label.getAttribute('y')) + dy;
            label.setAttribute('x', lx);
            label.setAttribute('y', ly);
          }

          const devices = devicesByMetro[draggedMetro] || [];
          devices.forEach(devObj => {
            const dev = (typeof devObj === 'string' ? devObj : devObj.name).toLowerCase();
            const nodeCoords = deviceCoords[dev];
            if (nodeCoords) {
              nodeCoords.x += dx;
              nodeCoords.y += dy;

              const group = document.getElementById('node-group-' + dev);
              if (group) {
                group.setAttribute('transform', 'translate(' + nodeCoords.x + ', ' + nodeCoords.y + ')');
              }
              updateNodeLinks(dev);
            }
          });

          if (selectedLsp) highlightPathsOnMap(selectedLsp);
        }
      }
    });

    window.addEventListener('mouseup', () => {
      isDragging = false;
      draggedNode = null;
      draggedMetro = null;
      container.style.cursor = 'grab';
    });

    container.addEventListener('wheel', e => {
      e.preventDefault();
      const coords = getSVGCoords(e);
      const delta = e.deltaY < 0 ? 1.1 : 0.9;
      zoom(delta, coords.x, coords.y);
    }, { passive: false });

    function startDragNode(e, node) {
      e.stopPropagation();
      e.preventDefault();
      draggedNode = node;
      const coords = getSVGCoords(e);
      const nodeCoords = deviceCoords[node] || { x: 0, y: 0 };
      dragOffset = {
        x: coords.x - nodeCoords.x,
        y: coords.y - nodeCoords.y
      };
      container.style.cursor = 'grabbing';
    }

    function updateNodeLinks(node) {
      document.querySelectorAll('#topology-links [data-start="' + node + '"], #topology-links [data-end="' + node + '"]').forEach(elem => {
        const localDev = elem.getAttribute('data-start');
        const remoteDev = elem.getAttribute('data-end');

        const start = resolveDeviceCoords(localDev);
        let end = resolveDeviceCoords(remoteDev);

        if (!end) {
          const remoteMetro = getMetroOfDevice(remoteDev);
          if (adjustedCoordinates[remoteMetro]) {
            const base = adjustedCoordinates[remoteMetro];
            end = { x: base.x, y: base.y };
          }
        }

        if (start && end) {
          const isLine = elem.tagName.toLowerCase() === 'line';
          const idx = parseInt(elem.getAttribute('data-link-index')) || 0;
          const totalLinks = parseInt(elem.getAttribute('data-total-links')) || 1;

          let x1 = start.x, y1 = start.y, x2 = end.x, y2 = end.y;

          if (isLine) {
            elem.setAttribute('x1', x1);
            elem.setAttribute('y1', y1);
            elem.setAttribute('x2', x2);
            elem.setAttribute('y2', y2);
          } else {
            let pathD = "";
            if (totalLinks > 1) {
              const dx = x2 - x1;
              const dy = y2 - y1;
              const len = Math.sqrt(dx * dx + dy * dy) || 1;
              const nx = -dy / len;
              const ny = dx / len;

              const offsetStep = 12;
              const offset = (idx - (totalLinks - 1) / 2) * offsetStep;

              const cx = (x1 + x2) / 2 + nx * offset * 2.5;
              const cy = (y1 + y2) / 2 + ny * offset * 2.5;

              pathD = 'M ' + x1 + ' ' + y1 + ' Q ' + cx + ' ' + cy + ' ' + x2 + ' ' + y2;
            } else {
              pathD = 'M ' + x1 + ' ' + y1 + ' L ' + x2 + ' ' + y2;
            }
            elem.setAttribute('d', pathD);
          }
        }
      });
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

    function showLinkTooltip(e, dev, intf) {
      const tooltip = document.getElementById('tooltip');
      const detail = topologyData[dev][intf];
      const remoteDev = detail.remote_device ? detail.remote_device.toLowerCase() : 'unknown';
      let remoteIntf = detail.remote_interface;

      if ((!remoteIntf || remoteIntf === 'N/A') && topologyData[remoteDev]) {
        const cleanRemoteIp = detail.remote_ip ? detail.remote_ip.split('/')[0] : '';
        const cleanLocalIp = detail.local_ip ? detail.local_ip.split('/')[0] : '';
        const localMembers = detail.members || [];

        // 1. IP match
        for (const rKey in topologyData[remoteDev]) {
          const rDetail = topologyData[remoteDev][rKey];
          const rLocalIp = rDetail.local_ip ? rDetail.local_ip.split('/')[0] : '';
          const rRemoteIp = rDetail.remote_ip ? rDetail.remote_ip.split('/')[0] : '';

          if ((cleanRemoteIp && rLocalIp === cleanRemoteIp) || (cleanLocalIp && rRemoteIp === cleanLocalIp)) {
            remoteIntf = rKey;
            detail.remote_interface = rKey;
            break;
          }
        }

        // 2. Member Overlap match
        if (!remoteIntf && localMembers.length > 0) {
          const localMemSet = new Set(localMembers.map(m => m.toLowerCase().split('.')[0]));
          for (const rKey in topologyData[remoteDev]) {
            const rDetail = topologyData[remoteDev][rKey];
            if (rDetail.remote_device === dev && rDetail.members) {
              for (const rm of rDetail.members) {
                if (localMemSet.has(rm.toLowerCase().split('.')[0])) {
                  remoteIntf = rKey;
                  detail.remote_interface = rKey;
                  break;
                }
              }
            }
            if (remoteIntf) break;
          }
        }

        // 3. Exact interface name match
        if (!remoteIntf) {
          for (const rKey in topologyData[remoteDev]) {
            const rDetail = topologyData[remoteDev][rKey];
            if (rDetail.remote_device === dev && rKey === intf) {
              remoteIntf = rKey;
              detail.remote_interface = rKey;
              break;
            }
          }
        }

        // 4. Index Order Fallback
        if (!remoteIntf) {
          const localPeerLinks = Object.keys(topologyData[dev]).filter(k => topologyData[dev][k].remote_device === remoteDev);
          const remotePeerLinks = Object.keys(topologyData[remoteDev]).filter(k => topologyData[remoteDev][k].remote_device === dev);
          const localIdx = localPeerLinks.indexOf(intf);
          if (localIdx !== -1 && localIdx < remotePeerLinks.length) {
            remoteIntf = remotePeerLinks[localIdx];
            detail.remote_interface = remoteIntf;
          } else if (remotePeerLinks.length > 0) {
            remoteIntf = remotePeerLinks[0];
            detail.remote_interface = remoteIntf;
          }
        }
      }
      if (!remoteIntf) remoteIntf = 'N/A';

      tooltip.style.display = 'block';
      tooltip.style.left = (e.clientX + 15) + 'px';
      tooltip.style.top = (e.clientY + 15) + 'px';

      tooltip.innerHTML =
        '<div style="font-weight:800; color:#38bdf8; font-size:12.5px; border-bottom:1px solid rgba(255,255,255,0.15); padding-bottom:4px; margin-bottom:6px;">' + dev.toUpperCase() + ' ➔ ' + remoteDev.toUpperCase() + '</div>' +
        '<div style="margin-bottom:4px;"><span style="color:#a855f7; font-weight:700;">Local Router:</span> ' + dev.toUpperCase() + ' <span style="color:#38bdf8; font-family:\'JetBrains Mono\', monospace; font-weight:700;">[' + intf + ']</span> ' + (detail.local_ip ? '(' + detail.local_ip + ')' : '') + '</div>' +
        '<div style="margin-bottom:4px;"><span style="color:#10b981; font-weight:700;">Remote Router:</span> ' + remoteDev.toUpperCase() + ' <span style="color:#38bdf8; font-family:\'JetBrains Mono\', monospace; font-weight:700;">[' + remoteIntf + ']</span> ' + (detail.remote_ip ? '(' + detail.remote_ip + ')' : '') + '</div>' +
        '<div><span style="color:#cbd5e1; font-weight:700;">Capacity:</span> ' + (detail.capacity_human || 'N/A') + '</div>';
    }

    function hideTooltip() {
      document.getElementById('tooltip').style.display = 'none';
    }

    function closeDiagPanel() {
      const panel = document.getElementById('lsp-diag-panel');
      panel.style.display = 'none';
      selectedLsp = null;
      document.getElementById('path-layer').innerHTML = '';
      document.querySelectorAll('.device-node-group').forEach(el => {
        el.classList.remove('dimmed', 'path-highlighted');
      });
      document.querySelectorAll('.topology-link').forEach(el => {
        el.classList.remove('dimmed');
      });
      renderLspCards();
    }

    function toggleDiagPanelCollapse() {
      const body = document.getElementById('diag-panel-body');
      if (body.style.display === 'none') {
        body.style.display = 'block';
      } else {
        body.style.display = 'none';
      }
    }

    function initDraggableDiagPanel() {
      const panel = document.getElementById('lsp-diag-panel');
      const header = document.getElementById('diag-panel-header');
      if (!panel || !header) return;

      let isDraggingPanel = false;
      let pStartX = 0, pStartY = 0;

      panel.addEventListener('mousedown', e => {
        e.stopPropagation();
      });

      header.addEventListener('mousedown', e => {
        if (e.target.tagName === 'BUTTON') return;
        e.stopPropagation();
        e.preventDefault();
        isDraggingPanel = true;
        pStartX = e.clientX - panel.offsetLeft;
        pStartY = e.clientY - panel.offsetTop;
        panel.style.right = 'auto';
        panel.style.bottom = 'auto';
      });

      window.addEventListener('mousemove', e => {
        if (isDraggingPanel) {
          panel.style.left = (e.clientX - pStartX) + 'px';
          panel.style.top = (e.clientY - pStartY) + 'px';
        }
      });

      window.addEventListener('mouseup', () => {
        isDraggingPanel = false;
      });
    }

    window.onload = () => {
      initApp();
      initDraggableDiagPanel();
    };
  </script>
</body>
</html>
`
