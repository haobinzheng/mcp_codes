package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const defaultPort = "9002"

type HighUtilFlow struct {
	Source string  `json:"source"`
	Target string  `json:"target"`
	Util   float64 `json:"util"`
	Peak   float64 `json:"peak"`
}

var (
	highUtilFlows   []HighUtilFlow
	highUtilFlowsMu sync.RWMutex

	validTopologyNodes   = make(map[string]bool)
	validTopologyNodesMu sync.RWMutex
)

func normalizeHostname(name string) string {
	name = strings.ToLower(name)
	name = strings.TrimSpace(name)

	// Remove re0- or re1- prefixes
	if strings.HasPrefix(name, "re0-") {
		name = strings.TrimPrefix(name, "re0-")
	} else if strings.HasPrefix(name, "re1-") {
		name = strings.TrimPrefix(name, "re1-")
	}

	// Map dr01 -> bng01, dr02 -> bng02, etc.
	if strings.HasPrefix(name, "dr") {
		parts := strings.Split(name, ".")
		if len(parts) > 0 && len(parts[0]) >= 4 && strings.HasPrefix(parts[0], "dr") {
			digits := parts[0][2:]
			parts[0] = "bng" + digits
			name = strings.Join(parts, ".")
		}
	}

	return name
}

func loadValidTopologyNodes(logger *slog.Logger) {
	jsonPath := "topology_discovery.json"
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		jsonPath = filepath.Join(".", "topology_discovery.json")
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		logger.Error("Failed to read topology JSON file for validation", "path", jsonPath, "error", err)
		return
	}

	var rawTopology map[string]interface{}
	if err := json.Unmarshal(data, &rawTopology); err != nil {
		logger.Error("Failed to unmarshal topology for validation", "error", err)
		return
	}

	validNodes := make(map[string]bool)
	for localDev, val := range rawTopology {
		validNodes[normalizeHostname(localDev)] = true

		intfs, ok := val.(map[string]interface{})
		if !ok {
			continue
		}
		for _, intfVal := range intfs {
			intfDetails, ok := intfVal.(map[string]interface{})
			if !ok {
				continue
			}
			remoteDev, _ := intfDetails["remote_device"].(string)
			if remoteDev != "" && strings.ToLower(remoteDev) != "unknown" {
				validNodes[normalizeHostname(remoteDev)] = true
			}
		}
	}

	validTopologyNodesMu.Lock()
	validTopologyNodes = validNodes
	validTopologyNodesMu.Unlock()

	logger.Info("Loaded valid topology nodes for validation", "count", len(validNodes))
}

func scanHighUtilization(logger *slog.Logger) {
	logger.Info("Starting high utilization scan...")
	today := time.Now().Format("2006-01-02")
	auditDir := filepath.Join("Audit_interfaces_data", today)

	// For safety/testing fallback, if today's directory doesn't exist or has no files,
	// we can check the most recent date folder in Audit_interfaces_data
	if _, err := os.Stat(auditDir); os.IsNotExist(err) {
		logger.Warn("Today's audit directory not found, finding most recent date directory...", "path", auditDir)
		files, err := ioutil.ReadDir("Audit_interfaces_data")
		if err == nil && len(files) > 0 {
			var mostRecent string
			for _, f := range files {
				if f.IsDir() && len(f.Name()) == 10 && strings.Count(f.Name(), "-") == 2 {
					if f.Name() > mostRecent {
						mostRecent = f.Name()
					}
				}
			}
			if mostRecent != "" {
				auditDir = filepath.Join("Audit_interfaces_data", mostRecent)
				logger.Info("Using most recent date directory instead", "path", auditDir)
			}
		}
	}

	deviceDirs, err := ioutil.ReadDir(auditDir)
	if err != nil {
		logger.Error("Failed to read audit directory", "dir", auditDir, "error", err)
		return
	}

	var newFlows []HighUtilFlow

	for _, d := range deviceDirs {
		if !d.IsDir() {
			continue
		}
		devName := normalizeHostname(d.Name())
		devDirPath := filepath.Join(auditDir, d.Name())

		jsonFiles, err := ioutil.ReadDir(devDirPath)
		if err != nil || len(jsonFiles) == 0 {
			continue
		}

		// Track peak utilization for each neighbor from all files today
		type neighborPeaks struct {
			outPeak float64
			inPeak  float64
			hasOut  bool
			hasIn   bool
		}
		peaksMap := make(map[string]*neighborPeaks)

		var latestFile string
		for _, jf := range jsonFiles {
			if jf.IsDir() || !strings.HasSuffix(jf.Name(), ".json") {
				continue
			}
			if jf.Name() > latestFile {
				latestFile = jf.Name()
			}

			filePath := filepath.Join(devDirPath, jf.Name())
			data, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}

			var result map[string]interface{}
			if err := json.Unmarshal(data, &result); err != nil {
				continue
			}

			for key, val := range result {
				if key == "role" || key == "year" || key == "audit_timestamp" {
					continue
				}

				intfDetails, ok := val.(map[string]interface{})
				if !ok {
					continue
				}

				neighbor, _ := intfDetails["neighbor"].(string)
				if neighbor == "" || strings.ToLower(neighbor) == "unknown" {
					continue
				}

				remoteDev := normalizeHostname(neighbor)

				outputVal, okOut := intfDetails["output_bps_percent"]
				inputVal, okIn := intfDetails["input_bps_percent"]

				p, exists := peaksMap[remoteDev]
				if !exists {
					p = &neighborPeaks{}
					peaksMap[remoteDev] = p
				}

				if okOut && outputVal != nil {
					if valFloat, ok := outputVal.(float64); ok {
						p.hasOut = true
						if valFloat > p.outPeak {
							p.outPeak = valFloat
						}
					}
				}
				if okIn && inputVal != nil {
					if valFloat, ok := inputVal.(float64); ok {
						p.hasIn = true
						if valFloat > p.inPeak {
							p.inPeak = valFloat
						}
					}
				}
			}
		}

		if latestFile == "" {
			continue
		}

		latestPath := filepath.Join(devDirPath, latestFile)
		latestData, err := os.ReadFile(latestPath)
		if err != nil {
			continue
		}

		var latestResult map[string]interface{}
		if err := json.Unmarshal(latestData, &latestResult); err != nil {
			continue
		}

		for key, val := range latestResult {
			if key == "role" || key == "year" || key == "audit_timestamp" {
				continue
			}

			intfDetails, ok := val.(map[string]interface{})
			if !ok {
				continue
			}

			neighbor, _ := intfDetails["neighbor"].(string)
			if neighbor == "" || strings.ToLower(neighbor) == "unknown" {
				continue
			}

			remoteDev := normalizeHostname(neighbor)

			// Validate that both devName and remoteDev exist in the topology
			validTopologyNodesMu.RLock()
			isSourceValid := validTopologyNodes[devName]
			isTargetValid := validTopologyNodes[remoteDev]
			validTopologyNodesMu.RUnlock()

			if !isSourceValid || !isTargetValid {
				continue
			}

			outputVal, okOut := intfDetails["output_bps_percent"]
			inputVal, okIn := intfDetails["input_bps_percent"]

			p := peaksMap[remoteDev]

			if okOut && outputVal != nil {
				if outputPct, ok := outputVal.(float64); ok {
					peakVal := outputPct
					if p != nil && p.hasOut {
						peakVal = p.outPeak
					}
					newFlows = append(newFlows, HighUtilFlow{
						Source: devName,
						Target: remoteDev,
						Util:   outputPct,
						Peak:   peakVal,
					})
				}
			}
			if okIn && inputVal != nil {
				if inputPct, ok := inputVal.(float64); ok {
					peakVal := inputPct
					if p != nil && p.hasIn {
						peakVal = p.inPeak
					}
					newFlows = append(newFlows, HighUtilFlow{
						Source: remoteDev,
						Target: devName,
						Util:   inputPct,
						Peak:   peakVal,
					})
				}
			}
		}
	}

	// Deduplicate flows based on Source -> Target
	uniqueFlows := make(map[string]HighUtilFlow)
	for _, flow := range newFlows {
		key := flow.Source + "-->" + flow.Target
		existing, exists := uniqueFlows[key]
		if !exists || flow.Util > existing.Util {
			uniqueFlows[key] = flow
		} else if exists && flow.Peak > existing.Peak {
			existing.Peak = flow.Peak
			uniqueFlows[key] = existing
		}
	}

	var finalFlows []HighUtilFlow
	for _, flow := range uniqueFlows {
		finalFlows = append(finalFlows, flow)
	}

	highUtilFlowsMu.Lock()
	highUtilFlows = finalFlows
	highUtilFlowsMu.Unlock()

	logger.Info("Completed high utilization scan", "found_flows", len(finalFlows))
}

type HistoricalPeakFlow struct {
	Source string  `json:"source"`
	Target string  `json:"target"`
	Peak   float64 `json:"peak"`
}

func scanHistoricalPeaks(startDate, endDate, filterType string, threshold float64) ([]HistoricalPeakFlow, error) {
	entries, err := os.ReadDir("Audit_interfaces_data")
	if err != nil {
		return nil, err
	}

	var activeDates []string
	for _, entry := range entries {
		if entry.IsDir() && len(entry.Name()) == 10 && strings.Count(entry.Name(), "-") == 2 {
			d := entry.Name()
			if (startDate == "" || d >= startDate) && (endDate == "" || d <= endDate) {
				activeDates = append(activeDates, d)
			}
		}
	}

	type flowKey struct {
		source string
		target string
	}
	peaksMap := make(map[flowKey]float64)

	for _, date := range activeDates {
		dateDir := filepath.Join("Audit_interfaces_data", date)
		deviceDirs, err := os.ReadDir(dateDir)
		if err != nil {
			continue
		}

		for _, d := range deviceDirs {
			if !d.IsDir() {
				continue
			}
			devName := normalizeHostname(d.Name())
			devDirPath := filepath.Join(dateDir, d.Name())

			jsonFiles, err := os.ReadDir(devDirPath)
			if err != nil {
				continue
			}

			for _, jf := range jsonFiles {
				if jf.IsDir() || !strings.HasSuffix(jf.Name(), ".json") {
					continue
				}

				filePath := filepath.Join(devDirPath, jf.Name())
				data, err := os.ReadFile(filePath)
				if err != nil {
					continue
				}

				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					continue
				}

				for key, val := range result {
					if key == "role" || key == "year" || key == "audit_timestamp" {
						continue
					}

					intfDetails, ok := val.(map[string]interface{})
					if !ok {
						continue
					}

					neighbor, _ := intfDetails["neighbor"].(string)
					if neighbor == "" || strings.ToLower(neighbor) == "unknown" {
						continue
					}

					remoteDev := normalizeHostname(neighbor)

					if filterType == "output" {
						if outputVal, ok := intfDetails["output_bps_percent"]; ok && outputVal != nil {
							if valFloat, ok := outputVal.(float64); ok {
								k := flowKey{source: devName, target: remoteDev}
								if valFloat > peaksMap[k] {
									peaksMap[k] = valFloat
								}
							}
						}
					} else if filterType == "input" {
						if inputVal, ok := intfDetails["input_bps_percent"]; ok && inputVal != nil {
							if valFloat, ok := inputVal.(float64); ok {
								k := flowKey{source: remoteDev, target: devName}
								if valFloat > peaksMap[k] {
									peaksMap[k] = valFloat
								}
							}
						}
					}
				}
			}
		}
	}

	var flows []HistoricalPeakFlow
	for k, peak := range peaksMap {
		if peak >= threshold {
			flows = append(flows, HistoricalPeakFlow{
				Source: k.source,
				Target: k.target,
				Peak:   peak,
			})
		}
	}

	return flows, nil
}

func startPeriodicAuditScanner(logger *slog.Logger) {
	scanHighUtilization(logger)

	ticker := time.NewTicker(10 * time.Minute)
	go func() {
		for range ticker.C {
			scanHighUtilization(logger)
		}
	}()
}

func main() {
	// Setup structured logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Load valid topology nodes
	loadValidTopologyNodes(logger)

	// Start background audit scanner
	startPeriodicAuditScanner(logger)

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

	// Endpoint to list available audit dates
	mux.HandleFunc("GET /api/dates", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		entries, err := os.ReadDir("Audit_interfaces_data")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": "failed to read audit directory"}`))
			return
		}

		var dates []string
		for _, entry := range entries {
			if entry.IsDir() && len(entry.Name()) == 10 && strings.Count(entry.Name(), "-") == 2 {
				dates = append(dates, entry.Name())
			}
		}
		sort.Strings(dates)

		type DatesResponse struct {
			Dates []string `json:"dates"`
		}
		data, _ := json.Marshal(DatesResponse{Dates: dates})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	// Endpoint to query historical peak utilization flows
	mux.HandleFunc("GET /api/historical_peak", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		startDate := r.URL.Query().Get("start_date")
		endDate := r.URL.Query().Get("end_date")
		filterType := r.URL.Query().Get("type")
		thresholdStr := r.URL.Query().Get("threshold")

		var threshold float64 = 50.0
		if thresholdStr != "" {
			fmt.Sscanf(thresholdStr, "%f", &threshold)
		}

		if filterType != "input" && filterType != "output" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": "invalid type, must be input or output"}`))
			return
		}

		flows, err := scanHistoricalPeaks(startDate, endDate, filterType, threshold)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": "failed to scan historical peaks"}`))
			return
		}

		data, _ := json.Marshal(flows)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

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

	// Endpoint to serve high utilization directed flows
	mux.HandleFunc("GET /api/high_utilization", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		highUtilFlowsMu.RLock()
		data, err := json.Marshal(highUtilFlows)
		highUtilFlowsMu.RUnlock()

		if err != nil {
			slog.Error("Failed to marshal high utilization flows", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`[]`))
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
  <title>My Metro Topology</title>
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
      flex-shrink: 0;
    }

    /* Sidebar Resizer */
    #sidebar-resizer {
      width: 6px;
      background: rgba(234, 179, 8, 0.02);
      border-left: 1px solid rgba(234, 179, 8, 0.1);
      border-right: 1px solid rgba(234, 179, 8, 0.1);
      cursor: col-resize;
      z-index: 20;
      transition: background 0.2s, border-color 0.2s, box-shadow 0.2s;
      flex-shrink: 0;
    }

    #sidebar-resizer:hover,
    #sidebar-resizer.resizing {
      background: rgba(234, 179, 8, 0.25);
      border-color: rgba(234, 179, 8, 0.6);
      box-shadow: 0 0 10px rgba(234, 179, 8, 0.3);
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
      stroke-width: 1.5px;
      transition: all 0.25s ease;
      cursor: grab;
    }

    .metro-bubble:active {
      cursor: grabbing;
    }

    .metro-bubble:hover {
      fill: rgba(39, 39, 42, 0.5);
      stroke: rgba(234, 179, 8, 0.25);
      filter: drop-shadow(0 4px 20px rgba(0,0,0,0.4));
    }

    .metro-label {
      font-size: 13px;
      font-weight: 800;
      fill: #ffffff;
      letter-spacing: 0.1em;
      pointer-events: none;
      text-shadow: 0 2px 4px rgba(0, 0, 0, 0.9), 0 0 10px rgba(0,0,0,0.9);
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

    .topology-link.edge-link {
      transition: opacity 0.25s, stroke-width 0.2s;
    }

    .topology-link.edge-link:hover {
      opacity: 1 !important;
      stroke-width: 2px !important;
    }

    .device-node {
      cursor: pointer;
      transition: stroke-width 0.2s, fill 0.2s, stroke 0.2s;
    }

    .device-node:hover {
      stroke: #ffffff !important;
      stroke-width: 2.5px !important;
      fill: #1e1e24 !important;
    }

    .device-node.active {
      stroke: #ffffff !important;
      stroke-width: 3px !important;
      fill: #272730 !important;
      filter: drop-shadow(0 0 12px rgba(255, 255, 255, 0.8));
    }

    /* Target the whole group for dimming */
    .device-node-group {
      transition: opacity 0.25s ease;
    }

    .device-node-group.dimmed {
      opacity: 0.15 !important;
    }

    /* Dimming overlay for inactive focus highlight */
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

    /* Search Box Styling */
    .search-container {
      position: relative;
      margin-bottom: 10px;
    }

    .search-input {
      width: 100%;
      box-sizing: border-box;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid rgba(234, 179, 8, 0.2);
      border-radius: 8px;
      padding: 10px 12px 10px 36px;
      color: var(--text-main);
      font-family: 'Inter', sans-serif;
      font-size: 13px;
      transition: border-color 0.2s, box-shadow 0.2s;
    }

    .search-input:focus {
      outline: none;
      border-color: rgba(234, 179, 8, 0.6);
      box-shadow: 0 0 10px rgba(234, 179, 8, 0.15);
    }

    .search-icon {
      position: absolute;
      left: 12px;
      top: 50%;
      transform: translateY(-50%);
      width: 14px;
      height: 14px;
      fill: none;
      stroke: var(--text-muted);
      stroke-width: 2;
      stroke-linecap: round;
      stroke-linejoin: round;
      pointer-events: none;
    }

    /* High Utilization Link Glow & Highlight */
    .high-util-link {
      stroke: #ef4444;
      stroke-linecap: round;
      filter: drop-shadow(0 0 8px #ef4444);
      opacity: 0.95;
      animation: high-util-pulse 2s infinite ease-in-out;
    }

    .high-util-flow-line {
      stroke: #ffffff;
      stroke-linecap: round;
      opacity: 0.8;
      pointer-events: none;
    }

    @keyframes high-util-pulse {
      0%, 100% {
        opacity: 0.75;
        stroke-width: 3.5px;
      }
      50% {
        opacity: 1.0;
        stroke-width: 5px;
        filter: drop-shadow(0 0 12px #ef4444);
      }
    }

    /* Historical Peak Link Glow & Highlight */
    .historical-peak-link {
      stroke: #eab308;
      stroke-linecap: round;
      filter: drop-shadow(0 0 8px #eab308);
      opacity: 0.95;
      animation: historical-peak-pulse 2s infinite ease-in-out;
    }

    .historical-peak-flow-line {
      stroke: #ffffff;
      stroke-linecap: round;
      opacity: 0.8;
      pointer-events: none;
    }

    @keyframes historical-peak-pulse {
      0%, 100% {
        opacity: 0.75;
        stroke-width: 3.5px;
      }
      50% {
        opacity: 1.0;
        stroke-width: 5px;
        filter: drop-shadow(0 0 12px #eab308);
      }
    }

    /* High-Utilization Flashing Alarm Styling */
    .alarm-dot-flashing {
      width: 8px;
      height: 8px;
      background-color: #ef4444;
      border-radius: 50%;
      display: inline-block;
      box-shadow: 0 0 8px #ef4444;
      animation: alarm-dot-pulse 1.2s infinite ease-in-out;
    }

    @keyframes alarm-dot-pulse {
      0%, 100% {
        transform: scale(0.8);
        opacity: 0.5;
        box-shadow: 0 0 4px #ef4444;
      }
      50% {
        transform: scale(1.2);
        opacity: 1.0;
        box-shadow: 0 0 12px #ef4444;
      }
    }

    .alarms-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
      max-height: 200px;
      overflow-y: auto;
      margin-bottom: 10px;
    }

    .alarm-card {
      background: rgba(239, 68, 68, 0.08);
      border: 1px solid rgba(239, 68, 68, 0.25);
      border-radius: 8px;
      padding: 10px 12px;
      font-size: 12.5px;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .alarm-card:hover {
      background: rgba(239, 68, 68, 0.18);
      border-color: rgba(239, 68, 68, 0.5);
      box-shadow: 0 0 10px rgba(239, 68, 68, 0.15);
      transform: translateY(-1px);
    }

    .alarm-arrow {
      color: #ef4444;
      font-weight: bold;
      margin: 0 4px;
    }

    .alarm-pct {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
      padding: 2px 6px;
      border-radius: 4px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
    }

    .control-card {
      background: rgba(0,0,0,0.25);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px 16px;
      margin-bottom: 10px;
    }

    .control-slider {
      -webkit-appearance: none;
      width: 100%;
      height: 6px;
      border-radius: 3px;
      background: rgba(234, 179, 8, 0.1);
      outline: none;
      margin: 8px 0;
    }

    .control-slider::-webkit-slider-thumb {
      -webkit-appearance: none;
      appearance: none;
      width: 16px;
      height: 16px;
      border-radius: 50%;
      background: var(--cap-high);
      box-shadow: 0 0 8px var(--cap-high);
      cursor: pointer;
      transition: transform 0.1s;
    }

    .control-slider::-webkit-slider-thumb:hover {
      transform: scale(1.2);
    }
  </style>
</head>
<body>
  <!-- Sidebar Info Panel -->
  <div id="sidebar">
    <div class="sidebar-header">
      <h1 class="sidebar-title">
        <div class="logo-dot"></div>
        <span>My Metro Topology</span>
      </h1>
    </div>
    <div class="sidebar-content">
      <!-- Search Section -->
      <div class="search-container">
        <svg class="search-icon" viewBox="0 0 24 24">
          <circle cx="11" cy="11" r="8" stroke="#a1a1aa" stroke-width="2" fill="none"></circle>
          <line x1="21" y1="21" x2="16.65" y2="16.65" stroke="#a1a1aa" stroke-width="2"></line>
        </svg>
        <input type="text" class="search-input" id="search-box" placeholder="Search device..." oninput="filterTopologyBySearch(this.value)" />
      </div>

      <!-- High Utilization Alarms Panel -->
      <div id="alarms-panel" style="display: none;">
        <div class="section-title" style="color: #ef4444; display: flex; align-items: center; gap: 6px;">
          <span class="alarm-dot-flashing"></span>
          <span>High Utilization Alarms</span>
        </div>
        <div class="alarms-list" id="alarms-list"></div>
      </div>

      <!-- Control Panel Section -->
      <div>
        <div class="section-title">Topology Controls</div>
        <div class="control-card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="font-size: 12px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.02em;">Alarm Threshold</span>
            <span id="threshold-value" style="font-family: 'JetBrains Mono', monospace; font-size: 14px; font-weight: 700; color: #ef4444;">70%</span>
          </div>
          <input type="range" id="threshold-slider" min="10" max="100" value="70" class="control-slider" oninput="updateThreshold(this.value)" />
        </div>
      </div>

      <!-- Historical Peak Filter Section -->
      <div>
        <div class="section-title">Historical Peak Filters</div>
        <div class="control-card" style="font-size: 12px;">
          <div style="margin-bottom: 8px;">
            <label style="font-size: 11px; color: var(--text-muted); font-weight: 600; text-transform: uppercase;">Filter Mode</label>
            <div style="display: flex; gap: 16px; margin-top: 4px;">
              <label style="display: flex; align-items: center; gap: 4px; cursor: pointer;">
                <input type="radio" name="peak-mode" value="input" checked onchange="togglePeakMode()" />
                <span>Peak Input</span>
              </label>
              <label style="display: flex; align-items: center; gap: 4px; cursor: pointer;">
                <input type="radio" name="peak-mode" value="output" onchange="togglePeakMode()" />
                <span>Peak Output</span>
              </label>
            </div>
          </div>
          
          <div style="margin-bottom: 8px;">
            <label style="font-size: 11px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; display: block; margin-bottom: 4px;">Date Range</label>
            <div style="display: flex; gap: 6px;">
              <select id="peak-start-date" style="flex: 1; background: rgba(0,0,0,0.3); border: 1px solid var(--border); border-radius: 4px; padding: 4px; color: var(--text-main); font-size: 11px;" onchange="onPeakFilterChange()"></select>
              <span style="color: var(--text-muted); display: flex; align-items: center;">to</span>
              <select id="peak-end-date" style="flex: 1; background: rgba(0,0,0,0.3); border: 1px solid var(--border); border-radius: 4px; padding: 4px; color: var(--text-main); font-size: 11px;" onchange="onPeakFilterChange()"></select>
            </div>
          </div>

          <div style="margin-bottom: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
              <label style="font-size: 11px; color: var(--text-muted); font-weight: 600; text-transform: uppercase;">Peak Threshold</label>
              <span id="peak-threshold-val" style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #eab308;">50%</span>
            </div>
            <input type="range" id="peak-threshold-slider" min="0" max="100" value="50" class="control-slider" style="margin: 4px 0;" oninput="updatePeakThresholdVal(this.value)" onchange="onPeakFilterChange()" />
          </div>

          <div style="display: flex; gap: 8px; margin-top: 10px;">
            <button class="tab-btn" onclick="applyPeakFilter()" style="flex: 1; padding: 6px; font-size: 12px; font-weight: 600; background: rgba(234, 179, 8, 0.15); border: 1px solid var(--border); color: #eab308; border-radius: 4px; cursor: pointer;">Apply Peak Filter</button>
            <button class="tab-btn" onclick="clearPeakFilter()" style="padding: 6px; font-size: 12px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); color: #ef4444; border-radius: 4px; cursor: pointer;">Clear</button>
          </div>
        </div>
      </div>

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

  <!-- Sidebar Resizer -->
  <div id="sidebar-resizer"></div>

  <!-- Interactive Map Container -->
  <div id="map-container">
    <div id="viewport">
      <svg id="map-svg" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid meet">
        <defs>
          <!-- Glowing Red Arrowhead Marker -->
          <marker id="high-util-arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
            <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#ef4444" />
          </marker>
          <!-- Glowing Gold/Yellow Arrowhead Marker for Historical Peak Filters -->
          <marker id="historical-peak-arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
            <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#eab308" />
          </marker>
        </defs>

        <!-- Grids -->
        <g id="svg-grid"></g>

        <!-- US Contour Approximation path scaled up by 1.6 for expanded viewbox -->
        <path class="us-outline" transform="scale(1.6)" d="M 100,150 C 150,100 300,110 350,90 C 400,70 500,80 600,70 C 700,60 800,80 850,110 C 890,130 920,110 940,180 C 960,220 950,280 930,300 C 910,320 930,380 910,400 C 890,420 850,400 820,440 C 800,460 820,520 780,530 C 750,540 700,480 680,480 C 660,480 620,500 590,480 C 560,460 510,460 470,480 C 450,490 430,520 400,530 C 380,540 340,520 310,480 C 280,450 250,460 230,420 C 210,400 180,380 160,370 C 140,360 130,320 110,310 C 90,300 60,310 50,270 C 40,230 70,210 80,190 Z" />

        <!-- Metro Bubbles group -->
        <g id="metro-bubbles"></g>

        <!-- Topologies links group -->
        <g id="topology-links"></g>

        <!-- High Utilization Flows group -->
        <g id="high-utilization-flows"></g>

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

    function getOffsetCoords(start, end, offsetStart, offsetEnd) {
      const dx = end.x - start.x;
      const dy = end.y - start.y;
      const len = Math.sqrt(dx * dx + dy * dy);
      if (len === 0) return { start: start, end: end };

      // Scale down offsets if the distance is too small to prevent lines/arrows from crossing
      let os = offsetStart;
      let oe = offsetEnd;
      if (len < (offsetStart + offsetEnd)) {
        const scale = (len * 0.6) / (offsetStart + offsetEnd);
        os = offsetStart * scale;
        oe = offsetEnd * scale;
      }

      return {
        start: {
          x: start.x + (dx / len) * os,
          y: start.y + (dy / len) * os
        },
        end: {
          x: end.x - (dx / len) * oe,
          y: end.y - (dy / len) * oe
        }
      };
    }

    let alarmThreshold = 70;
    let currentFlows = [];

    function updateThreshold(val) {
      alarmThreshold = parseInt(val);
      document.getElementById('threshold-value').textContent = alarmThreshold + '%';
      
      const valEl = document.getElementById('threshold-value');
      if (alarmThreshold >= 70) {
        valEl.style.color = '#ef4444';
      } else if (alarmThreshold >= 50) {
        valEl.style.color = '#f97316';
      } else {
        valEl.style.color = '#3b82f6';
      }
      
      renderFlows(currentFlows);
    }

    async function loadHighUtilizationFlows() {
      try {
        const resp = await fetch('/api/high_utilization');
        currentFlows = await resp.json();
        renderFlows(currentFlows);
      } catch (err) {
        console.error("Failed to load high utilization flows", err);
      }
    }

    function renderFlows(flows) {
      const container = document.getElementById('high-utilization-flows');
      if (!container) return;

      let html = '';
      const filteredFlows = flows.filter(flow => flow.util >= alarmThreshold);

      if (!peakFilterApplied) {
        filteredFlows.forEach(flow => {
          const start = deviceCoords[flow.source];
          const end = deviceCoords[flow.target];

          if (start && end) {
            const offset = getOffsetCoords(start, end, 48, 48);
            const flowKey = 'high-util-' + flow.source + '-' + flow.target;

            html += '<line class="high-util-link" id="' + flowKey + '" x1="' + offset.start.x + '" y1="' + offset.start.y + '" x2="' + offset.end.x + '" y2="' + offset.end.y + '" marker-end="url(#high-util-arrow)" />';
            html += '<line class="high-util-flow-line" x1="' + offset.start.x + '" y1="' + offset.start.y + '" x2="' + offset.end.x + '" y2="' + offset.end.y + '" stroke-width="1.2" stroke-dasharray="5, 8" style="animation: flow-anim 1.2s linear infinite;" />';
          }
        });

        container.innerHTML = html;

        // Update Sidebar Alarms Panel
        const alarmsPanel = document.getElementById('alarms-panel');
        const alarmsList = document.getElementById('alarms-list');

        if (alarmsPanel && alarmsList) {
          if (filteredFlows.length > 0) {
            alarmsPanel.style.display = 'block';
            let alarmsHTML = '';

            filteredFlows.forEach(flow => {
              alarmsHTML += '<div class="alarm-card" onclick="selectNode(\'' + flow.source + '\')">' +
                '<div>' +
                  '<span style="font-weight:600; color:#fafafa;">' + flow.source + '</span>' +
                  '<span class="alarm-arrow">➔</span>' +
                  '<span style="font-weight:600; color:#fafafa;">' + flow.target + '</span>' +
                '</div>' +
                '<span class="alarm-pct">' + Math.round(flow.util) + '%</span>' +
              '</div>';
            });

            alarmsList.innerHTML = alarmsHTML;
          } else {
            alarmsPanel.style.display = 'none';
            alarmsList.innerHTML = '';
          }
        }
      }
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

        // Update Node Group transform
        const group = document.getElementById('node-group-' + draggedNode);
        if (group) {
          group.setAttribute('transform', 'translate(' + newX + ', ' + newY + ')');
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
        document.querySelectorAll('.topology-hover-helper[data-start="' + draggedNode + '"]').forEach(helper => {
          helper.setAttribute('x1', newX);
          helper.setAttribute('y1', newY);
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
        document.querySelectorAll('.topology-hover-helper[data-end="' + draggedNode + '"]').forEach(helper => {
          helper.setAttribute('x2', newX);
          helper.setAttribute('y2', newY);
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

          // Update metro bubble rect position in DOM
          const bubble = document.getElementById('bubble-' + draggedMetro);
          if (bubble) {
            const bx = parseFloat(bubble.getAttribute('x')) + dx;
            const by = parseFloat(bubble.getAttribute('y')) + dy;
            bubble.setAttribute('x', bx);
            bubble.setAttribute('y', by);
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

              const group = document.getElementById('node-group-' + dev);
              if (group) {
                group.setAttribute('transform', 'translate(' + nodeCoords.x + ', ' + nodeCoords.y + ')');
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
              document.querySelectorAll('.topology-hover-helper[data-start="' + dev + '"]').forEach(helper => {
                helper.setAttribute('x1', nodeCoords.x);
                helper.setAttribute('y1', nodeCoords.y);
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
              document.querySelectorAll('.topology-hover-helper[data-end="' + dev + '"]').forEach(helper => {
                helper.setAttribute('x2', nodeCoords.x);
                helper.setAttribute('y2', nodeCoords.y);
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

        // 2. Calculate bubble sizes and coordinates for ALL device nodes (including peers)
        const bubbleSizes = {};
        const bngGroupsByMetro = {}; // maps metro -> bngGroups
        const bngRepsByMetro = {};   // maps metro -> bngReps

        const getConnectingCR = (bngName) => {
          const details = topologyData[bngName];
          if (!details) return 'cr01';
          for (const intf of Object.keys(details)) {
            const remote = details[intf].remote_device;
            if (remote && remote.startsWith('cr')) {
              return remote;
            }
          }
          return 'cr01';
        };

        Object.keys(devicesByMetro).forEach(metro => {
          const devices = devicesByMetro[metro];
          
          // Sort devices by role (placing CRs at the top of the grid to receive backbone connection lines)
          devices.sort((a, b) => {
            const roleA = getDeviceRole(a);
            const roleB = getDeviceRole(b);
            const order = { "cr-backbone": 1, "cr-metro": 2, "rr": 3, "pr": 4, "bng": 5, "unknown": 6 };
            return (order[roleA] || 99) - (order[roleB] || 99);
          });

          const bngs = devices.filter(d => getDeviceRole(d) === 'bng');
          const nonBngs = devices.filter(d => getDeviceRole(d) !== 'bng' && getDeviceRole(d) !== 'rr');

          const bngGroups = {};
          bngs.forEach(bng => {
            const cr = getConnectingCR(bng);
            bngGroups[cr] = bngGroups[cr] || [];
            bngGroups[cr].push(bng);
          });

          const logicalNodes = [...nonBngs];
          const bngReps = {};
          Object.keys(bngGroups).forEach(cr => {
            const group = bngGroups[cr];
            if (group.length > 0) {
              const rep = group[0];
              logicalNodes.push(rep);
              bngReps[rep] = group;
            }
          });

          bngGroupsByMetro[metro] = bngGroups;
          bngRepsByMetro[metro] = bngReps;

          let cols = 1;
          if (logicalNodes.length > 1) cols = 2;
          if (logicalNodes.length > 6) cols = 3;
          if (logicalNodes.length > 12) cols = 4;
          
          const rows = Math.ceil(logicalNodes.length / cols);
          const dx = 105;
          const dy = 36;
          
          const gridWidth = (cols - 1) * dx;
          const gridHeight = (rows - 1) * dy;
          
          const maxStackSize = Math.max(...Object.keys(bngGroups).map(k => bngGroups[k].length), 0);
          const stackHeightPadding = maxStackSize > 0 ? (maxStackSize - 1) * 8 : 0;
          const stackWidthPadding = maxStackSize > 0 ? (maxStackSize - 1) * 3 : 0;

          bubbleSizes[metro] = {
            width: gridWidth + 85 + 30 + stackWidthPadding,
            height: gridHeight + 22 + 30 + stackHeightPadding,
            cols: cols,
            rows: rows,
            dx: dx,
            dy: dy,
            gridWidth: gridWidth,
            gridHeight: gridHeight,
            logicalNodes: logicalNodes,
            bngReps: bngReps
          };
        });

        // Copy base coordinates and run physics solver to prevent any overlapping bubbles
        const adjustedCoordinates = {};
        Object.keys(devicesByMetro).forEach(metro => {
          const base = metroCoordinates[metro] || { x: 500, y: 300 };
          adjustedCoordinates[metro] = { x: base.x, y: base.y };
        });

        // Physics solver: 50 iterations to push overlapping bubble boundaries apart
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
              
              const margin = 35; // Ensure a clean gap of at least 35px between bubbles
              
              const dx = c2.x - c1.x;
              const dy = c2.y - c1.y;
              
              const minXDist = halfW1 + halfW2 + margin;
              const minYDist = halfH1 + halfH2 + margin;
              
              const overlapX = minXDist - Math.abs(dx);
              const overlapY = minYDist - Math.abs(dy);
              
              if (overlapX > 0 && overlapY > 0) {
                // We have an overlap! Push them apart along the smaller axis
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
          
          // Clamp all bubbles to stay strictly within the 1600x900 SVG viewBox bounds
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
        
        // Map device to its stack index for render layering order
        const stackIndices = {};

        Object.keys(devicesByMetro).forEach(metro => {
          const devices = devicesByMetro[metro];
          const base = adjustedCoordinates[metro];
          const size = bubbleSizes[metro];
          
          const bx = base.x - size.width / 2;
          const by = base.y - size.height / 2;

          // Check if it is a Backbone Site (BB Site) or standard Metro Site
          const bbMetros = new Set(["lax", "sjc", "slc", "cbf", "ord", "iad", "ewr"]);
          const isBB = bbMetros.has(metro.toLowerCase());
          
          const fill = isBB ? "rgba(69, 45, 10, 0.55)" : "rgba(30, 41, 59, 0.65)";
          const stroke = isBB ? "rgba(234, 179, 8, 0.55)" : "rgba(148, 163, 184, 0.45)";
          const shadowGlow = isBB ? "rgba(234, 179, 8, 0.25)" : "rgba(148, 163, 184, 0.15)";

          // Draw Metro Bubble with premium drop-shadow glow and distinguished background color
          bubblesHTML += '<rect class="metro-bubble" id="bubble-' + metro + '" data-metro="' + metro + '" x="' + bx + '" y="' + by + '" width="' + size.width + '" height="' + size.height + '" rx="16" ry="16" fill="' + fill + '" stroke="' + stroke + '" style="filter: drop-shadow(0 4px 12px ' + shadowGlow + ');" onmousedown="startDragMetro(event, \'' + metro + '\')" />';
          
          // Draw Metro Label
          labelsHTML += '<text class="metro-label" id="label-' + metro + '" x="' + base.x + '" y="' + (base.y + size.height / 2 + 14) + '" text-anchor="middle">' + metro.toUpperCase() + '</text>';

          const offsetX = -size.gridWidth / 2;
          const offsetY = -size.gridHeight / 2;
          
          size.logicalNodes.forEach((dev, idx) => {
            const r = Math.floor(idx / size.cols);
            const c = idx % size.cols;
            const group = size.bngReps[dev];
            
            if (group) {
              group.forEach((gDev, gIdx) => {
                stackIndices[gDev] = gIdx;
                deviceCoords[gDev] = {
                  x: base.x + offsetX + c * size.dx + gIdx * 3,
                  y: base.y + offsetY + r * size.dy + gIdx * 8
                };
              });
            } else {
              deviceCoords[dev] = {
                x: base.x + offsetX + c * size.dx,
                y: base.y + offsetY + r * size.dy
              };
            }
          });

          // Position Route Reflectors (RRs) slightly outside the bubble grid
          const rrs = devices.filter(d => getDeviceRole(d) === 'rr');
          rrs.forEach(rr => {
            let associatedCR = null;
            const parts = rr.split('.');
            if (parts.length >= 2) {
              const suffix = parts[1];
              const matchingCRs = devices.filter(d => getDeviceRole(d).startsWith('cr') && d.includes('.' + suffix));
              if (matchingCRs.length > 0) {
                associatedCR = matchingCRs[0];
              }
            }
            if (!associatedCR) {
              const allCrs = devices.filter(d => getDeviceRole(d).startsWith('cr'));
              if (allCrs.length > 0) {
                associatedCR = allCrs[0];
              }
            }

            if (associatedCR && deviceCoords[associatedCR]) {
              const crCoords = deviceCoords[associatedCR];
              const direction = crCoords.x < base.x ? -1 : 1;
              deviceCoords[rr] = {
                x: crCoords.x + direction * 95,
                y: crCoords.y
              };
            } else {
              deviceCoords[rr] = {
                x: base.x - size.width / 2 - 45,
                y: base.y
              };
            }
          });
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

            const roleLocal = getDeviceRole(localDev);
            const roleRemote = getDeviceRole(remoteDev);
            const isCoreLocal = (roleLocal === "cr-backbone" || roleLocal === "cr-metro" || roleLocal === "rr");
            const isCoreRemote = (roleRemote === "cr-backbone" || roleRemote === "cr-metro" || roleRemote === "rr");
            const isCoreLink = isCoreLocal && isCoreRemote;

            if (isCoreLink) {
              const width = getCapacityWidth(capBps);
              linksHTML += '<line class="topology-link" id="link-' + linkKey + '" data-start="' + localDev + '" data-end="' + remoteDev + '" x1="' + start.x + '" y1="' + start.y + '" x2="' + end.x + '" y2="' + end.y + '" stroke="' + color + '" stroke-width="' + width + '" onclick="selectLink(\'' + localDev + '\', \'' + intf + '\')" />';
              linksHTML += '<line class="topology-flow" id="flow-' + linkKey + '" x1="' + start.x + '" y1="' + start.y + '" x2="' + end.x + '" y2="' + end.y + '" stroke="rgba(255, 255, 255, 0.5)" stroke-width="' + Math.max(1.0, width * 0.25) + '" stroke-dasharray="6, 10" style="animation: flow-anim 1.5s linear infinite; pointer-events: none;" />';
            } else {
              linksHTML += '<line class="topology-link edge-link" id="link-' + linkKey + '" data-start="' + localDev + '" data-end="' + remoteDev + '" x1="' + start.x + '" y1="' + start.y + '" x2="' + end.x + '" y2="' + end.y + '" stroke="' + color + '" stroke-width="1.2" stroke-dasharray="4, 4" opacity="0.45" onclick="selectLink(\'' + localDev + '\', \'' + intf + '\')" />';
            }
            // Invisible thick hover helper (makes line hovering extremely responsive and sensitive)
            linksHTML += '<line class="topology-hover-helper" id="hover-link-' + linkKey + '" data-start="' + localDev + '" data-end="' + remoteDev + '" x1="' + start.x + '" y1="' + start.y + '" x2="' + end.x + '" y2="' + end.y + '" stroke="transparent" stroke-width="15" style="cursor: pointer;" onclick="selectLink(\'' + localDev + '\', \'' + intf + '\')" onmouseenter="showLinkTooltip(event, \'' + localDev + '\', \'' + intf + '\'); highlightLinkLine(\'' + linkKey + '\')" onmouseleave="hideTooltip(); unhighlightLinkLine(\'' + linkKey + '\')" />';
          });
        });
        linksGroup.innerHTML = linksHTML;

        // 4. Draw Device Nodes (Local + Discovered Peers)
        const nodesGroup = document.getElementById('device-nodes');
        let nodesHTML = '';

        const renderDevices = Array.from(allDevices);
        renderDevices.sort((a, b) => {
          const idxA = stackIndices[a] || 0;
          const idxB = stackIndices[b] || 0;
          return idxB - idxA; // Draw larger stack index (behind) first!
        });

        renderDevices.forEach(dev => {
          const coord = deviceCoords[dev];
          const role = getDeviceRole(dev);
          const color = getDeviceColor(role);

          const isCR = (role === "cr-backbone" || role === "cr-metro");
          const isRR = (role === "rr");
          const isCore = isCR || isRR;

          const w = isCore ? 90 : 76;
          const h = isCore ? 24 : 18;
          const halfW = w / 2;
          const halfH = h / 2;
          
          const fontSize = isCore ? "9px" : "7.8px";
          const textDy = isCore ? "3px" : "2.5px";
          const strokeW = isCore ? 2 : 1.2;

          nodesHTML += '<g class="device-node-group" id="node-group-' + dev + '" transform="translate(' + coord.x + ', ' + coord.y + ')">';
          
          if (isCR) {
            // Core Router: Hexagon shape
            nodesHTML += '  <polygon class="device-node-glow" points="-45,0 -33,-12 33,-12 45,0 33,12 -33,12" fill="none" stroke="' + color + '" stroke-width="4" opacity="0.18" style="pointer-events: none;" />';
            nodesHTML += '  <polygon class="device-node" id="node-' + dev + '" points="-45,0 -33,-12 33,-12 45,0 33,12 -33,12" fill="#121214" stroke="' + color + '" stroke-width="' + strokeW + '" onmousedown="startDragNode(event, \'' + dev + '\')" onclick="selectNode(\'' + dev + '\')" onmouseenter="showNodeTooltip(event, \'' + dev + '\')" onmouseleave="hideTooltip()" />';
          } else {
            // Route Reflector / Peering / BNG: Rectangle shape
            const rx = isRR ? 12 : 5;
            const ry = isRR ? 12 : 5;
            if (isCore) {
              nodesHTML += '  <rect class="device-node-glow" x="-' + halfW + '" y="-' + halfH + '" width="' + w + '" height="' + h + '" rx="' + rx + '" ry="' + ry + '" fill="none" stroke="' + color + '" stroke-width="4" opacity="0.18" style="pointer-events: none;" />';
            }
            nodesHTML += '  <rect class="device-node" id="node-' + dev + '" x="-' + halfW + '" y="-' + halfH + '" width="' + w + '" height="' + h + '" rx="' + rx + '" ry="' + ry + '" fill="#121214" stroke="' + color + '" stroke-width="' + strokeW + '" onmousedown="startDragNode(event, \'' + dev + '\')" onclick="selectNode(\'' + dev + '\')" onmouseenter="showNodeTooltip(event, \'' + dev + '\')" onmouseleave="hideTooltip()" />';
          }
          
          nodesHTML += '  <text class="device-node-text" x="0" y="0" dy="' + textDy + '" text-anchor="middle" fill="#ffffff" style="font-family: \'JetBrains Mono\', monospace; font-size: ' + fontSize + '; font-weight: 600; pointer-events: none; text-shadow: 0 1px 2px rgba(0,0,0,0.8);">' + dev + '</text>';
          nodesHTML += '</g>';
        });
        nodesGroup.innerHTML = nodesHTML;

        // Load directed high utilization overlays (>= 70%)
        await loadHighUtilizationFlows();
        await loadPeakFilterDates();

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

    function normalizeDevName(name) {
      name = name.toLowerCase().trim();
      if (name.startsWith("re0-")) name = name.replace("re0-", "");
      if (name.startsWith("re1-")) name = name.replace("re1-", "");
      if (name.startsWith("dr")) {
        const parts = name.split(".");
        if (parts.length > 0 && parts[0].length >= 4 && parts[0].startsWith("dr")) {
          const digits = parts[0].substring(2);
          parts[0] = "bng" + digits;
          name = parts.join(".");
        }
      }
      return name;
    }

    function getRemoteInterface(localDev, remoteDev, localIntf) {
      const remoteDevData = topologyData[remoteDev];
      if (!remoteDevData) return null;
      for (const remoteIntf of Object.keys(remoteDevData)) {
        const remoteLink = remoteDevData[remoteIntf];
        if (remoteLink.remote_device === localDev) {
          return remoteIntf;
        }
      }
      return null;
    }

    function getLinkUtilization(localDev, remoteDev) {
      if (!currentFlows) return { outUtil: null, inUtil: null, outPeak: null, inPeak: null };
      const nLocal = normalizeDevName(localDev);
      const nRemote = normalizeDevName(remoteDev);
      
      let outFlow = currentFlows.find(f => normalizeDevName(f.source) === nLocal && normalizeDevName(f.target) === nRemote);
      let inFlow = currentFlows.find(f => normalizeDevName(f.source) === nRemote && normalizeDevName(f.target) === nLocal);
      
      return {
        outUtil: outFlow ? outFlow.util : null,
        inUtil: inFlow ? inFlow.util : null,
        outPeak: outFlow ? outFlow.peak : null,
        inPeak: inFlow ? inFlow.peak : null
      };
    }

    // Links Tooltip Logic
    function showLinkTooltip(e, localDev, intf) {
      const link = topologyData[localDev][intf];
      const remoteDev = link.remote_device;
      const remoteIntf = getRemoteInterface(localDev, remoteDev, intf);
      const remoteIntfStr = remoteIntf ? " (" + remoteIntf + ")" : "";
      
      const utils = getLinkUtilization(localDev, remoteDev);
      const outStr = utils.outUtil !== null ? Math.round(utils.outUtil) + "%" : "n/a";
      const inStr = utils.inUtil !== null ? Math.round(utils.inUtil) + "%" : "n/a";
      const outPeakStr = utils.outPeak !== null ? Math.round(utils.outPeak) + "%" : "n/a";
      const inPeakStr = utils.inPeak !== null ? Math.round(utils.inPeak) + "%" : "n/a";
      
      tooltip.innerHTML = ` + "`" + `
        <strong>Link Details</strong><br/>
        <span style="color:#fafafa">${localDev} (${intf})</span><br/>
        <span style="color:#a1a1aa">to</span><br/>
        <span style="color:#fafafa">${remoteDev}${remoteIntfStr}</span><br/>
        <span style="color:#eab308; font-weight: 600; margin-top: 4px; display: inline-block;">Capacity: ${link.capacity_human}</span><br/>
        <div style="border-top: 1px solid rgba(234, 179, 8, 0.2); margin-top: 6px; padding-top: 6px; font-size: 11px;">
          <span style="color:#a1a1aa; font-weight: 600;">Utilization (${localDev}):</span><br/>
          <span style="color:#fafafa;">Current: TX: ${outStr} | RX: ${inStr}</span><br/>
          <span style="color:#fafafa;">Daily Peak: TX: ${outPeakStr} | RX: ${inPeakStr}</span>
        </div>
      ` + "`" + `;
      tooltip.style.display = 'block';
      positionTooltip(e);
    }

    function positionTooltip(e) {
      const containerRect = container.getBoundingClientRect();
      let x = e.clientX - containerRect.left + 15;
      let y = e.clientY - containerRect.top + 15;
      
      // Prevent overflowing right boundary
      if (x + tooltip.offsetWidth > containerRect.width) {
        x = e.clientX - containerRect.left - tooltip.offsetWidth - 15;
      }
      // Prevent overflowing bottom boundary
      if (y + tooltip.offsetHeight > containerRect.height) {
        y = e.clientY - containerRect.top - tooltip.offsetHeight - 15;
      }
      
      // Ensure it doesn't go below 0 (top or left boundaries)
      if (x < 0) x = 10;
      if (y < 0) y = 10;
      
      tooltip.style.left = x + 'px';
      tooltip.style.top = y + 'px';
    }

    function hideTooltip() {
      tooltip.style.display = 'none';
    }

    function highlightLinkLine(linkKey) {
      const link = document.getElementById('link-' + linkKey);
      if (link) {
        const baseWidth = parseFloat(link.getAttribute('stroke-width')) || 1.2;
        link.style.strokeWidth = (baseWidth + 2.5) + 'px';
        link.style.opacity = '1.0';
      }
    }

    function unhighlightLinkLine(linkKey) {
      const link = document.getElementById('link-' + linkKey);
      if (link) {
        link.style.strokeWidth = '';
        link.style.opacity = '';
      }
    }

    // Node & Link Selection Panels
    let selectedNode = null;

    function selectNode(device) {
      // Toggle selection off if clicking already selected node
      if (selectedNode === device) {
        resetSelection();
        return;
      }
      // Reset all dimming and active classes
      document.querySelectorAll('.device-node-group').forEach(group => {
        group.classList.remove('dimmed');
      });
      document.querySelectorAll('.device-node').forEach(node => {
        node.classList.remove('active');
      });
      document.querySelectorAll('.topology-link, .topology-flow').forEach(el => {
        el.classList.remove('dimmed');
      });

      const rect = document.getElementById('node-' + device);
      if (rect) {
        rect.classList.add('active');
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
        intfsStr += intf + ' -> ' + link.remote_device + ' (' + link.capacity_human + ')\n';
      });

      // 2. Scan other audited devices for incoming connections pointing to this device
      Object.keys(topologyData).forEach(localDev => {
        const intfs = topologyData[localDev];
        Object.keys(intfs).forEach(intf => {
          if (intfs[intf].remote_device === device) {
            connectedDevices.add(localDev);
            intfsStr += '[Peer] ' + localDev + ' (' + intf + ') -> This Device (' + intfs[intf].capacity_human + ')\n';
          }
        });
      });

      document.getElementById('info-interfaces').textContent = intfsStr || 'Device was unreachable during audit cycle.';
      
      // Dim out non-connected nodes
      document.querySelectorAll('.device-node-group').forEach(group => {
        const devName = group.id.replace('node-group-', '');
        if (devName !== device && !connectedDevices.has(devName)) {
          group.classList.add('dimmed');
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
      selectedNode = null;
      document.querySelectorAll('.device-node-group').forEach(group => {
        group.classList.remove('dimmed');
      });
      document.querySelectorAll('.device-node').forEach(node => {
        node.classList.remove('active');
      });
      document.querySelectorAll('.topology-link, .topology-flow').forEach(el => {
        el.classList.remove('dimmed');
      });
      document.getElementById('selection-panel').style.display = 'none';
    }

    function filterTopologyBySearch(query) {
      const q = query.toLowerCase().trim();
      if (!q) {
        resetSelection();
        return;
      }

      selectedNode = null;
      document.getElementById('selection-panel').style.display = 'none';

      const matchingDevices = new Set();
      
      document.querySelectorAll('.device-node-group').forEach(group => {
        const devName = group.id.replace('node-group-', '');
        if (devName.toLowerCase().indexOf(q) !== -1) {
          matchingDevices.add(devName);
        }
      });

      if (matchingDevices.size === 1) {
        const singleDev = Array.from(matchingDevices)[0];
        selectNode(singleDev);
        return;
      }

      // Highlight matching groups, dim non-matches
      document.querySelectorAll('.device-node-group').forEach(group => {
        const devName = group.id.replace('node-group-', '');
        if (matchingDevices.has(devName)) {
          group.classList.remove('dimmed');
          const node = document.getElementById('node-' + devName);
          if (node) {
            node.classList.add('active');
          }
        } else {
          group.classList.add('dimmed');
          const node = document.getElementById('node-' + devName);
          if (node) {
            node.classList.remove('active');
          }
        }
      });

      // Dim out links where neither end matches
      document.querySelectorAll('.topology-link').forEach(link => {
        const startDev = link.getAttribute('data-start');
        const endDev = link.getAttribute('data-end');
        if (matchingDevices.has(startDev) || matchingDevices.has(endDev)) {
          link.classList.remove('dimmed');
          const flowId = link.id.replace('link-', 'flow-');
          const flow = document.getElementById(flowId);
          if (flow) flow.classList.remove('dimmed');
        } else {
          link.classList.add('dimmed');
          const flowId = link.id.replace('link-', 'flow-');
          const flow = document.getElementById(flowId);
          if (flow) flow.classList.add('dimmed');
        }
      });
    }

    function selectLink(localDev, intf) {
      // Programmatically select the local device
      selectNode(localDev);
    }

    // Clear highlights by clicking on empty/blank SVG canvas areas
    document.addEventListener('DOMContentLoaded', () => {
      const svg = document.getElementById('map-svg');
      if (svg) {
        svg.addEventListener('click', (e) => {
          if (e.target.closest('.device-node') || e.target.closest('.topology-link') || e.target.closest('.metro-bubble') || e.target.closest('.device-node-glow')) return;
          resetSelection();
        });
      }
    });

    // Sidebar Resizing Logic
    document.addEventListener('DOMContentLoaded', () => {
      const sidebar = document.getElementById('sidebar');
      const resizer = document.getElementById('sidebar-resizer');
      let isResizing = false;

      if (resizer && sidebar) {
        resizer.addEventListener('mousedown', (e) => {
          isResizing = true;
          resizer.classList.add('resizing');
          document.body.style.cursor = 'col-resize';
          document.body.style.userSelect = 'none';
          e.preventDefault();
        });

        window.addEventListener('mousemove', (e) => {
          if (!isResizing) return;
          let newWidth = e.clientX;
          if (newWidth < 280) newWidth = 280;
          if (newWidth > 600) newWidth = 600;
          sidebar.style.width = newWidth + 'px';
        });

        window.addEventListener('mouseup', () => {
          if (isResizing) {
            isResizing = false;
            resizer.classList.remove('resizing');
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
          }
        });
      }

      // Poll high utilization flows every 30 seconds to keep map state reactive
      setInterval(loadHighUtilizationFlows, 30000);
    });

    let peakFilterApplied = false;
    let peakFlows = [];
    let peakThreshold = 50;
    let peakMode = 'input';

    async function loadPeakFilterDates() {
      try {
        const resp = await fetch('/api/dates');
        const data = await resp.json();
        const startSelect = document.getElementById('peak-start-date');
        const endSelect = document.getElementById('peak-end-date');
        
        if (startSelect && endSelect && data.dates) {
          startSelect.innerHTML = '';
          endSelect.innerHTML = '';
          
          data.dates.forEach(date => {
            const opt1 = document.createElement('option');
            opt1.value = date;
            opt1.textContent = date;
            startSelect.appendChild(opt1);
            
            const opt2 = document.createElement('option');
            opt2.value = date;
            opt2.textContent = date;
            endSelect.appendChild(opt2);
          });
          
          if (data.dates.length > 0) {
            startSelect.value = data.dates[0];
            endSelect.value = data.dates[data.dates.length - 1];
          }
        }
      } catch (err) {
        console.error("Failed to load peak filter dates", err);
      }
    }

    function togglePeakMode() {
      const radios = document.getElementsByName('peak-mode');
      for (const r of radios) {
        if (r.checked) {
          peakMode = r.value;
          break;
        }
      }
      if (peakFilterApplied) {
        applyPeakFilter();
      }
    }

    function updatePeakThresholdVal(val) {
      peakThreshold = val;
      const el = document.getElementById('peak-threshold-val');
      if (el) el.textContent = val + '%';
    }

    function onPeakFilterChange() {
      if (peakFilterApplied) {
        applyPeakFilter();
      }
    }

    async function applyPeakFilter() {
      const btn = document.querySelector("button[onclick='applyPeakFilter()']");
      const originalText = btn ? btn.textContent : 'Apply Peak Filter';
      if (btn) {
        btn.disabled = true;
        btn.textContent = 'Applying Filter...';
        btn.style.opacity = '0.6';
      }

      const startDate = document.getElementById('peak-start-date').value;
      const endDate = document.getElementById('peak-end-date').value;
      
      try {
        const resp = await fetch("/api/historical_peak?start_date=" + encodeURIComponent(startDate) + "&end_date=" + encodeURIComponent(endDate) + "&type=" + encodeURIComponent(peakMode) + "&threshold=" + encodeURIComponent(peakThreshold));
        peakFlows = await resp.json();
        peakFilterApplied = true;
        renderPeakFlows();
      } catch (err) {
        console.error("Failed to apply peak filter", err);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = originalText;
          btn.style.opacity = '';
        }
      }
    }

    function clearPeakFilter() {
      peakFilterApplied = false;
      peakFlows = [];
      const container = document.getElementById('high-utilization-flows');
      if (container) container.innerHTML = '';
      
      const alarmsPanel = document.getElementById('alarms-panel');
      if (alarmsPanel) {
        const titleSpan = alarmsPanel.querySelector('.section-title span:last-child');
        if (titleSpan) titleSpan.textContent = 'High Utilization Alarms';
      }
      
      renderFlows(currentFlows);
    }

    function renderPeakFlows() {
      const container = document.getElementById('high-utilization-flows');
      if (!container) return;
      
      let html = '';
      
      peakFlows.forEach(flow => {
        const start = deviceCoords[flow.source];
        const end = deviceCoords[flow.target];
        
        if (start && end) {
          const offset = getOffsetCoords(start, end, 48, 48);
          const flowKey = 'peak-flow-' + flow.source + '-' + flow.target;
          
          html += '<line class="historical-peak-link" id="' + flowKey + '" x1="' + offset.start.x + '" y1="' + offset.start.y + '" x2="' + offset.end.x + '" y2="' + offset.end.y + '" marker-end="url(#historical-peak-arrow)" />';
          html += '<line class="historical-peak-flow-line" x1="' + offset.start.x + '" y1="' + offset.start.y + '" x2="' + offset.end.x + '" y2="' + offset.end.y + '" stroke="#eab308" stroke-width="1.2" stroke-dasharray="5, 8" style="animation: flow-anim 1.2s linear infinite; pointer-events: none;" />';
        }
      });
      
      container.innerHTML = html;

      const alarmsPanel = document.getElementById('alarms-panel');
      const alarmsList = document.getElementById('alarms-list');
      
      if (alarmsPanel && alarmsList) {
        alarmsPanel.style.display = 'block';
        const titleSpan = alarmsPanel.querySelector('.section-title span:last-child');
        if (titleSpan) titleSpan.textContent = 'Peak Highlights (' + peakMode.toUpperCase() + ')';
        
        if (peakFlows.length > 0) {
          let listHTML = '';
          peakFlows.forEach(flow => {
            listHTML += '<div class="alarm-card" style="background: rgba(234, 179, 8, 0.08); border-color: rgba(234, 179, 8, 0.25);" onclick="selectNode(\'' + flow.source + '\')">' +
              '<div>' +
                '<span style="font-weight:600; color:#fafafa;">' + flow.source + '</span>' +
                '<span class="alarm-arrow" style="color:#eab308;">➔</span>' +
                '<span style="font-weight:600; color:#fafafa;">' + flow.target + '</span>' +
              '</div>' +
              '<span class="alarm-pct" style="background: rgba(234, 179, 8, 0.2); color:#eab308;">' + Math.round(flow.peak) + '%</span>' +
            '</div>';
          });
          alarmsList.innerHTML = listHTML;
        } else {
          alarmsList.innerHTML = '<div style="padding:12px; background: rgba(255, 255, 255, 0.03); border: 1px dashed rgba(234, 179, 8, 0.2); border-radius:8px; text-align:center; font-size:11.5px; color:var(--text-muted);">No links crossed the ' + peakThreshold + '% threshold in this date range.</div>';
        }
      }
    }

    document.addEventListener('DOMContentLoaded', loadTopology);
  </script>
</body>
</html>
`
