package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed index.html
var indexHTML []byte

var (
	webHost     = "127.0.0.1"
	webPort     = "9000"
	rootDataDir = "Audit_interfaces_data"

	// Regular expressions for input validation and filename parsing
	dateParamRegex   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	routerParamRegex = regexp.MustCompile(`^[a-zA-Z0-9\._\-]+$`)
	fileRegex        = regexp.MustCompile(`_(\d{4})_(\d{2})_(\d{2})_(\d{2})_(\d{2})\.json$`)
)

func init() {
	// Setup high-performance production-grade structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if host := os.Getenv("WEB_HOST"); host != "" {
		webHost = host
	}
	if port := os.Getenv("WEB_PORT"); port != "" {
		webPort = port
	}
	if dir := os.Getenv("ROOT_DATA_DIR"); dir != "" {
		rootDataDir = dir
	}
}

// Securely resolves paths to prevent directory traversal attacks.
func getSafePath(subpaths ...string) (string, error) {
	absRoot, err := filepath.Abs(rootDataDir)
	if err != nil {
		return "", err
	}
	canonicalRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return "", err
		}
		return "", err
	}

	joined := filepath.Join(append([]string{canonicalRoot}, subpaths...)...)
	absTarget, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	canonicalTarget, err := filepath.EvalSymlinks(absTarget)
	if err != nil {
		canonicalTarget = filepath.Clean(absTarget)
	}

	if canonicalTarget == canonicalRoot {
		return canonicalTarget, nil
	}
	if strings.HasPrefix(canonicalTarget, canonicalRoot+string(filepath.Separator)) {
		return canonicalTarget, nil
	}
	return "", errors.New("Security Violation: Path traversal detected")
}

// Data structures matching dynamic JSON file payloads
type AuditFileContent struct {
	Role           string                           `json:"role"`
	Year           int                              `json:"year"`
	AuditTimestamp string                           `json:"audit_timestamp"`
	Interfaces     map[string]ParsedInterfaceDetail `json:"-"`
}

type ParsedInterfaceDetail struct {
	Neighbor       string   `json:"neighbor"`
	Circuit        string   `json:"Circuit"`
	Description    string   `json:"description"`
	Speed          string   `json:"speed"`
	SpeedHuman     float64  `json:"speed_human"`
	InputBps       float64  `json:"input_bps"`
	InputPercent   float64  `json:"input_bps_percent"`
	OutputBps      float64  `json:"output_bps"`
	OutputPercent  float64  `json:"output_bps_percent"`
	InputPps       float64  `json:"input_pps"`
	OutputPps      float64  `json:"output_pps"`
	AEList         []string `json:"ae_list"`
	Is400GUpgraded bool     `json:"is_400g_upgraded"`
	UpgradeStatus  string   `json:"upgrade_status"`
}

// Parses dynamic interface dictionary keys from Juniper audit JSON outputs
func parseAuditFile(filePath string) (*AuditFileContent, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return nil, err
	}

	content := &AuditFileContent{
		Interfaces: make(map[string]ParsedInterfaceDetail),
	}

	if roleMsg, ok := rawMap["role"]; ok {
		_ = json.Unmarshal(roleMsg, &content.Role)
	}
	if yearMsg, ok := rawMap["year"]; ok {
		_ = json.Unmarshal(yearMsg, &content.Year)
	}
	if tsMsg, ok := rawMap["audit_timestamp"]; ok {
		_ = json.Unmarshal(tsMsg, &content.AuditTimestamp)
	}

	for k, v := range rawMap {
		if k == "role" || k == "year" || k == "audit_timestamp" {
			continue
		}
		var detail ParsedInterfaceDetail
		if err := json.Unmarshal(v, &detail); err == nil {
			content.Interfaces[k] = detail
		}
	}

	return content, nil
}

type parseJob struct {
	index    int
	filePath string
}

type parseResult struct {
	index   int
	content *AuditFileContent
	err     error
}

// High-performance concurrent file parsing using a worker pool
func parseFilesConcurrently(filePaths []string) (map[int]*AuditFileContent, error) {
	numFiles := len(filePaths)
	if numFiles == 0 {
		return make(map[int]*AuditFileContent), nil
	}

	jobs := make(chan parseJob, numFiles)
	results := make(chan parseResult, numFiles)

	// Limit worker pool scale to 16 to prevent OS file descriptor exhaustion
	numWorkers := 16
	if numFiles < numWorkers {
		numWorkers = numFiles
	}

	// Spin up concurrent worker pool
	for w := 0; w < numWorkers; w++ {
		go func() {
			for job := range jobs {
				content, err := parseAuditFile(job.filePath)
				results <- parseResult{
					index:   job.index,
					content: content,
					err:     err,
				}
			}
		}()
	}

	// Dispatch jobs
	for i, fp := range filePaths {
		jobs <- parseJob{index: i, filePath: fp}
	}
	close(jobs)

	// Aggregate results thread-safely
	resultsMap := make(map[int]*AuditFileContent)
	for i := 0; i < numFiles; i++ {
		res := <-results
		if res.err != nil {
			// Skip malformed files gracefully without halting entire pipeline
			slog.Warn("failed to parse audit file concurrently", "path", filePaths[res.index], "error", res.err)
			continue
		}
		resultsMap[res.index] = res.content
	}

	return resultsMap, nil
}

// Response models for frontend APIs
type DatesResponse struct {
	Dates []string `json:"dates"`
}

type RoutersResponse struct {
	Routers []string `json:"routers"`
}

type InterfaceInfoResponse struct {
	Neighbor       string  `json:"neighbor"`
	Circuit        string  `json:"circuit"`
	Speed          string  `json:"speed"`
	InputPercent   float64 `json:"input_percent"`
	OutputPercent  float64 `json:"output_percent"`
	Is400GUpgraded bool    `json:"is_400g_upgraded"`
	UpgradeStatus  string  `json:"upgrade_status"`
}

type SeriesResponse struct {
	Input  []*float64 `json:"input"`
	Output []*float64 `json:"output"`
}

type RouterDataResponse struct {
	Timestamps []string                         `json:"timestamps"`
	Interfaces map[string]InterfaceInfoResponse `json:"interfaces"`
	Series     map[string]SeriesResponse        `json:"series"`
}

type HighInterfaceResponse struct {
	Router         string         `json:"router"`
	Interface      string         `json:"interface"`
	Neighbor       string         `json:"neighbor"`
	Speed          string         `json:"speed"`
	PeakInput      float64        `json:"peak_input"`
	PeakOutput     float64        `json:"peak_output"`
	Timestamps     []string       `json:"timestamps"`
	Series         SeriesResponse `json:"series"`
	Is400GUpgraded bool           `json:"is_400g_upgraded"`
	UpgradeStatus  string         `json:"upgrade_status"`
}

type HighUtilizationResponse struct {
	HighInterfaces []HighInterfaceResponse `json:"high_interfaces"`
}

type HighUtilizationHistoryResponse struct {
	HighInterfacesHistory []HighInterfaceResponse `json:"high_interfaces_history"`
}

// Helper for JSON HTTP responses
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// Helper for error responses
func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"detail": detail})
}

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Logger middleware capturing metadata and latency
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(wrapped, r)
		
		slog.Info("http request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration", time.Since(start).String(),
			"client_ip", r.RemoteAddr,
		)
	})
}

// Recoverer middleware ensuring the server never crashes due to handler panics
func RecovererMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("panic recovered in HTTP handler",
					"error", err,
					"path", r.URL.Path,
					"stack", string(debug.Stack()),
				)
				writeError(w, http.StatusInternalServerError, "Internal Server Error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()

	// Serve Dashboard Index HTML
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexHTML)
	})

	// API: Dates Route
	mux.HandleFunc("GET /api/dates", func(w http.ResponseWriter, r *http.Request) {
		safeRoot, err := getSafePath()
		if err != nil {
			writeError(w, http.StatusForbidden, "Access Denied")
			return
		}

		entries, err := os.ReadDir(safeRoot)
		if err != nil {
			writeJSON(w, http.StatusOK, DatesResponse{Dates: []string{}})
			return
		}

		var dates []string
		for _, entry := range entries {
			if entry.IsDir() && dateParamRegex.MatchString(entry.Name()) {
				dates = append(dates, entry.Name())
			}
		}

		sort.Slice(dates, func(i, j int) bool {
			return dates[i] > dates[j] // Descending order
		})

		writeJSON(w, http.StatusOK, DatesResponse{Dates: dates})
	})

	// API: Routers Route
	mux.HandleFunc("GET /api/routers", func(w http.ResponseWriter, r *http.Request) {
		date := r.URL.Query().Get("date")
		if date == "" || !dateParamRegex.MatchString(date) {
			writeJSON(w, http.StatusOK, RoutersResponse{Routers: []string{}})
			return
		}

		datePath, err := getSafePath(date)
		if err != nil {
			writeError(w, http.StatusForbidden, "Access Denied")
			return
		}

		if _, err := os.Stat(datePath); os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, RoutersResponse{Routers: []string{}})
			return
		}

		entries, err := os.ReadDir(datePath)
		if err != nil {
			writeJSON(w, http.StatusOK, RoutersResponse{Routers: []string{}})
			return
		}

		var routers []string
		for _, entry := range entries {
			if entry.IsDir() {
				routers = append(routers, entry.Name())
			}
		}

		sort.Strings(routers)
		writeJSON(w, http.StatusOK, RoutersResponse{Routers: routers})
	})

	// API: Router Data Route
	mux.HandleFunc("GET /api/router_data", func(w http.ResponseWriter, r *http.Request) {
		date := r.URL.Query().Get("date")
		router := r.URL.Query().Get("router")
		if date == "" || router == "" || !dateParamRegex.MatchString(date) || !routerParamRegex.MatchString(router) {
			writeError(w, http.StatusBadRequest, "Missing or invalid parameters")
			return
		}

		routerPath, err := getSafePath(date, router)
		if err != nil {
			writeError(w, http.StatusForbidden, "Access Denied")
			return
		}

		if _, err := os.Stat(routerPath); os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, RouterDataResponse{
				Timestamps: []string{},
				Interfaces: make(map[string]InterfaceInfoResponse),
				Series:     make(map[string]SeriesResponse),
			})
			return
		}

		entries, err := os.ReadDir(routerPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to read directory")
			return
		}

		type FileData struct {
			TimestampLabel string
			FilePath       string
		}

		var validFiles []FileData
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if strings.HasPrefix(name, router+"_") && strings.HasSuffix(name, ".json") {
				matches := fileRegex.FindStringSubmatch(name)
				if len(matches) >= 6 {
					tsLabel := fmt.Sprintf("%s:%s", matches[4], matches[5])
					validFiles = append(validFiles, FileData{
						TimestampLabel: tsLabel,
						FilePath:       filepath.Join(routerPath, name),
					})
				}
			}
		}

		// Sort files chronologically
		sort.Slice(validFiles, func(i, j int) bool {
			return validFiles[i].FilePath < validFiles[j].FilePath
		})

		var timestamps []string
		for _, vf := range validFiles {
			timestamps = append(timestamps, vf.TimestampLabel)
		}

		seriesMap := make(map[string]SeriesResponse)
		latestIntfs := make(map[string]InterfaceInfoResponse)

		// Concurrent parsing of files
		filePaths := make([]string, len(validFiles))
		for i, vf := range validFiles {
			filePaths[i] = vf.FilePath
		}

		resultsMap, err := parseFilesConcurrently(filePaths)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to parse files concurrently")
			return
		}

		for fileIdx := range validFiles {
			content := resultsMap[fileIdx]
			if content == nil {
				continue
			}

			presentInterfaces := make(map[string]bool)
			for k, v := range content.Interfaces {
				presentInterfaces[k] = true

				if _, exists := seriesMap[k]; !exists {
					inputs := make([]*float64, fileIdx)
					outputs := make([]*float64, fileIdx)
					seriesMap[k] = SeriesResponse{Input: inputs, Output: outputs}
				}

				inVal := v.InputPercent
				outVal := v.OutputPercent

				series := seriesMap[k]
				series.Input = append(series.Input, &inVal)
				series.Output = append(series.Output, &outVal)
				seriesMap[k] = series

				latestIntfs[k] = InterfaceInfoResponse{
					Neighbor:       v.Neighbor,
					Circuit:        v.Circuit,
					Speed:          v.Speed,
					InputPercent:   inVal,
					OutputPercent:  outVal,
					Is400GUpgraded: v.Is400GUpgraded,
					UpgradeStatus:  v.UpgradeStatus,
				}
			}

			for k, series := range seriesMap {
				if !presentInterfaces[k] {
					series.Input = append(series.Input, nil)
					series.Output = append(series.Output, nil)
					seriesMap[k] = series
				}
			}
		}

		writeJSON(w, http.StatusOK, RouterDataResponse{
			Timestamps: timestamps,
			Interfaces: latestIntfs,
			Series:     seriesMap,
		})
	})

	// API: High Utilization Route
	mux.HandleFunc("GET /api/high_utilization", func(w http.ResponseWriter, r *http.Request) {
		date := r.URL.Query().Get("date")
		if date == "" || !dateParamRegex.MatchString(date) {
			writeJSON(w, http.StatusOK, HighUtilizationResponse{HighInterfaces: []HighInterfaceResponse{}})
			return
		}

		datePath, err := getSafePath(date)
		if err != nil {
			writeError(w, http.StatusForbidden, "Access Denied")
			return
		}

		if _, err := os.Stat(datePath); os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, HighUtilizationResponse{HighInterfaces: []HighInterfaceResponse{}})
			return
		}

		routersEntries, err := os.ReadDir(datePath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to read date directory")
			return
		}

		var routers []string
		for _, entry := range routersEntries {
			if entry.IsDir() {
				routers = append(routers, entry.Name())
			}
		}
		sort.Strings(routers)

		var highItems []HighInterfaceResponse

		for _, router := range routers {
			routerPath := filepath.Join(datePath, router)
			entries, err := os.ReadDir(routerPath)
			if err != nil {
				continue
			}

			type FileData struct {
				TimestampLabel string
				FilePath       string
			}

			var validFiles []FileData
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				name := entry.Name()
				if strings.HasPrefix(name, router+"_") && strings.HasSuffix(name, ".json") {
					matches := fileRegex.FindStringSubmatch(name)
					if len(matches) >= 6 {
						tsLabel := fmt.Sprintf("%s:%s", matches[4], matches[5])
						validFiles = append(validFiles, FileData{
							TimestampLabel: tsLabel,
							FilePath:       filepath.Join(routerPath, name),
						})
					}
				}
			}

			sort.Slice(validFiles, func(i, j int) bool {
				return validFiles[i].FilePath < validFiles[j].FilePath
			})

			var timestamps []string
			for _, vf := range validFiles {
				timestamps = append(timestamps, vf.TimestampLabel)
			}

			rSeries := make(map[string]SeriesResponse)
			type IntfMetadata struct {
				Neighbor       string
				Speed          string
				Is400GUpgraded bool
				UpgradeStatus  string
			}
			rMeta := make(map[string]IntfMetadata)

			// Concurrent file parsing
			filePaths := make([]string, len(validFiles))
			for i, vf := range validFiles {
				filePaths[i] = vf.FilePath
			}

			resultsMap, err := parseFilesConcurrently(filePaths)
			if err != nil {
				continue
			}

			for fileIdx := range validFiles {
				content := resultsMap[fileIdx]
				if content == nil {
					continue
				}

				presentInterfaces := make(map[string]bool)
				for k, v := range content.Interfaces {
					presentInterfaces[k] = true

					if _, exists := rSeries[k]; !exists {
						inputs := make([]*float64, fileIdx)
						outputs := make([]*float64, fileIdx)
						rSeries[k] = SeriesResponse{Input: inputs, Output: outputs}
					}

					inVal := v.InputPercent
					outVal := v.OutputPercent

					series := rSeries[k]
					series.Input = append(series.Input, &inVal)
					series.Output = append(series.Output, &outVal)
					rSeries[k] = series

					rMeta[k] = IntfMetadata{
						Neighbor:       v.Neighbor,
						Speed:          v.Speed,
						Is400GUpgraded: v.Is400GUpgraded,
						UpgradeStatus:  v.UpgradeStatus,
					}
				}

				for k, series := range rSeries {
					if !presentInterfaces[k] {
						series.Input = append(series.Input, nil)
						series.Output = append(series.Output, nil)
						rSeries[k] = series
					}
				}
			}

			for intf, series := range rSeries {
				var peakIn, peakOut float64
				for _, val := range series.Input {
					if val != nil && *val > peakIn {
						peakIn = *val
					}
				}
				for _, val := range series.Output {
					if val != nil && *val > peakOut {
						peakOut = *val
					}
				}

				if peakIn > 50 || peakOut > 50 {
					meta := rMeta[intf]
					highItems = append(highItems, HighInterfaceResponse{
						Router:         router,
						Interface:      intf,
						Neighbor:       meta.Neighbor,
						Speed:          meta.Speed,
						PeakInput:      peakIn,
						PeakOutput:     peakOut,
						Timestamps:     timestamps,
						Series:         series,
						Is400GUpgraded: meta.Is400GUpgraded,
						UpgradeStatus:  meta.UpgradeStatus,
					})
				}
			}
		}

		writeJSON(w, http.StatusOK, HighUtilizationResponse{HighInterfaces: highItems})
	})

	// API: High Utilization History Route
	mux.HandleFunc("GET /api/high_utilization_history", func(w http.ResponseWriter, r *http.Request) {
		startDate := r.URL.Query().Get("start_date")
		endDate := r.URL.Query().Get("end_date")
		thresholdStr := r.URL.Query().Get("threshold_percent")
		upgradeStatus := r.URL.Query().Get("upgrade_status")

		thresholdPercent := 50.0
		if thresholdStr != "" {
			if val, err := strconv.ParseFloat(thresholdStr, 64); err == nil {
				thresholdPercent = val
			}
		}

		safeRoot, err := getSafePath()
		if err != nil {
			writeError(w, http.StatusForbidden, "Access Denied")
			return
		}

		entries, err := os.ReadDir(safeRoot)
		if err != nil {
			writeJSON(w, http.StatusOK, HighUtilizationHistoryResponse{HighInterfacesHistory: []HighInterfaceResponse{}})
			return
		}

		var dateFolders []string
		for _, entry := range entries {
			if entry.IsDir() && dateParamRegex.MatchString(entry.Name()) {
				d := entry.Name()
				if startDate != "" && d < startDate {
					continue
				}
				if endDate != "" && d > endDate {
					continue
				}
				dateFolders = append(dateFolders, d)
			}
		}
		sort.Strings(dateFolders)

		type Key struct {
			Router    string
			Interface string
		}

		interfaceMap := make(map[Key]*HighInterfaceResponse)
		var keyOrder []Key

		for _, d := range dateFolders {
			datePath := filepath.Join(safeRoot, d)
			routersEntries, err := os.ReadDir(datePath)
			if err != nil {
				continue
			}

			for _, re := range routersEntries {
				if !re.IsDir() {
					continue
				}
				router := re.Name()
				routerPath := filepath.Join(datePath, router)
				files, err := os.ReadDir(routerPath)
				if err != nil {
					continue
				}

				type FileData struct {
					TimestampLabel string
					FilePath       string
				}

				var validFiles []FileData
				for _, f := range files {
					if f.IsDir() {
						continue
					}
					name := f.Name()
					if strings.HasPrefix(name, router+"_") && strings.HasSuffix(name, ".json") {
						matches := fileRegex.FindStringSubmatch(name)
						if len(matches) >= 6 {
							tsLabel := fmt.Sprintf("%s-%s-%s %s:%s", matches[1], matches[2], matches[3], matches[4], matches[5])
							validFiles = append(validFiles, FileData{
								TimestampLabel: tsLabel,
								FilePath:       filepath.Join(routerPath, name),
							})
						}
					}
				}

				sort.Slice(validFiles, func(i, j int) bool {
					return validFiles[i].FilePath < validFiles[j].FilePath
				})

				// Concurrent file parsing
				filePaths := make([]string, len(validFiles))
				for i, vf := range validFiles {
					filePaths[i] = vf.FilePath
				}

				resultsMap, err := parseFilesConcurrently(filePaths)
				if err != nil {
					continue
				}

				for vfIdx, vf := range validFiles {
					content := resultsMap[vfIdx]
					if content == nil {
						continue
					}

					for k, v := range content.Interfaces {
						key := Key{Router: router, Interface: k}
						inVal := v.InputPercent
						outVal := v.OutputPercent

						if _, exists := interfaceMap[key]; !exists {
							item := &HighInterfaceResponse{
								Router:     router,
								Interface:  k,
								Neighbor:   v.Neighbor,
								Speed:      v.Speed,
								Timestamps: []string{},
								Series:     SeriesResponse{Input: []*float64{}, Output: []*float64{}},
								PeakInput:  0,
								PeakOutput: 0,
							}
							interfaceMap[key] = item
							keyOrder = append(keyOrder, key)
						}

						item := interfaceMap[key]
						item.Timestamps = append(item.Timestamps, vf.TimestampLabel)
						item.Series.Input = append(item.Series.Input, &inVal)
						item.Series.Output = append(item.Series.Output, &outVal)
						item.Is400GUpgraded = v.Is400GUpgraded
						item.UpgradeStatus = v.UpgradeStatus

						if inVal > item.PeakInput {
							item.PeakInput = inVal
						}
						if outVal > item.PeakOutput {
							item.PeakOutput = outVal
						}
					}
				}
			}
		}

		var highHistory []HighInterfaceResponse
		for _, key := range keyOrder {
			item := interfaceMap[key]
			if item.PeakInput > thresholdPercent || item.PeakOutput > thresholdPercent {
				if upgradeStatus == "upgraded" && !item.Is400GUpgraded {
					continue
				}
				highHistory = append(highHistory, *item)
			}
		}

		sort.Slice(highHistory, func(i, j int) bool {
			if highHistory[i].Router != highHistory[j].Router {
				return highHistory[i].Router < highHistory[j].Router
			}
			return highHistory[i].Interface < highHistory[j].Interface
		})

		writeJSON(w, http.StatusOK, HighUtilizationHistoryResponse{HighInterfacesHistory: highHistory})
	})

	// API: P95 History Route
	mux.HandleFunc("GET /api/p95_history", func(w http.ResponseWriter, r *http.Request) {
		startDate := r.URL.Query().Get("start_date")
		endDate := r.URL.Query().Get("end_date")
		thresholdStr := r.URL.Query().Get("threshold_percent")
		upgradeStatus := r.URL.Query().Get("upgrade_status")

		thresholdPercent := 50.0
		if thresholdStr != "" {
			if val, err := strconv.ParseFloat(thresholdStr, 64); err == nil {
				thresholdPercent = val
			}
		}

		safeRoot, err := getSafePath()
		if err != nil {
			writeError(w, http.StatusForbidden, "Access Denied")
			return
		}

		entries, err := os.ReadDir(safeRoot)
		if err != nil {
			writeJSON(w, http.StatusOK, HighUtilizationHistoryResponse{HighInterfacesHistory: []HighInterfaceResponse{}})
			return
		}

		var dateFolders []string
		for _, entry := range entries {
			if entry.IsDir() && dateParamRegex.MatchString(entry.Name()) {
				d := entry.Name()
				if startDate != "" && d < startDate {
					continue
				}
				if endDate != "" && d > endDate {
					continue
				}
				dateFolders = append(dateFolders, d)
			}
		}
		sort.Strings(dateFolders)

		type Key struct {
			Router    string
			Interface string
		}

		type DatePeak struct {
			Input  float64
			Output float64
			Exists bool
		}

		type InterfaceInfo struct {
			Router         string
			Interface      string
			Neighbor       string
			Speed          string
			Is400GUpgraded bool
			UpgradeStatus  string
			PeaksPerDate   map[string]DatePeak
		}

		interfaceMap := make(map[Key]*InterfaceInfo)
		var keyOrder []Key

		for _, d := range dateFolders {
			datePath := filepath.Join(safeRoot, d)
			routersEntries, err := os.ReadDir(datePath)
			if err != nil {
				continue
			}

			for _, re := range routersEntries {
				if !re.IsDir() {
					continue
				}
				router := re.Name()
				routerPath := filepath.Join(datePath, router)
				files, err := os.ReadDir(routerPath)
				if err != nil {
					continue
				}

				type FileData struct {
					TimestampLabel string
					FilePath       string
				}

				var validFiles []FileData
				for _, f := range files {
					if f.IsDir() {
						continue
					}
					name := f.Name()
					if strings.HasPrefix(name, router+"_") && strings.HasSuffix(name, ".json") {
						matches := fileRegex.FindStringSubmatch(name)
						if len(matches) >= 6 {
							tsLabel := fmt.Sprintf("%s-%s-%s %s:%s", matches[1], matches[2], matches[3], matches[4], matches[5])
							validFiles = append(validFiles, FileData{
								TimestampLabel: tsLabel,
								FilePath:       filepath.Join(routerPath, name),
							})
						}
					}
				}

				sort.Slice(validFiles, func(i, j int) bool {
					return validFiles[i].FilePath < validFiles[j].FilePath
				})

				// Concurrent file parsing
				filePaths := make([]string, len(validFiles))
				for i, vf := range validFiles {
					filePaths[i] = vf.FilePath
				}

				resultsMap, err := parseFilesConcurrently(filePaths)
				if err != nil {
					continue
				}

				for vfIdx := range validFiles {
					content := resultsMap[vfIdx]
					if content == nil {
						continue
					}

					for k, v := range content.Interfaces {
						key := Key{Router: router, Interface: k}
						inVal := v.InputPercent
						outVal := v.OutputPercent

						if _, exists := interfaceMap[key]; !exists {
							item := &InterfaceInfo{
								Router:       router,
								Interface:    k,
								Neighbor:     v.Neighbor,
								Speed:        v.Speed,
								PeaksPerDate: make(map[string]DatePeak),
							}
							interfaceMap[key] = item
							keyOrder = append(keyOrder, key)
						}

						item := interfaceMap[key]
						item.Is400GUpgraded = v.Is400GUpgraded
						item.UpgradeStatus = v.UpgradeStatus

						dp := item.PeaksPerDate[d]
						if !dp.Exists {
							dp.Input = inVal
							dp.Output = outVal
							dp.Exists = true
						} else {
							if inVal > dp.Input {
								dp.Input = inVal
							}
							if outVal > dp.Output {
								dp.Output = outVal
							}
						}
						item.PeaksPerDate[d] = dp
					}
				}
			}
		}

		var p95History []HighInterfaceResponse
		for _, key := range keyOrder {
			info := interfaceMap[key]
			var overallPeakInput, overallPeakOutput float64

			inputs := make([]*float64, len(dateFolders))
			outputs := make([]*float64, len(dateFolders))

			for i, d := range dateFolders {
				dp, exists := info.PeaksPerDate[d]
				if exists {
					inVal := dp.Input
					outVal := dp.Output
					inputs[i] = &inVal
					outputs[i] = &outVal

					if inVal > overallPeakInput {
						overallPeakInput = inVal
					}
					if outVal > overallPeakOutput {
						overallPeakOutput = outVal
					}
				} else {
					inputs[i] = nil
					outputs[i] = nil
				}
			}

			if overallPeakInput > thresholdPercent || overallPeakOutput > thresholdPercent {
				if upgradeStatus == "upgraded" && !info.Is400GUpgraded {
					continue
				}

				p95History = append(p95History, HighInterfaceResponse{
					Router:         info.Router,
					Interface:      info.Interface,
					Neighbor:       info.Neighbor,
					Speed:          info.Speed,
					PeakInput:      overallPeakInput,
					PeakOutput:     overallPeakOutput,
					Timestamps:     dateFolders,
					Series:         SeriesResponse{Input: inputs, Output: outputs},
					Is400GUpgraded: info.Is400GUpgraded,
					UpgradeStatus:  info.UpgradeStatus,
				})
			}
		}

		sort.Slice(p95History, func(i, j int) bool {
			if p95History[i].Router != p95History[j].Router {
				return p95History[i].Router < p95History[j].Router
			}
			return p95History[i].Interface < p95History[j].Interface
		})

		writeJSON(w, http.StatusOK, HighUtilizationHistoryResponse{HighInterfacesHistory: p95History})
	})

	// Wrap http.Handler with robust Logging and Recoverer Middlewares
	handler := RecovererMiddleware(LoggingMiddleware(mux))

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", webHost, webPort),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start HTTP server inside a goroutine
	go func() {
		slog.Info("GFiber Interface Audit Dashboard running", "url", fmt.Sprintf("http://%s", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server failed to listen", "error", err)
			os.Exit(1)
		}
	}()

	// Listen for OS signals concurrently for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down web server gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("Server exited cleanly")
}
