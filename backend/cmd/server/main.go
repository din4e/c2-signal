package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	ListenAddr        string
	DataDir           string
	HistoryDir        string
	HistoryLimit      int
	ManagedYaraRoot   string
	WebRoot           string
	MaxUploadBytes    int64
	ScanTimeout       time.Duration
	MaxConcurrent     int
	KeepUploads       bool
	YaraRoots         []string
	SigmaRoot         string
	ChainsawMapping   string
	SuricataRuleRoots []string
}

type FileInfo struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Kind       string `json:"kind"`
	MediaType  string `json:"media_type"`
	Executable bool   `json:"executable"`
}

type Match struct {
	Detector  string   `json:"detector"`
	Rule      string   `json:"rule"`
	Source    string   `json:"source,omitempty"`
	Severity  string   `json:"severity,omitempty"`
	Category  string   `json:"category,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	Timestamp string   `json:"timestamp,omitempty"`
}

type DetectorResult struct {
	Name       string   `json:"name"`
	Status     string   `json:"status"`
	RuleFiles  int      `json:"rule_files"`
	DurationMS int64    `json:"duration_ms"`
	Matches    []Match  `json:"matches"`
	Warnings   []string `json:"warnings,omitempty"`
}

type Job struct {
	ID         string           `json:"id"`
	Status     string           `json:"status"`
	Stage      string           `json:"stage"`
	Verdict    string           `json:"verdict"`
	CreatedAt  time.Time        `json:"created_at"`
	FinishedAt *time.Time       `json:"finished_at,omitempty"`
	File       FileInfo         `json:"file"`
	Detectors  []DetectorResult `json:"detectors"`
	Matches    []Match          `json:"matches"`
	Error      string           `json:"error,omitempty"`
}

type RuleInventory struct {
	YARA        int       `json:"yara"`
	Sigma       int       `json:"sigma"`
	Suricata    int       `json:"suricata"`
	CSBeacon    int       `json:"cs_beacon"`
	Available   []string  `json:"available_detectors"`
	RefreshedAt time.Time `json:"refreshed_at"`
}

type ScanSummary struct {
	ID            string     `json:"id"`
	Status        string     `json:"status"`
	Stage         string     `json:"stage"`
	Verdict       string     `json:"verdict"`
	CreatedAt     time.Time  `json:"created_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	File          FileInfo   `json:"file"`
	DetectorNames []string   `json:"detectors"`
	MatchCount    int        `json:"match_count"`
	CSMatchCount  int        `json:"cs_match_count"`
}

type RuleFileResponse struct {
	Rule      string `json:"rule"`
	Source    string `json:"source"`
	Content   string `json:"content"`
	Size      int64  `json:"size"`
	Line      int    `json:"line"`
	Truncated bool   `json:"truncated"`
}

type ManagedYARARule struct {
	Name       string    `json:"name"`
	Enabled    bool      `json:"enabled"`
	Size       int64     `json:"size"`
	ModifiedAt time.Time `json:"modified_at"`
	RuleCount  int       `json:"rule_count"`
}

type ManagedYARADocument struct {
	ManagedYARARule
	Content string `json:"content"`
}

type Server struct {
	cfg         Config
	jobs        map[string]*Job
	mu          sync.RWMutex
	semaphore   chan struct{}
	rules       RuleInventory
	yaraFiles   []string
	yaraSources map[string]string
	ruleMu      sync.Mutex
}

var ruleNamePattern = regexp.MustCompile(`(?m)^\s*(?:(?:private|global)\s+)?rule\s+([A-Za-z0-9_]+)`)
var scanIDPattern = regexp.MustCompile(`^[a-f0-9]{24}$`)
var managedYARANamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,100}\.(?:yar|yara)$`)

func main() {
	cfg := loadConfig()
	for _, directory := range []string{cfg.DataDir, cfg.HistoryDir, cfg.ManagedYaraRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			log.Fatalf("create data directory: %v", err)
		}
	}
	cleanupOrphanUploads(cfg.DataDir, 24*time.Hour)

	s := &Server{
		cfg:       cfg,
		jobs:      make(map[string]*Job),
		semaphore: make(chan struct{}, cfg.MaxConcurrent),
	}
	s.loadHistory()
	s.reloadRules()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/rules", s.handleRules)
	mux.HandleFunc("GET /api/v1/scans", s.handleListScans)
	mux.HandleFunc("POST /api/v1/scans", s.handleCreateScan)
	mux.HandleFunc("GET /api/v1/scans/{id}", s.handleGetScan)
	mux.HandleFunc("DELETE /api/v1/scans/{id}", s.handleDeleteScan)
	mux.HandleFunc("GET /api/v1/scans/{id}/rule", s.handleGetRuleFile)
	mux.HandleFunc("GET /api/v1/yara/rules", s.handleListManagedYARA)
	mux.HandleFunc("GET /api/v1/yara/rules/{name}", s.handleGetManagedYARA)
	mux.HandleFunc("PUT /api/v1/yara/rules/{name}", s.handleSaveManagedYARA)
	mux.HandleFunc("PATCH /api/v1/yara/rules/{name}/enabled", s.handleSetManagedYARAEnabled)
	mux.Handle("/", staticHandler(cfg.WebRoot))

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	log.Printf("C2 / SIGNAL scanner listening on %s", cfg.ListenAddr)
	log.Printf("rule inventory: yara=%d sigma=%d suricata=%d", s.rules.YARA, s.rules.Sigma, s.rules.Suricata)
	log.Fatal(server.ListenAndServe())
}

func loadConfig() Config {
	return Config{
		ListenAddr:        envString("LISTEN_ADDR", ":8080"),
		DataDir:           envString("DATA_DIR", "/data/uploads"),
		HistoryDir:        envString("HISTORY_DIR", "/data/history"),
		HistoryLimit:      int(envInt64("HISTORY_LIMIT", 200)),
		ManagedYaraRoot:   envString("MANAGED_YARA_ROOT", "/rules/yara/local"),
		WebRoot:           envString("WEB_ROOT", "/app/web"),
		MaxUploadBytes:    envInt64("MAX_UPLOAD_BYTES", 100<<20),
		ScanTimeout:       time.Duration(envInt64("SCAN_TIMEOUT_SECONDS", 180)) * time.Second,
		MaxConcurrent:     int(envInt64("MAX_CONCURRENT_SCANS", 2)),
		KeepUploads:       envBool("KEEP_UPLOADS", false),
		YaraRoots:         splitPaths(envString("YARA_ROOTS", "/rules/yara")),
		SigmaRoot:         envString("SIGMA_ROOT", "/rules/sigma"),
		ChainsawMapping:   envString("CHAINSAW_MAPPING", "/rules/mappings/sigma-event-logs-all.yml"),
		SuricataRuleRoots: splitPaths(envString("SURICATA_RULE_ROOTS", "/rules/suricata:/opt/suricata/share/suricata/rules")),
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "c2-signal-scanner"})
}

func (s *Server) handleRules(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	limit := 30
	if requested, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && requested > 0 {
		limit = min(requested, 100)
	}

	s.mu.RLock()
	summaries := make([]ScanSummary, 0, len(s.jobs))
	for _, job := range s.jobs {
		detectors := make([]string, 0, len(job.Detectors))
		for _, detector := range job.Detectors {
			detectors = append(detectors, detector.Name)
		}
		csMatches := 0
		for _, match := range job.Matches {
			if isCobaltStrikeMatch(match.Rule, match.Source) {
				csMatches++
			}
		}
		summaries = append(summaries, ScanSummary{
			ID: job.ID, Status: job.Status, Stage: job.Stage, Verdict: job.Verdict,
			CreatedAt: job.CreatedAt, FinishedAt: job.FinishedAt, File: job.File,
			DetectorNames: detectors, MatchCount: len(job.Matches), CSMatchCount: csMatches,
		})
	}
	s.mu.RUnlock()

	sort.Slice(summaries, func(i, j int) bool { return summaries[i].CreatedAt.After(summaries[j].CreatedAt) })
	if len(summaries) > limit {
		summaries = summaries[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": summaries, "count": len(summaries)})
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "上传内容无效或超过大小限制")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "缺少 file 字段")
		return
	}
	defer file.Close()

	id, err := randomID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法创建扫描任务")
		return
	}
	jobDir := filepath.Join(s.cfg.DataDir, id)
	if err := os.Mkdir(jobDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "无法创建隔离目录")
		return
	}
	artifactPath := filepath.Join(jobDir, "artifact.bin")
	info, err := saveUpload(file, header, artifactPath, s.cfg.MaxUploadBytes)
	if err != nil {
		_ = os.RemoveAll(jobDir)
		if errors.Is(err, errUploadTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "文件超过大小限制")
			return
		}
		writeError(w, http.StatusBadRequest, "保存上传文件失败")
		return
	}

	job := &Job{ID: id, Status: "queued", Stage: "等待扫描器", Verdict: "pending", CreatedAt: time.Now().UTC(), File: info, Detectors: []DetectorResult{}, Matches: []Match{}}
	s.mu.Lock()
	s.jobs[id] = job
	s.mu.Unlock()

	go s.scanJob(id, jobDir, artifactPath)
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.RLock()
	job, ok := s.jobs[id]
	if ok {
		copyJob := *job
		// Preserve the API contract: collection fields are always JSON arrays.
		// append to a nil slice turns an empty collection into JSON null, which
		// breaks clients while a scan is still running.
		copyJob.Detectors = append([]DetectorResult{}, job.Detectors...)
		copyJob.Matches = append([]Match{}, job.Matches...)
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, copyJob)
		return
	}
	s.mu.RUnlock()
	writeError(w, http.StatusNotFound, "扫描任务不存在")
}

func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !scanIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "扫描任务 ID 无效")
		return
	}

	s.mu.Lock()
	job, ok := s.jobs[id]
	if !ok {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "扫描任务不存在")
		return
	}
	if job.Status == "queued" || job.Status == "running" {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "运行中的扫描不能删除")
		return
	}
	historyPath := filepath.Join(s.cfg.HistoryDir, id+".json")
	if err := os.Remove(historyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "删除扫描记录失败")
		return
	}
	delete(s.jobs, id)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func (s *Server) handleGetRuleFile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ruleName := strings.TrimSpace(r.URL.Query().Get("name"))
	if ruleName == "" {
		writeError(w, http.StatusBadRequest, "缺少规则名称")
		return
	}

	s.mu.RLock()
	job, ok := s.jobs[id]
	var source string
	if ok {
		for _, match := range job.Matches {
			if match.Rule == ruleName && strings.Contains(strings.ToLower(match.Detector), "yara") && match.Source != "" {
				source = match.Source
				break
			}
		}
	}
	s.mu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "扫描任务不存在")
		return
	}
	if source == "" {
		writeError(w, http.StatusNotFound, "该扫描没有对应的 YARA 规则文件")
		return
	}
	if !pathWithinRoots(source, s.cfg.YaraRoots) {
		writeError(w, http.StatusForbidden, "规则文件不在允许目录中")
		return
	}

	const maxRuleFileBytes = int64(1 << 20)
	file, err := os.Open(source)
	if err != nil {
		writeError(w, http.StatusNotFound, "规则文件不存在")
		return
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxRuleFileBytes+1))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取规则文件失败")
		return
	}
	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取规则文件信息失败")
		return
	}
	truncated := int64(len(content)) > maxRuleFileBytes
	if truncated {
		content = content[:maxRuleFileBytes]
	}
	ruleContent := string(content)
	writeJSON(w, http.StatusOK, RuleFileResponse{Rule: ruleName, Source: source, Content: ruleContent, Size: info.Size(), Line: findYARARuleLine(ruleContent, ruleName), Truncated: truncated})
}

func (s *Server) handleListManagedYARA(w http.ResponseWriter, _ *http.Request) {
	rules, err := listManagedYARA(s.cfg.ManagedYaraRoot)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法读取本地 YARA 规则")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rules, "count": len(rules)})
}

func (s *Server) handleGetManagedYARA(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !managedYARANamePattern.MatchString(name) {
		writeError(w, http.StatusBadRequest, "YARA 文件名无效")
		return
	}
	path, enabled, err := findManagedYARA(s.cfg.ManagedYaraRoot, name)
	if err != nil {
		writeError(w, http.StatusNotFound, "本地 YARA 规则不存在")
		return
	}
	content, err := os.ReadFile(path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法读取本地 YARA 规则")
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法读取规则文件信息")
		return
	}
	writeJSON(w, http.StatusOK, ManagedYARADocument{ManagedYARARule: ManagedYARARule{Name: name, Enabled: enabled, Size: info.Size(), ModifiedAt: info.ModTime().UTC(), RuleCount: len(ruleNamePattern.FindAll(content, -1))}, Content: string(content)})
}

func (s *Server) handleSaveManagedYARA(w http.ResponseWriter, r *http.Request) {
	s.ruleMu.Lock()
	defer s.ruleMu.Unlock()
	name := r.PathValue("name")
	if !managedYARANamePattern.MatchString(name) {
		writeError(w, http.StatusBadRequest, "文件名必须以 .yar 或 .yara 结尾，且只能包含字母、数字、点、横线和下划线")
		return
	}
	var request struct {
		Content string `json:"content"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || strings.TrimSpace(request.Content) == "" {
		writeError(w, http.StatusBadRequest, "规则内容不能为空或超过 2 MB")
		return
	}

	_, enabled, lookupErr := findManagedYARA(s.cfg.ManagedYaraRoot, name)
	if lookupErr != nil {
		enabled = true
	}
	temporary, err := os.CreateTemp(s.cfg.ManagedYaraRoot, ".editing-*.yar")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法创建规则临时文件")
		return
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	err = temporary.Chmod(0o600)
	if err == nil {
		_, err = temporary.WriteString(request.Content)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法写入规则临时文件")
		return
	}
	if validationError := validateYARAFile(temporaryPath, s.cfg.ManagedYaraRoot); validationError != "" {
		writeError(w, http.StatusUnprocessableEntity, "YARA 语法校验失败："+validationError)
		return
	}
	enabledPath, disabledPath := managedYARAPaths(s.cfg.ManagedYaraRoot, name)
	target := enabledPath
	alternate := disabledPath
	if !enabled {
		target, alternate = disabledPath, enabledPath
	}
	if err := os.Rename(temporaryPath, target); err != nil {
		writeError(w, http.StatusInternalServerError, "无法保存规则文件")
		return
	}
	_ = os.Remove(alternate)
	s.reloadRules()
	s.handleGetManagedYARA(w, r)
}

func (s *Server) handleSetManagedYARAEnabled(w http.ResponseWriter, r *http.Request) {
	s.ruleMu.Lock()
	defer s.ruleMu.Unlock()
	name := r.PathValue("name")
	if !managedYARANamePattern.MatchString(name) {
		writeError(w, http.StatusBadRequest, "YARA 文件名无效")
		return
	}
	var request struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&request); err != nil || request.Enabled == nil {
		writeError(w, http.StatusBadRequest, "缺少 enabled 布尔值")
		return
	}
	currentPath, currentlyEnabled, err := findManagedYARA(s.cfg.ManagedYaraRoot, name)
	if err != nil {
		writeError(w, http.StatusNotFound, "本地 YARA 规则不存在")
		return
	}
	if *request.Enabled == currentlyEnabled {
		s.handleGetManagedYARA(w, r)
		return
	}
	if *request.Enabled {
		if validationError := validateYARAFile(currentPath, s.cfg.ManagedYaraRoot); validationError != "" {
			writeError(w, http.StatusUnprocessableEntity, "启用前语法校验失败："+validationError)
			return
		}
	}
	enabledPath, disabledPath := managedYARAPaths(s.cfg.ManagedYaraRoot, name)
	target := disabledPath
	if *request.Enabled {
		target = enabledPath
	}
	if err := os.Rename(currentPath, target); err != nil {
		writeError(w, http.StatusInternalServerError, "无法更新规则启用状态")
		return
	}
	s.reloadRules()
	s.handleGetManagedYARA(w, r)
}

func (s *Server) scanJob(id, jobDir, artifactPath string) {
	s.semaphore <- struct{}{}
	defer func() { <-s.semaphore }()
	if !s.cfg.KeepUploads {
		defer os.RemoveAll(jobDir)
	}

	s.updateJob(id, func(job *Job) { job.Status = "running"; job.Stage = "识别制品类型" })
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ScanTimeout)
	defer cancel()

	var results []DetectorResult
	s.mu.RLock()
	kind := s.jobs[id].File.Kind
	s.mu.RUnlock()
	if kind == "evtx" {
		s.updateJob(id, func(job *Job) { job.Stage = "Sigma / EVTX 规则扫描" })
		results = append(results, runChainsaw(ctx, artifactPath, s.cfg.SigmaRoot, s.cfg.ChainsawMapping))
	} else if kind == "pcap" {
		s.updateJob(id, func(job *Job) { job.Stage = "Suricata 流量规则扫描" })
		results = append(results, runSuricata(ctx, artifactPath, jobDir, s.cfg.SuricataRuleRoots))
	} else {
		s.updateJob(id, func(job *Job) { job.Stage = "YARA 规则扫描" })
		s.mu.RLock()
		yaraFiles := append([]string{}, s.yaraFiles...)
		yaraSources := make(map[string]string, len(s.yaraSources))
		for rule, source := range s.yaraSources {
			yaraSources[rule] = source
		}
		s.mu.RUnlock()
		results = append(results, runYARA(ctx, artifactPath, yaraFiles, yaraSources))
	}

	allMatches := deduplicateMatches(results)
	verdict := "clean"
	for _, result := range results {
		if result.Status != "completed" {
			verdict = "inconclusive"
			break
		}
	}
	if len(allMatches) > 0 {
		verdict = "matched"
	}
	finished := time.Now().UTC()
	s.updateJob(id, func(job *Job) {
		job.Status = "completed"
		job.Stage = "扫描完成"
		job.Verdict = verdict
		job.Detectors = results
		job.Matches = allMatches
		job.FinishedAt = &finished
	})
	s.persistJob(id)
}

func (s *Server) updateJob(id string, update func(*Job)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job := s.jobs[id]; job != nil {
		update(job)
	}
}

func runYARA(ctx context.Context, artifact string, files []string, sources map[string]string) DetectorResult {
	started := time.Now()
	result := DetectorResult{Name: "YARA", Status: "completed", Matches: []Match{}, Warnings: []string{}}
	if _, err := exec.LookPath("yara"); err != nil {
		result.Status = "unavailable"
		result.Warnings = append(result.Warnings, "yara binary not found")
		return finishDetector(result, started)
	}

	result.RuleFiles = len(files)
	if len(files) == 0 {
		result.Status = "skipped"
		result.Warnings = append(result.Warnings, "no YARA rules mounted")
		return finishDetector(result, started)
	}

	for start := 0; start < len(files); start += 64 {
		end := min(start+64, len(files))
		matches, warnings := runYARAGroup(ctx, artifact, files[start:end], sources)
		result.Matches = append(result.Matches, matches...)
		result.Warnings = appendLimited(result.Warnings, warnings, 30)
		if ctx.Err() != nil {
			result.Status = "timeout"
			result.Warnings = append(result.Warnings, "YARA scan reached time limit")
			break
		}
	}
	result.Matches = deduplicateMatchSlice(result.Matches)
	return finishDetector(result, started)
}

func runYARAGroup(ctx context.Context, artifact string, rules []string, sources map[string]string) ([]Match, []string) {
	if len(rules) == 0 {
		return nil, nil
	}
	args := append([]string{"-w"}, rules...)
	args = append(args, artifact)
	cmd := exec.CommandContext(ctx, "yara", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(rules) > 1 {
			middle := len(rules) / 2
			leftMatches, leftWarnings := runYARAGroup(ctx, artifact, rules[:middle], sources)
			rightMatches, rightWarnings := runYARAGroup(ctx, artifact, rules[middle:], sources)
			return append(leftMatches, rightMatches...), append(leftWarnings, rightWarnings...)
		}
		return nil, []string{fmt.Sprintf("ignored invalid rule file %s: %s", filepath.Base(rules[0]), compactOutput(output))}
	}

	matches := make([]Match, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		rule := fields[0]
		source := sources[rule]
		detector, category, severity := "YARA", "artifact", inferSeverity(rule)
		if isCobaltStrikeMatch(rule, source) {
			detector, category, severity = "CS Beacon / YARA", "cobalt-strike-beacon", "high"
		}
		matches = append(matches, Match{Detector: detector, Rule: rule, Source: source, Severity: severity, Category: category})
	}
	return matches, nil
}

func runChainsaw(ctx context.Context, artifact, sigmaRoot, mapping string) DetectorResult {
	started := time.Now()
	result := DetectorResult{Name: "Sigma / Chainsaw", Status: "completed", Matches: []Match{}, Warnings: []string{}}
	if _, err := exec.LookPath("chainsaw"); err != nil {
		result.Status = "unavailable"
		result.Warnings = append(result.Warnings, "chainsaw binary not found")
		return finishDetector(result, started)
	}
	result.RuleFiles = len(discoverRuleFiles([]string{sigmaRoot}, map[string]bool{".yml": true, ".yaml": true}))
	if result.RuleFiles == 0 {
		result.Status = "skipped"
		result.Warnings = append(result.Warnings, "no Sigma rules mounted")
		return finishDetector(result, started)
	}
	args := []string{"hunt", artifact, "-s", sigmaRoot, "--mapping", mapping, "--json", "--skip-errors", "--load-unknown", "-q"}
	output, err := exec.CommandContext(ctx, "chainsaw", args...).CombinedOutput()
	if err != nil {
		result.Status = "error"
		result.Warnings = append(result.Warnings, compactOutput(output))
		return finishDetector(result, started)
	}
	result.Matches = extractGenericJSONMatches(output, "Sigma / Chainsaw")
	return finishDetector(result, started)
}

func runSuricata(ctx context.Context, artifact, jobDir string, ruleRoots []string) DetectorResult {
	started := time.Now()
	result := DetectorResult{Name: "Suricata", Status: "completed", Matches: []Match{}, Warnings: []string{}}
	if _, err := exec.LookPath("suricata"); err != nil {
		result.Status = "unavailable"
		result.Warnings = append(result.Warnings, "suricata binary not found")
		return finishDetector(result, started)
	}
	ruleFiles := discoverRuleFiles(ruleRoots, map[string]bool{".rules": true})
	result.RuleFiles = len(ruleFiles)
	args := []string{"-r", artifact, "-l", jobDir, "--set", "outputs.1.eve-log.enabled=yes"}
	if len(ruleFiles) > 0 {
		combined := filepath.Join(jobDir, "combined.rules")
		if err := combineTextFiles(combined, ruleFiles); err == nil {
			args = append(args, "-S", combined)
		}
	} else {
		result.Warnings = append(result.Warnings, "no custom Suricata rules mounted; using image defaults")
	}
	output, err := exec.CommandContext(ctx, "suricata", args...).CombinedOutput()
	if err != nil {
		result.Status = "error"
		result.Warnings = append(result.Warnings, compactOutput(output))
		return finishDetector(result, started)
	}
	evePath := filepath.Join(jobDir, "eve.json")
	file, err := os.Open(evePath)
	if err != nil {
		return finishDetector(result, started)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 4<<20)
	for scanner.Scan() {
		var event map[string]any
		if json.Unmarshal(scanner.Bytes(), &event) != nil || valueString(event["event_type"]) != "alert" {
			continue
		}
		alert, _ := event["alert"].(map[string]any)
		result.Matches = append(result.Matches, Match{Detector: "Suricata", Rule: valueString(alert["signature"]), Severity: fmt.Sprint(alert["severity"]), Category: valueString(alert["category"]), Timestamp: valueString(event["timestamp"]), Detail: fmt.Sprintf("%s → %s", valueString(event["src_ip"]), valueString(event["dest_ip"]))})
	}
	return finishDetector(result, started)
}

func saveUpload(src multipart.File, header *multipart.FileHeader, destination string, limit int64) (FileInfo, error) {
	dst, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return FileInfo{}, err
	}
	defer dst.Close()
	hash := sha256.New()
	reader := io.LimitReader(src, limit+1)
	written, err := io.Copy(io.MultiWriter(dst, hash), reader)
	if err != nil {
		return FileInfo{}, err
	}
	if written > limit {
		return FileInfo{}, errUploadTooLarge
	}
	if err := dst.Sync(); err != nil {
		return FileInfo{}, err
	}

	prefix := make([]byte, 8192)
	file, err := os.Open(destination)
	if err != nil {
		return FileInfo{}, err
	}
	n, _ := file.Read(prefix)
	_ = file.Close()
	prefix = prefix[:n]
	kind, executable := identifyKind(prefix, header.Filename)
	mediaType := http.DetectContentType(prefix)
	return FileInfo{Name: safeDisplayName(header.Filename), Size: written, SHA256: hex.EncodeToString(hash.Sum(nil)), Kind: kind, MediaType: mediaType, Executable: executable}, nil
}

var errUploadTooLarge = errors.New("upload too large")

func identifyKind(data []byte, name string) (string, bool) {
	ext := strings.ToLower(filepath.Ext(name))
	if len(data) >= 8 && string(data[:8]) == "ElfFile\x00" || ext == ".evtx" {
		return "evtx", false
	}
	if isPCAP(data) || ext == ".pcap" || ext == ".pcapng" {
		return "pcap", false
	}
	if len(data) >= 2 && string(data[:2]) == "MZ" {
		return "pe", true
	}
	if len(data) >= 4 && string(data[:4]) == "\x7fELF" {
		return "elf", true
	}
	if len(data) >= 4 && (string(data[:4]) == "\xcf\xfa\xed\xfe" || string(data[:4]) == "\xfe\xed\xfa\xcf") {
		return "macho", true
	}
	if ext == ".zip" || ext == ".jar" || ext == ".docx" || ext == ".xlsx" {
		return "archive", false
	}
	return "artifact", false
}

func isPCAP(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := hex.EncodeToString(data[:4])
	return magic == "d4c3b2a1" || magic == "a1b2c3d4" || magic == "4d3cb2a1" || magic == "a1b23c4d" || magic == "0a0d0d0a"
}

func buildRuleInventory(cfg Config) RuleInventory {
	available := make([]string, 0, 3)
	if _, err := exec.LookPath("yara"); err == nil {
		available = append(available, "YARA")
	}
	if _, err := exec.LookPath("chainsaw"); err == nil {
		available = append(available, "Sigma / Chainsaw")
	}
	if _, err := exec.LookPath("suricata"); err == nil {
		available = append(available, "Suricata")
	}
	yaraFiles := discoverRuleFiles(cfg.YaraRoots, map[string]bool{".yar": true, ".yara": true})
	csBeaconRules := 0
	for rule, source := range indexYARARules(yaraFiles) {
		if isCobaltStrikeMatch(rule, source) {
			csBeaconRules++
		}
	}
	return RuleInventory{
		YARA:      len(yaraFiles),
		Sigma:     len(discoverRuleFiles([]string{cfg.SigmaRoot}, map[string]bool{".yml": true, ".yaml": true})),
		Suricata:  len(discoverRuleFiles(cfg.SuricataRuleRoots, map[string]bool{".rules": true})),
		CSBeacon:  csBeaconRules,
		Available: available, RefreshedAt: time.Now().UTC(),
	}
}

func (s *Server) reloadRules() {
	yaraFiles := discoverRuleFiles(s.cfg.YaraRoots, map[string]bool{".yar": true, ".yara": true})
	yaraSources := indexYARARules(yaraFiles)
	inventory := buildRuleInventory(s.cfg)
	s.mu.Lock()
	s.yaraFiles = yaraFiles
	s.yaraSources = yaraSources
	s.rules = inventory
	s.mu.Unlock()
}

func listManagedYARA(root string) ([]ManagedYARARule, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]ManagedYARARule)
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		name := entry.Name()
		enabled := true
		if strings.HasSuffix(name, ".disabled") {
			enabled = false
			name = strings.TrimSuffix(name, ".disabled")
		}
		if !managedYARANamePattern.MatchString(name) {
			continue
		}
		content, readErr := os.ReadFile(filepath.Join(root, entry.Name()))
		info, infoErr := entry.Info()
		if readErr != nil || infoErr != nil {
			continue
		}
		rule := ManagedYARARule{Name: name, Enabled: enabled, Size: info.Size(), ModifiedAt: info.ModTime().UTC(), RuleCount: len(ruleNamePattern.FindAll(content, -1))}
		if existing, exists := byName[name]; !exists || rule.Enabled && !existing.Enabled {
			byName[name] = rule
		}
	}
	rules := make([]ManagedYARARule, 0, len(byName))
	for _, rule := range byName {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	return rules, nil
}

func managedYARAPaths(root, name string) (string, string) {
	enabled := filepath.Join(root, name)
	return enabled, enabled + ".disabled"
}

func findManagedYARA(root, name string) (string, bool, error) {
	enabled, disabled := managedYARAPaths(root, name)
	if info, err := os.Stat(enabled); err == nil && !info.IsDir() {
		return enabled, true, nil
	}
	if info, err := os.Stat(disabled); err == nil && !info.IsDir() {
		return disabled, false, nil
	}
	return "", false, os.ErrNotExist
}

func validateYARAFile(path, workingDirectory string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "yara", "-w", path, "/dev/null")
	cmd.Dir = workingDirectory
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "校验超时"
	}
	if err != nil {
		return compactOutput(output)
	}
	return ""
}

func discoverRuleFiles(roots []string, extensions map[string]bool) []string {
	files := make([]string, 0)
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "deprecated" || entry.Name() == "tests") {
				return filepath.SkipDir
			}
			if !entry.IsDir() && strings.HasPrefix(entry.Name(), ".") {
				return nil
			}
			if !entry.IsDir() && extensions[strings.ToLower(filepath.Ext(path))] {
				files = append(files, path)
			}
			return nil
		})
	}
	sort.Strings(files)
	return files
}

func indexYARARules(files []string) map[string]string {
	index := make(map[string]string)
	for _, path := range files {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, match := range ruleNamePattern.FindAllSubmatch(content, -1) {
			index[string(match[1])] = path
		}
	}
	return index
}

func extractGenericJSONMatches(output []byte, detector string) []Match {
	var matches []Match
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	for {
		var value any
		if err := decoder.Decode(&value); err != nil {
			break
		}
		walkJSON(value, func(object map[string]any) {
			rule := firstString(object, "title", "name", "rule", "detection")
			if rule == "" {
				return
			}
			matches = append(matches, Match{Detector: detector, Rule: rule, Severity: firstString(object, "level", "severity"), Category: "event-log", Timestamp: firstString(object, "timestamp", "time", "datetime")})
		})
	}
	return matches
}

func walkJSON(value any, visit func(map[string]any)) {
	switch typed := value.(type) {
	case map[string]any:
		if firstString(typed, "title", "name", "rule") != "" {
			visit(typed)
		}
		for _, nested := range typed {
			walkJSON(nested, visit)
		}
	case []any:
		for _, nested := range typed {
			walkJSON(nested, visit)
		}
	}
}

func deduplicateMatches(results []DetectorResult) []Match {
	matches := make([]Match, 0)
	for _, result := range results {
		matches = append(matches, result.Matches...)
	}
	matches = deduplicateMatchSlice(matches)
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Detector == matches[j].Detector {
			return matches[i].Rule < matches[j].Rule
		}
		return matches[i].Detector < matches[j].Detector
	})
	return matches
}

func deduplicateMatchSlice(input []Match) []Match {
	seen := make(map[string]bool)
	output := make([]Match, 0, len(input))
	for _, match := range input {
		key := match.Detector + "\x00" + match.Rule + "\x00" + match.Detail
		if !seen[key] {
			seen[key] = true
			output = append(output, match)
		}
	}
	return output
}

func combineTextFiles(destination string, files []string) error {
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	for _, path := range files {
		input, err := os.Open(path)
		if err != nil {
			continue
		}
		_, _ = io.Copy(out, input)
		_, _ = out.WriteString("\n")
		_ = input.Close()
	}
	return out.Close()
}

func finishDetector(result DetectorResult, started time.Time) DetectorResult {
	result.DurationMS = time.Since(started).Milliseconds()
	return result
}
func appendLimited(base, values []string, limit int) []string {
	for _, value := range values {
		if len(base) >= limit {
			break
		}
		base = append(base, value)
	}
	return base
}
func compactOutput(output []byte) string {
	value := strings.Join(strings.Fields(string(output)), " ")
	if len(value) > 300 {
		return value[:300] + "…"
	}
	return value
}
func inferSeverity(rule string) string {
	lower := strings.ToLower(rule)
	if strings.Contains(lower, "cobalt") || strings.Contains(lower, "beacon") || strings.Contains(lower, "malware") || strings.Contains(lower, "trojan") {
		return "high"
	}
	return "medium"
}

func isCobaltStrikeMatch(rule, source string) bool {
	value := strings.ToLower(rule + " " + source)
	return strings.Contains(value, "cobalt") || strings.Contains(value, "beacon") || strings.Contains(value, "c2signal_cs_")
}

func findYARARuleLine(content, ruleName string) int {
	declaration := regexp.MustCompile(`(?m)^[\t ]*(?:(?:private|global)[\t ]+)*rule[\t ]+` + regexp.QuoteMeta(ruleName) + `(?:[\t ]|:|\{|$)`)
	location := declaration.FindStringIndex(content)
	if location == nil {
		return 0
	}
	return strings.Count(content[:location[0]], "\n") + 1
}
func firstString(object map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := valueString(object[key]); value != "" {
			return value
		}
	}
	return ""
}
func valueString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}
func splitPaths(value string) []string {
	var paths []string
	for _, path := range strings.Split(value, ":") {
		if strings.TrimSpace(path) != "" {
			paths = append(paths, strings.TrimSpace(path))
		}
	}
	return paths
}

func pathWithinRoots(path string, roots []string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	if extension != ".yar" && extension != ".yara" {
		return false
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	for _, root := range roots {
		resolvedRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		relative, err := filepath.Rel(resolvedRoot, resolvedPath)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func cleanupOrphanUploads(root string, olderThan time.Duration) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-olderThan)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			_ = os.RemoveAll(filepath.Join(root, entry.Name()))
		}
	}
}

func (s *Server) loadHistory() {
	type historyFile struct {
		path    string
		modTime time.Time
	}
	entries, err := os.ReadDir(s.cfg.HistoryDir)
	if err != nil {
		return
	}
	files := make([]historyFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.ToLower(filepath.Ext(entry.Name())) != ".json" {
			continue
		}
		info, err := entry.Info()
		if err == nil {
			files = append(files, historyFile{path: filepath.Join(s.cfg.HistoryDir, entry.Name()), modTime: info.ModTime()})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modTime.After(files[j].modTime) })
	if len(files) > s.cfg.HistoryLimit {
		files = files[:s.cfg.HistoryLimit]
	}
	for _, file := range files {
		content, err := os.ReadFile(file.path)
		if err != nil {
			continue
		}
		var job Job
		if json.Unmarshal(content, &job) != nil || job.ID == "" {
			continue
		}
		if job.Detectors == nil {
			job.Detectors = []DetectorResult{}
		}
		if job.Matches == nil {
			job.Matches = []Match{}
		}
		s.jobs[job.ID] = &job
	}
}

func (s *Server) persistJob(id string) {
	s.mu.RLock()
	job, ok := s.jobs[id]
	if !ok {
		s.mu.RUnlock()
		return
	}
	copyJob := *job
	copyJob.Detectors = append([]DetectorResult{}, job.Detectors...)
	copyJob.Matches = append([]Match{}, job.Matches...)
	s.mu.RUnlock()

	content, err := json.Marshal(copyJob)
	if err != nil {
		log.Printf("persist scan %s: %v", id, err)
		return
	}
	temporary := filepath.Join(s.cfg.HistoryDir, "."+id+".tmp")
	destination := filepath.Join(s.cfg.HistoryDir, id+".json")
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		log.Printf("persist scan %s: %v", id, err)
		return
	}
	if err := os.Rename(temporary, destination); err != nil {
		_ = os.Remove(temporary)
		log.Printf("persist scan %s: %v", id, err)
		return
	}
	s.pruneHistory()
}

func (s *Server) pruneHistory() {
	entries, err := os.ReadDir(s.cfg.HistoryDir)
	if err != nil {
		return
	}
	type historyFile struct {
		path    string
		modTime time.Time
	}
	files := make([]historyFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.ToLower(filepath.Ext(entry.Name())) != ".json" {
			continue
		}
		if info, err := entry.Info(); err == nil {
			files = append(files, historyFile{path: filepath.Join(s.cfg.HistoryDir, entry.Name()), modTime: info.ModTime()})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modTime.After(files[j].modTime) })
	for _, file := range files[min(len(files), s.cfg.HistoryLimit):] {
		_ = os.Remove(file.path)
	}
}
func safeDisplayName(value string) string {
	name := filepath.Base(strings.ReplaceAll(value, "\\", "/"))
	if len(name) > 180 {
		name = name[:180]
	}
	if name == "." || name == "" {
		return "artifact"
	}
	return name
}

func randomID() (string, error) {
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func envInt64(key string, fallback int64) int64 {
	value, err := strconv.ParseInt(os.Getenv(key), 10, 64)
	if err == nil && value > 0 {
		return value
	}
	return fallback
}
func envBool(key string, fallback bool) bool {
	value := strings.ToLower(os.Getenv(key))
	if value == "true" || value == "1" {
		return true
	}
	if value == "false" || value == "0" {
		return false
	}
	return fallback
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func staticHandler(root string) http.Handler {
	files := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		requested := filepath.Join(root, filepath.Clean(r.URL.Path))
		if info, err := os.Stat(requested); err == nil && !info.IsDir() {
			files.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
}
