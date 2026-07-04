package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIdentifyKind(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		filename string
		want     string
	}{
		{"PE", []byte("MZpayload"), "sample.bin", "pe"},
		{"EVTX", []byte("ElfFile\x00data"), "events.bin", "evtx"},
		{"PCAPNG", []byte{0x0a, 0x0d, 0x0d, 0x0a}, "capture.bin", "pcap"},
		{"extension fallback", []byte("data"), "capture.pcap", "pcap"},
		{"generic", []byte("hello"), "note.txt", "artifact"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _ := identifyKind(test.data, test.filename)
			if got != test.want {
				t.Fatalf("identifyKind() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSafeDisplayName(t *testing.T) {
	if got := safeDisplayName("../../payload.exe"); got != "payload.exe" {
		t.Fatalf("safeDisplayName() = %q", got)
	}
}

func TestGetRunningScanReturnsArrays(t *testing.T) {
	server := &Server{jobs: map[string]*Job{
		"running-job": {
			ID:        "running-job",
			Status:    "running",
			Detectors: []DetectorResult{},
			Matches:   []Match{},
		},
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/scans/{id}", server.handleGetScan)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/scans/running-job", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)

	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if string(body["detectors"]) != "[]" {
		t.Fatalf("detectors = %s, want []", body["detectors"])
	}
	if string(body["matches"]) != "[]" {
		t.Fatalf("matches = %s, want []", body["matches"])
	}
}

func TestScanHistoryPersistsAcrossServerRestart(t *testing.T) {
	historyDir := t.TempDir()
	finished := time.Now().UTC()
	first := &Server{
		cfg: Config{HistoryDir: historyDir, HistoryLimit: 20},
		jobs: map[string]*Job{"scan-1": {
			ID: "scan-1", Status: "completed", Verdict: "matched", CreatedAt: finished.Add(-time.Second), FinishedAt: &finished,
			File: FileInfo{Name: "beacon.bin", SHA256: "abc"}, Detectors: []DetectorResult{},
			Matches: []Match{{Detector: "CS Beacon / YARA", Rule: "C2SIGNAL_CS_Beacon_Decoded_Config"}},
		}},
	}
	first.persistJob("scan-1")
	if _, err := os.Stat(filepath.Join(historyDir, "scan-1.json")); err != nil {
		t.Fatalf("find persisted history: %v", err)
	}

	second := &Server{cfg: first.cfg, jobs: map[string]*Job{}}
	second.loadHistory()
	loaded := second.jobs["scan-1"]
	if loaded == nil || len(loaded.Matches) != 1 || loaded.File.Name != "beacon.bin" {
		t.Fatalf("history was not restored: %#v", loaded)
	}
}

func TestDeleteScanRemovesMemoryAndPersistedHistory(t *testing.T) {
	historyDir := t.TempDir()
	id := "0123456789abcdef01234567"
	server := &Server{
		cfg: Config{HistoryDir: historyDir, HistoryLimit: 20},
		jobs: map[string]*Job{id: {
			ID: id, Status: "completed", Verdict: "clean", Detectors: []DetectorResult{}, Matches: []Match{},
		}},
	}
	server.persistJob(id)
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /api/v1/scans/{id}", server.handleDeleteScan)

	request := httptest.NewRequest(http.MethodDelete, "/api/v1/scans/"+id, nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", response.Code, response.Body.String())
	}
	if _, exists := server.jobs[id]; exists {
		t.Fatal("deleted scan still exists in memory")
	}
	if _, err := os.Stat(filepath.Join(historyDir, id+".json")); !os.IsNotExist(err) {
		t.Fatalf("persisted history still exists: %v", err)
	}
}

func TestGetRuleFileOnlyForMatchedYARASource(t *testing.T) {
	ruleRoot := t.TempDir()
	rulePath := filepath.Join(ruleRoot, "matched.yar")
	content := "// fixture\n\nprivate rule matched_rule\n{\n    condition: true\n}\n"
	if err := os.WriteFile(rulePath, []byte(content), 0o600); err != nil {
		t.Fatalf("write rule fixture: %v", err)
	}
	server := &Server{
		cfg: Config{YaraRoots: []string{ruleRoot}},
		jobs: map[string]*Job{"scan-1": {
			ID: "scan-1", Matches: []Match{{Detector: "YARA", Rule: "matched_rule", Source: rulePath}},
		}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/scans/{id}/rule", server.handleGetRuleFile)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/scans/scan-1/rule?name=matched_rule", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("rule file status = %d, body = %s", response.Code, response.Body.String())
	}
	var body RuleFileResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode rule response: %v", err)
	}
	if body.Content != content || body.Rule != "matched_rule" || body.Line != 3 || body.Truncated {
		t.Fatalf("unexpected rule response: %#v", body)
	}
}

func TestGetRuleFileRejectsSourceOutsideRuleRoots(t *testing.T) {
	ruleRoot := t.TempDir()
	outsidePath := filepath.Join(t.TempDir(), "outside.yar")
	if err := os.WriteFile(outsidePath, []byte("rule outside { condition: true }"), 0o600); err != nil {
		t.Fatalf("write outside rule: %v", err)
	}
	server := &Server{
		cfg: Config{YaraRoots: []string{ruleRoot}},
		jobs: map[string]*Job{"scan-1": {
			ID: "scan-1", Matches: []Match{{Detector: "YARA", Rule: "outside", Source: outsidePath}},
		}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/scans/{id}/rule", server.handleGetRuleFile)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/scans/scan-1/rule?name=outside", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("outside rule status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestManagedYARASaveValidateAndToggle(t *testing.T) {
	binDir := t.TempDir()
	fakeYARA := filepath.Join(binDir, "yara")
	if err := os.WriteFile(fakeYARA, []byte("#!/bin/sh\ngrep -q INVALID \"$2\" && { echo syntax-error >&2; exit 1; }\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("write fake yara: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ruleRoot := t.TempDir()
	server := &Server{cfg: Config{ManagedYaraRoot: ruleRoot, YaraRoots: []string{ruleRoot}}, jobs: map[string]*Job{}}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/v1/yara/rules/{name}", server.handleSaveManagedYARA)
	mux.HandleFunc("PATCH /api/v1/yara/rules/{name}/enabled", server.handleSetManagedYARAEnabled)

	valid := `rule managed_test { strings: $a = "signal" condition: $a }`
	save := httptest.NewRequest(http.MethodPut, "/api/v1/yara/rules/managed.yar", strings.NewReader(`{"content":`+strconvQuote(valid)+`}`))
	save.Header.Set("Content-Type", "application/json")
	saveResponse := httptest.NewRecorder()
	mux.ServeHTTP(saveResponse, save)
	if saveResponse.Code != http.StatusOK {
		t.Fatalf("save status = %d, body = %s", saveResponse.Code, saveResponse.Body.String())
	}
	if len(server.yaraFiles) != 1 {
		t.Fatalf("enabled rule inventory = %d, want 1", len(server.yaraFiles))
	}

	disable := httptest.NewRequest(http.MethodPatch, "/api/v1/yara/rules/managed.yar/enabled", strings.NewReader(`{"enabled":false}`))
	disableResponse := httptest.NewRecorder()
	mux.ServeHTTP(disableResponse, disable)
	if disableResponse.Code != http.StatusOK || len(server.yaraFiles) != 0 {
		t.Fatalf("disable status = %d, inventory = %d", disableResponse.Code, len(server.yaraFiles))
	}
	if _, err := os.Stat(filepath.Join(ruleRoot, "managed.yar.disabled")); err != nil {
		t.Fatalf("disabled rule file: %v", err)
	}

	invalid := httptest.NewRequest(http.MethodPut, "/api/v1/yara/rules/managed.yar", strings.NewReader(`{"content":"INVALID"}`))
	invalidResponse := httptest.NewRecorder()
	mux.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid save status = %d, want %d", invalidResponse.Code, http.StatusUnprocessableEntity)
	}
}

func strconvQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
