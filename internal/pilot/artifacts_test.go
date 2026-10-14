package pilot

import (
	"aiforensics.local/platform/collectors"
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactIntegrityAndCatalog(t *testing.T) {
	dir := t.TempDir()
	binary, source := []byte("test EXE"), []byte("test ZIP")
	manifest := buildManifest{1, artifactHash(binary), len(binary), artifactHash(source), len(source), strings.Repeat("a", 64), collectors.All()}
	save := func() {
		m, _ := json.Marshal(manifest)
		if err := os.WriteFile(filepath.Join(dir, "agent-build.json"), m, 0600); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(dir, "forensics-agent-x86.exe"), binary, 0600)
	os.WriteFile(filepath.Join(dir, "forensics-agent-source.zip"), source, 0600)
	save()
	if _, _, _, err := loadArtifacts(dir); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "forensics-agent-source.zip"), []byte("wrong ZIP"), 0600)
	if _, _, _, err := loadArtifacts(dir); err == nil {
		t.Fatal("corrupt archive accepted")
	}
	os.WriteFile(filepath.Join(dir, "forensics-agent-source.zip"), source, 0600)
	os.WriteFile(filepath.Join(dir, "forensics-agent-x86.exe"), []byte("wrong EXE"), 0600)
	if _, _, _, err := loadArtifacts(dir); err == nil {
		t.Fatal("wrong binary accepted")
	}
	os.WriteFile(filepath.Join(dir, "forensics-agent-x86.exe"), binary, 0600)
	manifest.Collectors = manifest.Collectors[:1]
	save()
	if _, _, _, err := loadArtifacts(dir); err == nil {
		t.Fatal("stale catalog accepted")
	}
	a := fixture(t)
	for _, path := range []string{"/api/agent/update", "/api/agent/build", "/api/collectors"} {
		if call(a, "GET", path, "", false).Code != 401 {
			t.Fatal("unauthenticated artifact", path)
		}
	}
}
func TestCapabilitiesUpgradeDowngradeAndScope(t *testing.T) {
	a := fixture(t)
	body := `{"customer_id":"a","device_id":"da","collector_id":"F15"}`
	if call(a, "POST", "/api/jobs", body, true).Code != 409 {
		t.Fatal("old agent accepted F15")
	}
	identity := `{"status":"complete","hostname":"XP","os":"Windows XP","agent_arch":"x86","logical_processors":1,"ram_total_bytes":1000000,"ram_free_bytes":500000,"ipv4":[]}`
	poll := func(ids, source string, duplicate bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://lab.forensics/agent/poll", strings.NewReader(identity))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.TLS = &tls.ConnectionState{}
		if ids != "" {
			r.Header.Set("X-Agent-Collectors", ids)
		}
		if source != "" {
			r.Header.Set("X-Agent-Source", source)
		}
		if duplicate {
			r.Header.Add("X-Agent-Collectors", ids)
		}
		w := httptest.NewRecorder()
		a.AgentHandler().ServeHTTP(w, r)
		return w
	}
	for _, ids := range []string{"F01,F99", "F01,F01", "F15", "F01,F04,cmd.exe"} {
		if poll(ids, strings.Repeat("a", 64), false).Code != 400 {
			t.Fatal("bad report accepted", ids)
		}
	}
	if poll("F01,F15", "not-sha", false).Code != 400 || poll("F01,F15", strings.Repeat("a", 64), true).Code != 400 {
		t.Fatal("invalid headers accepted")
	}
	if poll("F01,F04,F08,F15", strings.Repeat("a", 64), false).Code != 204 {
		t.Fatal("upgrade failed")
	}
	if call(a, "POST", "/api/jobs", strings.Replace(body, `"da"`, `"db"`, 1), true).Code != 404 {
		t.Fatal("cross customer")
	}
	approved := strings.TrimSuffix(body, "}") + `,"agent_source":"` + strings.Repeat("a", 64) + `"}`
	if call(a, "POST", "/api/jobs", body, true).Code != 409 {
		t.Fatal("approval missing version accepted")
	}
	if call(a, "POST", "/api/jobs/approve", approved, true).Code != 201 {
		t.Fatal("F15 not accepted")
	}
	if poll("", "", false).Code != 204 {
		t.Fatal("legacy agent received unsupported queued job")
	}
	if a.state.Jobs[0].Status != "queued" || supports(&a.state.Devices[0], "F15") {
		t.Fatal("downgrade persisted incorrectly")
	}
	if poll("F01,F04,F08,F15", strings.Repeat("a", 64), false).Code != 200 {
		t.Fatal("upgraded agent did not receive F15")
	}

}

func TestApprovalPinnedToAgentSourceVersion(t *testing.T) {
	a := fixture(t)
	old, newVersion := strings.Repeat("a", 64), strings.Repeat("b", 64)
	a.state.Devices[0].SourceFingerprint = old
	body := `{"customer_id":"a","device_id":"da","collector_id":"F04","agent_source":"` + old + `"}`
	if call(a, "POST", "/api/jobs/approve", body, false).Code != 401 {
		t.Fatal("anonymous approval")
	}
	a.state.Devices[0].SourceFingerprint = newVersion
	if call(a, "POST", "/api/jobs/approve", body, true).Code != 409 {
		t.Fatal("stale approval accepted")
	}
	a.state.Devices[0].SourceFingerprint = old
	if call(a, "POST", "/api/jobs/approve", body, true).Code != 201 {
		t.Fatal("valid approval failed")
	}
	if a.state.Jobs[0].AgentSource != old {
		t.Fatal("job not pinned")
	}
	poll := func(version string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://lab.forensics/agent/poll", strings.NewReader(`{"status":"complete","hostname":"XP","os":"Windows XP","agent_arch":"x86","logical_processors":1,"ram_total_bytes":1000,"ram_free_bytes":500,"ipv4":[]}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("X-Agent-Collectors", "F01,F04")
		r.Header.Set("X-Agent-Source", version)
		r.TLS = &tls.ConnectionState{}
		w := httptest.NewRecorder()
		a.AgentHandler().ServeHTTP(w, r)
		return w
	}
	if poll(newVersion).Code != 204 || a.state.Jobs[0].Status != "queued" {
		t.Fatal("job delivered to changed version")
	}
	w := poll(old)
	if w.Code != 200 || !strings.HasPrefix(w.Body.String(), "JOB2 ") || !strings.HasSuffix(w.Body.String(), old+"\n") {
		t.Fatal("missing executable source pin", w.Code, w.Body)
	}
}

func TestSourcesNotExposedInCustomerGUI(t *testing.T) {
	a := fixture(t)
	for _, logged := range []bool{false, true} {
		if w := call(a, "GET", "/api/agent/source", "", logged); w.Code != 404 {
			t.Fatal("source route exists", w.Code)
		}
	}
	w := call(a, "GET", "/control", "", true)
	if strings.Contains(w.Body.String(), "/api/agent/source") || strings.Contains(w.Body.String(), "collector-catalog") {
		t.Fatal("source UI exposed")
	}
	w = call(a, "GET", "/api/collectors", "", true)
	if w.Code != 200 || strings.Contains(w.Body.String(), "entrypoint") || strings.Contains(w.Body.String(), "collectors/windows/") {
		t.Fatal("catalog exposed implementation details")
	}
}
