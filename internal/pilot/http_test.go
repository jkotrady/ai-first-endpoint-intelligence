package pilot

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) *App {
	t.Helper()
	a := &App{dir: t.TempDir(), sessions: map[string]session{}, attempts: map[string][]time.Time{}, now: func() time.Time { return time.Unix(1791918000, 0) }, loginSlots: make(chan struct{}, 2)}
	h, _ := passwordHash("a-long-test-password", "test-salt")
	a.state = State{Version: 1, Users: []User{{Name: "analyst", Salt: "test-salt", Hash: h, TOTP: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", LastCounter: -1, Customers: []string{"a"}}}, Customers: []Customer{{"a", "A"}, {"b", "B"}}, Devices: []Device{{ID: "da", CustomerID: "a", Capabilities: []string{"F01", "F04", "F08"}, CredentialHash: tokenHash(strings.Repeat("a", 64))}, {ID: "db", CustomerID: "b", Capabilities: []string{"F01", "F04", "F08"}, CredentialHash: tokenHash(strings.Repeat("b", 64))}}, Jobs: []Job{}, Audit: []Event{}}
	a.sessions["test"] = session{"analyst", a.now().Add(time.Hour), a.now().Add(time.Hour)}
	if e := a.save(); e != nil {
		t.Fatal(e)
	}
	return a
}
func call(a *App, method, path, body string, logged bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	if logged {
		r.AddCookie(&http.Cookie{Name: "pilot_session", Value: "test"})
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}
func agentCall(a *App, path, body, token string, secure bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://lab.forensics"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	if secure {
		r.TLS = &tls.ConnectionState{}
	} else {
		r.TLS = nil
	}
	w := httptest.NewRecorder()
	a.AgentHandler().ServeHTTP(w, r)
	return w
}
func TestTOTPVector(t *testing.T) {
	if v := totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1); v != "287082" {
		t.Fatal(v)
	}
}
func TestLoginMFAReplayLogout(t *testing.T) {
	a := fixture(t)
	code := totp(a.state.Users[0].TOTP, a.now().Unix()/30)
	body := `{"username":"analyst","password":"a-long-test-password","code":"` + code + `"}`
	w := call(a, "POST", "/auth/login", body, false)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("cookie protections")
	}
	if call(a, "POST", "/auth/login", body, false).Code != 401 {
		t.Fatal("TOTP replay accepted")
	}
	if call(a, "DELETE", "/auth/session", "", true).Code != 204 || call(a, "GET", "/api/me", "", true).Code != 401 {
		t.Fatal("logout")
	}
	again, e := Open(a.dir)
	if e != nil || again.state.Users[0].LastCounter < 0 {
		t.Fatal("MFA replay marker not durable", e)
	}
}
func TestWrongMFAAndRateLimit(t *testing.T) {
	a := fixture(t)
	for i := 0; i < 10; i++ {
		w := call(a, "POST", "/auth/login", `{"username":"analyst","password":"wrong","code":"000000"}`, false)
		if w.Code != 401 {
			t.Fatal(i, w.Code)
		}
	}
	if call(a, "POST", "/auth/login", `{"username":"analyst","password":"wrong","code":"000000"}`, false).Code != 429 {
		t.Fatal("missing throttle")
	}
}
func TestCustomerAndDeviceBoundaries(t *testing.T) {
	a := fixture(t)
	for _, p := range []string{"/api/customers/b/devices", "/api/customers/b/jobs", "/api/customers/b/audit"} {
		if call(a, "GET", p, "", true).Code != 404 {
			t.Fatal(p)
		}
	}
	if call(a, "DELETE", "/api/devices/db", "", true).Code != 404 {
		t.Fatal("cross tenant revoke")
	}
	if call(a, "POST", "/api/jobs", `{"customer_id":"a","device_id":"db","collector_id":"F04"}`, true).Code != 404 {
		t.Fatal("cross tenant job")
	}
	w := call(a, "GET", "/api/customers/a/devices", "", true)
	if bytes.Contains(w.Body.Bytes(), []byte("credential_hash")) {
		t.Fatal("credential hash leaked")
	}
}
func TestJobLifecycleReplayAndPersistence(t *testing.T) {
	a := fixture(t)
	w := call(a, "POST", "/api/jobs", `{"customer_id":"a","device_id":"da","collector_id":"F04"}`, true)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	j := a.state.Jobs[0]
	identity := `{"status":"complete","hostname":"XP","os":"Windows XP","agent_arch":"x86","logical_processors":1,"ram_total_bytes":1000000,"ram_free_bytes":500000,"ipv4":["192.0.2.1"]}`
	token := strings.Repeat("a", 64)
	if agentCall(a, "/agent/poll", identity, token, false).Code != 403 {
		t.Fatal("plaintext accepted")
	}
	if agentCall(a, "/agent/poll", identity, strings.Repeat("z", 64), true).Code != 401 {
		t.Fatal("bad token")
	}
	poll := agentCall(a, "/agent/poll", identity, token, true)
	if poll.Code != 200 || !strings.Contains(poll.Body.String(), j.Nonce) {
		t.Fatal("delivery", poll.Code)
	}
	result := `{"job_id":"` + j.ID + `","nonce":"` + j.Nonce + `","collector_id":"F04","data":{"status":"complete","items":[]}}`
	if agentCall(a, "/agent/result", result, strings.Repeat("b", 64), true).Code != 404 {
		t.Fatal("other device result")
	}
	if agentCall(a, "/agent/result", result, token, true).Code != 204 {
		t.Fatal("result rejected")
	}
	if agentCall(a, "/agent/result", result, token, true).Code != 204 {
		t.Fatal("idempotent retry")
	}
	changed := strings.Replace(result, `"complete"`, `"partial"`, 1)
	if agentCall(a, "/agent/result", changed, token, true).Code != 409 {
		t.Fatal("changed replay accepted")
	}
	again, e := Open(a.dir)
	if e != nil || again.state.Jobs[0].Status != "completed" {
		t.Fatal("persistence", e)
	}
	if agentCall(again, "/agent/result", result, token, true).Code != 204 {
		t.Fatal("retry after restart")
	}
	var stored map[string]any
	if json.Unmarshal(again.state.Jobs[0].Result, &stored) != nil {
		t.Fatal("bad stored json")
	}
}
func TestRejectUnsafeDuplicateAndExpiredJobs(t *testing.T) {
	a := fixture(t)
	for _, body := range []string{`{"customer_id":"a","device_id":"da","collector_id":"shell"}`, `{"customer_id":"a","customer_id":"b","device_id":"da","collector_id":"F04"}`, `{"customer_id":"a","device_id":"da","collector_id":null}`, `{"customer_id":"a","device_id":"da","collector_id":"F04","command":"whoami"}`} {
		if call(a, "POST", "/api/jobs", body, true).Code != 400 {
			t.Fatal(body)
		}
	}
	call(a, "POST", "/api/jobs", `{"customer_id":"a","device_id":"da","collector_id":"F01"}`, true)
	j := &a.state.Jobs[0]
	j.Status = "delivered"
	j.Expires = a.now().Add(-time.Second)
	result := `{"job_id":"` + j.ID + `","nonce":"` + j.Nonce + `","collector_id":"F01","data":{"status":"complete"}}`
	if agentCall(a, "/agent/result", result, strings.Repeat("a", 64), true).Code != 409 {
		t.Fatal("expired result")
	}
}
func TestRevocationCancelsAndInvalidates(t *testing.T) {
	a := fixture(t)
	call(a, "POST", "/api/jobs", `{"customer_id":"a","device_id":"da","collector_id":"F01"}`, true)
	if call(a, "DELETE", "/api/devices/da", "", true).Code != 204 {
		t.Fatal("revoke")
	}
	if a.state.Jobs[0].Status != "revoked" {
		t.Fatal("pending job survives")
	}
	if agentCall(a, "/agent/poll", "{}", strings.Repeat("a", 64), true).Code != 401 {
		t.Fatal("revoked token works")
	}
}
func TestStorageFailureDoesNotApproveJob(t *testing.T) {
	a := fixture(t)
	a.dir = filepath.Join(a.dir, "missing")
	if call(a, "POST", "/api/jobs", `{"customer_id":"a","device_id":"da","collector_id":"F04"}`, true).Code != 503 {
		t.Fatal("storage failure accepted")
	}
	if len(a.state.Jobs) != 0 {
		t.Fatal("uncommitted job visible")
	}
}
func TestOriginSessionExpiryAndPermissions(t *testing.T) {
	a := fixture(t)
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/jobs", strings.NewReader("{}"))
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("origin")
	}
	a.sessions["test"] = session{"analyst", a.now().Add(-time.Second), a.now().Add(time.Hour)}
	if call(a, "GET", "/api/me", "", true).Code != 401 {
		t.Fatal("expired session")
	}
	os.Chmod(filepath.Join(a.dir, "state.json"), 0644)
	if _, e := Open(a.dir); e == nil {
		t.Fatal("world-readable state accepted")
	}
}

func TestConnectionProbeDoesNotDeliverJobs(t *testing.T) {
	a := fixture(t)
	w := call(a, "POST", "/api/jobs", `{"customer_id":"a","device_id":"da","collector_id":"F01"}`, true)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		token  string
		secure bool
		want   int
	}{
		{strings.Repeat("a", 64), true, 204}, {strings.Repeat("0", 64), true, 401}, {strings.Repeat("a", 64), false, 403},
	} {
		r := agentCall(a, "/agent/check", `{}`, tc.token, tc.secure)
		if r.Code != tc.want {
			t.Fatal(r.Code, tc.want)
		}
	}
	if a.state.Jobs[0].Status != "queued" {
		t.Fatal("probe delivered job")
	}
	a.state.Devices[0].Revoked = true
	if r := agentCall(a, "/agent/check", `{}`, strings.Repeat("a", 64), true); r.Code != 401 {
		t.Fatal(r.Code)
	}
}
