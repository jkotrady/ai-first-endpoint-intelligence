package pilot

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func aiBody(customer, job string, consent bool) string {
	b, _ := json.Marshal(map[string]any{"customer_id": customer, "prompt": "Prever procesy", "api_key": "test-secret-api-key", "model": "test-model", "job_id": job, "consent": consent})
	return string(b)
}
func provider(body string) *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
func TestAIProposesWithoutExecutionOrSecretPersistence(t *testing.T) {
	a := fixture(t)
	a.state.Jobs = append(a.state.Jobs, Job{ID: "ja", CustomerID: "a", DeviceID: "da", Status: "completed", Result: json.RawMessage(`{"status":"complete","items":["untrusted"]}`)})
	a.aiTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://api.openai.com/v1/responses" || r.Header.Get("Authorization") != "Bearer test-secret-api-key" {
			t.Fatal("fixed destination/auth")
		}
		raw, _ := io.ReadAll(r.Body)
		var payload map[string]any
		json.Unmarshal(raw, &payload)
		if payload["store"] != false || strings.Contains(string(raw), `"db"`) || !strings.Contains(string(raw), "untrusted") {
			t.Fatal("wrong context")
		}
		return provider(`{"status":"completed","output":[{"type":"function_call","name":"propose_collection","arguments":"{\"device_id\":\"da\",\"collector_id\":\"F04\",\"reason\":\"Preveriť procesy\"}"}]}`), nil
	})
	w := call(a, "POST", "/api/ai/chat", aiBody("a", "ja", true), true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "F04") {
		t.Fatal(w.Code, w.Body)
	}
	if len(a.state.Jobs) != 1 {
		t.Fatal("AI executed a job")
	}
	raw, _ := os.ReadFile(filepath.Join(a.dir, "state.json"))
	if strings.Contains(string(raw), "test-secret-api-key") || strings.Contains(string(raw), "Prever procesy") {
		t.Fatal("secret/prompt persisted")
	}
}
func TestAIRequiresAuthConsentAndCustomerBoundary(t *testing.T) {
	a := fixture(t)
	a.aiTransport = roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("provider must not be called"); return nil, nil })
	for _, tc := range []struct {
		customer, job string
		consent, auth bool
		want          int
	}{{"a", "", true, false, 401}, {"a", "", false, true, 400}, {"b", "", true, true, 404}, {"a", "foreign-job", true, true, 404}} {
		if w := call(a, "POST", "/api/ai/chat", aiBody(tc.customer, tc.job, tc.consent), tc.auth); w.Code != tc.want {
			t.Fatal(w.Code, tc.want, w.Body)
		}
	}
}
func TestAIRejectsUnsafeProviderCalls(t *testing.T) {
	a := fixture(t)
	cases := []string{
		`{"device_id":"db","collector_id":"F04","reason":"cross customer"}`,
		`{"device_id":"da","collector_id":"shell","reason":"bad"}`,
		`{"device_id":"da","collector_id":"F04","reason":"bad","command":"whoami"}`,
		`{"device_id":"db","device_id":"da","collector_id":"F04","reason":"duplicate"}`,
		`{"device_id":"da","collector_id":"F04","reason":null}`,
	}
	for _, args := range cases {
		raw, _ := json.Marshal(map[string]any{"status": "completed", "output": []any{map[string]any{"type": "function_call", "name": "propose_collection", "arguments": args}}})
		a.aiTransport = roundTripFunc(func(*http.Request) (*http.Response, error) { return provider(string(raw)), nil })
		if w := call(a, "POST", "/api/ai/chat", aiBody("a", "", true), true); w.Code != 502 {
			t.Fatal(args, w.Code, w.Body)
		}
	}
	if len(a.state.Jobs) != 0 {
		t.Fatal("unsafe execution")
	}
}
func TestAIRechecksRevocationAndSessionAfterProvider(t *testing.T) {
	for _, logout := range []bool{false, true} {
		a := fixture(t)
		a.aiTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			a.mu.Lock()
			if logout {
				delete(a.sessions, "test")
			} else {
				a.state.Devices[0].Revoked = true
			}
			a.mu.Unlock()
			return provider(`{"status":"completed","output":[{"type":"function_call","name":"propose_collection","arguments":"{\"device_id\":\"da\",\"collector_id\":\"F04\",\"reason\":\"test\"}"}]}`), nil
		})
		want := 409
		if logout {
			want = 401
		}
		if w := call(a, "POST", "/api/ai/chat", aiBody("a", "", true), true); w.Code != want {
			t.Fatal(w.Code, want)
		}
	}
}
func TestAIProviderFailureRedactedAndRateLimited(t *testing.T) {
	a := fixture(t)
	a.aiTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		r := provider("sensitive provider body")
		r.StatusCode = 401
		return r, nil
	})
	for i := 0; i < 5; i++ {
		w := call(a, "POST", "/api/ai/chat", aiBody("a", "", true), true)
		if w.Code != 502 || strings.Contains(w.Body.String(), "sensitive") {
			t.Fatal(w.Code, w.Body)
		}
	}
	if w := call(a, "POST", "/api/ai/chat", aiBody("a", "", true), true); w.Code != 429 {
		t.Fatal("no limit", w.Code)
	}
}

func TestAIHonorsDeviceCollectorCapabilities(t *testing.T) {
	a := fixture(t)
	a.aiTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return provider(`{"status":"completed","output":[{"type":"function_call","name":"propose_collection","arguments":"{\"device_id\":\"da\",\"collector_id\":\"F15\",\"reason\":\"Read service inventory\"}"}]}`), nil
	})
	if w := call(a, "POST", "/api/ai/chat", aiBody("a", "", true), true); w.Code != 409 {
		t.Fatal("unsupported proposal", w.Code, w.Body)
	}
	a.state.Devices[0].Capabilities = append(a.state.Devices[0].Capabilities, "F15")
	if w := call(a, "POST", "/api/ai/chat", aiBody("a", "", true), true); w.Code != 200 {
		t.Fatal("valid proposal", w.Code, w.Body)
	}
	if len(a.state.Jobs) != 0 {
		t.Fatal("AI bypassed human approval")
	}
}

func TestAIRejectsVersionChangeDuringProviderRequest(t *testing.T) {
	a := fixture(t)
	a.state.Devices[0].SourceFingerprint = strings.Repeat("a", 64)
	a.aiTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		a.mu.Lock()
		a.state.Devices[0].SourceFingerprint = strings.Repeat("b", 64)
		a.mu.Unlock()
		return provider(`{"status":"completed","output":[{"type":"function_call","name":"propose_collection","arguments":"{\"device_id\":\"da\",\"collector_id\":\"F04\",\"reason\":\"Read processes\"}"}]}`), nil
	})
	if w := call(a, "POST", "/api/ai/chat", aiBody("a", "", true), true); w.Code != 409 {
		t.Fatal("version changed during AI request", w.Code, w.Body)
	}
	if len(a.state.Jobs) != 0 {
		t.Fatal("AI executed job")
	}
}
