package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func request(a *App, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}
func login(t *testing.T, a *App) *http.Cookie {
	t.Helper()
	w := request(a, "POST", "/demo/session", `{"mode":"synthetic_demo"}`, nil)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	return w.Result().Cookies()[0]
}
func TestSessionRequired(t *testing.T) {
	a := New()
	for _, p := range []string{"/v1/me", "/v1/customers", "/v1/collectors", "/v1/customers/customer-alfa/endpoints", "/v1/job-plans/x"} {
		if w := request(a, "GET", p, "", nil); w.Code != 401 {
			t.Fatal(p, w.Code)
		}
	}
}
func TestCookieAndLogout(t *testing.T) {
	a := New()
	c := login(t, a)
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.MaxAge != 28800 {
		t.Fatal(c)
	}
	if w := request(a, "DELETE", "/demo/session", "", c); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w := request(a, "GET", "/v1/me", "", c); w.Code != 401 {
		t.Fatal(w.Code)
	}
}
func TestSessionExpiry(t *testing.T) {
	a := New()
	c := login(t, a)
	a.now = func() time.Time { return time.Now().Add(9 * time.Hour) }
	if w := request(a, "GET", "/v1/me", "", c); w.Code != 401 {
		t.Fatal(w.Code)
	}
}
func TestCustomerIsolation(t *testing.T) {
	a := New()
	c := login(t, a)
	w := request(a, "GET", "/v1/customers", "", c)
	if strings.Contains(w.Body.String(), "customer-private") || w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	for _, path := range []string{"/v1/customers/customer-private/endpoints", "/v1/customers/unknown/endpoints", "/v1/customers/customer-alfa/endpoints/ep-private", "/v1/customers/customer-alfa/endpoints/ep-ltsc"} {
		if w := request(a, "GET", path, "", c); w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
}
func TestMembershipDoesNotBypassOrganization(t *testing.T) {
	a := New()
	c := login(t, a)
	p := a.sessions[c.Value]
	p.Customers = append(p.Customers, "customer-private")
	a.sessions[c.Value] = p
	if w := request(a, "GET", "/v1/customers/customer-private/endpoints", "", c); w.Code != 404 {
		t.Fatal(w.Code)
	}
}
func TestPlanRejectsUnsafeInputs(t *testing.T) {
	a := New()
	c := login(t, a)
	cases := []struct {
		body   string
		status int
	}{
		{`{"customer_id":"customer-alfa","endpoint_ids":["ep-ltsc"],"collector_id":"F04"}`, 404},
		{`{"customer_id":"customer-private","endpoint_ids":["ep-private"],"collector_id":"F04"}`, 404},
		{`{"customer_id":"customer-alfa","endpoint_ids":["ep-xp"],"collector_id":"F48"}`, 422},
		{`{"customer_id":"customer-alfa","endpoint_ids":["ep-xp","ep-xp"],"collector_id":"F04"}`, 422},
		{`{"customer_id":"customer-alfa","endpoint_ids":[],"collector_id":"F04"}`, 422},
		{`{"customer_id":"customer-alfa","endpoint_ids":["ep-xp"],"collector_id":"F04","shell":"cmd.exe"}`, 400},
		{`{"customer_id":"customer-alfa","endpoint_ids":["ep-xp"],"collector_id":"F04"} {}`, 400},
		{strings.Repeat("x", 9000), 400},
	}
	for _, tc := range cases {
		w := request(a, "POST", "/v1/job-plans", tc.body, c)
		if w.Code != tc.status {
			t.Errorf("got %d want %d: %s", w.Code, tc.status, w.Body.String())
		}
	}
	if len(a.plans) != 0 {
		t.Fatal("invalid plan persisted")
	}
}
func TestPlanStableDigestAndNoExecution(t *testing.T) {
	a := New()
	c := login(t, a)
	var plans []Plan
	for _, ids := range []string{`["ep-xp","ep-win7"]`, `["ep-win7","ep-xp"]`} {
		w := request(a, "POST", "/v1/job-plans", `{"customer_id":"customer-alfa","endpoint_ids":`+ids+`,"collector_id":"F04"}`, c)
		if w.Code != 201 {
			t.Fatal(w.Code, w.Body.String())
		}
		var p Plan
		_ = json.Unmarshal(w.Body.Bytes(), &p)
		plans = append(plans, p)
		if p.ExecutionEnabled || p.Status != "draft" {
			t.Fatal(p)
		}
	}
	if plans[0].Digest != plans[1].Digest || plans[0].ID == plans[1].ID {
		t.Fatal("digest/id invariant")
	}
	if w := request(a, "POST", "/v1/jobs", "{}", c); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if w := request(a, "GET", "/v1/job-plans/"+plans[0].ID, "", c); w.Code != 200 {
		t.Fatal(w.Code)
	}
	a.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	if w := request(a, "GET", "/v1/job-plans/"+plans[0].ID, "", c); w.Code != 404 {
		t.Fatal(w.Code)
	}
}
func TestPlanOwnership(t *testing.T) {
	a := New()
	c := login(t, a)
	w := request(a, "POST", "/v1/job-plans", `{"customer_id":"customer-alfa","endpoint_ids":["ep-xp"],"collector_id":"F04"}`, c)
	var plan Plan
	_ = json.Unmarshal(w.Body.Bytes(), &plan)
	other := login(t, a)
	p := a.sessions[other.Value]
	p.Subject = "other-analyst"
	a.sessions[other.Value] = p
	if w := request(a, "GET", "/v1/job-plans/"+plan.ID, "", other); w.Code != 404 {
		t.Fatal(w.Code)
	}
}
func TestOriginAndHostGuards(t *testing.T) {
	a := New()
	for _, tc := range []struct{ url, origin string }{{"http://127.0.0.1:8080/demo/session", "https://evil.example"}, {"http://evil.example:8080/demo/session", "http://evil.example:8080"}, {"http://127.0.0.1:8080/demo/session", ""}} {
		r := httptest.NewRequest("POST", tc.url, strings.NewReader(`{"mode":"synthetic_demo"}`))
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(tc, w.Code)
		}
	}
}
func TestCatalogIsPlannedAndComplete(t *testing.T) {
	a := New()
	c := login(t, a)
	w := request(a, "GET", "/v1/collectors", "", c)
	var items []map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 50 {
		t.Fatal(len(items))
	}
	seen := map[string]bool{}
	for _, x := range items {
		if seen[x["id"]] || x["implementation_status"] != "planned" {
			t.Fatal(x)
		}
		seen[x["id"]] = true
	}
}
func TestStaticSecurityHeaders(t *testing.T) {
	a := New()
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		w := request(a, "GET", path, "", nil)
		if w.Code != 200 || w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(path, w.Code)
		}
		if path == "/app.js" && !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") {
			t.Fatal(w.Header())
		}
	}
}

func TestAmbiguousJSONRejected(t *testing.T) {
	a := New()
	c := login(t, a)
	for _, body := range []string{
		`{"customer_id":"customer-alfa","customer_id":"customer-beta","endpoint_ids":["ep-ltsc"],"collector_id":"F04"}`,
		`{"CUSTOMER_ID":"customer-alfa","endpoint_ids":["ep-xp"],"collector_id":"F04"}`,
		`{"customer_id":null,"endpoint_ids":["ep-xp"],"collector_id":"F04"}`,
		`{"customer_id":"customer-alfa","endpoint_ids":["ep-xp"]}`,
		`null`, `[]`,
	} {
		if w := request(a, "POST", "/v1/job-plans", body, c); w.Code != 400 {
			t.Fatal(body, w.Code)
		}
	}
	if len(a.plans) != 0 {
		t.Fatal("ambiguous input persisted")
	}
}
