package console

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed web/* collectors.json
var assets embed.FS

type Customer struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	OrganizationID string `json:"organization_id"`
}
type Endpoint struct {
	ID               string `json:"id"`
	CustomerID       string `json:"customer_id"`
	Hostname         string `json:"hostname"`
	OS               string `json:"os"`
	IP               string `json:"ip"`
	Status           string `json:"status"`
	CapabilityStatus string `json:"capability_status"`
}
type principal struct {
	Subject        string    `json:"subject"`
	OrganizationID string    `json:"organization_id"`
	Customers      []string  `json:"customer_ids"`
	Expires        time.Time `json:"-"`
}
type planInput struct {
	CustomerID  string   `json:"customer_id"`
	EndpointIDs []string `json:"endpoint_ids"`
	CollectorID string   `json:"collector_id"`
}
type Plan struct {
	ID string `json:"id"`
	planInput
	Digest           string    `json:"digest"`
	Status           string    `json:"status"`
	ExecutionEnabled bool      `json:"execution_enabled"`
	Expires          time.Time `json:"expires_at"`
	owner            string
}
type App struct {
	mu        sync.Mutex
	sessions  map[string]principal
	plans     map[string]Plan
	customers []Customer
	endpoints []Endpoint
	now       func() time.Time
}

func New() *App {
	return &App{sessions: map[string]principal{}, plans: map[string]Plan{}, now: time.Now,
		customers: []Customer{{"customer-alfa", "Alfa · výroba", "msp-demo"}, {"customer-beta", "Beta · služby", "msp-demo"}, {"customer-private", "Oddelený zákazník", "msp-other"}},
		endpoints: []Endpoint{
			{"ep-xp", "customer-alfa", "ALFA-XP-LAB", "Windows XP Professional SP3 x86", "192.0.2.10", "demo", "not_verified"},
			{"ep-win7", "customer-alfa", "ALFA-W7-01", "Windows 7 SP1 x64", "192.0.2.11", "demo", "not_verified"},
			{"ep-win11", "customer-alfa", "ALFA-W11-01", "Windows 11 x64", "192.0.2.12", "demo", "not_verified"},
			{"ep-ltsc", "customer-beta", "BETA-LTSC-01", "Windows 10 Enterprise LTSC x86", "198.51.100.10", "demo", "not_verified"},
			{"ep-private", "customer-private", "PRIVATE-01", "Windows 11 x64", "203.0.113.10", "demo", "not_verified"},
		}}
}
func randomID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func send(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code string) {
	send(w, status, map[string]string{"error": code})
}
func (a *App) allowed(p principal, id string) bool {
	for _, c := range a.customers {
		if c.ID == id && c.OrganizationID == p.OrganizationID {
			for _, grant := range p.Customers {
				if grant == id {
					return true
				}
			}
		}
	}
	return false
}
func (a *App) auth(r *http.Request) (principal, bool) {
	cookie, err := r.Cookie("demo_session")
	if err != nil {
		return principal{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.sessions[cookie.Value]
	if !ok || !a.now().Before(p.Expires) {
		delete(a.sessions, cookie.Value)
		return principal{}, false
	}
	return p, true
}
func (a *App) protect(next func(http.ResponseWriter, *http.Request, principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := a.auth(r)
		if !ok {
			fail(w, 401, "session_required")
			return
		}
		next(w, r, p)
	}
}
func decode(w http.ResponseWriter, r *http.Request, v any, fields ...string) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		fail(w, 415, "json_required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		fail(w, 400, "invalid_request")
		return false
	}
	values := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			fail(w, 400, "invalid_request")
			return false
		}
		known := false
		for _, field := range fields {
			if field == key {
				known = true
			}
		}
		if _, duplicate := values[key]; duplicate || !known {
			fail(w, 400, "invalid_request")
			return false
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil || strings.TrimSpace(string(value)) == "null" {
			fail(w, 400, "invalid_request")
			return false
		}
		values[key] = value
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(values) != len(fields) {
		fail(w, 400, "invalid_request")
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		fail(w, 400, "invalid_request")
		return false
	}
	encoded, err := json.Marshal(values)
	if err != nil || json.Unmarshal(encoded, v) != nil {
		fail(w, 400, "invalid_request")
		return false
	}
	return true
}
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		send(w, 200, map[string]string{"status": "ok", "mode": "synthetic_demo"})
	})
	mux.HandleFunc("POST /demo/session", a.login)
	mux.HandleFunc("DELETE /demo/session", a.protect(a.logout))
	mux.HandleFunc("GET /v1/me", a.protect(func(w http.ResponseWriter, r *http.Request, p principal) { send(w, 200, p) }))
	mux.HandleFunc("GET /v1/customers", a.protect(func(w http.ResponseWriter, r *http.Request, p principal) {
		items := []Customer{}
		for _, c := range a.customers {
			if a.allowed(p, c.ID) {
				items = append(items, c)
			}
		}
		send(w, 200, map[string]any{"items": items, "mode": "synthetic_demo"})
	}))
	mux.HandleFunc("GET /v1/customers/{customer}/endpoints", a.protect(a.listEndpoints))
	mux.HandleFunc("GET /v1/customers/{customer}/endpoints/{endpoint}", a.protect(a.getEndpoint))
	mux.HandleFunc("GET /v1/collectors", a.protect(func(w http.ResponseWriter, r *http.Request, p principal) {
		data, _ := assets.ReadFile("collectors.json")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	mux.HandleFunc("POST /v1/job-plans", a.protect(a.createPlan))
	mux.HandleFunc("GET /v1/job-plans/{plan}", a.protect(a.getPlan))
	mux.HandleFunc("POST /v1/jobs", a.protect(func(w http.ResponseWriter, r *http.Request, p principal) {
		fail(w, 409, "agent_executor_not_implemented")
	}))
	web, _ := fs.Sub(assets, "web")
	mux.Handle("/", http.FileServer(http.FS(web)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.Host != "127.0.0.1:8080" && r.Host != "localhost:8080" {
			fail(w, 403, "host_not_allowed")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Header.Get("Origin") != "http://"+r.Host {
			fail(w, 403, "origin_not_allowed")
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if !decode(w, r, &body, "mode") {
		return
	}
	if body.Mode != "synthetic_demo" {
		fail(w, 400, "demo_mode_required")
		return
	}
	id, err := randomID()
	if err != nil {
		fail(w, 500, "session_creation_failed")
		return
	}
	a.mu.Lock()
	now := a.now()
	for k, p := range a.sessions {
		if !now.Before(p.Expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 100 {
		a.mu.Unlock()
		fail(w, 429, "demo_session_limit")
		return
	}
	a.sessions[id] = principal{"demo-analyst", "msp-demo", []string{"customer-alfa", "customer-beta"}, now.Add(8 * time.Hour)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "demo_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 28800})
	send(w, 201, map[string]string{"mode": "synthetic_demo"})
}
func (a *App) logout(w http.ResponseWriter, r *http.Request, p principal) {
	c, _ := r.Cookie("demo_session")
	a.mu.Lock()
	delete(a.sessions, c.Value)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "demo_session", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(204)
}
func (a *App) listEndpoints(w http.ResponseWriter, r *http.Request, p principal) {
	id := r.PathValue("customer")
	if !a.allowed(p, id) {
		fail(w, 404, "not_found")
		return
	}
	items := []Endpoint{}
	for _, e := range a.endpoints {
		if e.CustomerID == id {
			items = append(items, e)
		}
	}
	send(w, 200, map[string]any{"items": items, "mode": "synthetic_demo"})
}
func (a *App) getEndpoint(w http.ResponseWriter, r *http.Request, p principal) {
	id := r.PathValue("customer")
	if a.allowed(p, id) {
		for _, e := range a.endpoints {
			if e.CustomerID == id && e.ID == r.PathValue("endpoint") {
				send(w, 200, e)
				return
			}
		}
	}
	fail(w, 404, "not_found")
}
func (a *App) createPlan(w http.ResponseWriter, r *http.Request, p principal) {
	var in planInput
	if !decode(w, r, &in, "customer_id", "endpoint_ids", "collector_id") {
		return
	}
	if !a.allowed(p, in.CustomerID) {
		fail(w, 404, "not_found")
		return
	}
	if in.CollectorID != "F01" && in.CollectorID != "F04" && in.CollectorID != "F08" {
		fail(w, 422, "collector_not_available_for_demo_planning")
		return
	}
	if len(in.EndpointIDs) == 0 || len(in.EndpointIDs) > 10 {
		fail(w, 422, "endpoint_limit")
		return
	}
	sort.Strings(in.EndpointIDs)
	for i, id := range in.EndpointIDs {
		if i > 0 && id == in.EndpointIDs[i-1] {
			fail(w, 422, "duplicate_endpoint")
			return
		}
		found := false
		for _, e := range a.endpoints {
			if e.ID == id && e.CustomerID == in.CustomerID {
				found = true
			}
		}
		if !found {
			fail(w, 404, "not_found")
			return
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for id, plan := range a.plans {
		if !now.Before(plan.Expires) {
			delete(a.plans, id)
		}
	}
	if len(a.plans) >= 1000 {
		fail(w, 429, "demo_plan_limit")
		return
	}
	id, err := randomID()
	if err != nil {
		fail(w, 500, "plan_creation_failed")
		return
	}
	// A demo digest only: production signed envelopes/versioning belong to T012.
	content, _ := json.Marshal(in)
	digest := sha256.Sum256(content)
	plan := Plan{ID: id, planInput: in, Digest: hex.EncodeToString(digest[:]), Status: "draft", ExecutionEnabled: false, Expires: now.Add(15 * time.Minute), owner: p.Subject}
	a.plans[id] = plan
	send(w, 201, plan)
}
func (a *App) getPlan(w http.ResponseWriter, r *http.Request, p principal) {
	a.mu.Lock()
	defer a.mu.Unlock()
	plan, ok := a.plans[r.PathValue("plan")]
	if !ok || !a.now().Before(plan.Expires) || plan.owner != p.Subject || !a.allowed(p, plan.CustomerID) {
		fail(w, 404, "not_found")
		return
	}
	send(w, 200, plan)
}
