package pilot

import (
	"aiforensics.local/platform/collectors"
	"archive/zip"
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

//go:embed web/*
var web embed.FS

func send(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code string) {
	send(w, status, map[string]string{"error": code})
}
func decode(w http.ResponseWriter, r *http.Request, v any, fields ...string) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		fail(w, 415, "json_required")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 270000))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		fail(w, 400, "invalid_request")
		return false
	}
	m := map[string]json.RawMessage{}
	for d.More() {
		t, e = d.Token()
		k, ok := t.(string)
		known := false
		for _, f := range fields {
			if k == f {
				known = true
			}
		}
		if _, dup := m[k]; e != nil || !ok || !known || dup {
			fail(w, 400, "invalid_request")
			return false
		}
		var b json.RawMessage
		if d.Decode(&b) != nil || string(b) == "null" {
			fail(w, 400, "invalid_request")
			return false
		}
		m[k] = b
	}
	t, e = d.Token()
	var extra any
	if e != nil || t != json.Delim('}') || len(m) != len(fields) || d.Decode(&extra) != io.EOF {
		fail(w, 400, "invalid_request")
		return false
	}
	b, _ := json.Marshal(m)
	if json.Unmarshal(b, v) != nil {
		fail(w, 400, "invalid_request")
		return false
	}
	return true
}
func (a *App) auth(r *http.Request) string {
	c, e := r.Cookie("pilot_session")
	if e != nil {
		return ""
	}
	s, ok := a.sessions[c.Value]
	now := a.now()
	if !ok || !now.Before(s.Expires) || !now.Before(s.Idle) {
		delete(a.sessions, c.Value)
		return ""
	}
	if a.user(s.User) == nil {
		return ""
	}
	s.Idle = now.Add(30 * time.Minute)
	a.sessions[c.Value] = s
	return s.User
}
func (a *App) guard(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		u := a.auth(r)
		if u == "" {
			fail(w, 401, "login_required")
			return
		}
		fn(w, r, u)
	}
}
func (a *App) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		send(w, 200, map[string]string{"status": "ok", "mode": "internal_pilot"})
	})
	m.HandleFunc("GET /api/agent/update", a.guard(a.agentArtifact))
	m.HandleFunc("GET /api/agent/build", a.guard(a.agentArtifact))
	m.HandleFunc("GET /api/collectors", a.guard(func(w http.ResponseWriter, r *http.Request, u string) {
		list := []map[string]string{}
		for _, entry := range collectors.All() {
			list = append(list, map[string]string{"id": entry.ID, "name": entry.Name, "limitations": entry.Limitations})
		}
		send(w, 200, list)
	}))
	m.HandleFunc("GET /auth/methods", func(w http.ResponseWriter, r *http.Request) {
		send(w, 200, map[string]bool{"oidc": a.oidc != nil})
	})
	m.HandleFunc("POST /auth/oidc/start", a.oidcStart)
	m.HandleFunc("GET /auth/oidc/callback", a.oidcCallback)
	m.HandleFunc("POST /auth/oidc/confirm", a.oidcConfirm)
	m.HandleFunc("POST /auth/login", a.login)
	m.HandleFunc("POST /auth/register/start", a.registrationStart)
	m.HandleFunc("POST /auth/register/confirm", a.registrationConfirm)
	m.HandleFunc("POST /api/ai/chat", a.aiChat)
	m.HandleFunc("POST /api/invitations", a.guard(a.invite))
	m.HandleFunc("DELETE /auth/session", a.guard(func(w http.ResponseWriter, r *http.Request, u string) {
		c, _ := r.Cookie("pilot_session")
		delete(a.sessions, c.Value)
		http.SetCookie(w, &http.Cookie{Name: "pilot_session", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
		w.WriteHeader(204)
	}))
	m.HandleFunc("DELETE /auth/sessions", a.guard(func(w http.ResponseWriter, r *http.Request, u string) {
		if a.transaction(func() { a.event(u, "sessions_revoked", "", "") }) != nil {
			fail(w, 503, "storage_unavailable")
			return
		}
		for id, session := range a.sessions {
			if session.User == u {
				delete(a.sessions, id)
			}
		}
		if a.oidc != nil {
			for id, factor := range a.oidc.factors {
				if factor.User == u {
					delete(a.oidc.factors, id)
				}
			}
		}
		http.SetCookie(w, &http.Cookie{Name: "pilot_session", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
		w.WriteHeader(204)
	}))
	m.HandleFunc("GET /api/me", a.guard(func(w http.ResponseWriter, r *http.Request, u string) {
		customers := []Customer{}
		for _, c := range a.state.Customers {
			if a.allowed(u, c.ID) {
				customers = append(customers, c)
			}
		}
		send(w, 200, map[string]any{"username": u, "customers": customers, "mode": "internal_pilot"})
	}))
	m.HandleFunc("GET /api/customers/{customer}/devices", a.guard(a.devices))
	m.HandleFunc("POST /api/customers/{customer}/devices", a.guard(a.enroll))
	m.HandleFunc("DELETE /api/devices/{device}", a.guard(a.revoke))
	m.HandleFunc("GET /api/customers/{customer}/jobs", a.guard(a.jobs))
	m.HandleFunc("POST /api/jobs", a.guard(a.createJob))
	m.HandleFunc("POST /api/jobs/approve", a.guard(a.createJob))
	m.HandleFunc("GET /api/jobs/{job}", a.guard(a.result))
	m.HandleFunc("GET /api/customers/{customer}/audit", a.guard(a.audit))
	assets, _ := fs.Sub(web, "web")
	files := http.FileServer(http.FS(assets))
	for route, file := range map[string]string{"/portal": "portal.html", "/register": "portal.html", "/control": "control.html", "/setup": "setup.html"} {
		m.HandleFunc("GET "+route, func(w http.ResponseWriter, r *http.Request) {
			content, err := fs.ReadFile(assets, file)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(content)
		})
	}
	m.Handle("/", files)
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
		m.ServeHTTP(w, r)
	})
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decode(w, r, &b, "username", "password", "code") {
		return
	}
	if len(b.Username) > 128 || len(b.Password) > 256 || len(b.Code) != 6 {
		fail(w, 401, "login_failed")
		return
	}
	select {
	case a.loginSlots <- struct{}{}:
		defer func() { <-a.loginSlots }()
	default:
		fail(w, 429, "try_later")
		return
	}
	a.mu.Lock()
	now := a.now()
	times := []time.Time{}
	for _, t := range a.attempts["global"] {
		if now.Sub(t) < 15*time.Minute {
			times = append(times, t)
		}
	}
	if len(times) >= 10 {
		a.mu.Unlock()
		fail(w, 429, "try_later")
		return
	}
	a.attempts["global"] = append(times, now)
	u := a.user(b.Username)
	copyUser := User{Salt: "dummy-user-constant-salt"}
	if u != nil {
		copyUser = *u
	}
	a.mu.Unlock()
	hash, e := passwordHash(b.Password, copyUser.Salt)
	a.mu.Lock()
	defer a.mu.Unlock()
	u = a.user(b.Username)
	if e != nil || u == nil || subtle.ConstantTimeCompare([]byte(hash), []byte(u.Hash)) != 1 {
		fail(w, 401, "login_failed")
		return
	}
	counter, ok := checkTOTP(*u, b.Code, a.now())
	if !ok {
		fail(w, 401, "login_failed")
		return
	}
	for k, s := range a.sessions {
		if !a.now().Before(s.Expires) || !a.now().Before(s.Idle) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 100 {
		fail(w, 429, "session_limit")
		return
	}
	if a.transaction(func() { u.LastCounter = counter; a.event(u.Name, "login", "", "") }) != nil {
		fail(w, 503, "storage_unavailable")
		return
	}
	a.attempts["global"] = nil
	id := randomHex()
	a.sessions[id] = session{u.Name, a.now().Add(8 * time.Hour), a.now().Add(30 * time.Minute)}
	http.SetCookie(w, &http.Cookie{Name: "pilot_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 28800})
	send(w, 200, map[string]string{"username": u.Name})
}
func (a *App) devices(w http.ResponseWriter, r *http.Request, u string) {
	c := r.PathValue("customer")
	if !a.allowed(u, c) {
		fail(w, 404, "not_found")
		return
	}
	items := []Device{}
	for _, d := range a.state.Devices {
		if d.CustomerID == c {
			d.CredentialHash = ""
			items = append(items, d)
		}
	}
	send(w, 200, items)
}
func (a *App) enroll(w http.ResponseWriter, r *http.Request, u string) {
	c := r.PathValue("customer")
	if !a.allowed(u, c) {
		fail(w, 404, "not_found")
		return
	}
	var b struct {
		Label string `json:"label"`
		Host  string `json:"host"`
	}
	if !decode(w, r, &b, "label", "host") {
		return
	}
	if len(b.Label) < 1 || len(b.Label) > 80 || (b.Host != "10.0.2.100" && b.Host != "127.0.0.1") {
		fail(w, 400, "invalid_label_or_lab_host")
		return
	}
	if len(a.state.Devices) >= 10 {
		fail(w, 409, "pilot_device_limit")
		return
	}
	exe, _, manifest, e := loadArtifacts("work/bin")
	if e != nil {
		fail(w, 503, "agent_build_unverified")
		return
	}
	cert, e := os.ReadFile(filepath.Join(a.dir, "ca.pem"))
	if e != nil {
		fail(w, 503, "ca_missing")
		return
	}
	token := randomHex()
	id := randomHex()
	d := Device{ID: id, CustomerID: c, Label: b.Label, CredentialHash: tokenHash(token), Capabilities: []string{}}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	files := map[string][]byte{"forensics-agent.exe": exe, "agent-build.json": manifest, "ca.pem": cert, "agent.conf": []byte(fmt.Sprintf("%s 8443 lab.forensics %s ca.pem\n", b.Host, token)), "run.cmd": []byte("@echo off\r\ncd /d \"%~dp0\"\r\nforensics-agent.exe --run agent.conf\r\npause\r\n"), "README.txt": []byte("INTERNAL PILOT. Contains a private device token. Extract to a dedicated local directory accessible only to your operator. Run run.cmd in that directory. Foreground; Ctrl+C stops. Allowlist in agent --list and agent-build.json; source publication will be maintained separately in GitHub. No service installer or automatic updates. TLS verification required. The configured lab gateway must be reachable. Keep ca.pem and agent.conf together. Do not reuse this identity on another endpoint. Revoke device in console to invalidate token. x86 build: partial XP SP3 and Win7 Ultimate SP1 x86 runtime tests are recorded separately; remaining Windows matrix variants need actual tests.\r\n")}
	for _, license := range []string{"MBEDTLS.txt", "MINGW.txt", "GCC-RUNTIME.txt"} {
		content, err := os.ReadFile(filepath.Join("agent/windows/licenses", license))
		if err != nil {
			fail(w, 503, "license_notice_missing")
			return
		}
		files["licenses/"+license] = content
	}
	for n, b := range files {
		f, e := z.Create(n)
		if e != nil {
			fail(w, 500, "bundle_failed")
			return
		}
		if _, e = f.Write(b); e != nil {
			fail(w, 500, "bundle_failed")
			return
		}
	}
	if e = z.Close(); e != nil {
		fail(w, 500, "bundle_failed")
		return
	}
	if a.transaction(func() { a.state.Devices = append(a.state.Devices, d); a.event(u, "device_enrolled", c, id) }) != nil {
		fail(w, 503, "storage_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=forensics-agent-"+id[:8]+".zip")
	w.Write(buf.Bytes())
}
func (a *App) revoke(w http.ResponseWriter, r *http.Request, u string) {
	id := r.PathValue("device")
	for i := range a.state.Devices {
		d := &a.state.Devices[i]
		if d.ID == id && a.allowed(u, d.CustomerID) {
			if a.transaction(func() {
				d.Revoked = true
				for j := range a.state.Jobs {
					job := &a.state.Jobs[j]
					if job.DeviceID == id && (job.Status == "queued" || job.Status == "delivered") {
						job.Status = "revoked"
					}
				}
				a.event(u, "device_revoked", d.CustomerID, id)
			}) != nil {
				fail(w, 503, "storage_unavailable")
				return
			}
			w.WriteHeader(204)
			return
		}
	}
	fail(w, 404, "not_found")
}
func (a *App) jobs(w http.ResponseWriter, r *http.Request, u string) {
	c := r.PathValue("customer")
	if !a.allowed(u, c) {
		fail(w, 404, "not_found")
		return
	}
	items := []Job{}
	for _, j := range a.state.Jobs {
		if j.CustomerID == c {
			j.Nonce = ""
			j.Result = nil
			if (j.Status == "queued" || j.Status == "delivered") && !a.now().Before(j.Expires) {
				j.Status = "expired"
			}
			items = append(items, j)
		}
	}
	send(w, 200, items)
}
func (a *App) createJob(w http.ResponseWriter, r *http.Request, u string) {
	var b struct {
		DeviceID    string `json:"device_id"`
		Collector   string `json:"collector_id"`
		CustomerID  string `json:"customer_id"`
		AgentSource string `json:"agent_source"`
	}
	fields := []string{"device_id", "collector_id", "customer_id"}
	if r.URL.Path == "/api/jobs/approve" {
		fields = append(fields, "agent_source")
	}
	if !decode(w, r, &b, fields...) {
		return
	}
	if !a.allowed(u, b.CustomerID) {
		fail(w, 404, "not_found")
		return
	}
	if !collectors.Allowed(b.Collector) {
		fail(w, 400, "collector_not_allowed")
		return
	}
	var d *Device
	for i := range a.state.Devices {
		v := &a.state.Devices[i]
		if v.ID == b.DeviceID && v.CustomerID == b.CustomerID && !v.Revoked {
			d = v
		}
	}
	if d == nil {
		fail(w, 404, "not_found")
		return
	}
	if b.AgentSource != d.SourceFingerprint {
		fail(w, 409, "agent_version_changed_refresh_approval")
		return
	}
	if !supports(d, b.Collector) {
		fail(w, 409, "collector_not_supported_by_device")
		return
	}
	if len(a.state.Jobs) >= 100 {
		fail(w, 409, "pilot_job_capacity")
		return
	}
	for _, j := range a.state.Jobs {
		if j.DeviceID == d.ID && (j.Status == "queued" || j.Status == "delivered") && a.now().Before(j.Expires) {
			fail(w, 409, "device_busy")
			return
		}
	}
	job := Job{ID: randomHex(), Nonce: randomHex(), CustomerID: d.CustomerID, DeviceID: d.ID, Collector: b.Collector, AgentSource: d.SourceFingerprint, Status: "queued", Created: a.now().UTC(), Expires: a.now().Add(5 * time.Minute).UTC(), CreatedBy: u}
	if a.transaction(func() { a.state.Jobs = append(a.state.Jobs, job); a.event(u, "job_approved", job.CustomerID, job.ID) }) != nil {
		fail(w, 503, "storage_unavailable")
		return
	}
	job.Nonce = ""
	send(w, 201, job)
}
func (a *App) result(w http.ResponseWriter, r *http.Request, u string) {
	for _, j := range a.state.Jobs {
		if j.ID == r.PathValue("job") && a.allowed(u, j.CustomerID) {
			j.Nonce = ""
			send(w, 200, j)
			return
		}
	}
	fail(w, 404, "not_found")
}
func (a *App) audit(w http.ResponseWriter, r *http.Request, u string) {
	c := r.PathValue("customer")
	if !a.allowed(u, c) {
		fail(w, 404, "not_found")
		return
	}
	items := []Event{}
	for _, e := range a.state.Audit {
		if e.CustomerID == c {
			items = append(items, e)
		}
	}
	send(w, 200, items)
}
func (a *App) AgentHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /agent/check", func(w http.ResponseWriter, r *http.Request) {
		if a.deviceAuth(r) == nil {
			fail(w, 401, "device_auth_failed")
			return
		}
		w.WriteHeader(204)
	})
	m.HandleFunc("POST /agent/poll", a.poll)
	m.HandleFunc("POST /agent/result", a.upload)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil {
			fail(w, 403, "tls_required")
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		m.ServeHTTP(w, r)
	})
}
func (a *App) deviceAuth(r *http.Request) *Device {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") || len(v) != 71 {
		return nil
	}
	h := tokenHash(v[7:])
	for i := range a.state.Devices {
		d := &a.state.Devices[i]
		if !d.Revoked && subtle.ConstantTimeCompare([]byte(h), []byte(d.CredentialHash)) == 1 {
			return d
		}
	}
	return nil
}
func (a *App) poll(w http.ResponseWriter, r *http.Request) {
	d := a.deviceAuth(r)
	if d == nil {
		fail(w, 401, "device_auth_failed")
		return
	}
	caps, source, valid := reportedCapabilities(r)
	if !valid {
		fail(w, 400, "invalid_capabilities")
		return
	}
	var b struct {
		Status   string   `json:"status"`
		Hostname string   `json:"hostname"`
		OS       string   `json:"os"`
		Arch     string   `json:"agent_arch"`
		CPU      uint32   `json:"logical_processors"`
		Total    uint64   `json:"ram_total_bytes"`
		Free     uint64   `json:"ram_free_bytes"`
		IPv4     []string `json:"ipv4"`
	}
	if !decode(w, r, &b, "status", "hostname", "os", "agent_arch", "logical_processors", "ram_total_bytes", "ram_free_bytes", "ipv4") {
		return
	}
	if b.Status != "complete" || len(b.Hostname) > 256 || len(b.OS) > 256 || b.Arch != "x86" {
		fail(w, 400, "invalid_identity")
		return
	}
	if len(b.IPv4) > 128 {
		fail(w, 400, "invalid_identity")
		return
	}
	for _, ip := range b.IPv4 {
		if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
			fail(w, 400, "invalid_identity")
			return
		}
	}
	var next *Job
	for i := range a.state.Jobs {
		j := &a.state.Jobs[i]
		if j.DeviceID == d.ID && j.AgentSource == source && slices.Contains(caps, j.Collector) && (j.Status == "queued" || j.Status == "delivered") && a.now().Before(j.Expires) {
			next = j
			break
		}
	}
	if a.transaction(func() {
		d.Capabilities = caps
		d.SourceFingerprint = source
		d.Hostname = b.Hostname
		d.OS = b.OS
		d.IPv4 = append([]string{}, b.IPv4...)
		d.LastSeen = a.now().UTC()
		if next != nil && next.Status == "queued" {
			next.Status = "delivered"
			a.event(d.ID, "job_delivered", d.CustomerID, next.ID)
		}
	}) != nil {
		fail(w, 503, "storage_unavailable")
		return
	}
	if next == nil {
		w.WriteHeader(204)
		return
	}
	line := fmt.Sprintf("JOB %s %s %s\n", next.ID, next.Nonce, next.Collector)
	if next.AgentSource != "" {
		line = fmt.Sprintf("JOB2 %s %s %s %s\n", next.ID, next.Nonce, next.Collector, next.AgentSource)
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", fmt.Sprint(len(line)))
	w.Write([]byte(line))
}
func (a *App) upload(w http.ResponseWriter, r *http.Request) {
	d := a.deviceAuth(r)
	if d == nil {
		fail(w, 401, "device_auth_failed")
		return
	}
	var b struct {
		ID        string          `json:"job_id"`
		Nonce     string          `json:"nonce"`
		Collector string          `json:"collector_id"`
		Data      json.RawMessage `json:"data"`
	}
	if !decode(w, r, &b, "job_id", "nonce", "collector_id", "data") {
		return
	}
	if len(b.Data) > 262144 {
		fail(w, 413, "result_too_large")
		return
	}
	var record map[string]json.RawMessage
	if json.Unmarshal(b.Data, &record) != nil {
		fail(w, 400, "invalid_result")
		return
	}
	var status string
	if json.Unmarshal(record["status"], &status) != nil || (status != "complete" && status != "partial" && status != "error") {
		fail(w, 400, "invalid_result_status")
		return
	}
	for i := range a.state.Jobs {
		j := &a.state.Jobs[i]
		if j.ID != b.ID || j.DeviceID != d.ID || j.CustomerID != d.CustomerID {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(b.Nonce), []byte(j.Nonce)) != 1 || b.Collector != j.Collector {
			fail(w, 409, "job_mismatch")
			return
		}
		hash := tokenHash(string(b.Data))
		if j.Status == "completed" {
			if j.ResultHash == hash {
				w.WriteHeader(204)
			} else {
				fail(w, 409, "result_conflict")
			}
			return
		}
		if j.Status != "delivered" || !a.now().Before(j.Expires) {
			fail(w, 409, "job_not_active")
			return
		}
		if a.transaction(func() {
			j.Status = "completed"
			j.Result = append(json.RawMessage{}, b.Data...)
			j.ResultHash = hash
			a.event(d.ID, "result_received", d.CustomerID, j.ID)
		}) != nil {
			fail(w, 503, "storage_unavailable")
			return
		}
		w.WriteHeader(204)
		return
	}
	fail(w, 404, "not_found")
}
