package pilot

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func inviteToken(t *testing.T, a *App) string {
	t.Helper()
	w := call(a, "POST", "/api/invitations", "", true)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	var b map[string]string
	json.Unmarshal(w.Body.Bytes(), &b)
	return b["invitation"]
}
func startRegistration(a *App, token string) *httptest.ResponseRecorder {
	return call(a, "POST", "/auth/register/start", `{"invitation":"`+token+`","username":"new-user","password":"long-test-password-123","workspace":"New workspace"}`, false)
}
func TestRegistrationRequiresMFAAndIsolatesWorkspace(t *testing.T) {
	a := fixture(t)
	token := inviteToken(t, a)
	w := startRegistration(a, token)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	var setup map[string]string
	json.Unmarshal(w.Body.Bytes(), &setup)
	if len(a.state.Users) != 1 {
		t.Fatal("activated before MFA")
	}
	if startRegistration(a, token).Code != 409 {
		t.Fatal("secret redisclosed")
	}
	code := totp(setup["secret"], a.now().Unix()/30)
	body := `{"invitation":"` + token + `","code":"` + code + `"}`
	w = call(a, "POST", "/auth/register/confirm", body, false)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	if a.allowed("new-user", "a") || a.allowed("new-user", "b") || len(a.user("new-user").Customers) != 1 {
		t.Fatal("tenant isolation")
	}
	if call(a, "POST", "/auth/register/confirm", body, false).Code != 403 {
		t.Fatal("invite reused")
	}
	if call(a, "POST", "/auth/login", `{"username":"new-user","password":"long-test-password-123","code":"`+code+`"}`, false).Code != 401 {
		t.Fatal("MFA counter replay")
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:8080/api/me", nil)
	r.AddCookie(w.Result().Cookies()[0])
	out := httptest.NewRecorder()
	a.Handler().ServeHTTP(out, r)
	if out.Code != 200 || strings.Contains(out.Body.String(), `"id":"a"`) {
		t.Fatal("new session scope")
	}
	again, e := Open(a.dir)
	if e != nil || again.user("new-user") == nil || len(again.state.Invitations) != 0 {
		t.Fatal("registration not durable", e)
	}
}
func TestRegistrationInvitationExpiryAndAttemptLimit(t *testing.T) {
	a := fixture(t)
	if call(a, "POST", "/api/invitations", "", false).Code != 401 {
		t.Fatal("public invitation")
	}
	if startRegistration(a, strings.Repeat("0", 64)).Code != 403 {
		t.Fatal("guessed invitation")
	}
	token := inviteToken(t, a)
	a.state.Invitations[0].Expires = a.now().Add(-time.Second)
	if startRegistration(a, token).Code != 403 {
		t.Fatal("expired invitation")
	}
	token = inviteToken(t, a)
	if startRegistration(a, token).Code != 201 {
		t.Fatal("start")
	}
	for i := 0; i < 5; i++ {
		if call(a, "POST", "/auth/register/confirm", `{"invitation":"`+token+`","code":"bad"}`, false).Code != 401 {
			t.Fatal("attempt", i)
		}
	}
	if len(a.state.Invitations) != 0 {
		t.Fatal("attempt limit missing")
	}
}
func TestPublicPagesAndProtectedControlData(t *testing.T) {
	a := fixture(t)
	for _, path := range []string{"/", "/portal", "/register", "/control", "/setup", "/style.css", "/app.js"} {
		w := call(a, http.MethodGet, path, "", false)
		if w.Code != 200 || w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(path, w.Code)
		}
	}
	if call(a, "GET", "/api/customers/a/devices", "", false).Code != 401 {
		t.Fatal("public data")
	}
}

func TestInvitationStorageFailureRollsBackOmittedSlice(t *testing.T) {
	a := fixture(t)
	a.dir = a.dir + "/missing"
	if w := call(a, "POST", "/api/invitations", "", true); w.Code != 503 {
		t.Fatal(w.Code)
	}
	if len(a.state.Invitations) != 0 {
		t.Fatal("failed transaction left an invitation in memory")
	}
}

func TestInvalidInvitationDoesNotRevealExistingAccount(t *testing.T) {
	a := fixture(t)
	body := `{"invitation":"` + strings.Repeat("0", 64) + `","username":"analyst","password":"long-test-password-123","workspace":"Test"}`
	if w := call(a, "POST", "/auth/register/start", body, false); w.Code != 403 {
		t.Fatal(w.Code, w.Body)
	}
}
