package pilot

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeOIDC struct {
	server                                 *httptest.Server
	key                                    *rsa.PrivateKey
	mu                                     sync.Mutex
	claims                                 map[string]any
	expectedNonce, expectedChallenge, mode string
	exchanges                              int
	now                                    time.Time
}

func testOIDC(t *testing.T, a *App) *fakeOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOIDC{key: key, now: a.now()}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		issuer := f.server.URL
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			send(w, 200, map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"}})
		case "/keys":
			send(w, 200, map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "key1", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), "e": "AQAB"}}})
		case "/token":
			f.exchanges++
			r.ParseForm()
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "valid-code" || r.Form.Get("client_id") != "test-client" || r.Form.Get("redirect_uri") != oidcCallbackURL || base64.RawURLEncoding.EncodeToString(challenge[:]) != f.expectedChallenge {
				fail(w, 400, "invalid_grant")
				return
			}
			claims := map[string]any{"iss": issuer, "sub": "external-subject", "aud": "test-client", "exp": f.now.Add(5 * time.Minute).Unix(), "iat": f.now.Unix(), "auth_time": f.now.Unix(), "nonce": f.expectedNonce, "email": "analyst@example.test"}
			for k, v := range f.claims {
				claims[k] = v
			}
			head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"key1"}`))
			body, _ := json.Marshal(claims)
			input := head + "." + base64.RawURLEncoding.EncodeToString(body)
			digest := sha256.Sum256([]byte(input))
			sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
			if f.mode == "bad-signature" {
				sig[0] ^= 1
			}
			send(w, 200, map[string]any{"token_type": "Bearer", "access_token": "never-persist-access-token", "id_token": input + "." + base64.RawURLEncoding.EncodeToString(sig), "expires_in": 300})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	err = a.configureOIDCTransport(context.Background(), OIDCConfig{Issuer: f.server.URL, ClientID: "test-client", Subjects: map[string]string{"external-subject": "analyst"}}, f.server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func oidcCall(a *App, method, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}
func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}
func beginOIDC(t *testing.T, a *App, f *fakeOIDC) (string, *http.Cookie) {
	t.Helper()
	w := oidcCall(a, "POST", "/auth/oidc/start", "{}")
	if w.Code != 200 {
		t.Fatalf("start %d %s", w.Code, w.Body)
	}
	var d map[string]string
	json.Unmarshal(w.Body.Bytes(), &d)
	u, _ := url.Parse(d["authorization_url"])
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("scope") != "openid" || q.Get("prompt") != "login" || q.Get("max_age") != "0" || q.Get("redirect_uri") != oidcCallbackURL {
		t.Fatal("auth parameters", q)
	}
	f.mu.Lock()
	f.expectedNonce = q.Get("nonce")
	f.expectedChallenge = q.Get("code_challenge")
	f.mu.Unlock()
	c := cookieNamed(w, "oidc_flow")
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/auth/oidc" {
		t.Fatal("flow cookie")
	}
	return "/auth/oidc/callback?code=valid-code&state=" + q.Get("state"), c
}
func TestOIDCLoginRequiresLocalFactorAndPreservesTenant(t *testing.T) {
	a := fixture(t)
	f := testOIDC(t, a)
	path, c := beginOIDC(t, a, f)
	w := oidcCall(a, "GET", path, "", c)
	if w.Header().Get("Location") != "/portal#oidc-factor" {
		t.Fatal("callback", w.Code, w.Header())
	}
	factor := cookieNamed(w, "oidc_factor")
	if factor == nil || !factor.HttpOnly || factor.SameSite != http.SameSiteStrictMode {
		t.Fatal("factor cookie")
	}
	if cookieNamed(w, "pilot_session") != nil {
		t.Fatal("callback bypassed MFA")
	}
	if oidcCall(a, "GET", "/api/me", "", factor).Code != 401 {
		t.Fatal("factor has API access")
	}
	if oidcCall(a, "POST", "/auth/oidc/confirm", `{"code":"bad"}`, factor).Code != 401 {
		t.Fatal("bad MFA accepted")
	}
	code := totp(a.state.Users[0].TOTP, a.now().Unix()/30)
	w = oidcCall(a, "POST", "/auth/oidc/confirm", `{"code":"`+code+`"}`, factor, &http.Cookie{Name: "pilot_session", Value: "test"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	session := cookieNamed(w, "pilot_session")
	if session == nil || session.Value == "test" {
		t.Fatal("session rotation")
	}
	if _, ok := a.sessions["test"]; ok {
		t.Fatal("old session retained")
	}
	if oidcCall(a, "GET", "/api/customers/a/devices", "", session).Code != 200 || oidcCall(a, "GET", "/api/customers/b/devices", "", session).Code != 404 {
		t.Fatal("tenant grant changed")
	}
	if oidcCall(a, "POST", "/auth/oidc/confirm", `{"code":"`+code+`"}`, factor).Code != 401 {
		t.Fatal("MFA replay")
	}
	if oidcCall(a, "GET", path, "", c).Header().Get("Location") != "/portal#oidc-error" {
		t.Fatal("callback replay")
	}
	data, _ := os.ReadFile(filepath.Join(a.dir, "state.json"))
	for _, s := range []string{"never-persist-access-token", f.expectedNonce, "external-subject"} {
		if strings.Contains(string(data), s) {
			t.Fatal("protocol data persisted")
		}
	}
	if oidcCall(a, "DELETE", "/auth/session", "", session).Code != 204 || oidcCall(a, "GET", "/api/me", "", session).Code != 401 {
		t.Fatal("logout")
	}
}
func TestOIDCRejectsClaimsAndBinding(t *testing.T) {
	a := fixture(t)
	f := testOIDC(t, a)
	cases := []struct {
		name   string
		claims map[string]any
		mode   string
	}{
		{"nonce", map[string]any{"nonce": "wrong"}, ""},
		{"issuer", map[string]any{"iss": "https://other.invalid"}, ""},
		{"audience", map[string]any{"aud": "other-client"}, ""},
		{"expired", map[string]any{"exp": a.now().Add(-time.Minute).Unix()}, ""},
		{"future_iat", map[string]any{"iat": a.now().Add(2 * time.Minute).Unix()}, ""},
		{"missing_iat", map[string]any{"iat": nil}, ""},
		{"old_auth", map[string]any{"auth_time": a.now().Add(-10 * time.Minute).Unix()}, ""},
		{"missing_auth", map[string]any{"auth_time": nil}, ""},
		{"unmapped_same_email", map[string]any{"sub": "unmapped", "preferred_username": "analyst"}, ""},
		{"multi_audience_no_azp", map[string]any{"aud": []string{"test-client", "other"}}, ""},
		{"wrong_azp", map[string]any{"azp": "other"}, ""},
		{"signature", nil, "bad-signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.mu.Lock()
			f.claims = tc.claims
			f.mode = tc.mode
			f.mu.Unlock()
			path, c := beginOIDC(t, a, f)
			w := oidcCall(a, "GET", path, "", c)
			if w.Header().Get("Location") != "/portal#oidc-error" || cookieNamed(w, "oidc_factor") != nil {
				t.Fatal("accepted invalid claims", w.Header())
			}
		})
	}
	f.mu.Lock()
	f.claims = nil
	f.mode = ""
	before := f.exchanges
	f.mu.Unlock()
	path, c := beginOIDC(t, a, f)
	for _, cookies := range [][]*http.Cookie{nil, {{Name: "oidc_flow", Value: "wrong"}}} {
		if oidcCall(a, "GET", path, "", cookies...).Header().Get("Location") != "/portal#oidc-error" {
			t.Fatal("binding bypass")
		}
	}
	f.mu.Lock()
	after := f.exchanges
	f.mu.Unlock()
	if before != after {
		t.Fatal("exchange before binding")
	}
	if oidcCall(a, "GET", path+"&state=duplicate", "", c).Header().Get("Location") != "/portal#oidc-error" {
		t.Fatal("duplicate state")
	}
	if oidcCall(a, "GET", path+"&iss=https://other.invalid", "", c).Header().Get("Location") != "/portal#oidc-error" {
		t.Fatal("response issuer")
	}
	if len(a.oidc.factors) != 0 {
		t.Fatal("invalid flow created factors")
	}
}
func TestOIDCExpiryLimitsOriginAndDisabled(t *testing.T) {
	a := fixture(t)
	if oidcCall(a, "POST", "/auth/oidc/start", "{}").Code != 404 {
		t.Fatal("OIDC default enabled")
	}
	f := testOIDC(t, a)
	path, c := beginOIDC(t, a, f)
	now := a.now()
	a.now = func() time.Time { return now.Add(6 * time.Minute) }
	if oidcCall(a, "GET", path, "", c).Header().Get("Location") != "/portal#oidc-error" {
		t.Fatal("expired flow")
	}
	a.now = func() time.Time { return now }
	path, c = beginOIDC(t, a, f)
	w := oidcCall(a, "GET", path, "", c)
	factor := cookieNamed(w, "oidc_factor")
	for i := 0; i < 10; i++ {
		if oidcCall(a, "POST", "/auth/oidc/confirm", `{"code":"bad"}`, factor).Code != 401 {
			t.Fatal("factor attempts")
		}
	}
	if oidcCall(a, "POST", "/auth/oidc/confirm", `{"code":"bad"}`, factor).Code != 429 {
		t.Fatal("factor limit")
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/auth/oidc/start", nil)
	r.Header.Set("Origin", "https://attacker.invalid")
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("origin")
	}
	for i := 0; i < 100; i++ {
		a.oidc.flows[fmt.Sprint(i)] = oidcFlow{Expires: now.Add(time.Hour)}
	}
	if oidcCall(a, "POST", "/auth/oidc/start", "{}").Code != 429 {
		t.Fatal("flow bound")
	}
}
func TestOIDCConfigFailsClosed(t *testing.T) {
	a := fixture(t)
	for _, issuer := range []string{"http://example.com", "http://localhost:9080", "https://x.test/path?x=1", "https://u:p@x.test", "https://x.test/#x"} {
		if a.configureOIDC(context.Background(), OIDCConfig{Issuer: issuer, ClientID: "x", AllowLoopbackHTTP: true, Subjects: map[string]string{"s": "analyst"}}) == nil {
			t.Fatal("bad issuer", issuer)
		}
	}
	if a.configureOIDC(context.Background(), OIDCConfig{Issuer: "https://example.com", ClientID: "x", Subjects: map[string]string{"s": "missing"}}) == nil {
		t.Fatal("unknown local user")
	}
	p := filepath.Join(a.dir, "oidc.json")
	os.WriteFile(p, []byte(`{}`), 0644)
	if a.ConfigureOIDC(context.Background(), p) == nil {
		t.Fatal("public config")
	}
	os.Chmod(p, 0600)
	os.WriteFile(p, []byte(`{"unknown":true}`), 0600)
	if a.ConfigureOIDC(context.Background(), p) == nil {
		t.Fatal("unknown fields")
	}
	f := testOIDC(t, a)
	client := &http.Client{Transport: oidcTransport{f.server.Client().Transport, f.server.URL}}
	if _, err := client.Get("https://other.invalid/keys"); err == nil {
		t.Fatal("origin escaped")
	}
}

// Opt-in integration probe, not a browser login or MFA acceptance test.
func TestOIDCLocalProviderDiscovery(t *testing.T) {
	if os.Getenv("FORENSICS_OIDC_LAB") != "1" {
		t.Skip("local Keycloak lab not requested")
	}
	a := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := a.configureOIDC(ctx, OIDCConfig{Issuer: "http://127.0.0.1:9080/realms/forensics-lab", ClientID: "forensics-console", AllowLoopbackHTTP: true, Subjects: map[string]string{"probe-subject-not-a-real-account": "analyst"}})
	if err != nil {
		t.Fatal(err)
	}
	w := oidcCall(a, "POST", "/auth/oidc/start", "{}")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/protocol/openid-connect/auth?") {
		t.Fatal("real provider authorization URL", w.Code)
	}
}

func TestSessionRevocationIncludesPendingOIDCFactor(t *testing.T) {
	a := fixture(t)
	f := testOIDC(t, a)
	path, c := beginOIDC(t, a, f)
	factor := cookieNamed(oidcCall(a, "GET", path, "", c), "oidc_factor")
	a.sessions["second"] = session{"analyst", a.now().Add(time.Hour), a.now().Add(time.Hour)}
	a.state.Users = append(a.state.Users, User{Name: "other", Customers: []string{"b"}})
	a.sessions["other-session"] = session{"other", a.now().Add(time.Hour), a.now().Add(time.Hour)}
	if call(a, "DELETE", "/auth/sessions", "", true).Code != 204 {
		t.Fatal("revoke all")
	}
	if len(a.sessions) != 1 || a.sessions["other-session"].User != "other" {
		t.Fatal("revocation scope")
	}
	code := totp(a.state.Users[0].TOTP, a.now().Unix()/30)
	if oidcCall(a, "POST", "/auth/oidc/confirm", `{"code":"`+code+`"}`, factor).Code != 401 {
		t.Fatal("revoked pending login accepted")
	}
}

func TestOIDCFactorExpiryStorageFailureAndBoundedTransport(t *testing.T) {
	a := fixture(t)
	f := testOIDC(t, a)
	path, c := beginOIDC(t, a, f)
	factor := cookieNamed(oidcCall(a, "GET", path, "", c), "oidc_factor")
	now := a.now()
	a.now = func() time.Time { return now.Add(4 * time.Minute) }
	if oidcCall(a, "POST", "/auth/oidc/confirm", `{"code":"000000"}`, factor).Code != 401 {
		t.Fatal("expired factor")
	}
	a.now = func() time.Time { return now }
	path, c = beginOIDC(t, a, f)
	factor = cookieNamed(oidcCall(a, "GET", path, "", c), "oidc_factor")
	os.WriteFile(filepath.Join(a.dir, "state.json.tmp"), []byte("block atomic write"), 0600)
	code := totp(a.state.Users[0].TOTP, now.Unix()/30)
	w := oidcCall(a, "POST", "/auth/oidc/confirm", `{"code":"`+code+`"}`, factor)
	if w.Code != 503 || cookieNamed(w, "pilot_session") != nil || len(a.sessions) != 1 || a.state.Users[0].LastCounter != -1 {
		t.Fatal("storage failure granted login or consumed counter")
	}
	rt := oidcTransport{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", (1<<20)+1)))}, nil
	}), origin: "https://provider.test"}
	req, _ := http.NewRequest("GET", "https://provider.test/keys", nil)
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("oversize accepted")
	}
}
