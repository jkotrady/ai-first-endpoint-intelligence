package pilot

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const oidcCallbackURL = "http://127.0.0.1:8080/auth/oidc/callback"

type OIDCConfig struct {
	Issuer            string            `json:"issuer"`
	ClientID          string            `json:"client_id"`
	AllowLoopbackHTTP bool              `json:"allow_loopback_http"`
	Subjects          map[string]string `json:"subjects"`
}
type oidcFlow struct {
	Binding, Nonce, Verifier string
	Created, Expires         time.Time
}
type oidcFactor struct {
	User    string
	Expires time.Time
}
type oidcLogin struct {
	config   OIDCConfig
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
	flows    map[string]oidcFlow
	factors  map[string]oidcFactor
}

// This transport is scoped to one administrator-configured provider origin.
// Redirects and oversized responses fail closed, including discovery and JWKS.
type oidcTransport struct {
	base   http.RoundTripper
	origin string
}

func (t oidcTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme+"://"+r.URL.Host != t.origin || r.URL.User != nil {
		return nil, errors.New("OIDC origin not allowed")
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(b) > 1<<20 {
		return nil, errors.New("OIDC response rejected")
	}
	resp.Body = io.NopCloser(strings.NewReader(string(b)))
	return resp, nil
}

// ConfigureOIDC must run before serving requests. No username/email auto-linking.
func (a *App) ConfigureOIDC(ctx context.Context, path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return errors.New("OIDC configuration unavailable")
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 65536 {
		return errors.New("OIDC configuration must be owner-only regular file <=64KiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var c OIDCConfig
	dec := json.NewDecoder(io.LimitReader(f, 65537))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil || dec.Decode(new(any)) != io.EOF {
		return errors.New("invalid OIDC configuration")
	}
	return a.configureOIDC(ctx, c)
}
func (a *App) configureOIDC(ctx context.Context, c OIDCConfig) error {
	return a.configureOIDCTransport(ctx, c, http.DefaultTransport)
}
func (a *App) configureOIDCTransport(ctx context.Context, c OIDCConfig, base http.RoundTripper) error {
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(c.Issuer, "/") || (u.Scheme != "https" && !(c.AllowLoopbackHTTP && u.Scheme == "http" && u.Host == "127.0.0.1:9080")) {
		return errors.New("invalid OIDC issuer")
	}
	if c.ClientID == "" || len(c.ClientID) > 128 || len(c.Subjects) == 0 || len(c.Subjects) > 100 {
		return errors.New("OIDC requires client and explicit subject mappings")
	}
	subjects := map[string]string{}
	for sub, user := range c.Subjects {
		local := a.user(user)
		if sub == "" || len(sub) > 255 || local == nil || local.TOTP == "" {
			return errors.New("OIDC mapping requires an existing TOTP account")
		}
		subjects[sub] = user
	}
	c.Subjects = subjects
	client := &http.Client{Timeout: 10 * time.Second, Transport: oidcTransport{base, u.Scheme + "://" + u.Host}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("OIDC redirects disabled") }}
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return errors.New("OIDC discovery failed")
	}
	var meta struct {
		Authorization string   `json:"authorization_endpoint"`
		Token         string   `json:"token_endpoint"`
		JWKS          string   `json:"jwks_uri"`
		PKCE          []string `json:"code_challenge_methods_supported"`
	}
	if provider.Claims(&meta) != nil {
		return errors.New("invalid OIDC discovery")
	}
	for _, endpoint := range []string{meta.Authorization, meta.Token, meta.JWKS} {
		e, err := url.Parse(endpoint)
		if err != nil || e.Scheme != u.Scheme || e.Host != u.Host || e.User != nil || e.Fragment != "" || e.RawQuery != "" {
			return errors.New("OIDC endpoints must share issuer origin")
		}
	}
	supported := false
	for _, method := range meta.PKCE {
		if method == "S256" {
			supported = true
		}
	}
	if !supported {
		return errors.New("OIDC provider must advertise PKCE S256")
	}
	// Background client context is intentional: key rotation survives startup timeout.
	verifier := provider.VerifierContext(oidc.ClientContext(context.Background(), client), &oidc.Config{ClientID: c.ClientID, SupportedSigningAlgs: []string{oidc.RS256}, Now: a.now})
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	a.oidc = &oidcLogin{config: c, oauth: oauth2.Config{ClientID: c.ClientID, RedirectURL: oidcCallbackURL, Scopes: []string{oidc.ScopeOpenID}, Endpoint: endpoint}, verifier: verifier, client: client, flows: map[string]oidcFlow{}, factors: map[string]oidcFactor{}}
	return nil
}
func oidcCookie(w http.ResponseWriter, name, value string, seconds int, lax bool) {
	mode := http.SameSiteStrictMode
	if lax {
		mode = http.SameSiteLaxMode
	}
	// This pilot serves exclusively on HTTP loopback; production TLS is a separate gate.
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/auth/oidc", HttpOnly: true, SameSite: mode, MaxAge: seconds})
}
func (o *oidcLogin) prune(now time.Time) {
	for k, v := range o.flows {
		if !now.Before(v.Expires) {
			delete(o.flows, k)
		}
	}
	for k, v := range o.factors {
		if !now.Before(v.Expires) {
			delete(o.factors, k)
		}
	}
}
func (a *App) oidcStart(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.oidc == nil {
		fail(w, 404, "not_found")
		return
	}
	if r.Host != "127.0.0.1:8080" {
		fail(w, 400, "use_canonical_host")
		return
	}
	o := a.oidc
	o.prune(a.now())
	if len(o.flows)+len(o.factors) >= 100 {
		fail(w, 429, "try_later")
		return
	}
	state, binding, nonce, verifier := randomHex(), randomHex(), randomHex(), oauth2.GenerateVerifier()
	if old, err := r.Cookie("oidc_flow"); err == nil {
		for k, v := range o.flows {
			if v.Binding == tokenHash(old.Value) {
				delete(o.flows, k)
			}
		}
	}
	o.flows[state] = oidcFlow{tokenHash(binding), nonce, verifier, a.now(), a.now().Add(5 * time.Minute)}
	oidcCookie(w, "oidc_flow", binding, 300, true)
	location := o.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce), oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	send(w, 200, map[string]string{"authorization_url": location})
}
func oidcReject(w http.ResponseWriter, r *http.Request) {
	oidcCookie(w, "oidc_flow", "", -1, true)
	http.Redirect(w, r, "/portal#oidc-error", http.StatusSeeOther)
}
func (a *App) oidcCallback(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	o := a.oidc
	if o == nil {
		a.mu.Unlock()
		fail(w, 404, "not_found")
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	c, ce := r.Cookie("oidc_flow")
	flow, ok := o.flows[q.Get("state")]
	if err != nil || ce != nil || r.Host != "127.0.0.1:8080" || len(q["state"]) != 1 || !ok || !a.now().Before(flow.Expires) || subtle.ConstantTimeCompare([]byte(flow.Binding), []byte(tokenHash(c.Value))) != 1 {
		a.mu.Unlock()
		oidcReject(w, r)
		return
	}
	delete(o.flows, q.Get("state")) // one attempt; exchange errors require a fresh login
	if len(q["code"]) != 1 || q.Get("code") == "" || len(q.Get("code")) > 4096 || len(q["error"]) != 0 || (len(q["iss"]) > 0 && (len(q["iss"]) != 1 || q.Get("iss") != o.config.Issuer)) {
		a.mu.Unlock()
		oidcReject(w, r)
		return
	}
	a.mu.Unlock()
	select {
	case a.loginSlots <- struct{}{}:
		defer func() { <-a.loginSlots }()
	default:
		oidcReject(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(r.Context(), o.client), 15*time.Second)
	defer cancel()
	token, err := o.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		oidcReject(w, r)
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 32768 {
		oidcReject(w, r)
		return
	}
	id, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		oidcReject(w, r)
		return
	}
	var claims struct {
		AZP      string `json:"azp"`
		AuthTime int64  `json:"auth_time"`
	}
	if id.Claims(&claims) != nil {
		oidcReject(w, r)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	user := o.config.Subjects[id.Subject]
	if id.Issuer != o.config.Issuer || id.Subject == "" || user == "" || a.user(user) == nil || !now.Before(flow.Expires) || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(flow.Nonce)) != 1 || id.IssuedAt.IsZero() || id.IssuedAt.After(now.Add(time.Minute)) || claims.AuthTime < flow.Created.Add(-time.Minute).Unix() || claims.AuthTime > now.Add(time.Minute).Unix() || (len(id.Audience) > 1 && claims.AZP == "") || (claims.AZP != "" && claims.AZP != o.config.ClientID) {
		oidcReject(w, r)
		return
	}
	o.prune(now)
	if len(o.factors) >= 100 {
		oidcReject(w, r)
		return
	}
	challenge := randomHex()
	o.factors[tokenHash(challenge)] = oidcFactor{user, now.Add(3 * time.Minute)}
	oidcCookie(w, "oidc_flow", "", -1, true)
	oidcCookie(w, "oidc_factor", challenge, 180, false)
	http.Redirect(w, r, "/portal#oidc-factor", http.StatusSeeOther)
}
func (a *App) oidcConfirm(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &b, "code") {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.oidc == nil {
		fail(w, 404, "not_found")
		return
	}
	c, err := r.Cookie("oidc_factor")
	if err != nil {
		fail(w, 401, "login_failed")
		return
	}
	o := a.oidc
	o.prune(a.now())
	factor, ok := o.factors[tokenHash(c.Value)]
	if !ok {
		fail(w, 401, "login_failed")
		return
	}
	user := a.user(factor.User)
	if user == nil {
		delete(o.factors, tokenHash(c.Value))
		fail(w, 401, "login_failed")
		return
	}
	key := "oidc:" + user.Name
	attempts := []time.Time{}
	for _, t := range a.attempts[key] {
		if a.now().Sub(t) < 15*time.Minute {
			attempts = append(attempts, t)
		}
	}
	a.attempts[key] = attempts
	if len(attempts) >= 10 {
		delete(o.factors, tokenHash(c.Value))
		fail(w, 429, "try_later")
		return
	}
	a.attempts[key] = append(attempts, a.now())
	counter, valid := checkTOTP(*user, b.Code, a.now())
	if !valid {
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
	if a.transaction(func() { user.LastCounter = counter; a.event(user.Name, "login_oidc_totp", "", "") }) != nil {
		fail(w, 503, "storage_unavailable")
		return
	}
	a.attempts[key] = nil
	delete(o.factors, tokenHash(c.Value))
	if old, e := r.Cookie("pilot_session"); e == nil {
		delete(a.sessions, old.Value)
	}
	id := randomHex()
	a.sessions[id] = session{user.Name, a.now().Add(8 * time.Hour), a.now().Add(30 * time.Minute)}
	oidcCookie(w, "oidc_factor", "", -1, false)
	http.SetCookie(w, &http.Cookie{Name: "pilot_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 28800})
	send(w, 200, map[string]string{"username": user.Name})
}
