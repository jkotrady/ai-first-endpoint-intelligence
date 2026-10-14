package pilot

import (
	"crypto/rand"
	"encoding/base32"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Invitations create an isolated workspace, never a grant to the inviter's evidence.
type Invitation struct {
	Hash           string    `json:"hash"`
	Expires        time.Time `json:"expires"`
	Pending        *User     `json:"pending,omitempty"`
	Workspace      string    `json:"workspace,omitempty"`
	PendingExpires time.Time `json:"pending_expires,omitempty"`
	Attempts       int       `json:"attempts"`
}

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

func (a *App) invite(w http.ResponseWriter, r *http.Request, u string) {
	live := []Invitation{}
	for _, i := range a.state.Invitations {
		if a.now().Before(i.Expires) {
			live = append(live, i)
		}
	}
	if len(live) >= 10 || len(a.state.Users) >= 10 {
		fail(w, 409, "pilot_account_limit")
		return
	}
	token := randomHex()
	if a.transaction(func() {
		a.state.Invitations = append(live, Invitation{Hash: tokenHash(token), Expires: a.now().Add(24 * time.Hour)})
		a.event(u, "invitation_created", "", "")
	}) != nil {
		fail(w, 503, "storage_unavailable")
		return
	}
	send(w, 201, map[string]string{"invitation": token, "expires_at": a.now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
}
func (a *App) registrationStart(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Invitation string `json:"invitation"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		Workspace  string `json:"workspace"`
	}
	if !decode(w, r, &b, "invitation", "username", "password", "workspace") {
		return
	}
	b.Workspace = strings.TrimSpace(b.Workspace)
	if len(b.Invitation) != 64 || !usernamePattern.MatchString(b.Username) || len(b.Password) < 14 || len(b.Password) > 256 || len(b.Workspace) < 1 || len(b.Workspace) > 80 {
		fail(w, 400, "invalid_registration")
		return
	}
	// Bounded concurrent PBKDF; only an existing invitation may reach it.
	select {
	case a.loginSlots <- struct{}{}:
		defer func() { <-a.loginSlots }()
	default:
		fail(w, 429, "try_later")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for n := range a.state.Invitations {
		i := &a.state.Invitations[n]
		if i.Hash != tokenHash(b.Invitation) || !a.now().Before(i.Expires) {
			continue
		}
		if len(a.state.Users) >= 10 || a.user(b.Username) != nil {
			fail(w, 409, "account_unavailable")
			return
		}
		if i.Pending != nil && a.now().Before(i.PendingExpires) {
			fail(w, 409, "registration_already_started")
			return
		}
		for _, other := range a.state.Invitations {
			if other.Pending != nil && other.Pending.Name == b.Username && a.now().Before(other.PendingExpires) {
				fail(w, 409, "account_unavailable")
				return
			}
		}
		salt := randomHex()
		hash, err := passwordHash(b.Password, salt)
		if err != nil {
			fail(w, 500, "registration_failed")
			return
		}
		var secretBytes [20]byte
		if _, err = rand.Read(secretBytes[:]); err != nil {
			fail(w, 500, "registration_failed")
			return
		}
		secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes[:])
		if a.transaction(func() {
			i.Pending = &User{Name: b.Username, Salt: salt, Hash: hash, TOTP: secret, LastCounter: -1, Customers: []string{randomHex()}}
			i.Workspace = b.Workspace
			i.PendingExpires = a.now().Add(10 * time.Minute)
			i.Attempts = 0
		}) != nil {
			fail(w, 503, "storage_unavailable")
			return
		}
		send(w, 201, map[string]string{"secret": secret, "account": b.Username, "issuer": "AI-first Forensics", "expires_at": i.PendingExpires.UTC().Format(time.RFC3339)})
		return
	}
	fail(w, 403, "invitation_invalid_or_expired")
}
func (a *App) registrationConfirm(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Invitation string `json:"invitation"`
		Code       string `json:"code"`
	}
	if !decode(w, r, &b, "invitation", "code") {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for n := range a.state.Invitations {
		i := a.state.Invitations[n]
		if len(b.Invitation) != 64 || i.Hash != tokenHash(b.Invitation) || !a.now().Before(i.Expires) || i.Pending == nil || !a.now().Before(i.PendingExpires) {
			continue
		}
		counter, ok := checkTOTP(*i.Pending, b.Code, a.now())
		if !ok {
			if a.transaction(func() {
				a.state.Invitations[n].Attempts++
				if a.state.Invitations[n].Attempts >= 5 {
					a.state.Invitations = append(a.state.Invitations[:n], a.state.Invitations[n+1:]...)
				}
			}) != nil {
				fail(w, 503, "storage_unavailable")
				return
			}
			fail(w, 401, "verification_failed")
			return
		}
		if a.user(i.Pending.Name) != nil || len(a.state.Users) >= 10 {
			fail(w, 409, "account_unavailable")
			return
		}
		if len(a.sessions) >= 100 {
			fail(w, 429, "session_limit")
			return
		}
		u := *i.Pending
		u.LastCounter = counter
		if a.transaction(func() {
			a.state.Users = append(a.state.Users, u)
			a.state.Customers = append(a.state.Customers, Customer{u.Customers[0], i.Workspace})
			a.state.Invitations = append(a.state.Invitations[:n], a.state.Invitations[n+1:]...)
			a.event(u.Name, "registration_completed", u.Customers[0], "")
		}) != nil {
			fail(w, 503, "storage_unavailable")
			return
		}
		id := randomHex()
		a.sessions[id] = session{u.Name, a.now().Add(8 * time.Hour), a.now().Add(30 * time.Minute)}
		http.SetCookie(w, &http.Cookie{Name: "pilot_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 28800})
		send(w, 201, map[string]string{"username": u.Name})
		return
	}
	fail(w, 403, "invitation_invalid_or_expired")
}
