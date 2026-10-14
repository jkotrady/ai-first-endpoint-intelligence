package pilot

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type User struct {
	Name        string   `json:"name"`
	Salt        string   `json:"salt"`
	Hash        string   `json:"hash"`
	TOTP        string   `json:"totp"`
	LastCounter int64    `json:"last_counter"`
	Customers   []string `json:"customers"`
}
type Customer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Device struct {
	ID                string    `json:"id"`
	CustomerID        string    `json:"customer_id"`
	Label             string    `json:"label"`
	CredentialHash    string    `json:"credential_hash,omitempty"`
	Revoked           bool      `json:"revoked"`
	Hostname          string    `json:"hostname"`
	OS                string    `json:"os"`
	IPv4              []string  `json:"ipv4"`
	LastSeen          time.Time `json:"last_seen"`
	SourceFingerprint string    `json:"reported_source_fingerprint,omitempty"`
	Capabilities      []string  `json:"capabilities"`
}
type Job struct {
	ID          string          `json:"id"`
	CustomerID  string          `json:"customer_id"`
	DeviceID    string          `json:"device_id"`
	Collector   string          `json:"collector_id"`
	AgentSource string          `json:"agent_source,omitempty"`
	Nonce       string          `json:"nonce,omitempty"`
	Status      string          `json:"status"`
	Created     time.Time       `json:"created_at"`
	Expires     time.Time       `json:"expires_at"`
	Result      json.RawMessage `json:"result,omitempty"`
	ResultHash  string          `json:"result_hash,omitempty"`
	CreatedBy   string          `json:"created_by"`
}
type Event struct {
	At         time.Time `json:"at"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	CustomerID string    `json:"customer_id"`
	ObjectID   string    `json:"object_id"`
}
type State struct {
	Version     int          `json:"version"`
	Invitations []Invitation `json:"invitations,omitempty"`
	Users       []User       `json:"users"`
	Customers   []Customer   `json:"customers"`
	Devices     []Device     `json:"devices"`
	Jobs        []Job        `json:"jobs"`
	Audit       []Event      `json:"audit"`
}
type session struct {
	User    string
	Expires time.Time
	Idle    time.Time
}
type App struct {
	oidc        *oidcLogin
	aiActive    int
	aiTransport http.RoundTripper
	mu          sync.Mutex
	state       State
	dir         string
	sessions    map[string]session
	attempts    map[string][]time.Time
	now         func() time.Time
	loginSlots  chan struct{}
}

func randomHex() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func tokenHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func passwordHash(password, salt string) (string, error) {
	b, e := pbkdf2.Key(sha256.New, password, []byte(salt), 600000, 32)
	return hex.EncodeToString(b), e
}
func totp(secret string, counter int64) string {
	key, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e != nil {
		return ""
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(counter))
	h := hmac.New(sha1.New, key)
	h.Write(b)
	sum := h.Sum(nil)
	o := sum[len(sum)-1] & 15
	n := binary.BigEndian.Uint32(sum[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1000000)
}
func checkTOTP(u User, code string, now time.Time) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for d := int64(-1); d <= 1; d++ {
		c := now.Unix()/30 + d
		if c > u.LastCounter && subtle.ConstantTimeCompare([]byte(totp(u.TOTP, c)), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}
func privateWrite(path string, b []byte) error {
	f, e := os.OpenFile(path+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path + ".tmp")
		}
	}()
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(path+".tmp", path); e != nil {
		return e
	}
	ok = true
	d, e := os.Open(filepath.Dir(path))
	if e == nil {
		defer d.Close()
		e = d.Sync()
	}
	return e
}
func Open(dir string) (*App, error) {
	a := &App{dir: dir, sessions: map[string]session{}, attempts: map[string][]time.Time{}, now: time.Now, loginSlots: make(chan struct{}, 2)}
	p := filepath.Join(dir, "state.json")
	st, e := os.Stat(p)
	if e != nil {
		return nil, e
	}
	if st.Size() > 32<<20 || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state must be <=32MiB and owner-only")
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(b, &a.state); e != nil {
		return nil, e
	}
	if a.state.Version != 1 {
		return nil, errors.New("unsupported state version")
	}
	return a, nil
}
func (a *App) save() error {
	b, e := json.MarshalIndent(a.state, "", "  ")
	if e != nil {
		return e
	}
	if len(b) > 32<<20 {
		return errors.New("state capacity reached")
	}
	return privateWrite(filepath.Join(a.dir, "state.json"), b)
}
func (a *App) transaction(fn func()) error {
	before, _ := json.Marshal(a.state)
	fn()
	if e := a.save(); e != nil {
		var restored State
		_ = json.Unmarshal(before, &restored)
		a.state = restored
		return e
	}
	return nil
}
func (a *App) event(actor, action, customer, id string) {
	a.state.Audit = append(a.state.Audit, Event{a.now().UTC(), actor, action, customer, id})
	if len(a.state.Audit) > 2000 {
		a.state.Audit = a.state.Audit[len(a.state.Audit)-2000:]
	}
}
func (a *App) user(name string) *User {
	for i := range a.state.Users {
		if a.state.Users[i].Name == name {
			return &a.state.Users[i]
		}
	}
	return nil
}
func (a *App) allowed(name, customer string) bool {
	u := a.user(name)
	if u == nil {
		return false
	}
	for _, c := range u.Customers {
		if c == customer {
			return true
		}
	}
	return false
}
func Init(dir, username string) error {
	if strings.TrimSpace(username) == "" || len(username) > 128 {
		return errors.New("invalid username")
	}
	if _, e := os.Stat(dir); e == nil {
		return errors.New("initialization requires a new directory")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	var p [24]byte
	var s [20]byte
	rand.Read(p[:])
	rand.Read(s[:])
	password := base64.RawURLEncoding.EncodeToString(p[:])
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(s[:])
	salt := randomHex()
	hash, e := passwordHash(password, salt)
	if e != nil {
		return e
	}
	a := &App{dir: dir, state: State{Version: 1, Users: []User{{Name: username, Salt: salt, Hash: hash, TOTP: secret, LastCounter: -1, Customers: []string{"lab"}}}, Customers: []Customer{{"lab", "Interné laboratórium"}}, Devices: []Device{}, Jobs: []Job{}, Audit: []Event{}}}
	if e = a.save(); e != nil {
		return e
	}
	if e = createCertificates(dir); e != nil {
		return e
	}
	return privateWrite(filepath.Join(dir, "first-login.txt"), []byte("LOCAL PILOT ONLY\nUsername: "+username+"\nPassword: "+password+"\nTOTP secret (RFC6238 SHA1, 6 digits, 30 seconds): "+secret+"\nOpen http://127.0.0.1:8080/setup for the Slovak step-by-step guide. Add the TOTP secret above as a time-based account in your authenticator (SHA1, 6 digits, 30 seconds). Enter the current 6-digit code at /portal. Hash and salt are NOT enrollment secrets. Store these credentials privately.\n"))
}
