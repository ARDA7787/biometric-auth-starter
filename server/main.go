package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Credentials are never stored in plaintext: only the random-token hashes.
// The server's master admin token lives solely in the process environment.
type Device struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	PublicKeyB64 string    `json:"public_key_b64"` // ANSI X9.63, uncompressed P-256
	TokenHash    string    `json:"token_hash"`
	CreatedAt    time.Time `json:"created_at"`
}
type Pairing struct {
	TokenHash string    `json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Challenge struct {
	V         int       `json:"v"`
	RequestID string    `json:"request_id"`
	DeviceID  string    `json:"device_id"`
	Action    string    `json:"action"`
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Request struct {
	ID           string     `json:"id"`
	DeviceID     string     `json:"device_id"`
	Action       string     `json:"action"`
	PayloadB64   string     `json:"payload_b64"`
	Status       string     `json:"status"` // pending, approved, denied, consumed; expiry is derived
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	SignatureB64 string     `json:"signature_b64,omitempty"`
	ApprovedAt   *time.Time `json:"approved_at,omitempty"`
	ConsumedAt   *time.Time `json:"consumed_at,omitempty"`
}
type Database struct {
	Devices  map[string]Device  `json:"devices"`
	Pairings map[string]Pairing `json:"pairings"`
	Requests map[string]Request `json:"requests"`
}
type Store struct {
	mu   sync.Mutex
	path string
	data Database
}

func emptyDB() Database {
	return Database{map[string]Device{}, map[string]Pairing{}, map[string]Request{}}
}
func openStore(path string) (*Store, error) {
	s := &Store{path: path, data: emptyDB()}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	if s.data.Devices == nil || s.data.Pairings == nil || s.data.Requests == nil {
		return nil, errors.New("state file is incomplete")
	}
	return s, nil
}
func (s *Store) view(fn func(Database) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(s.data)
}
func (s *Store) update(fn func(*Database) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := emptyDB()
	for k, v := range s.data.Devices {
		next.Devices[k] = v
	}
	for k, v := range s.data.Pairings {
		next.Pairings[k] = v
	}
	for k, v := range s.data.Requests {
		next.Requests[k] = v
	}
	if err := fn(&next); err != nil {
		return err
	}
	if err := s.persist(next); err != nil {
		return fmt.Errorf("persist state: %w", err)
	}
	s.data = next
	return nil
}
func (s *Store) persist(data Database) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".bioauth-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	// Sync the containing directory for durable rename on supported filesystems.
	d, err := os.Open(dir)
	if err == nil {
		defer d.Close()
		_ = d.Sync()
	}
	return nil
}

type App struct {
	store      *Store
	adminToken string
	now        func() time.Time
}

func (a *App) clock() time.Time { return a.now().UTC() }
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func tokenHash(s string) string    { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }
func secureEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}
func reply(w http.ResponseWriter, code int, x any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(x)
}
func failure(w http.ResponseWriter, code int, msg string) {
	reply(w, code, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, into any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(into); err != nil {
		failure(w, 400, "invalid JSON body")
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		failure(w, 400, "expected exactly one JSON object")
		return false
	}
	return true
}
func (a *App) admin(w http.ResponseWriter, r *http.Request) bool {
	if !secureEqual(bearer(r), a.adminToken) {
		failure(w, 401, "unauthorized")
		return false
	}
	return true
}
func (a *App) device(w http.ResponseWriter, r *http.Request, id string) (Device, bool) {
	var d Device
	ok := false
	_ = a.store.view(func(db Database) error { d, ok = db.Devices[id]; return nil })
	tok := bearer(r)
	if !ok || tok == "" || !secureEqual(tokenHash(tok), d.TokenHash) {
		failure(w, 401, "unauthorized device")
		return Device{}, false
	}
	return d, true
}
func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, map[string]bool{"ok": true}) })
	mux.HandleFunc("POST /v1/pairings", a.pair)
	mux.HandleFunc("POST /v1/devices", a.enroll)
	mux.HandleFunc("GET /v1/devices", a.listDevices)
	mux.HandleFunc("POST /v1/devices/{id}/revoke", a.revoke)
	mux.HandleFunc("GET /v1/devices/{id}/requests", a.pending)
	mux.HandleFunc("POST /v1/requests", a.createRequest)
	mux.HandleFunc("GET /v1/requests/{id}", a.requestStatus)
	mux.HandleFunc("POST /v1/requests/{id}/consume", a.consume)
	mux.HandleFunc("POST /v1/requests/{id}/approve", a.approve)
	mux.HandleFunc("POST /v1/requests/{id}/deny", a.deny)
	return mux
}
func (a *App) pair(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	token := randHex(24) // 192 bits: unguessable, one-time, 5-minute pairing capability
	expiration := a.clock().Add(5 * time.Minute)
	if err := a.store.update(func(db *Database) error {
		for k, v := range db.Pairings {
			if !v.ExpiresAt.After(a.clock()) {
				delete(db.Pairings, k)
			}
		}
		db.Pairings[tokenHash(token)] = Pairing{TokenHash: tokenHash(token), ExpiresAt: expiration}
		return nil
	}); err != nil {
		failure(w, 500, "storage error")
		return
	}
	reply(w, 201, map[string]any{"pairing_token": token, "expires_at": expiration})
}
func parsePublicKey(encoded string) (*ecdsa.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(b) != 65 {
		return nil, errors.New("expected base64 ANSI X9.63 P-256 public key")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), b)
	if x == nil {
		return nil, errors.New("invalid P-256 curve point")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
func (a *App) enroll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PairingToken string `json:"pairing_token"`
		Name         string `json:"name"`
		PublicKeyB64 string `json:"public_key_b64"`
	}
	if !decode(w, r, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if len(body.Name) == 0 || len(body.Name) > 80 {
		failure(w, 400, "name must have 1-80 characters")
		return
	}
	if _, err := parsePublicKey(body.PublicKeyB64); err != nil {
		failure(w, 400, err.Error())
		return
	}
	if len(body.PairingToken) != 48 {
		failure(w, 403, "invalid or expired pairing token")
		return
	}
	deviceID := randHex(16)
	deviceToken := randHex(32)
	now := a.clock()
	invalid := errors.New("invalid or expired pairing token")
	err := a.store.update(func(db *Database) error {
		p, found := db.Pairings[tokenHash(body.PairingToken)]
		if !found || !p.ExpiresAt.After(now) {
			return invalid
		}
		delete(db.Pairings, p.TokenHash)
		db.Devices[deviceID] = Device{ID: deviceID, Name: body.Name, PublicKeyB64: body.PublicKeyB64, TokenHash: tokenHash(deviceToken), CreatedAt: now}
		return nil
	})
	if errors.Is(err, invalid) {
		failure(w, 403, invalid.Error())
		return
	}
	if err != nil {
		failure(w, 500, "storage error")
		return
	}
	reply(w, 201, map[string]string{"device_id": deviceID, "device_token": deviceToken})
}
func (a *App) listDevices(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	result := []map[string]any{}
	_ = a.store.view(func(db Database) error {
		for _, d := range db.Devices {
			result = append(result, map[string]any{"device_id": d.ID, "name": d.Name, "created_at": d.CreatedAt})
		}
		return nil
	})
	reply(w, 200, map[string]any{"devices": result})
}
func (a *App) revoke(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	id := r.PathValue("id")
	missing := errors.New("device not found")
	err := a.store.update(func(db *Database) error {
		if _, ok := db.Devices[id]; !ok {
			return missing
		}
		delete(db.Devices, id)
		for rid, req := range db.Requests {
			// A verified but not yet consumed approval MUST also be revoked.
			if req.DeviceID == id && (req.Status == "pending" || req.Status == "approved") {
				req.Status = "denied"
				db.Requests[rid] = req
			}
		}
		return nil
	})
	if errors.Is(err, missing) {
		failure(w, 404, missing.Error())
		return
	}
	if err != nil {
		failure(w, 500, "storage error")
		return
	}
	reply(w, 200, map[string]bool{"revoked": true})
}
func (a *App) createRequest(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var body struct {
		DeviceID string `json:"device_id"`
		Action   string `json:"action"`
	}
	if !decode(w, r, &body) {
		return
	}
	body.Action = strings.TrimSpace(body.Action)
	if len(body.Action) == 0 || len(body.Action) > 200 {
		failure(w, 400, "action must have 1-200 characters")
		return
	}
	now := a.clock()
	id := randHex(16)
	expires := now.Add(60 * time.Second)
	challenge := Challenge{V: 1, RequestID: id, DeviceID: body.DeviceID, Action: body.Action, Nonce: randHex(32), ExpiresAt: expires}
	payload, err := json.Marshal(challenge)
	if err != nil {
		failure(w, 500, "encoding error")
		return
	}
	req := Request{ID: id, DeviceID: body.DeviceID, Action: body.Action, PayloadB64: base64.StdEncoding.EncodeToString(payload), Status: "pending", CreatedAt: now, ExpiresAt: expires}
	invalid := errors.New("device not found")
	err = a.store.update(func(db *Database) error {
		if _, ok := db.Devices[body.DeviceID]; !ok {
			return invalid
		}
		db.Requests[id] = req
		return nil
	})
	if errors.Is(err, invalid) {
		failure(w, 404, invalid.Error())
		return
	}
	if err != nil {
		failure(w, 500, "storage error")
		return
	}
	reply(w, 201, requestResult(req, a.clock()))
}
func effectiveStatus(req Request, now time.Time) string {
	if req.Status == "pending" && !now.Before(req.ExpiresAt) {
		return "expired"
	}
	// Signed approvals also expire if the relying server never consumes them.
	if req.Status == "approved" && (req.ApprovedAt == nil || !now.Before(req.ApprovedAt.Add(60*time.Second))) {
		return "approval_expired"
	}
	return req.Status
}
func requestResult(req Request, now time.Time) map[string]any {
	status := effectiveStatus(req, now)
	return map[string]any{"request_id": req.ID, "device_id": req.DeviceID, "action": req.Action, "status": status, "authorized": status == "approved", "expires_at": req.ExpiresAt}
}
func (a *App) requestStatus(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var req Request
	found := false
	_ = a.store.view(func(db Database) error { req, found = db.Requests[r.PathValue("id")]; return nil })
	if !found {
		failure(w, 404, "request not found")
		return
	}
	reply(w, 200, requestResult(req, a.clock()))
}
func (a *App) pending(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := a.device(w, r, id); !ok {
		return
	}
	now := a.clock()
	result := []map[string]any{}
	_ = a.store.view(func(db Database) error {
		for _, req := range db.Requests {
			if req.DeviceID == id && effectiveStatus(req, now) == "pending" {
				result = append(result, map[string]any{"request_id": req.ID, "payload_b64": req.PayloadB64})
			}
		}
		return nil
	})
	reply(w, 200, map[string]any{"requests": result})
}
func (a *App) approve(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceID     string `json:"device_id"`
		SignatureB64 string `json:"signature_b64"`
	}
	if !decode(w, r, &body) {
		return
	}
	device, ok := a.device(w, r, body.DeviceID)
	if !ok {
		return
	}
	signature, err := base64.StdEncoding.DecodeString(body.SignatureB64)
	if err != nil || len(signature) > 128 || len(signature) < 8 {
		failure(w, 400, "invalid signature encoding")
		return
	}
	pub, err := parsePublicKey(device.PublicKeyB64)
	if err != nil {
		failure(w, 500, "stored public key invalid")
		return
	}
	id := r.PathValue("id")
	invalid := errors.New("request missing, expired, completed or belongs to another device")
	badSignature := errors.New("invalid biometric signature")
	var result Request
	err = a.store.update(func(db *Database) error {
		req, found := db.Requests[id]
		if !found || req.DeviceID != body.DeviceID || effectiveStatus(req, a.clock()) != "pending" {
			return invalid
		}
		payload, e := base64.StdEncoding.DecodeString(req.PayloadB64)
		if e != nil {
			return errors.New("stored challenge corrupt")
		}
		digest := sha256.Sum256(payload)
		if !ecdsa.VerifyASN1(pub, digest[:], signature) {
			return badSignature
		}
		req.Status = "approved"
		approvedAt := a.clock()
		req.ApprovedAt = &approvedAt
		req.SignatureB64 = body.SignatureB64
		db.Requests[id] = req
		result = req
		return nil
	})
	if errors.Is(err, invalid) {
		failure(w, 409, invalid.Error())
		return
	}
	if errors.Is(err, badSignature) {
		failure(w, 403, badSignature.Error())
		return
	}
	if err != nil {
		failure(w, 500, "storage error")
		return
	}
	reply(w, 200, requestResult(result, a.clock()))
}

// This is the final authorization gate for a business action. Read-only GET
// is for monitoring; consumption atomically transfers permission to the
// caller at most once. Callers must execute their own operation idempotently.
func (a *App) consume(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	id := r.PathValue("id")
	invalid := errors.New("authorization not approved, expired, or already consumed")
	var result Request
	err := a.store.update(func(db *Database) error {
		req, found := db.Requests[id]
		if !found || effectiveStatus(req, a.clock()) != "approved" {
			return invalid
		}
		consumedAt := a.clock()
		req.ConsumedAt = &consumedAt
		req.Status = "consumed"
		db.Requests[id] = req
		result = req
		return nil
	})
	if errors.Is(err, invalid) {
		failure(w, 409, invalid.Error())
		return
	}
	if err != nil {
		failure(w, 500, "storage error")
		return
	}
	reply(w, 200, map[string]any{"request_id": result.ID, "authorized": true, "status": "consumed"})
}
func (a *App) deny(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &body) {
		return
	}
	if _, ok := a.device(w, r, body.DeviceID); !ok {
		return
	}
	invalid := errors.New("request missing, expired, completed or belongs to another device")
	var result Request
	err := a.store.update(func(db *Database) error {
		req, found := db.Requests[r.PathValue("id")]
		if !found || req.DeviceID != body.DeviceID || effectiveStatus(req, a.clock()) != "pending" {
			return invalid
		}
		req.Status = "denied"
		db.Requests[req.ID] = req
		result = req
		return nil
	})
	if errors.Is(err, invalid) {
		failure(w, 409, invalid.Error())
		return
	}
	if err != nil {
		failure(w, 500, "storage error")
		return
	}
	reply(w, 200, requestResult(result, a.clock()))
}
func main() {
	token := os.Getenv("BIOAUTH_ADMIN_TOKEN")
	if len(token) < 32 {
		log.Fatal("Set BIOAUTH_ADMIN_TOKEN to a random secret of at least 32 characters (example: openssl rand -hex 32)")
	}
	path := os.Getenv("BIOAUTH_DATA")
	if path == "" {
		path = "./private/state.json"
	}
	store, err := openStore(path)
	if err != nil {
		log.Fatal(err)
	}
	app := &App{store: store, adminToken: token, now: time.Now}
	addr := "127.0.0.1:8080"
	log.Printf("BioAuth listening at http://%s (put an HTTPS reverse proxy in front)", addr)
	server := http.Server{Addr: addr, Handler: app.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Fatal(server.ListenAndServe())
}
