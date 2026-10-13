package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func testApp(t *testing.T) (*App, *time.Time) {
	t.Helper()
	store, err := openStore(filepath.Join(t.TempDir(), "private", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	return &App{store: store, adminToken: "12345678901234567890123456789012", now: func() time.Time { return now }}, &now
}
func call(t *testing.T, a *App, method, path, token string, body any, code int) map[string]any {
	t.Helper()
	var b []byte
	if body != nil {
		var err error
		b, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != code {
		t.Fatalf("%s %s: got HTTP %d expected %d: %s", method, path, w.Code, code, w.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func register(t *testing.T, a *App) (*ecdsa.PrivateKey, string, string, string) {
	t.Helper()
	admin := a.adminToken
	pair := call(t, a, "POST", "/v1/pairings", admin, nil, 201)["pairing_token"].(string)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	dev := call(t, a, "POST", "/v1/devices", "", map[string]string{"name": "test iPhone", "pairing_token": pair, "public_key_b64": base64.StdEncoding.EncodeToString(public)}, 201)
	call(t, a, "POST", "/v1/devices", "", map[string]string{"name": "attacker", "pairing_token": pair, "public_key_b64": base64.StdEncoding.EncodeToString(public)}, 403)
	return key, dev["device_id"].(string), dev["device_token"].(string), pair
}
func TestApproveRequiresValidSignatureAndIsOneTime(t *testing.T) {
	a, _ := testApp(t)
	key, id, token, _ := register(t, a)
	c := call(t, a, "POST", "/v1/requests", a.adminToken, map[string]string{"device_id": id, "action": "Approve $10 to demo merchant"}, 201)
	rid := c["request_id"].(string)
	if c["authorized"] != false {
		t.Fatal("prematurely authorized")
	}
	pending := call(t, a, "GET", "/v1/devices/"+id+"/requests", token, nil, 200)
	items := pending["requests"].([]any)
	if len(items) != 1 {
		t.Fatalf("pending count %d", len(items))
	}
	b64 := items[0].(map[string]any)["payload_b64"].(string)
	payload, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	invalid := base64.StdEncoding.EncodeToString([]byte("not-a-real-ecdsa-signature"))
	call(t, a, "POST", "/v1/requests/"+rid+"/approve", token, map[string]string{"device_id": id, "signature_b64": invalid}, 403)
	call(t, a, "POST", "/v1/requests/"+rid+"/approve", "wrong", map[string]string{"device_id": id, "signature_b64": base64.StdEncoding.EncodeToString(sig)}, 401)
	result := call(t, a, "POST", "/v1/requests/"+rid+"/approve", token, map[string]string{"device_id": id, "signature_b64": base64.StdEncoding.EncodeToString(sig)}, 200)
	if result["authorized"] != true || result["status"] != "approved" {
		t.Fatal(result)
	}
	call(t, a, "POST", "/v1/requests/"+rid+"/approve", token, map[string]string{"device_id": id, "signature_b64": base64.StdEncoding.EncodeToString(sig)}, 409)
	result = call(t, a, "GET", "/v1/requests/"+rid, a.adminToken, nil, 200)
	if result["authorized"] != true {
		t.Fatal(result)
	}
	// Durable across process restart.
	reopened, err := openStore(a.store.path)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &App{store: reopened, adminToken: a.adminToken, now: a.now}
	result = call(t, restarted, "GET", "/v1/requests/"+rid, a.adminToken, nil, 200)
	if result["authorized"] != true {
		t.Fatal(result)
	}
	consumed := call(t, restarted, "POST", "/v1/requests/"+rid+"/consume", a.adminToken, nil, 200)
	if consumed["authorized"] != true || consumed["status"] != "consumed" {
		t.Fatal(consumed)
	}
	call(t, restarted, "POST", "/v1/requests/"+rid+"/consume", a.adminToken, nil, 409)
	final := call(t, restarted, "GET", "/v1/requests/"+rid, a.adminToken, nil, 200)
	if final["authorized"] != false || final["status"] != "consumed" {
		t.Fatal(final)
	}
}
func TestExpiryDenyAndRevocation(t *testing.T) {
	a, now := testApp(t)
	_, id, token, _ := register(t, a)
	c := call(t, a, "POST", "/v1/requests", a.adminToken, map[string]string{"device_id": id, "action": "Demo login"}, 201)
	rid := c["request_id"].(string)
	*now = now.Add(61 * time.Second)
	result := call(t, a, "GET", "/v1/requests/"+rid, a.adminToken, nil, 200)
	if result["status"] != "expired" || result["authorized"] != false {
		t.Fatal(result)
	}
	c = call(t, a, "POST", "/v1/requests", a.adminToken, map[string]string{"device_id": id, "action": "Demo login 2"}, 201)
	rid = c["request_id"].(string)
	result = call(t, a, "POST", "/v1/requests/"+rid+"/deny", token, map[string]string{"device_id": id}, 200)
	if result["status"] != "denied" || result["authorized"] != false {
		t.Fatal(result)
	}
	call(t, a, "POST", "/v1/devices/"+id+"/revoke", a.adminToken, nil, 200)
	call(t, a, "GET", "/v1/devices/"+id+"/requests", token, nil, 401)
}
func TestNoAdminReadWithoutSecret(t *testing.T) {
	a, _ := testApp(t)
	call(t, a, "GET", "/v1/devices", "", nil, 401)
	call(t, a, "POST", "/v1/requests", "", map[string]string{"device_id": "x", "action": "y"}, 401)
}

func TestRevocationCancelsEvenSignedButUnconsumedApproval(t *testing.T) {
	a, _ := testApp(t)
	key, id, token, _ := register(t, a)
	created := call(t, a, "POST", "/v1/requests", a.adminToken, map[string]string{"device_id": id, "action": "Sensitive test operation"}, 201)
	rid := created["request_id"].(string)
	pending := call(t, a, "GET", "/v1/devices/"+id+"/requests", token, nil, 200)
	payload64 := pending["requests"].([]any)[0].(map[string]any)["payload_b64"].(string)
	payload, err := base64.StdEncoding.DecodeString(payload64)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	call(t, a, "POST", "/v1/requests/"+rid+"/approve", token, map[string]string{"device_id": id, "signature_b64": base64.StdEncoding.EncodeToString(signature)}, 200)
	call(t, a, "POST", "/v1/devices/"+id+"/revoke", a.adminToken, nil, 200)
	call(t, a, "POST", "/v1/requests/"+rid+"/consume", a.adminToken, nil, 409)
	result := call(t, a, "GET", "/v1/requests/"+rid, a.adminToken, nil, 200)
	if result["authorized"] != false {
		t.Fatal(result)
	}
}

func TestApprovedRequestCanExpireBeforeRedemption(t *testing.T) {
	a, now := testApp(t)
	key, id, token, _ := register(t, a)
	created := call(t, a, "POST", "/v1/requests", a.adminToken, map[string]string{"device_id": id, "action": "Test redemption deadline"}, 201)
	rid := created["request_id"].(string)
	pending := call(t, a, "GET", "/v1/devices/"+id+"/requests", token, nil, 200)
	payload64 := pending["requests"].([]any)[0].(map[string]any)["payload_b64"].(string)
	payload, err := base64.StdEncoding.DecodeString(payload64)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	call(t, a, "POST", "/v1/requests/"+rid+"/approve", token, map[string]string{"device_id": id, "signature_b64": base64.StdEncoding.EncodeToString(signature)}, 200)
	*now = now.Add(61 * time.Second)
	call(t, a, "POST", "/v1/requests/"+rid+"/consume", a.adminToken, nil, 409)
	result := call(t, a, "GET", "/v1/requests/"+rid, a.adminToken, nil, 200)
	if result["status"] != "approval_expired" || result["authorized"] != false {
		t.Fatal(result)
	}
}

// Prevent go test from silently not testing response JSON.
var _ = http.MethodGet
