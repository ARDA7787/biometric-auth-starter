# BioAuth — iPhone biometric approval, verified by a Go server

A native SwiftUI iPhone prototype and a dependency-free Go 1.23 server. The iPhone does **not** send a trusted boolean. Instead, it produces an ECDSA P-256 signature using a **Secure Enclave private key whose use is gated by Face ID or Touch ID**. The server checks that signature over an expiring challenge it created. No images, face templates, or fingerprints ever leave the device.

> Status: The Go backend and its automated tests run successfully (including under `go test -race`). All Swift source files passed Swift syntax parsing. **This environment cannot run Xcode or test the iOS hardware APIs; install/build on a physical iPhone to finish validation.** This is a security-minded *starter*, not a production-ready payment authenticator.

## Protocol

```text
Admin / relying service                  Go backend                   iPhone
      |                                    |                         |
      | POST /v1/pairings                  |                         |
      |<--- one-time random pairing token  |                         |
      |                                    |    User enters token + HTTPS URL
      |                                    |<--- P-256 public key (X9.63)
      |                                    |---> device ID + token   |
      |                                    |                         |
      | POST /v1/requests                  |                         |
      | (device ID + readable action)      |                         |
      |<--- request ID, pending            |                         |
      |                                    |<--- GET pending (3 s)   |
      |                                    |---> signed payload      |
      |                                    |      display action     |
      |                                    |      prompt Face ID     |
      |                                    |      Secure Enclave     |
      |                                    |<--- ECDSA signature     |
      |                                    | verify signature/nonce |
      | GET /v1/requests/{id}              | enforce 60 s deadline  |
      |<--- approved, authorized: true     |                         |
      | POST /v1/requests/{id}/consume     |                         |
      |<--- authorized: true (ONCE)        |                         |
      | [only now perform business action] |                         |
```

A reject button sends `denied` / `authorized:false`. This **does not prove failed biometrics**—it is an authenticated device-level rejection. No biometric or invalid signature can ever cause `authorized:true`.

## Requirements

- Mac with **Xcode 15+** and a physical iPhone with **iOS 17+**, a passcode, and enrolled Face ID or Touch ID.
- Go **1.23+** on your Mac (the backend can later run on Linux).
- A **publicly trusted HTTPS endpoint** accessible from your iPhone. Easiest *development-only* example below: `ngrok http 8080`.
- `curl` and `openssl`, included with macOS. `jq` is optional for JSON readability.
- No Python, CocoaPods, Swift packages, database driver, or third-party Go library.

## Step 1: Start Go

Open Terminal **A**:

```bash
cd biometric-auth-starter/server
export BIOAUTH_ADMIN_TOKEN="$(openssl rand -hex 32)"
printf '\nSAVE THIS SECRET FOR TERMINAL B:\n%s\n\n' "$BIOAUTH_ADMIN_TOKEN"
go run .
```

The backend binds to `127.0.0.1:8080`, **not the public network**. It generates a durable `server/private/state.json` file with filesystem permissions `0600` (also ignore this file in Git). Keep the admin secret private. When restarting the Go backend, **reuse the same secret**; otherwise existing clients will not be able to make administrative calls with the old secret. The admin secret is not stored in the state file.

Optional health check in another shell:

```bash
curl -fsS http://127.0.0.1:8080/healthz
```

## Step 2: Make an HTTPS endpoint for the iPhone

Use a **development-only** tunnel as an easy way to avoid iOS blocking insecure HTTP:

```bash
# Set up ngrok using its official installation/login instructions first.
ngrok http 8080
```

Copy the generated `https://....ngrok-free.app` URL. Enter this full **HTTPS** URL in the iPhone app. ngrok terminates TLS; it is trusted with your application traffic. For stronger privacy or production, use your own trusted TLS reverse proxy and domain instead, or private HTTPS service reachable through your VPN. **Never disable certificate validation or add a blanket ATS exception.** The app rejects `http://`.

## Step 3: Build the iPhone app

1. Open `ios/BioAuth/BioAuth.xcodeproj` in Xcode on your Mac.
2. In the BioAuth target, open **Signing & Capabilities**, select your **Apple developer team**, and change the example bundle identifier to something you own (such as `com.yourname.bioauth`).
3. Select your connected **physical iPhone** as the run target. Enable Developer Mode if Xcode asks. Run the app.
4. Face ID / Touch ID must already be set up in iOS Settings, and a device passcode must be configured. **The iOS Simulator does not provide real Secure Enclave validation.**

Xcode's generated `Info.plist` includes the `NSFaceIDUsageDescription` value defined by the project's build settings. No cloud identity service is required.

## Step 4: Pair the device

Open Terminal **B**, set the *same* admin secret printed in Terminal A, and create a one-time pairing token:

```bash
export BIOAUTH_ADMIN_TOKEN='PASTE_SECRET_FROM_TERMINAL_A'

curl -fsS -X POST 'http://127.0.0.1:8080/v1/pairings' \
  -H "Authorization: Bearer $BIOAUTH_ADMIN_TOKEN"
```

Copy `pairing_token` from the JSON response and paste it into the iPhone app, alongside the HTTPS URL from Step 2 and a device name. Tap **Pair with Secure Enclave**.

The pairing token has **192 random bits**, is **single use**, and expires after **5 minutes**. The iPhone sends only its **public key** to enroll; the private key is generated inside that iPhone's Secure Enclave and cannot be exported. On success, the backend returns a device ID and separate device-read token that the iPhone stores in its local Keychain.

List enrolled devices (admin-only):

```bash
curl -fsS 'http://127.0.0.1:8080/v1/devices' \
  -H "Authorization: Bearer $BIOAUTH_ADMIN_TOKEN"
```

Copy the `device_id` value.

## Step 5: Send an authentication request

Replace `YOUR_DEVICE_ID` below:

```bash
export DEVICE_ID='YOUR_DEVICE_ID'

curl -fsS -X POST 'http://127.0.0.1:8080/v1/requests' \
  -H "Authorization: Bearer $BIOAUTH_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"device_id\":\"$DEVICE_ID\",\"action\":\"Approve test login to my application\"}"
```

Copy the returned `request_id` and query it:

```bash
export REQUEST_ID='YOUR_REQUEST_ID'

curl -fsS "http://127.0.0.1:8080/v1/requests/$REQUEST_ID" \
  -H "Authorization: Bearer $BIOAUTH_ADMIN_TOKEN"
```

Initially:

```json
{
  "request_id":"...",
  "device_id":"...",
  "action":"Approve test login to my application",
  "status":"pending",
  "authorized":false,
  "expires_at":"..."
}
```

With the app **open in the foreground**, the request appears within about 3 seconds. Tap **Approve with Face ID**, authenticate, then repeat the `GET`. You should see `status:"approved"` and `authorized:true` (if checked before the approval redemption window closes). Tap **Reject** instead to get `status:"denied",authorized:false`. Let an untouched request sit 60 seconds to see `status:"expired",authorized:false`.

## Step 6: Consume the authorization exactly once

**For any security-sensitive server-side operation, do not use the `GET` result as the final authorization gate.** Once your app sees `approved`, make this admin-authenticated call before carrying out the action:

```bash
curl -fsS -X POST \
  "http://127.0.0.1:8080/v1/requests/$REQUEST_ID/consume" \
  -H "Authorization: Bearer $BIOAUTH_ADMIN_TOKEN"
```

First successful response:

```json
{"authorized":true,"request_id":"...","status":"consumed"}
```

Second attempt returns HTTP **409** and cannot approve the action again. The redemption window is **60 seconds after biometric approval**. After consumption, subsequent `GET` returns `authorized:false` and `status:"consumed"`.

For a real application, the relying service must **atomically coordinate this consume step with its own idempotent business operation**, or a crash after consumption could drop the operation. This starter provides *single-use approval*, not exactly-once execution of external money movements.

## Step 7: Revoke a lost or old device

```bash
curl -fsS -X POST "http://127.0.0.1:8080/v1/devices/$DEVICE_ID/revoke" \
  -H "Authorization: Bearer $BIOAUTH_ADMIN_TOKEN"
```

The server removes its credential and denies pending requests. This does not undo actions previously consumed. If you tap **Forget local pairing** in the app, also call the server's revoke endpoint.

## Endpoint inventory

| Method | Route | Authentication | Purpose |
| --- | --- | --- | --- |
| `POST` | `/v1/pairings` | Admin token | Generate 5-min pairing capability |
| `POST` | `/v1/devices` | One-time pairing capability | Register P-256 public key |
| `GET` | `/v1/devices` | Admin token | Get device IDs |
| `POST` | `/v1/devices/{id}/revoke` | Admin token | Revoke a device |
| `GET` | `/v1/devices/{id}/requests` | Device token | List pending signed payloads |
| `POST` | `/v1/requests` | Admin token | Make a 60-second challenge |
| `GET` | `/v1/requests/{id}` | Admin token | Check status, no use-once claim |
| `POST` | `/v1/requests/{id}/approve` | Device token + **Secure Enclave ECDSA signature** | Validate real biometric-gated approval |
| `POST` | `/v1/requests/{id}/deny` | Device token | Reject without biometrics |
| `POST` | `/v1/requests/{id}/consume` | Admin token | Redeem one approved request exactly once |

## Security properties (and exact limits)

1. **Biometric-gated key use.** Secure Enclave P-256 signing key has `.privateKeyUsage` and `.biometryCurrentSet` access control. Code explicitly evaluates `.deviceOwnerAuthenticationWithBiometrics` for each tap using a new `LAContext`. Changing enrolled biometric data invalidates the key. An untrusted client-supplied `true` can never approve anything.
2. **Challenge binding.** Backend signs nothing. It creates a random 256-bit nonce within exact bytes that include protocol version, request ID, device ID, human-readable action, and expiration. The iPhone signs *those exact bytes*; the backend verifies with the corresponding enrolled public key.
3. **Replay protection.** Requests are 60-second, single-use state transitions. Approved requests can be redeemed once within the next 60 seconds. A valid signature for one challenge cannot approve another challenge.
4. **Enrollment matters.** A random one-time pairing token authorizes registration of a public key. This is **not hardware attestation**, real-world identity verification, account recovery, or proof a particular named human owns the device. The administrator must ensure the token reaches the intended iPhone securely.
5. **TLS is mandatory on the iPhone.** The Go service deliberately accepts loopback HTTP and requires a correctly secured HTTPS termination layer. A developer tunnel is not a recommended payment deployment architecture.
6. **Server secrets and keys.** Admin bearer stays in an environment variable, device bearer stays in iPhone Keychain, private signing key cannot be exported. The server stores only bearer **hashes**, public keys, challenges, timestamps, and successful signature evidence.
7. **Denial versus biometric failure.** A tapped Reject is a device-token authenticated explicit denial. Failed Face ID, cancellation, disconnected phone, or timeout lead to **no approval**, not a biometric-verification claim of `false`.
8. **Operational limitations.** This is a *single-process* server using an atomic JSON snapshot file. Writes and fsyncs keep the demonstration simple but cost latency as state grows. No account platform, app/device attestation, APNs notification, hardware assurance statement, enterprise audit trail, durable queue, key rotation, recovery flow, abuse control/rate limiting, or horizontal scalability. For production, migrate to a transactional database, purpose-specific authorization, rate limits, authentication of human administrators, app/device attestation as feasible, and external security review.
9. **Approval UI phishing risks.** The iPhone trusts the backend to describe the real action accurately. Future payments must use separately signed structured fields—amount, currency, merchant/payee, order ID, and account—rather than an arbitrary free-form `action` string. Your backend must compare signed values with the *exact* operation it will execute.
10. **Mobile notifications.** The 3-second foreground polling model **does not deliver real-time approval requests when iOS suspends the app**. APNs plus foreground challenge fetch is the next iteration.

## Automated backend tests

```bash
cd server
go test -race -v ./...
go vet ./...
```

Tests include: random enrollment, one-time pairing consumption, server-side P-256 signature validation, invalid signature and stolen/incorrect device token rejection, approval replay rejection, expiry, explicit denial, revocation, unauthorized admin access, state surviving restart, and one-time authorization consumption.

## Next build steps

1. Replace polling with APNs + fetch the full request after opening the app.
2. Replace JSON file storage with SQLite (single node) or PostgreSQL (multi-instance), including compare-and-swap state transitions.
3. Introduce account identity and strong enrollment procedures; evaluate Apple App Attest separately from Secure Enclave key use.
4. Define a versioned typed action protocol (`login`, `payment`, `device_register`, `consent`) and sign the complete structured context.
5. Build Android support with Android Keystore/StrongBox and `BiometricPrompt`, keeping the Go challenge-verification contract.

## Project structure

```text
biometric-auth-starter/
├── README.md
├── server/
│   ├── go.mod
│   ├── main.go
│   └── main_test.go
└── ios/
    └── BioAuth/
        ├── BioAuth.xcodeproj/project.pbxproj
        └── BioAuth/
            ├── BioAuthApp.swift
            ├── ContentView.swift
            ├── AuthViewModel.swift
            ├── API.swift
            ├── CredentialStore.swift
            └── SecureEnclaveSigner.swift
```
