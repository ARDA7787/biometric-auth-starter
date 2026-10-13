import Foundation
import SwiftUI

@MainActor
final class AuthViewModel: ObservableObject {
    @Published var serverURL = ""
    @Published var deviceName = "My iPhone"
    @Published var pairingToken = ""
    @Published var pending: [PendingAction] = []
    @Published var message = ""
    @Published var busy = false
    @Published var busyRequestID: String?
    @Published private(set) var credential: StoredCredential?

    init() {
        do {
            credential = try CredentialStore.load()
            serverURL = credential?.serverURL ?? ""
        } catch {
            message = error.localizedDescription
        }
    }

    var enrolled: Bool { credential != nil }
    var deviceID: String { credential?.deviceID ?? "" }

    func enroll() async {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        do {
            let publicKey = try SecureEnclaveSigner.publicKeyBase64()
            let api = BioAuthAPI(serverURL: serverURL)
            let body = EnrollmentBody(
                pairing_token: pairingToken.trimmingCharacters(in: .whitespacesAndNewlines),
                name: deviceName.trimmingCharacters(in: .whitespacesAndNewlines),
                public_key_b64: publicKey
            )
            let result: EnrollmentReply = try await api.send(
                method: "POST", path: "/v1/devices", token: nil, body: body
            )
            let saved = StoredCredential(
                deviceID: result.device_id, deviceToken: result.device_token,
                serverURL: serverURL.trimmingCharacters(in: .whitespacesAndNewlines)
            )
            try CredentialStore.save(saved)
            credential = saved
            pairingToken = ""
            message = "Paired successfully. Ready to receive approval requests."
            await refresh()
        } catch {
            message = "Pairing failed: \(error.localizedDescription)"
        }
    }

    func refresh() async {
        guard let cred = credential, !busy else { return }
        do {
            let api = BioAuthAPI(serverURL: cred.serverURL)
            let result: PendingReply = try await api.send(
                method: "GET",
                path: "/v1/devices/\(cred.deviceID)/requests",
                token: cred.deviceToken,
                body: Optional<DenialBody>.none
            )
            var valid: [PendingAction] = []
            for raw in result.requests {
                if let item = try? PendingAction(raw: raw, deviceID: cred.deviceID) {
                    valid.append(item)
                }
            }
            pending = valid.sorted { $0.expiryText < $1.expiryText }
        } catch {
            message = "Cannot fetch requests: \(error.localizedDescription)"
        }
    }

    func approve(_ request: PendingAction) async {
        guard let cred = credential, busyRequestID == nil else { return }
        busyRequestID = request.id
        defer { busyRequestID = nil }
        do {
            // A *fresh* biometric check gates each signed approval.
            let signature = try await SecureEnclaveSigner.sign(request.payload, action: request.action)
            let api = BioAuthAPI(serverURL: cred.serverURL)
            let response: AuthResult = try await api.send(
                method: "POST", path: "/v1/requests/\(request.id)/approve",
                token: cred.deviceToken,
                body: ApprovalBody(device_id: cred.deviceID, signature_b64: signature)
            )
            guard response.authorized && response.status == "approved" else {
                throw AuthError.networking("Backend did not approve the action.")
            }
            pending.removeAll { $0.id == request.id }
            message = "Approved. Server verified your device's signature."
        } catch {
            message = "Not approved: \(error.localizedDescription)"
            await refresh()
        }
    }

    func deny(_ request: PendingAction) async {
        guard let cred = credential, busyRequestID == nil else { return }
        busyRequestID = request.id
        defer { busyRequestID = nil }
        do {
            let api = BioAuthAPI(serverURL: cred.serverURL)
            let response: AuthResult = try await api.send(
                method: "POST", path: "/v1/requests/\(request.id)/deny",
                token: cred.deviceToken,
                body: DenialBody(device_id: cred.deviceID)
            )
            guard !response.authorized && response.status == "denied" else {
                throw AuthError.networking("Unexpected deny result")
            }
            pending.removeAll { $0.id == request.id }
            message = "Denied. The server returned authorized=false."
        } catch {
            message = "Deny failed: \(error.localizedDescription)"
            await refresh()
        }
    }

    func pollWhileVisible() async {
        while !Task.isCancelled {
            await refresh()
            try? await Task.sleep(for: .seconds(3))
        }
    }

    func forgetLocalDevice() {
        // This intentionally doesn't revoke the server registration.
        // Administrators should call POST /v1/devices/{id}/revoke first.
        do {
            try CredentialStore.delete()
            try SecureEnclaveSigner.deleteKey()
            credential = nil
            pending = []
            pairingToken = ""
            message = "Local pairing removed. Revoke the previous device on the server."
        } catch {
            message = "Reset failed: \(error.localizedDescription)"
        }
    }
}
