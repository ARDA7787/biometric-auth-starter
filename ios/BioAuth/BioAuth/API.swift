import Foundation

struct EnrollmentBody: Encodable {
    let pairing_token: String
    let name: String
    let public_key_b64: String
}
struct EnrollmentReply: Decodable {
    let device_id: String
    let device_token: String
}
struct RawPending: Decodable {
    let request_id: String
    let payload_b64: String
}
struct PendingReply: Decodable {
    let requests: [RawPending]
}
struct SignedChallenge: Decodable {
    let v: Int
    let request_id: String
    let device_id: String
    let action: String
    let nonce: String
    let expires_at: String
}
struct PendingAction: Identifiable {
    let id: String
    let action: String
    let expiryText: String
    let payload: Data

    init(raw: RawPending, deviceID: String) throws {
        guard let bytes = Data(base64Encoded: raw.payload_b64),
              let message = try? JSONDecoder().decode(SignedChallenge.self, from: bytes),
              message.v == 1,
              message.request_id == raw.request_id,
              message.device_id == deviceID,
              !message.action.isEmpty,
              !message.nonce.isEmpty,
              Self.parseDate(message.expires_at).map({ $0 > Date() }) == true
        else { throw AuthError.security("Received an invalid, wrong-device, or expired challenge.") }
        id = raw.request_id
        action = message.action
        expiryText = message.expires_at
        payload = bytes // Sign the server's exact bytes: NEVER reconstruct this JSON.
    }

    private static func parseDate(_ text: String) -> Date? {
        let dateFormatter = ISO8601DateFormatter()
        dateFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = dateFormatter.date(from: text) { return date }
        dateFormatter.formatOptions = [.withInternetDateTime]
        return dateFormatter.date(from: text)
    }
}
struct ApprovalBody: Encodable {
    let device_id: String
    let signature_b64: String
}
struct DenialBody: Encodable {
    let device_id: String
}
struct AuthResult: Decodable {
    let status: String
    let authorized: Bool
}
struct APIErrorReply: Decodable {
    let error: String
}

struct BioAuthAPI {
    let serverURL: String

    private func url(_ path: String) throws -> URL {
        guard let origin = URLComponents(string: serverURL),
              origin.scheme?.lowercased() == "https",
              let host = origin.host, !host.isEmpty,
              origin.user == nil, origin.password == nil,
              origin.query == nil, origin.fragment == nil,
              origin.path.isEmpty || origin.path == "/"
        else { throw AuthError.networking("Enter a valid HTTPS server URL, e.g. https://your-name.ngrok-free.app") }
        let base = serverURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let result = URL(string: base + path) else {
            throw AuthError.networking("Invalid request URL")
        }
        return result
    }

    func send<Response: Decodable, Body: Encodable>(
        method: String, path: String, token: String?, body: Body?
    ) async throws -> Response {
        var request = URLRequest(url: try url(path))
        request.httpMethod = method
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        // This has no effect on normal HTTPS servers. It bypasses the
        // developer-facing interstitial on some free ngrok HTTPS tunnels.
        request.setValue("true", forHTTPHeaderField: "ngrok-skip-browser-warning")
        if let token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONEncoder().encode(body)
        }
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw AuthError.networking("Non-HTTP server response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let detail = (try? JSONDecoder().decode(APIErrorReply.self, from: data).error)
                ?? "HTTP \(http.statusCode)"
            throw AuthError.networking(detail)
        }
        return try JSONDecoder().decode(Response.self, from: data)
    }
}
