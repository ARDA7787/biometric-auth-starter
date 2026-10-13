import Foundation
import Security

struct StoredCredential: Codable {
    let deviceID: String
    let deviceToken: String
    let serverURL: String
}

enum CredentialStore {
    private static let account = "com.example.bioauth.device.v1"

    static func load() throws -> StoredCredential? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var output: CFTypeRef?
        let code = SecItemCopyMatching(query as CFDictionary, &output)
        if code == errSecItemNotFound { return nil }
        guard code == errSecSuccess, let bytes = output as? Data else {
            throw AuthError.security("Cannot read device credential (\(code)).")
        }
        return try JSONDecoder().decode(StoredCredential.self, from: bytes)
    }

    static func save(_ credential: StoredCredential) throws {
        let encoded = try JSONEncoder().encode(credential)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account
        ]
        let values: [String: Any] = [
            kSecValueData as String: encoded,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        var code = SecItemAdd(query.merging(values) { _, new in new } as CFDictionary, nil)
        if code == errSecDuplicateItem {
            code = SecItemUpdate(query as CFDictionary, values as CFDictionary)
        }
        guard code == errSecSuccess else {
            throw AuthError.security("Cannot store device token (\(code)).")
        }
    }

    static func delete() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account
        ]
        let code = SecItemDelete(query as CFDictionary)
        guard code == errSecSuccess || code == errSecItemNotFound else {
            throw AuthError.security("Cannot delete credential (\(code)).")
        }
    }
}
