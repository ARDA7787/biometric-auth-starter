import Foundation
import LocalAuthentication
import Security

// Face ID / Touch ID protects *use of the private signing key*, not merely
// a boolean from a LocalAuthentication callback. The private key never leaves
// the Secure Enclave. Public keys are exported as 65-byte X9.63 P-256 points.
enum SecureEnclaveSigner {
    private static let tag = Data("com.example.bioauth.signing-key.v1".utf8)

    private static func keyQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true
        ]
    }

    private static func existingKey(context: LAContext? = nil) throws -> SecKey? {
        var query = keyQuery()
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let key = item else {
            throw AuthError.security("Key lookup failed (OSStatus \(status)).")
        }
        return (key as! SecKey)
    }

    static func publicKeyBase64() throws -> String {
        let privateKey: SecKey
        if let existing = try existingKey() {
            privateKey = existing
        } else {
            var accessError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                [.privateKeyUsage, .biometryCurrentSet],
                &accessError
            ) else {
                throw (accessError?.takeRetainedValue() as Error?) ?? AuthError.security("Cannot make key access control.")
            }

            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: true,
                    kSecAttrApplicationTag as String: tag,
                    kSecAttrAccessControl as String: access
                ]
            ]
            var keyError: Unmanaged<CFError>?
            guard let generated = SecKeyCreateRandomKey(attributes as CFDictionary, &keyError) else {
                throw (keyError?.takeRetainedValue() as Error?) ?? AuthError.security("Secure Enclave key generation failed.")
            }
            privateKey = generated
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw AuthError.security("Could not read signing public key.")
        }
        var copyError: Unmanaged<CFError>?
        guard let external = SecKeyCopyExternalRepresentation(publicKey, &copyError) else {
            throw (copyError?.takeRetainedValue() as Error?) ?? AuthError.security("Could not export public key.")
        }
        let bytes = external as Data
        guard bytes.count == 65, bytes.first == 0x04 else {
            throw AuthError.security("Unexpected X9.63 public key format.")
        }
        return bytes.base64EncodedString()
    }

    static func sign(_ payload: Data, action: String) async throws -> String {
        let context = LAContext()
        context.localizedFallbackTitle = ""
        var canAuthenticateError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &canAuthenticateError) else {
            throw canAuthenticateError ?? AuthError.security("Face ID / Touch ID is unavailable or not enrolled.")
        }

        // Explicitly require biometric-only policy; no passcode-as-biometric substitution.
        // The SAME LAContext is passed to Keychain so hardware key usage is bound to this check.
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Authorize: \(action)"
            ) { approved, error in
                if approved { continuation.resume() }
                else { continuation.resume(throwing: error ?? AuthError.security("Biometric verification failed.")) }
            }
        }

        guard let privateKey = try existingKey(context: context) else {
            throw AuthError.security("Signing key missing. Re-pair this device.")
        }
        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw AuthError.security("Secure Enclave does not support the signing algorithm.")
        }
        var signingError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, payload as CFData, &signingError) else {
            throw (signingError?.takeRetainedValue() as Error?) ?? AuthError.security("Unable to sign challenge.")
        }
        context.invalidate()
        return (signature as Data).base64EncodedString()
    }

    static func deleteKey() throws {
        var query = keyQuery()
        query.removeValue(forKey: kSecReturnRef as String)
        let code = SecItemDelete(query as CFDictionary)
        guard code == errSecSuccess || code == errSecItemNotFound else {
            throw AuthError.security("Cannot delete old Secure Enclave key (\(code)).")
        }
    }
}

enum AuthError: LocalizedError {
    case security(String)
    case networking(String)

    var errorDescription: String? {
        switch self {
        case .security(let message), .networking(let message): message
        }
    }
}
