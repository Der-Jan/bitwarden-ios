import BitwardenKit
import BitwardenResources
import CryptoKit
import Foundation
import Security

// MARK: - ClientCertificateService

/// A service for managing client certificates used for mTLS authentication.
///
protocol ClientCertificateService: AnyObject { // sourcery: AutoMockable
    /// Gets the client certificate identity for mTLS authentication from the current environment.
    ///
    /// The environment service determines which URLs are active (pre-auth or logged-in account),
    /// so this returns the correct certificate for the current context.
    ///
    /// - Returns: A `SecIdentity` for the certificate, or `nil` if none is configured.
    ///
    func getClientCertificateIdentity() async -> SecIdentity?

    /// Returns validity dates for the identity referenced by an account's fingerprint.
    func getCertificateValidity(fingerprint: String) async throws -> ClientCertificateValidity?

    /// Imports and persists a replacement for one account, leaving other accounts unchanged.
    func replaceCertificate(data: Data, password: String, userId: String) async throws

    /// Import a client certificate from PKCS#12 data.
    ///
    /// Parses the certificate, stores the identity in the Keychain, and returns the SHA-256
    /// fingerprint of the imported certificate.
    ///
    /// - Parameters:
    ///   - data: The PKCS#12 certificate data.
    ///   - password: The password for the certificate.
    ///   - alias: The human-readable label to associate with the certificate.
    /// - Returns: The SHA-256 fingerprint of the imported certificate.
    /// - Throws: An error if the certificate cannot be imported.
    ///
    func importCertificate(
        data: Data,
        password: String,
        alias: String,
    ) async throws -> String

    /// Removes the client certificate with the given fingerprint from the Keychain if no other
    /// account still references it.
    ///
    /// - Parameter fingerprint: The SHA-256 fingerprint of the certificate to remove.
    ///
    /// sourcery: useSelectorName
    func removeCertificate(fingerprint: String) async throws

    /// Removes the client certificate for a specific user account.
    ///
    /// Used during account logout to clean up certificate data. Reads the certificate fingerprint
    /// from the account's stored environment URLs and deletes the Keychain identity only if no
    /// other account still references it.
    ///
    /// - Parameter userId: The user ID of the account being removed.
    ///
    /// sourcery: useSelectorName
    func removeCertificate(userId: String) async throws
}

// MARK: - DefaultClientCertificateService

/// Default implementation of the `ClientCertificateService`.
///
final class DefaultClientCertificateService: ClientCertificateService {
    // MARK: Private Properties

    /// The service used to manage environment URLs (handles pre-auth vs active account).
    private let environmentService: EnvironmentService

    /// The service used by the application to report non-fatal errors.
    private let errorReporter: ErrorReporter

    /// The repository used to store certificate data in the keychain.
    private let keychainRepository: KeychainRepository

    /// The service used to manage application state.
    private let stateService: StateService

    /// The clock used when checking imported certificates.
    private let timeProvider: TimeProvider

    // MARK: Initialization

    /// Initialize a `DefaultClientCertificateService`.
    ///
    /// - Parameters:
    ///   - environmentService: The service used to manage environment URLs.
    ///   - errorReporter: The service used by the application to report non-fatal errors.
    ///   - keychainRepository: The repository used to store sensitive certificate data in the Keychain.
    ///   - stateService: The service used to manage application state.
    ///
    init(
        environmentService: EnvironmentService,
        errorReporter: ErrorReporter,
        keychainRepository: KeychainRepository,
        stateService: StateService,
        timeProvider: TimeProvider = CurrentTime(),
    ) {
        self.environmentService = environmentService
        self.errorReporter = errorReporter
        self.keychainRepository = keychainRepository
        self.stateService = stateService
        self.timeProvider = timeProvider
    }

    // MARK: Methods

    func getClientCertificateIdentity() async -> SecIdentity? {
        guard let fingerprint = environmentService.clientCertificateFingerprint,
              !fingerprint.isEmpty else {
            return nil
        }
        do {
            return try await keychainRepository.getClientCertificateIdentity(fingerprint: fingerprint)
        } catch {
            errorReporter.log(error: error)
            return nil
        }
    }

    func importCertificate(
        data: Data,
        password: String,
        alias: String,
    ) async throws -> String {
        let importOptions: [String: Any] = [
            kSecImportExportPassphrase as String: password,
        ]

        var importResult: CFArray?
        let status = SecPKCS12Import(data as CFData, importOptions as CFDictionary, &importResult)

        if status == errSecAuthFailed {
            throw ClientCertificateError.invalidPassword
        }

        guard status == errSecSuccess,
              let importArray = importResult as? [[String: Any]],
              let firstItem = importArray.first,
              let identityRef = firstItem[kSecImportItemIdentity as String] else {
            throw ClientCertificateError.invalidCertificate
        }

        // SecIdentity is a CoreFoundation type; use CFTypeRef bridge instead of conditional cast.
        let identity = identityRef as! SecIdentity // swiftlint:disable:this force_cast
        let validity = try certificateValidity(for: identity)
        guard validity.notAfter > timeProvider.presentTime else { throw ClientCertificateError.certificateExpired }
        guard validity.notBefore <= timeProvider.presentTime else {
            throw ClientCertificateError.certificateNotYetValid
        }
        let fingerprint = try certificateFingerprint(for: identity)

        // Only add to Keychain if this certificate isn't already stored.
        // Multiple users may share the same certificate — keyed by fingerprint, not userId.
        let existing = try await keychainRepository.getClientCertificateIdentity(fingerprint: fingerprint)
        if existing == nil {
            try await keychainRepository.setClientCertificateIdentity(identity, fingerprint: fingerprint)
        }

        return fingerprint
    }

    func getCertificateValidity(fingerprint: String) async throws -> ClientCertificateValidity? {
        guard let identity = try await keychainRepository.getClientCertificateIdentity(fingerprint: fingerprint) else {
            return nil
        }
        return try certificateValidity(for: identity)
    }

    func replaceCertificate(data: Data, password: String, userId: String) async throws {
        // Resolve the selected account before import; never recreate an account removed during import.
        let previousURLs = try await stateService.getEnvironmentURLs(userId: userId)
        let fingerprint = try await importCertificate(
            data: data, password: password, alias: previousURLs?.clientCertificateAlias ?? "",
        )
        do {
            try await stateService.setClientCertificate(fingerprint: fingerprint, userId: userId)
        } catch {
            try? await removeCertificate(fingerprint: fingerprint)
            throw error
        }
        if await (try? stateService.getAccountIdOrActiveId(userId: nil)) == userId {
            await environmentService.loadURLsForActiveAccount()
        }
        if let previous = previousURLs?.clientCertificateFingerprint, previous != fingerprint {
            do {
                try await removeCertificate(fingerprint: previous)
            } catch {
                // The replacement is already saved; cleanup failure must not report import failure.
                errorReporter.log(error: error)
            }
        }
    }

    func removeCertificate(fingerprint: String) async throws {
        // Only delete the Keychain item if no other account still references this certificate.
        let inUse = await isFingerprintInUse(fingerprint)
        if !inUse {
            try await keychainRepository.deleteClientCertificateIdentity(fingerprint: fingerprint)
        }
    }

    func removeCertificate(userId: String) async throws {
        // Read the fingerprint from the account's stored environment URLs.
        let environmentURLs = try await stateService.getEnvironmentURLs(userId: userId)
        let fingerprint = environmentURLs?.clientCertificateFingerprint

        guard let fingerprint else { return }

        // Only delete the Keychain item if no other account still references this certificate.
        let inUse = await isFingerprintInUse(fingerprint, excludingUserId: userId)
        if !inUse {
            try await keychainRepository.deleteClientCertificateIdentity(fingerprint: fingerprint)
        }
    }

    // MARK: Private

    /// Extracts public validity metadata without exposing the private key.
    private func certificateValidity(for identity: SecIdentity) throws -> ClientCertificateValidity {
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else {
            throw ClientCertificateError.invalidCertificate
        }
        return try ClientCertificateValidity(certificate: certificate)
    }

    /// Computes the SHA-256 fingerprint of the certificate within a SecIdentity.
    ///
    private func certificateFingerprint(for identity: SecIdentity) throws -> String {
        var certificate: SecCertificate?
        let status = SecIdentityCopyCertificate(identity, &certificate)
        guard status == errSecSuccess, let cert = certificate else {
            throw ClientCertificateError.invalidCertificate
        }
        let data = SecCertificateCopyData(cert) as Data
        let digest = SHA256.hash(data: data)
        return digest.compactMap { String(format: "%02x", $0) }.joined()
    }

    /// Returns whether any account's environment URLs still reference the given fingerprint.
    ///
    /// - Parameters:
    ///   - fingerprint: The certificate fingerprint to check.
    ///   - excludingUserId: An optional user ID to exclude from the check (e.g., the account being removed).
    ///
    private func isFingerprintInUse(_ fingerprint: String, excludingUserId: String? = nil) async -> Bool {
        // Check the pre-auth environment URLs.
        let preAuthURLs = await stateService.getPreAuthEnvironmentURLs()
        if preAuthURLs?.clientCertificateFingerprint == fingerprint {
            return true
        }

        // Keep the identity if account references cannot be checked safely.
        do {
            let accounts = try await stateService.getAccounts()
            for account in accounts {
                let accountUserId = account.profile.userId
                if let excludingUserId, accountUserId == excludingUserId { continue }
                let accountURLs = try await stateService.getEnvironmentURLs(userId: accountUserId)
                if accountURLs?.clientCertificateFingerprint == fingerprint { return true }
            }
            return false
        } catch {
            errorReporter.log(error: error)
            return true
        }
    }
}

// MARK: - ClientCertificateError

/// Errors that can occur when working with client certificates.
///
enum ClientCertificateError: Error, LocalizedError {
    /// The certificate data is invalid or cannot be parsed.
    case invalidCertificate

    /// The certificate password is incorrect.
    case invalidPassword

    /// The certificate has expired.
    case certificateExpired

    /// The certificate's validity interval has not started.
    case certificateNotYetValid

    var errorDescription: String? {
        switch self {
        case .invalidCertificate:
            Localizations.theCertificateFileIsInvalidOrCorrupted
        case .invalidPassword:
            Localizations.theCertificatePasswordIsIncorrect
        case .certificateExpired:
            Localizations.theCertificateHasExpired
        case .certificateNotYetValid:
            Localizations.theCertificateIsNotYetValid
        }
    }
}
