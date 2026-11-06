import BitwardenKit
import BitwardenKitMocks
import Foundation
import TestHelpers
import Testing

@testable import BitwardenShared
@testable import BitwardenSharedMocks

struct ClientCertificateServiceTests {
    // MARK: Properties

    var environmentService: MockEnvironmentService
    var errorReporter: MockErrorReporter
    var keychainRepository: MockKeychainRepository
    var stateService: MockStateService
    var timeProvider: MockTimeProvider
    var subject: DefaultClientCertificateService

    /// Synthetic self-signed identity for tests only; the private key has no real-world use.
    private var certificateData: Data {
        Data(base64Encoded: """
        MIIDkgIBAzCCA1gGCSqGSIb3DQEHAaCCA0kEggNFMIIDQTCCAjcGCSqGSIb3DQEHBqCCAigwggIkAgEAMIICHQYJKoZIhvcNAQcB
        MBwGCiqGSIb3DQEMAQMwDgQIoMkPitPnYZ8CAggAgIIB8C1A0WQ3cY8LRRJ9x756TnFL7SiW1OKvAGMxhYJC5jfjvtldw+78ABRw
        Z7B19I3iQ89OtaubHgYDk1S1a5oAkiCTOtC+DNOv57Sc3k6a/ICpS6w2rC5BneDF+8FF0IxiKL81/ayBk/dbbfB358PISxUVUAml
        dNZ8sD4VLgeWCyN2MtMU7NCIct9G0RlVC3tTwlbNX3bGM2Q+MI98Y2ZH+VURIz5/YenJZ675fRllmuV/TYudDTOqcs48QVigg1LH
        w6F/MA6u9ZDHTK1M/H3nWFiUCAaYOpynIQs1Yzde2rD424mwFy6GdO4qY4iQYVgmluu2iaq49PiDwlaCAni8O+YqHetzPc22DYic
        d7i+5OpUW1sofDR8fV2e8UCRA7gZWmruxzdDa9hC7D5AevRvIX8feAudNLUBBdivZGr+/y+IA8w8Njm/SIb5EFTr4hswtZXNxylA
        iOekj9BZMgL8LJeSaZ9WWqihuU2dxXod65IgaYwFP9G481YFpR63LVUshUn6AROc8vkx/MXgbjkN2mvGqGhbaZBtlHlXES/CMdRl
        Tg8a4Z44Rifx3hl/6dHjEbrgSL/pvdJOSnC3OZJQpOG7CBt5L/hxIshyJgr5vcPByr5nt1Dqy0TTWDBSb0AdALW9086y5GgaBtYR
        Ya9s1f4wggECBgkqhkiG9w0BBwGggfQEgfEwge4wgesGCyqGSIb3DQEMCgECoIG0MIGxMBwGCiqGSIb3DQEMAQMwDgQI28ajVD7y
        IikCAggABIGQdILTE2bbkXkl/JXz7mj69h8zhdEOv1oQBqPQ2xBLJeHPawGoFdyjsITyWvJT0qTXAYbSpwM5ga6KI3RPI2qZ/ehy
        SzL87+4kSiPjdboxxnPQXe4qOlIzz2SPFrH42oe1L/bszfBJxwC/wcD06IVo+ZME+b3ciF87MYdc4c2gynALAzXM9PqAg/Nnhtn9
        4VbeMSUwIwYJKoZIhvcNAQkVMRYEFMYuBIiQqv87aiGsPSNGzFy/gkpQMDEwITAJBgUrDgMCGgUABBSK8w2IBy2/kMrkrfb+NOSi
        nC7pmQQIYBePul47SncCAggA
        """, options: .ignoreUnknownCharacters)!
    }

    // MARK: Initialization

    init() {
        environmentService = MockEnvironmentService()
        errorReporter = MockErrorReporter()
        keychainRepository = MockKeychainRepository()
        stateService = MockStateService()
        stateService.accounts = []
        timeProvider = MockTimeProvider(.mockTime(Date(timeIntervalSince1970: 1_800_000_000)))
        subject = DefaultClientCertificateService(
            environmentService: environmentService,
            errorReporter: errorReporter,
            keychainRepository: keychainRepository,
            stateService: stateService,
            timeProvider: timeProvider,
        )
    }

    // MARK: Tests - getClientCertificateIdentity()

    /// `getClientCertificateIdentity()` returns nil when the fingerprint is set but the keychain
    /// identity is missing.
    @Test
    func getClientCertificateIdentity_fingerprintSetButKeychainMissing_returnsNil() async {
        environmentService.clientCertificateFingerprint = "missing-from-keychain"

        let result = await subject.getClientCertificateIdentity()

        #expect(result == nil)
    }

    /// `getClientCertificateIdentity()` returns nil and logs an error when the keychain throws an
    /// unexpected error.
    @Test
    func getClientCertificateIdentity_keychainThrows_logsErrorAndReturnsNil() async {
        let error = BitwardenTestError.example
        environmentService.clientCertificateFingerprint = "some-fingerprint"
        keychainRepository.getClientCertificateIdentityThrowableError = error

        let result = await subject.getClientCertificateIdentity()

        #expect(result == nil)
        #expect(errorReporter.errors as? [BitwardenTestError] == [error])
    }

    /// `getClientCertificateIdentity()` returns nil when no fingerprint is in the environment.
    @Test
    func getClientCertificateIdentity_noFingerprint_returnsNil() async {
        environmentService.clientCertificateFingerprint = nil

        let result = await subject.getClientCertificateIdentity()

        #expect(result == nil)
    }

    // MARK: Tests - removeCertificate(fingerprint:)

    /// `removeCertificate(fingerprint:)` deletes the keychain identity when no other account
    /// references the given fingerprint.
    @Test
    func removeCertificate_fingerprint_deletesKeychainIdentity() async throws {
        let fingerprint = "current-env-fingerprint"

        stateService.accounts = []

        try await subject.removeCertificate(fingerprint: fingerprint)

        #expect(keychainRepository.deleteClientCertificateIdentityReceivedFingerprint == fingerprint)
    }

    /// `removeCertificate(fingerprint:)` keeps the keychain identity when another account
    /// references the same fingerprint.
    @Test
    func removeCertificate_fingerprint_sharedFingerprint_doesNotDeleteKeychainIdentity() async throws {
        let user1 = "1"
        let fingerprint = "shared-fingerprint"

        stateService.accounts = [.fixture(profile: .fixture(userId: user1))]
        stateService.environmentURLs[user1] = EnvironmentURLData(
            base: URL(string: "https://example.com"),
            clientCertificateAlias: "Cert A",
            clientCertificateFingerprint: fingerprint,
        )

        try await subject.removeCertificate(fingerprint: fingerprint)

        #expect(!keychainRepository.deleteClientCertificateIdentityCalled)
    }

    // MARK: Tests - removeCertificate(userId:)

    /// `removeCertificate(userId:)` deletes the keychain identity when the removed user is the
    /// last reference to the certificate fingerprint.
    @Test
    func removeCertificate_lastFingerprintReference_deletesKeychainIdentity() async throws {
        let user1 = "1"
        let fingerprint = "only-fingerprint"

        stateService.accounts = [
            .fixture(profile: .fixture(userId: user1)),
        ]
        stateService.activeAccount = .fixture(profile: .fixture(userId: user1))
        stateService.environmentURLs[user1] = EnvironmentURLData(
            base: URL(string: "https://example.com"),
            clientCertificateAlias: "Cert A",
            clientCertificateFingerprint: fingerprint,
        )

        try await subject.removeCertificate(userId: user1)

        #expect(keychainRepository.deleteClientCertificateIdentityReceivedFingerprint == fingerprint)
    }

    /// `removeCertificate(userId:)` succeeds gracefully when no certificate is configured.
    @Test
    func removeCertificate_noCertConfigured_succeeds() async throws {
        let user1 = "1"

        stateService.accounts = [
            .fixture(profile: .fixture(userId: user1)),
        ]
        stateService.activeAccount = .fixture(profile: .fixture(userId: user1))
        stateService.environmentURLs[user1] = EnvironmentURLData(
            base: URL(string: "https://example.com"),
        )

        try await subject.removeCertificate(userId: user1)

        #expect(!keychainRepository.deleteClientCertificateIdentityCalled)
    }

    /// `removeCertificate(userId:)` keeps the keychain identity when another account references
    /// the same certificate fingerprint in its environment URLs.
    @Test
    func removeCertificate_sharedFingerprintAcrossAccounts_doesNotDeleteKeychainIdentity() async throws {
        let user1 = "1"
        let user2 = "2"
        let fingerprint = "shared-fingerprint"

        stateService.accounts = [
            .fixture(profile: .fixture(userId: user1)),
            .fixture(profile: .fixture(userId: user2)),
        ]
        stateService.activeAccount = .fixture(profile: .fixture(userId: user1))
        stateService.environmentURLs[user1] = EnvironmentURLData(
            base: URL(string: "https://example.com"),
            clientCertificateAlias: "Cert A",
            clientCertificateFingerprint: fingerprint,
        )
        stateService.environmentURLs[user2] = EnvironmentURLData(
            base: URL(string: "https://example.com"),
            clientCertificateAlias: "Cert B",
            clientCertificateFingerprint: fingerprint,
        )

        try await subject.removeCertificate(userId: user1)

        #expect(!keychainRepository.deleteClientCertificateIdentityCalled)
    }

    /// `removeCertificate(userId:)` keeps the keychain identity when the pre-auth environment URLs
    /// still reference the same certificate fingerprint.
    @Test
    func removeCertificate_sharedWithPreAuth_doesNotDeleteKeychainIdentity() async throws {
        let user1 = "1"
        let fingerprint = "shared-with-preauth"

        stateService.accounts = [
            .fixture(profile: .fixture(userId: user1)),
        ]
        stateService.activeAccount = .fixture(profile: .fixture(userId: user1))
        stateService.environmentURLs[user1] = EnvironmentURLData(
            base: URL(string: "https://example.com"),
            clientCertificateAlias: "Cert A",
            clientCertificateFingerprint: fingerprint,
        )
        stateService.preAuthEnvironmentURLs = EnvironmentURLData(
            base: URL(string: "https://example.com"),
            clientCertificateAlias: "PreAuth Cert",
            clientCertificateFingerprint: fingerprint,
        )

        try await subject.removeCertificate(userId: user1)

        #expect(!keychainRepository.deleteClientCertificateIdentityCalled)
    }

    @Test
    func importCertificate_expired_doesNotStoreIdentity() async throws {
        timeProvider.timeConfig = .mockTime(.distantFuture)
        await #expect(throws: ClientCertificateError.certificateExpired) {
            try await subject.importCertificate(data: certificateData, password: "testpassword", alias: "Test")
        }
        #expect(!keychainRepository.setClientCertificateIdentityCalled)
    }

    @Test
    func importCertificate_notYetValid_doesNotStoreIdentity() async throws {
        timeProvider.timeConfig = .mockTime(.distantPast)
        await #expect(throws: ClientCertificateError.certificateNotYetValid) {
            try await subject.importCertificate(data: certificateData, password: "testpassword", alias: "Test")
        }
        #expect(!keychainRepository.setClientCertificateIdentityCalled)
    }

    @Test
    func importCertificate_wrongPassword_doesNotStoreIdentity() async throws {
        await #expect(throws: ClientCertificateError.invalidPassword) {
            try await subject.importCertificate(data: certificateData, password: "wrong", alias: "Test")
        }
        #expect(!keychainRepository.setClientCertificateIdentityCalled)
    }

    @Test
    func getCertificateValidity_missingIdentity_returnsNil() async throws {
        let validity = try await subject.getCertificateValidity(fingerprint: "missing")
        #expect(validity == nil)
    }

    @Test
    func replaceCertificate_preservesOtherAccountsAndRefreshesActiveEnvironment() async throws {
        stateService.activeAccount = .fixture(profile: .fixture(userId: "1"))
        stateService.accounts = [.fixture(profile: .fixture(userId: "1")), .fixture(profile: .fixture(userId: "2"))]
        let urls = EnvironmentURLData(
            base: .example, clientCertificateAlias: "Original", clientCertificateFingerprint: "old",
        )
        stateService.environmentURLs = ["1": urls, "2": urls]

        try await subject.replaceCertificate(data: certificateData, password: "testpassword", userId: "1")

        #expect(stateService.environmentURLs["1"]?.clientCertificateAlias == "Original")
        #expect(stateService.environmentURLs["1"]?.clientCertificateFingerprint != "old")
        #expect(stateService.environmentURLs["2"] == urls)
        #expect(environmentService.didLoadURLsForActiveAccount)
        #expect(!keychainRepository.deleteClientCertificateIdentityCalled)
    }

    @Test
    func replaceCertificate_saveFails_preservesOldReferenceAndCleansImportedIdentity() async throws {
        stateService.activeAccount = .fixture(profile: .fixture(userId: "1"))
        stateService.environmentURLs["1"] = EnvironmentURLData(base: .example, clientCertificateFingerprint: "old")
        stateService.setClientCertificateError = BitwardenTestError.example

        await #expect(throws: BitwardenTestError.example) {
            try await subject.replaceCertificate(
                data: certificateData, password: "testpassword", userId: "1",
            )
        }

        #expect(stateService.environmentURLs["1"]?.clientCertificateFingerprint == "old")
        #expect(keychainRepository.deleteClientCertificateIdentityCalled)
        #expect(!environmentService.didLoadURLsForActiveAccount)
    }

    @Test
    func replaceCertificate_inactiveAccount_doesNotSwitchEnvironment() async throws {
        stateService.activeAccount = .fixture(profile: .fixture(userId: "2"))
        stateService.environmentURLs["1"] = EnvironmentURLData(base: .example, clientCertificateFingerprint: "old")

        try await subject.replaceCertificate(data: certificateData, password: "testpassword", userId: "1")

        #expect(stateService.activeAccount?.profile.userId == "2")
        #expect(!environmentService.didLoadURLsForActiveAccount)
        #expect(keychainRepository.deleteClientCertificateIdentityReceivedFingerprint == "old")
    }

    @Test
    func removeCertificate_unableToReadAccounts_doesNotDeleteIdentity() async throws {
        stateService.accounts = nil
        try await subject.removeCertificate(fingerprint: "possibly-shared")
        #expect(!keychainRepository.deleteClientCertificateIdentityCalled)
        #expect(errorReporter.errors.last as? StateServiceError == .noAccounts)
    }
}
