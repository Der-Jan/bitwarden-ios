import BitwardenResources
import Foundation
import Testing

@testable import BitwardenShared

struct ClientCertificateValidityTests {
    @Test
    func readsUTCTimeWithAndWithoutVersion() throws {
        for versioned in [false, true] {
            let validity = try ClientCertificateValidity(der: certificate(
                start: "260101000000Z", end: "270101000000Z", versioned: versioned,
            ))
            #expect(validity.notBefore == Date(timeIntervalSince1970: 1_767_225_600))
            #expect(validity.notAfter == Date(timeIntervalSince1970: 1_798_761_600))
        }
    }

    @Test
    func readsGeneralizedTime() throws {
        let validity = try ClientCertificateValidity(der: certificate(
            start: "20500101000000Z", end: "20510101000000Z", tag: 0x18,
        ))
        #expect(validity.notBefore == Date(timeIntervalSince1970: 2_524_608_000))
        #expect(validity.notAfter > validity.notBefore)
    }

    @Test
    func readsUTCTimeCenturyBoundary() throws {
        let validity = try ClientCertificateValidity(der: certificate(start: "500101000000Z", end: "490101000000Z"))
        let calendar = Calendar(identifier: .gregorian)
        #expect(calendar.component(.year, from: validity.notBefore) == 1950)
        #expect(calendar.component(.year, from: validity.notAfter) == 2049)
    }

    @Test
    func rejectsMalformedOrTruncatedDER() {
        let valid = certificate(start: "260101000000Z", end: "270101000000Z")
        for length in 0 ..< valid.count {
            #expect(throws: ClientCertificateError.invalidCertificate) {
                try ClientCertificateValidity(der: valid.prefix(length))
            }
        }
        #expect(throws: ClientCertificateError.invalidCertificate) {
            try ClientCertificateValidity(der: Data([0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]))
        }
        #expect(throws: ClientCertificateError.invalidCertificate) {
            try ClientCertificateValidity(der: certificate(start: "261301000000Z", end: "270101000000Z"))
        }
        #expect(throws: ClientCertificateError.invalidCertificate) {
            try ClientCertificateValidity(der: certificate(start: "280101000000Z", end: "270101000000Z"))
        }
    }

    @Test
    func statusChangesOnlyAtValidityBoundaries() {
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        let end = start.addingTimeInterval(60 * 24 * 60 * 60)
        var state = AccountSecurityState()
        #expect(state.certificateStatus(at: start) == Localizations.clientCertificateUnavailable)
        state.certificateValidity = ClientCertificateValidity(notBefore: start, notAfter: end)
        #expect(state.certificateStatus(at: start.addingTimeInterval(-1)) == Localizations.theCertificateIsNotYetValid)
        #expect(state.certificateStatus(at: start) == Localizations.clientCertificateValid)
        #expect(state.certificateStatus(at: end.addingTimeInterval(-30 * 24 * 60 * 60))
            == Localizations.clientCertificateValid)
        #expect(state.certificateStatus(at: end.addingTimeInterval(-1)) == Localizations.clientCertificateValid)
        #expect(state.certificateStatus(at: end) == Localizations.theCertificateHasExpired)
    }

    /// A minimal DER envelope for exercising the fallback parser independently of the platform API.
    private func certificate(start: String, end: String, tag: UInt8 = 0x17, versioned: Bool = true) -> Data {
        func field(_ tag: UInt8, _ bytes: [UInt8]) -> [UInt8] { [tag, UInt8(bytes.count)] + bytes }
        let version: [UInt8] = versioned ? field(0xA0, field(0x02, [2])) : []
        let validity = field(0x30, field(tag, Array(start.utf8)) + field(tag, Array(end.utf8)))
        let body = version + field(0x02, [1]) + field(0x30, []) + field(0x30, []) + validity
        return Data(field(0x30, field(0x30, body)))
    }
}
