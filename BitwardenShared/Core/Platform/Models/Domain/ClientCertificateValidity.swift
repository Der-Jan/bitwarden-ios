import Foundation
import Security

/// The validity interval of a client certificate. Trust is still evaluated by the mTLS server.
struct ClientCertificateValidity: Equatable {
    let notBefore: Date
    let notAfter: Date

    /// Reads the certificate's validity interval, including on iOS versions before 18.
    init(certificate: SecCertificate) throws {
        if #available(iOS 18, *) {
            guard let start = SecCertificateCopyNotValidBeforeDate(certificate),
                  let end = SecCertificateCopyNotValidAfterDate(certificate) else {
                throw ClientCertificateError.invalidCertificate
            }
            self.init(notBefore: start as Date, notAfter: end as Date)
        } else {
            try self.init(der: SecCertificateCopyData(certificate) as Data)
        }
    }

    init(notBefore: Date, notAfter: Date) {
        self.notBefore = notBefore
        self.notAfter = notAfter
    }

    /// X.509 TBSCertificate contains optional version, serial, signature, issuer, then validity.
    /// This reads only DER lengths and the two RFC 5280 time values; it does not evaluate trust.
    init(der: Data) throws {
        var root = DERReader(bytes: Array(der))
        var certificate = try DERReader(bytes: root.read(tag: 0x30))
        var body = try DERReader(bytes: certificate.read(tag: 0x30))
        if body.nextTag == 0xA0 { _ = try body.read(tag: 0xA0) }
        _ = try body.read(tag: 0x02) // serial number
        _ = try body.read(tag: 0x30) // signature algorithm
        _ = try body.read(tag: 0x30) // issuer
        var validity = try DERReader(bytes: body.read(tag: 0x30))
        notBefore = try validity.readDate()
        notAfter = try validity.readDate()
        guard validity.nextTag == nil, notBefore <= notAfter else {
            throw ClientCertificateError.invalidCertificate
        }
    }
}

/// A bounded reader for the small portion of DER needed by the validity-date fallback.
private struct DERReader {
    let bytes: [UInt8]
    var offset = 0

    var nextTag: UInt8? { offset < bytes.count ? bytes[offset] : nil }

    mutating func read(tag: UInt8) throws -> [UInt8] {
        guard nextTag == tag, bytes.count - offset >= 2 else {
            throw ClientCertificateError.invalidCertificate
        }
        offset += 1
        let firstLength = Int(bytes[offset])
        offset += 1
        var length = firstLength
        if firstLength & 0x80 != 0 {
            let count = firstLength & 0x7F
            guard count > 0, count <= 4, count <= bytes.count - offset else {
                throw ClientCertificateError.invalidCertificate
            }
            length = 0
            for _ in 0 ..< count {
                length = (length << 8) | Int(bytes[offset])
                offset += 1
            }
        }
        guard length <= bytes.count - offset else { throw ClientCertificateError.invalidCertificate }
        defer { offset += length }
        return Array(bytes[offset ..< offset + length])
    }

    mutating func readDate() throws -> Date {
        guard let tag = nextTag, tag == 0x17 || tag == 0x18 else {
            throw ClientCertificateError.invalidCertificate
        }
        let value = try read(tag: tag)
        guard value.count == (tag == 0x17 ? 13 : 15), value.last == 0x5A,
              value.dropLast().allSatisfy({ (0x30 ... 0x39).contains($0) }),
              var text = String(bytes: value, encoding: .ascii) else {
            throw ClientCertificateError.invalidCertificate
        }
        if tag == 0x17 {
            // RFC 5280: UTCTime years 50–99 mean 1950–1999; 00–49 mean 2000–2049.
            text = (value[0] >= 0x35 ? "19" : "20") + text
        }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMddHHmmss'Z'"
        formatter.isLenient = false
        guard let date = formatter.date(from: text) else { throw ClientCertificateError.invalidCertificate }
        return date
    }
}
