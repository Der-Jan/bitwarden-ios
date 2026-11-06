import BitwardenSdk
import Foundation
import Testing

@testable import BitwardenShared
@testable import BitwardenSharedMocks

struct VaultListSortOrderTests {
    // MARK: Tests

    /// Base domains ignore schemes and subdomains, including multi-part suffixes and bare hosts.
    @Test(arguments: [
        ("https://z.alpha.com/login", "http://a.beta.com"),
        ("https://z.example.co.uk", "https://a.other.co.uk"),
        ("z.example.com:8080/login", "https://a.other.com"),
    ])
    func baseDomain(firstURL: String, secondURL: String) {
        let first = item(id: "1", name: "Zulu", urls: [firstURL])
        let second = item(id: "2", name: "Alpha", urls: [secondURL])
        #expect(VaultListSortOrder.baseDomain.sorted([second, first]) == [first, second])
    }

    /// Items on the same base domain are ordered by name, regardless of their subdomain or path.
    @Test(arguments: ["example.com", "example.co.uk"])
    func baseDomain_groupsSubdomains(domain: String) {
        let first = item(id: "1", name: "Alpha", urls: ["https://z.\(domain)/login"])
        let second = item(id: "2", name: "Zulu", urls: ["http://a.\(domain)"])
        #expect(VaultListSortOrder.baseDomain.sorted([second, first]) == [first, second])
    }

    /// Missing and malformed URLs sort after usable domains, with name as the fallback.
    @Test
    func baseDomain_missingAndInvalidURLs() {
        let first = item(id: "1", name: "Zulu", urls: ["", "https://sub.example.com"])
        let missing = item(id: "2", name: "Alpha")
        let invalid = item(id: "3", name: "Beta", urls: ["http://["])
        #expect(VaultListSortOrder.baseDomain.sorted([missing, invalid, first]) == [first, missing, invalid])
    }

    /// The existing domain helper also supports IP addresses and local hostnames.
    @Test(arguments: ["http://localhost:8080", "http://192.0.2.1", "http://[2001:db8::1]"])
    func baseDomain_usesExistingHostFallbacks(url: String) {
        let first = item(id: "1", name: "Zulu", urls: [url])
        let missing = item(id: "2", name: "Alpha")
        #expect(VaultListSortOrder.baseDomain.sorted([missing, first]) == [first, missing])
    }

    /// Detailed vault lists initially sort by name.
    @Test
    func defaultState() {
        #expect(VaultGroupState(vaultFilterType: .allVaults).sortOrder == .name)
    }

    /// Most recently revised items appear first, regardless of name.
    @Test
    func lastUpdated() {
        let older = item(id: "old", name: "Alpha", revision: 1)
        let newer = item(id: "new", name: "Zulu", revision: 2)
        #expect(VaultListSortOrder.lastUpdated.sorted([older, newer]) == [newer, older])
    }

    /// Names sort naturally and without regard to case.
    @Test
    func name() {
        let first = item(id: "1", name: "account 2")
        let second = item(id: "2", name: "Account 10")
        #expect(VaultListSortOrder.name.sorted([second, first]) == [first, second])
    }

    /// Section metadata and group row positions are preserved.
    @Test
    func sectionsAndGroups() {
        let older = item(id: "old", name: "Alpha", revision: 1)
        let newer = item(id: "new", name: "Zulu", revision: 2)
        let group = VaultListItem.fixtureGroup(group: .login, count: 2)
        let section = VaultListSection(id: "items", items: [older, group, newer], name: "Items")
        let empty = VaultListSection(id: "empty", items: [], name: "Empty")
        #expect(VaultListSortOrder.lastUpdated.sorted([section, empty]) == [
            VaultListSection(id: "items", items: [newer, group, older], name: "Items"),
            empty,
        ])
    }

    /// Equal dates or URLs fall back to name, then ID, for deterministic ordering.
    @Test(arguments: VaultListSortOrder.allCases)
    func ties(order: VaultListSortOrder) {
        let first = item(id: "1", name: "Alpha", urls: ["https://example.com"])
        let second = item(id: "2", name: "Alpha", urls: ["https://example.com"])
        let third = item(id: "3", name: "Zulu", urls: ["https://example.com"])
        #expect(order.sorted([third, second, first]) == [first, second, third])
    }

    /// URL sorting uses the first nonempty URL and puts missing URLs last.
    @Test
    func url() {
        let first = item(id: "1", name: "Zulu", urls: ["", "https://a.example", "https://z.example"])
        let second = item(id: "2", name: "Alpha", urls: ["https://b.example"])
        let missing = item(id: "3", name: "Aardvark")
        #expect(VaultListSortOrder.url.sorted([missing, second, first]) == [first, second, missing])
    }

    /// Group and verification code lists retain their existing ordering.
    @Test(arguments: VaultListSortOrder.allCases)
    func verificationCodesAndGroups(order: VaultListSortOrder) {
        let items: [VaultListItem] = [
            .fixtureTOTP(name: "Zulu", totp: .fixture(id: "1")),
            .fixtureGroup(),
            .fixtureTOTP(name: "Alpha", totp: .fixture(id: "2")),
        ]
        #expect(order.sorted(items) == items)
        #expect(order.sorted([VaultListItem]()).isEmpty)
    }

    // MARK: Private Methods

    private func item(
        id: String,
        name: String,
        revision: TimeInterval = 0,
        urls: [String] = [],
    ) -> VaultListItem {
        .fixture(cipherListView: .fixture(
            id: id,
            name: name,
            type: .login(.fixture(uris: urls.map { .fixture(uri: $0) })),
            revisionDate: Date(timeIntervalSince1970: revision),
        ))
    }
}
