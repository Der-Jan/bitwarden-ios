import BitwardenKit
import BitwardenResources
import BitwardenSdk
import Foundation

/// The ordering of cipher rows in the vault. Group rows retain their existing positions.
enum VaultListSortOrder: String, CaseIterable, Sendable {
    /// Base domains in alphabetical order, ignoring URL schemes and subdomains.
    case baseDomain

    /// Most recently modified items first.
    case lastUpdated

    /// Item names in alphabetical order.
    case name

    /// Primary login URLs in alphabetical order.
    case url

    /// The label displayed in the sort picker.
    var localizedName: String {
        switch self {
        case .baseDomain: Localizations.baseDomain
        case .lastUpdated: Localizations.lastUpdated
        case .name: Localizations.name
        case .url: Localizations.url
        }
    }

    /// Sorts cipher rows while preserving group and verification code rows.
    func sorted(_ items: [VaultListItem]) -> [VaultListItem] {
        var ciphers = items.compactMap { item -> VaultListItem? in
            guard case .cipher = item.itemType else { return nil }
            return item
        }.sorted { lhs, rhs in
            guard case let .cipher(left, _) = lhs.itemType,
                  case let .cipher(right, _) = rhs.itemType else { return false }
            switch self {
            case .lastUpdated:
                if left.revisionDate != right.revisionDate {
                    return left.revisionDate > right.revisionDate
                }
            case .baseDomain, .url:
                let leftURL = urlSortValue(for: left)
                let rightURL = urlSortValue(for: right)
                if leftURL.isEmpty != rightURL.isEmpty {
                    return !leftURL.isEmpty
                }
                let comparison = leftURL.localizedStandardCompare(rightURL)
                if comparison != .orderedSame {
                    return comparison == .orderedAscending
                }
            case .name:
                break
            }
            let comparison = left.name.localizedStandardCompare(right.name)
            return comparison == .orderedSame ? lhs.id < rhs.id : comparison == .orderedAscending
        }.makeIterator()
        return items.map { item in
            guard case .cipher = item.itemType else { return item }
            return ciphers.next() ?? item
        }
    }

    /// Sorts the items in each section without changing the section order.
    func sorted(_ sections: [VaultListSection]) -> [VaultListSection] {
        sections.map { VaultListSection(id: $0.id, items: sorted($0.items), name: $0.name) }
    }

    /// Uses the first nonempty login URL, or its base domain using the existing URL helpers.
    /// Items without a usable value sort last.
    private func urlSortValue(for cipher: CipherListView) -> String {
        let uri = cipher.type.loginListView?.uris?.compactMap(\.uri).first { !$0.isEmpty } ?? ""
        guard self == .baseDomain else { return uri }
        guard let url = URL(string: uri) else { return "" }
        return url.domain ?? url.sanitized.domain ?? ""
    }
}
