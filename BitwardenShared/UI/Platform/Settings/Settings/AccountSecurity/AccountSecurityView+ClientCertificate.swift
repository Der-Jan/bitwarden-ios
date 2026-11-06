import BitwardenKit
import BitwardenResources
import SwiftUI

extension AccountSecurityView {
    /// Account-scoped mTLS status remains available when an expired certificate blocks the server.
    @ViewBuilder var clientCertificateSection: some View {
        if let alias = store.state.certificateAlias {
            SectionView(Localizations.clientCertificateMtls, contentSpacing: 8) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(alias)
                        .styleGuide(.body)
                    TimelineView(.periodic(from: .now, by: 60)) { context in
                        Text(store.state.certificateStatus(at: context.date))
                            .styleGuide(.body)
                            .foregroundColor(Color(asset: store.state.certificateValidity.map { validity in
                                validity.notAfter <= context.date || validity.notBefore > context.date
                            } ?? true ? SharedAsset.Colors.error : SharedAsset.Colors.textPrimary))
                            .accessibilityIdentifier("ClientCertificateStatus")
                    }
                    if let validity = store.state.certificateValidity {
                        Text(Localizations.clientCertificateExpiresOn(
                            validity.notAfter.formatted(date: .abbreviated, time: .shortened),
                        ))
                        .styleGuide(.footnote)
                    }
                    Text(Localizations.clientCertificateReplacementDescription)
                        .styleGuide(.footnote)
                    Button(Localizations.replaceCertificate) {
                        store.send(.replaceCertificateTapped)
                    }
                    .buttonStyle(.primary())
                    .accessibilityIdentifier("ReplaceClientCertificateButton")
                }
                .padding(16)
                .contentBlock()
            }
        }
    }
}
