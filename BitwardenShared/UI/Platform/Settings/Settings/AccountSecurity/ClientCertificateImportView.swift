import BitwardenKit
import BitwardenResources
import SwiftUI
import UniformTypeIdentifiers

/// Imports a replacement identity while the existing identity remains usable until commit.
struct ClientCertificateImportView: View {
    @ObservedObject var store: Store<AccountSecurityState, AccountSecurityAction, AccountSecurityEffect>

    @SwiftUI.State private var password = ""
    @SwiftUI.State private var showingFileImporter = false

    private var isSaveDisabled: Bool {
        store.state.pendingCertificateData == nil || store.state.isImportingCertificate
    }

    var body: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 16) {
                Text(store.state.certificateAlias ?? Localizations.clientCertificateMtls)
                    .styleGuide(.body)
                BitwardenTextField(
                    title: Localizations.password,
                    text: $password,
                    accessibilityIdentifier: "ClientCertificatePassword",
                    canViewPassword: false,
                    isPasswordVisible: .constant(false),
                )
                .textFieldConfiguration(.password)
                Button(Localizations.importCertificate) {
                    showingFileImporter = true
                }
                .buttonStyle(.secondary())
                if store.state.pendingCertificateData != nil {
                    Text(Localizations.clientCertificateFileSelected)
                        .styleGuide(.footnote)
                }
                if let error = store.state.certificateImportError {
                    Text(error)
                        .styleGuide(.body)
                        .foregroundColor(Color(asset: SharedAsset.Colors.error))
                        .accessibilityIdentifier("ClientCertificateImportError")
                }
                if store.state.isImportingCertificate { ProgressView() }
            }
            .padding(16)
            .scrollView()
            .navigationBar(title: Localizations.replaceCertificate, titleDisplayMode: .inline)
            .toolbar {
                cancelToolbarItem {
                    password = ""
                    store.send(.certificateImportDismissed)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    saveToolbarButton {
                        await store.perform(.replaceClientCertificate(password: password))
                        password = ""
                    }
                    .disabled(isSaveDisabled)
                }
            }
            .disabled(store.state.isImportingCertificate)
            .fileImporter(
                isPresented: $showingFileImporter,
                allowedContentTypes: ["p12", "pfx"].compactMap { UTType(filenameExtension: $0) },
            ) { result in
                switch result {
                case let .success(url):
                    Task { await store.perform(.readCertificateFile(url)) }
                case let .failure(error):
                    if (error as NSError).code != NSUserCancelledError {
                        store.send(.certificateFileImportFailed(Localizations.unableToReadCertificateFile))
                    }
                }
            }
        }
        .navigationViewStyle(.stack)
        .interactiveDismissDisabled(store.state.isImportingCertificate)
    }
}
