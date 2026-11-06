import BitwardenKit
import BitwardenResources
import Foundation

extension AccountSecurityProcessor {
    /// Handles presentation and cleanup for the certificate import sheet.
    func receiveCertificateAction(_ action: AccountSecurityAction) {
        switch action {
        case .replaceCertificateTapped:
            state.pendingCertificateData = nil
            state.certificateImportError = nil
            state.showingCertificateImport = true
        case .certificateImportDismissed:
            guard !state.isImportingCertificate else { return }
            state.showingCertificateImport = false
            state.pendingCertificateData = nil
            state.certificateImportError = nil
        case let .certificateFileImportFailed(message):
            state.pendingCertificateData = nil
            state.certificateImportError = message
        default:
            break
        }
    }

    /// Reads a selected certificate without retaining access to the file.
    func readCertificateFile(_ url: URL) {
        do {
            let accessed = url.startAccessingSecurityScopedResource()
            defer { if accessed { url.stopAccessingSecurityScopedResource() } }
            state.pendingCertificateData = try Data(contentsOf: url)
            state.certificateImportError = nil
        } catch {
            state.pendingCertificateData = nil
            state.certificateImportError = Localizations.unableToReadCertificateFile
        }
    }

    /// Loads certificate metadata from this account, even if the server is unreachable.
    func loadClientCertificate() async {
        do {
            let userId = try await services.stateService.getAccountIdOrActiveId(userId: nil)
            let urls = try await services.stateService.getEnvironmentURLs(userId: userId)
            state.certificateUserId = userId
            state.certificateAlias = nil
            state.certificateValidity = nil
            guard let fingerprint = urls?.clientCertificateFingerprint, !fingerprint.isEmpty else { return }
            state.certificateAlias = urls?.clientCertificateAlias ?? Localizations.clientCertificateMtls
            state.certificateValidity = try await services.clientCertificateService
                .getCertificateValidity(fingerprint: fingerprint)
        } catch {
            services.errorReporter.log(error: error)
        }
    }

    /// Commits a replacement only after the certificate and password have been validated.
    func replaceClientCertificate(password: String) async {
        guard !state.isImportingCertificate, let userId = state.certificateUserId,
              let data = state.pendingCertificateData else { return }
        state.isImportingCertificate = true
        defer { state.isImportingCertificate = false }
        do {
            try await services.clientCertificateService.replaceCertificate(
                data: data,
                password: password,
                userId: userId,
            )
            state.showingCertificateImport = false
            state.pendingCertificateData = nil
            state.certificateImportError = nil
            await loadClientCertificate()
        } catch let error as ClientCertificateError {
            state.certificateImportError = error.localizedDescription
        } catch {
            services.errorReporter.log(error: error)
            state.certificateImportError = Localizations.theCertificateCouldNotBeInstalled
        }
    }
}
