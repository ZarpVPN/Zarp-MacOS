import Foundation
import SwiftUI
import ZarpCore
import ZarpSubscriptions

/// Drives only saved server configuration. It has no daemon or connection provider.
@MainActor
final class ServerLibraryViewModel: ObservableObject {
    @Published private(set) var snapshot: ConnectionLibrarySnapshot?
    @Published private(set) var isWorking = false
    @Published private(set) var isRefreshing = false
    @Published private(set) var message: Msg?
    @Published private(set) var problem: Msg?
    private let library: ConnectionLibrary
    private var operation: Task<Void, Never>?

    init(library: ConnectionLibrary) { self.library = library }

    convenience init(directory: URL) {
        self.init(library: ConnectionLibrary(directory: directory, transport: FoundationSubscriptionTransport()))
    }

    func load() async {
        guard !isWorking else { return }
        do {
            snapshot = try await library.snapshot()
            problem = nil
        } catch { problem = Self.notice(error) }
    }

    func importLinks(_ text: String) {
        perform { [library] in
            let result = try await library.importLinks(text)
            return Msg("sources.imported", String(result.profiles.count), String(result.unsupported + result.refused + result.excess))
        }
    }

    func saveSubscription(label: String, url: String) {
        perform { [library] in
            _ = try await library.saveSubscription(label: label, url: url)
            return Msg("sources.saved")
        }
    }

    func refresh(sourceId: String) {
        perform(refresh: true) { [library] in
            let result = try await library.refresh(sourceId: sourceId)
            return Msg("sources.updated", String(result.snapshot.library.profiles.count),
                       String(result.snapshot.unsupported + result.snapshot.refused + result.snapshot.excess))
        }
    }

    func deleteSubscription(sourceId: String) {
        perform { [library] in
            try await library.deleteSubscription(sourceId: sourceId)
            return Msg("sources.deleted")
        }
    }

    func selectServer(id: String?, sourceId: String) {
        perform { [library] in
            try await library.selectServer(id: id, sourceId: sourceId)
            return Msg("sources.selectionSaved")
        }
    }

    func removeManualServer(id: String) {
        perform { [library] in
            try await library.removeManualServer(id: id)
            return Msg("sources.deleted")
        }
    }

    func cancel() { operation?.cancel() }

    func close() async {
        operation?.cancel()
        await library.close()
    }

    private func perform(refresh: Bool = false, _ action: @escaping () async throws -> Msg) {
        guard !isWorking, snapshot != nil else { return }
        isWorking = true
        isRefreshing = refresh
        message = nil
        problem = nil
        operation = Task {
            defer { isWorking = false; isRefreshing = false; operation = nil }
            do {
                let notice = try await action()
                snapshot = try await library.snapshot()
                message = notice
            } catch {
                if error is CancellationError || (error as? SubscriptionError) == .cancelled {
                    message = Msg("sources.cancelled")
                } else {
                    problem = Self.notice(error)
                }
                // A failed refresh keeps its last successful list. A partial disk
                // failure still reloads whatever was actually committed.
                do { snapshot = try await library.snapshot() }
                catch { problem = Self.notice(error) }
            }
        }
    }

    static func configurationNotice(_ error: Error) -> Msg { notice(error) }

    private static func notice(_ error: Error) -> Msg {
        if let error = error as? SubscriptionError {
            switch error {
            case .network: return Msg("sources.networkError")
            case .tls: return Msg("sources.tlsError")
            case .timeout: return Msg("sources.timeoutError")
            case .size: return Msg("sources.sizeError")
            case .source, .redirect: return Msg("sources.invalid", "sourceURL")
            case .busy: return Msg("sources.busyError")
            case .cancelled: return Msg("sources.cancelled")
            default: return Msg("sources.formatError")
            }
        }
        if let error = error as? SubscriptionHTTPError { return Msg("sources.httpError", String(error.status)) }
        if let error = error as? ConnectionContractError { return Msg("sources.invalid", error.field.rawValue) }
        // Filesystem errors may contain private paths. Never stringify them.
        return Msg("sources.storageError")
    }
}
