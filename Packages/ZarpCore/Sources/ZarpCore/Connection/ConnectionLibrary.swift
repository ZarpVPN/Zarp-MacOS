import Foundation

public enum ConnectionLibraryError: String, Error, Sendable {
    case source, selection, emptyConfiguration, busy
}

/// Saved configuration only. This owner cannot open IPC, enroll WARP, or change a tunnel.
public struct ConnectionLibrarySnapshot: Sendable {
    public let sources: ConnectionSourceLibrary
    public let manual: ServerProfileLibrary
    public let subscriptions: [String: SubscriptionSnapshot]
    public let unreadableSourceIds: Set<String>

    public func library(sourceId: String) -> ServerProfileLibrary? {
        guard let source = sources.sources.first(where: { $0.id == sourceId }) else { return nil }
        switch source.kind {
        case .warp: return nil
        case .manual: return manual
        case .subscription: return subscriptions[sourceId]?.library
        }
    }
}

/// Coordinates the existing private stores and downloader for the unprivileged GUI.
/// Loading, importing and selecting never download. Refresh is explicit or
/// requested by the connection lifecycle when a subscription cache is stale.
public actor ConnectionLibrary {
    private let sources: ConnectionSourceStore
    private let manual: ServerProfileStore
    private let cache: SubscriptionCache
    private let repository: SubscriptionRepository
    private var refreshing = Set<String>()

    public init(directory: URL, transport: any SubscriptionHTTPTransport) {
        sources = ConnectionSourceStore(url: directory.appendingPathComponent("connection-sources.json"))
        manual = ServerProfileStore(url: directory.appendingPathComponent("server-profiles.json"))
        cache = SubscriptionCache(directory: directory.appendingPathComponent("subscriptions", isDirectory: true))
        repository = SubscriptionRepository(cache: cache, downloader: SubscriptionDownloader(transport: transport))
    }

    public func snapshot() throws -> ConnectionLibrarySnapshot {
        let sourceLibrary = try sources.load()
        let manualLibrary = try manual.load()
        var subscriptions: [String: SubscriptionSnapshot] = [:]
        var unreadable = Set<String>()
        for source in sourceLibrary.sources where source.kind == .subscription {
            do { subscriptions[source.id] = try cache.load(source: source) }
            catch { unreadable.insert(source.id) }
        }
        return ConnectionLibrarySnapshot(sources: sourceLibrary, manual: manualLibrary, subscriptions: subscriptions,
                                         unreadableSourceIds: unreadable)
    }

    /// Validate the complete merged collection before writing profiles. An empty or
    /// over-capacity import leaves the previous collection intact.
    @discardableResult
    public func importLinks(_ text: String) throws -> SubscriptionResult {
        let result = try SubscriptionParser.parse(Data(text.utf8)).requiringProfiles()
        var profiles = try manual.load()
        for profile in result.profiles { try profiles.upsert(profile) }
        var library = try sources.load()
        let source = try ConnectionSource(kind: .manual)
        try library.upsert(source)
        // If the second write fails, only an empty manual source can be added.
        // Existing server profiles are never partially replaced by a failed merge.
        try sources.save(library)
        try manual.save(profiles)
        return result
    }

    /// The exact URL defines identity. Renaming the same URL keeps its cache and
    /// selection. A new URL creates a new source without rebinding the old one.
    @discardableResult
    public func saveSubscription(label: String, url: String) throws -> ConnectionSource {
        let source = try ConnectionSource(kind: .subscription, label: label, subscriptionURL: url)
        var library = try sources.load()
        try library.upsert(source)
        try sources.save(library)
        return source
    }

    public func selectServer(id: String?, sourceId: String) throws {
        let state = try snapshot()
        guard let source = state.sources.sources.first(where: { $0.id == sourceId }), source.kind != .warp,
              let profiles = state.library(sourceId: sourceId) else { throw ConnectionLibraryError.source }
        guard id == nil || profiles.profiles.contains(where: { $0.id == id }) else { throw ConnectionLibraryError.selection }
        if source.kind == .manual {
            var changed = profiles
            try changed.select(id: id)
            try manual.save(changed)
        } else {
            try cache.select(serverId: id, source: source)
        }
    }

    public func selectSource(id: String) throws {
        var library = try sources.load()
        guard library.sources.contains(where: { $0.id == id }) else { throw ConnectionLibraryError.source }
        try library.select(id: id)
        try sources.save(library)
    }

    /// The compact connection editor accepts one subscription URL or an inline link list.
    /// Saving a URL refreshes it before activation; failed downloads never select empty data.
    public func configureServer(input: String, existingSourceID: String?) async throws -> ConnectionSource {
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.lowercased().hasPrefix("https://") {
            let previous = try snapshot().sources.sources.first { $0.id == existingSourceID && $0.subscriptionURL == text }
            let source = try saveSubscription(label: previous?.label ?? "", url: text)
            _ = try await refresh(sourceId: source.id)
            try Task.checkCancellation()
            return source
        }
        if !text.isEmpty {
            let parsed = try SubscriptionParser.parse(Data(text.utf8)).requiringProfiles()
            guard parsed.unsupported == 0, parsed.refused == 0, parsed.excess == 0 else { throw ConnectionLibraryError.source }
            let profiles = try ServerProfileLibrary(profiles: parsed.profiles)
            let source = try ConnectionSource(kind: .manual)
            var saved = try sources.load()
            try saved.upsert(source)
            try sources.save(saved)
            try manual.save(profiles)
            return source
        }
        let current = try snapshot()
        guard let source = current.sources.sources.first(where: { $0.id == existingSourceID && $0.kind != .warp }),
              !(current.library(sourceId: source.id)?.profiles.isEmpty ?? true) else {
            throw ConnectionLibraryError.emptyConfiguration
        }
        return source
    }

    public func refreshIfNeeded(sourceId: String) async throws -> SubscriptionRefreshOutcome? {
        guard let source = try sources.load().sources.first(where: { $0.id == sourceId }) else {
            throw ConnectionLibraryError.source
        }
        guard source.kind == .subscription else { return nil }
        let result = try await repository.refreshIfNeeded(source: source)
        guard try sources.load().sources.contains(where: { $0.id == sourceId }) else { throw SubscriptionError.cancelled }
        return result
    }

    public func removeManualServer(id: String) throws {
        var library = try manual.load()
        library.remove(id: id)
        try manual.save(library)
    }

    public func refresh(sourceId: String) async throws -> SubscriptionCacheUpdate {
        guard let source = try sources.load().sources.first(where: { $0.id == sourceId && $0.kind == .subscription }) else {
            throw ConnectionLibraryError.source
        }
        guard refreshing.insert(sourceId).inserted else { throw SubscriptionError.busy }
        defer { refreshing.remove(sourceId) }
        let update = try await repository.refresh(source: source)
        // Deleting a source while awaiting HTTP cannot publish it back into the GUI.
        guard try sources.load().sources.contains(where: { $0.id == sourceId }) else { throw SubscriptionError.cancelled }
        return update
    }

    public func deleteSubscription(sourceId: String) async throws {
        var library = try sources.load()
        guard let source = library.sources.first(where: { $0.id == sourceId && $0.kind == .subscription }) else {
            throw ConnectionLibraryError.source
        }
        try library.remove(id: sourceId)
        // Commit metadata before waiting for the cache owner, so future refresh
        // calls cannot begin for a removed source. The repository cancels its fetch.
        try sources.save(library)
        try await repository.delete(source: source)
    }

    public func close() async { await repository.close() }
}
