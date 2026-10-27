import Foundation

public struct SubscriptionRefreshNotice: Equatable, Sendable {
    public let reason: SubscriptionError
    public let httpStatus: Int?
}

public enum SubscriptionRefreshOutcome: Sendable {
    case fresh(SubscriptionSnapshot)
    case updated(SubscriptionCacheUpdate)
    case cached(SubscriptionSnapshot, SubscriptionRefreshNotice)
}

/// An unprivileged owner of cache refreshes. It has no connection/provider/IPC
/// reference, so a refresh cannot change an active pair or enroll a WARP account.
/// ConnectionLibrary coordinates source metadata and GUI actions separately.
public actor SubscriptionRepository {
    private struct Pending {
        let generation: UUID
        let task: Task<SubscriptionResult, Error>
    }
    private let cache: SubscriptionCache
    private let downloader: SubscriptionDownloader
    private let now: @Sendable () -> Date
    private var pending: [String: Pending] = [:]
    private var closed = false

    public init(cache: SubscriptionCache, downloader: SubscriptionDownloader, now: @escaping @Sendable () -> Date = { Date() }) {
        self.cache = cache; self.downloader = downloader; self.now = now
    }

    public func cached(source: ConnectionSource) throws -> SubscriptionSnapshot? { try cache.load(source: source) }

    public func select(serverId: String?, source: ConnectionSource) throws {
        guard !closed else { throw SubscriptionError.cancelled }
        try cache.select(serverId: serverId, source: source)
    }

    public func refresh(source: ConnectionSource) async throws -> SubscriptionCacheUpdate {
        guard !closed else { throw SubscriptionError.cancelled }
        do { try source.validate() } catch { throw SubscriptionError.source }
        guard source.kind == .subscription else { throw SubscriptionError.source }
        guard pending[source.id] == nil, pending.count < 4 else { throw SubscriptionError.busy }
        try Task.checkCancellation()
        let generation = UUID(), downloader = self.downloader
        let task = Task { try await downloader.load(source: source).requiringProfiles() }
        pending[source.id] = Pending(generation: generation, task: task)
        defer {
            if pending[source.id]?.generation == generation { pending.removeValue(forKey: source.id) }
        }
        return try await withTaskCancellationHandler {
            do {
                let result = try await task.value
                try Task.checkCancellation()
                guard !closed, pending[source.id]?.generation == generation else { throw SubscriptionError.cancelled }
                // Load the current selection under the cache lock after fetching.
                // User selection changes during the request must not be lost.
                return try cache.replace(source: source, result: result, updatedAt: now())
            } catch is CancellationError { throw SubscriptionError.cancelled }
        } onCancel: { task.cancel() }
    }

    /// A stale list can be used offline with a static warning after a failed
    /// refresh. User cancellation is propagated and never becomes a connect.
    public func refreshIfNeeded(source: ConnectionSource) async throws -> SubscriptionRefreshOutcome {
        guard !closed else { throw SubscriptionError.cancelled }
        let previous = try cache.load(source: source)
        if let previous, previous.isFresh(at: now()) { return .fresh(previous) }
        do { return .updated(try await refresh(source: source)) }
        catch let error as SubscriptionError {
            guard error != .cancelled, error != .busy, let previous else { throw error }
            return .cached(previous, SubscriptionRefreshNotice(reason: error, httpStatus: nil))
        } catch let error as SubscriptionHTTPError {
            guard let previous else { throw error }
            return .cached(previous, SubscriptionRefreshNotice(reason: .http, httpStatus: error.status))
        }
    }

    /// Cancelling/removing this generation before deletion prevents its delayed
    /// completion from recreating the cache. Other sources/runs are unaffected.
    public func delete(source: ConnectionSource) throws {
        guard !closed else { throw SubscriptionError.cancelled }
        pending.removeValue(forKey: source.id)?.task.cancel()
        try cache.delete(source: source)
    }

    public func close() async {
        closed = true
        let tasks = pending.values.map(\.task)
        pending.removeAll()
        for task in tasks { task.cancel() }
        for task in tasks { _ = try? await task.value }
    }
}
