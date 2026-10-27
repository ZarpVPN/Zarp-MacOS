import Foundation

public enum SubscriptionCacheError: String, Error, Sendable {
    case source, version, snapshot, stale, location, permissions, io
}

/// A cache is bound to the hash of the exact original URL, not a redirect target.
/// Secrets stay in the restricted source/profile documents and out of diagnostics.
public struct SubscriptionSnapshot: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public static let schemaVersion = 1
    public static let maxBytes = 2 * 1024 * 1024
    public static let maxAgeMilliseconds: Int64 = 12 * 60 * 60 * 1000
    public let version: Int
    public let sourceId: String
    public let updatedAtMilliseconds: Int64
    public private(set) var library: ServerProfileLibrary
    public let unsupported: Int
    public let refused: Int
    public let excess: Int

    public var description: String { "SubscriptionSnapshot(\(library.profiles.count) profiles, redacted)" }
    public var debugDescription: String { description }

    public init(source: ConnectionSource, result: SubscriptionResult, updatedAt: Date, selectedServerId: String? = nil) throws {
        try source.validate()
        guard source.kind == .subscription else { throw SubscriptionCacheError.source }
        _ = try result.requiringProfiles()
        let milliseconds = updatedAt.timeIntervalSince1970 * 1000
        guard milliseconds.isFinite, milliseconds > 0, milliseconds <= 253_402_300_799_999 else { throw SubscriptionCacheError.snapshot }
        version = Self.schemaVersion
        sourceId = source.id
        updatedAtMilliseconds = Int64(milliseconds)
        library = try ServerProfileLibrary(profiles: result.profiles, selectedServerId: selectedServerId)
        unsupported = result.unsupported; refused = result.refused; excess = result.excess
        try validate()
    }

    public func isFresh(at date: Date) -> Bool {
        let milliseconds = date.timeIntervalSince1970 * 1000
        guard milliseconds.isFinite, milliseconds >= Double(updatedAtMilliseconds) else { return false }
        return milliseconds - Double(updatedAtMilliseconds) < Double(Self.maxAgeMilliseconds)
    }

    public mutating func select(serverId: String?) throws { try library.select(id: serverId) }

    public func validate() throws {
        guard version == Self.schemaVersion else { throw SubscriptionCacheError.version }
        guard sourceId.hasPrefix("source-v1-"), sourceId.utf8.count == 74,
              sourceId.dropFirst(10).utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              updatedAtMilliseconds > 0, updatedAtMilliseconds <= 253_402_300_799_999,
              !library.profiles.isEmpty, [unsupported, refused, excess].allSatisfy({ (0...SubscriptionParser.maxBytes).contains($0) }) else {
            throw SubscriptionCacheError.snapshot
        }
        try library.validate()
    }

    public static func decode(_ data: Data) throws -> Self {
        guard data.count <= maxBytes else { throw SubscriptionCacheError.snapshot }
        do {
            try StrictContractJSON.validate(data)
            return try JSONDecoder().decode(Self.self, from: data)
        } catch let error as SubscriptionCacheError { throw error }
        catch { throw SubscriptionCacheError.snapshot }
    }

    private enum CodingKeys: String, CodingKey {
        case version, sourceId, updatedAtMilliseconds, library, unsupported, refused, excess
    }
    private struct Key: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
    public init(from decoder: Decoder) throws {
        do {
            let raw = try decoder.container(keyedBy: Key.self)
            guard raw.allKeys.allSatisfy({ ["version", "sourceId", "updatedAtMilliseconds", "library", "unsupported", "refused", "excess"].contains($0.stringValue) }) else {
                throw SubscriptionCacheError.snapshot
            }
            let c = try decoder.container(keyedBy: CodingKeys.self)
            version = try c.decode(Int.self, forKey: .version)
            sourceId = try c.decode(String.self, forKey: .sourceId)
            updatedAtMilliseconds = try c.decode(Int64.self, forKey: .updatedAtMilliseconds)
            library = try c.decode(ServerProfileLibrary.self, forKey: .library)
            unsupported = try c.decode(Int.self, forKey: .unsupported)
            refused = try c.decode(Int.self, forKey: .refused)
            excess = try c.decode(Int.self, forKey: .excess)
            try validate()
        } catch let error as SubscriptionCacheError { throw error }
        catch { throw SubscriptionCacheError.snapshot }
    }
}

public struct SubscriptionCacheUpdate: Sendable {
    public let snapshot: SubscriptionSnapshot
    /// Configuration IDs removed by the refresh. The runtime owner decides when
    /// to invalidate their results; refreshing this document never changes a run.
    public let removedServerIds: Set<String>
}

/// Each source gets one restricted, atomic document. This store never downloads,
/// replaces an active pair, changes sources or touches WARP preferences/accounts.
public final class SubscriptionCache: @unchecked Sendable {
    private let directory: URL
    private let lock = NSLock()

    public init(directory: URL) { self.directory = directory }

    public func load(source: ConnectionSource) throws -> SubscriptionSnapshot? {
        lock.lock(); defer { lock.unlock() }
        return try loadLocked(source: source)
    }

    public func replace(source: ConnectionSource, result: SubscriptionResult, updatedAt: Date) throws -> SubscriptionCacheUpdate {
        lock.lock(); defer { lock.unlock() }
        let old = try loadLocked(source: source)
        let snapshot = try SubscriptionSnapshot(source: source, result: result, updatedAt: updatedAt, selectedServerId: old?.library.selectedServerId)
        if let old, snapshot.updatedAtMilliseconds < old.updatedAtMilliseconds { throw SubscriptionCacheError.stale }
        try saveLocked(snapshot, source: source)
        let removed = Set(old?.library.profiles.map(\.id) ?? []).subtracting(snapshot.library.profiles.map(\.id))
        return SubscriptionCacheUpdate(snapshot: snapshot, removedServerIds: removed)
    }

    public func select(serverId: String?, source: ConnectionSource) throws {
        lock.lock(); defer { lock.unlock() }
        guard var snapshot = try loadLocked(source: source) else { throw SubscriptionCacheError.snapshot }
        try snapshot.select(serverId: serverId)
        try saveLocked(snapshot, source: source)
    }

    public func delete(source: ConnectionSource) throws {
        lock.lock(); defer { lock.unlock() }
        try withFileErrors { try file(source: source).delete() }
    }

    private func loadLocked(source: ConnectionSource) throws -> SubscriptionSnapshot? {
        try withFileErrors {
            guard let data = try file(source: source).load() else { return nil }
            let snapshot = try SubscriptionSnapshot.decode(data)
            guard snapshot.sourceId == source.id else { throw SubscriptionCacheError.source }
            return snapshot
        }
    }

    private func saveLocked(_ snapshot: SubscriptionSnapshot, source: ConnectionSource) throws {
        try snapshot.validate()
        guard snapshot.sourceId == source.id else { throw SubscriptionCacheError.source }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data: Data
        do { data = try encoder.encode(snapshot) } catch { throw SubscriptionCacheError.snapshot }
        try withFileErrors { try file(source: source).save(data) }
    }

    private func file(source: ConnectionSource) throws -> PrivateConnectionFile {
        try source.validate()
        guard source.kind == .subscription, directory.isFileURL else { throw SubscriptionCacheError.source }
        return PrivateConnectionFile(url: directory.appendingPathComponent(source.id + ".json"), maxBytes: SubscriptionSnapshot.maxBytes)
    }

    private func withFileErrors<T>(_ body: () throws -> T) throws -> T {
        do { return try body() }
        catch let error as PrivateConnectionFileError {
            switch error {
            case .location: throw SubscriptionCacheError.location
            case .permissions: throw SubscriptionCacheError.permissions
            case .io: throw SubscriptionCacheError.io
            case .size: throw SubscriptionCacheError.snapshot
            }
        }
    }
}
