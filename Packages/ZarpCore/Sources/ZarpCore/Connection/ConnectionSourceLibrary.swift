import Foundation

public enum ConnectionSourceLibraryError: String, Error, Sendable {
    case version, sources, selection, location, permissions, io
}

/// Source metadata is independent of WARP preferences and server/cache contents.
/// Renaming preserves identity. Changing a URL creates a different source.
public struct ConnectionSourceLibrary: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public static let schemaVersion = 1
    public static let maxSources = 32
    public static let maxBytes = 512 * 1024

    public let version: Int
    public private(set) var sources: [ConnectionSource]
    public private(set) var selectedSourceId: String

    public enum Selection: Equatable, Sendable {
        case available(ConnectionSource)
        case unavailable(String)
    }

    public var selection: Selection {
        sources.first(where: { $0.id == selectedSourceId }).map(Selection.available) ?? .unavailable(selectedSourceId)
    }
    public var description: String { "ConnectionSourceLibrary(\(sources.count) sources, redacted)" }
    public var debugDescription: String { description }

    /// Missing storage migrates to WARP without changing settings, enrolling an
    /// account, fetching URLs or activating a runtime.
    public init(sources: [ConnectionSource]? = nil, selectedSourceId: String? = nil) throws {
        let warp = try ConnectionSource(kind: .warp)
        version = Self.schemaVersion
        self.sources = sources ?? [warp]
        self.selectedSourceId = selectedSourceId ?? warp.id
        try validate()
    }

    public func validate() throws {
        guard version == Self.schemaVersion else { throw ConnectionSourceLibraryError.version }
        guard sources.count <= Self.maxSources, sources.contains(where: { $0.kind == .warp }),
              Set(sources.map(\.id)).count == sources.count else { throw ConnectionSourceLibraryError.sources }
        for source in sources { try source.validate() }
        guard selectedSourceId.hasPrefix("source-v1-"), selectedSourceId.utf8.count == 74,
              selectedSourceId.dropFirst(10).utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw ConnectionSourceLibraryError.selection
        }
    }

    public mutating func upsert(_ source: ConnectionSource) throws {
        try source.validate()
        if let index = sources.firstIndex(where: { $0.id == source.id }) {
            sources[index] = source
        } else {
            guard sources.count < Self.maxSources else { throw ConnectionSourceLibraryError.sources }
            sources.append(source)
        }
    }

    /// WARP remains available. Removing a chosen server source preserves its
    /// unavailable ID without silently selecting another source or WARP.
    public mutating func remove(id: String) throws {
        guard !sources.contains(where: { $0.id == id && $0.kind == .warp }) else { throw ConnectionSourceLibraryError.sources }
        sources.removeAll { $0.id == id }
    }

    public mutating func select(id: String) throws {
        var changed = self
        changed.selectedSourceId = id
        try changed.validate()
        self = changed
    }

    public static func decode(_ data: Data) throws -> Self {
        guard data.count <= maxBytes else { throw ConnectionSourceLibraryError.sources }
        do {
            try StrictContractJSON.validate(data)
            return try JSONDecoder().decode(Self.self, from: data)
        } catch let error as ConnectionSourceLibraryError { throw error }
        catch let error as ConnectionContractError { throw error }
        catch { throw ConnectionSourceLibraryError.sources }
    }

    private enum CodingKeys: String, CodingKey { case version, sources, selectedSourceId }
    private struct Key: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }

    public init(from decoder: Decoder) throws {
        do {
            let raw = try decoder.container(keyedBy: Key.self)
            guard raw.allKeys.allSatisfy({ ["version", "sources", "selectedSourceId"].contains($0.stringValue) }) else {
                throw ConnectionSourceLibraryError.sources
            }
            let c = try decoder.container(keyedBy: CodingKeys.self)
            version = try c.decode(Int.self, forKey: .version)
            guard version == Self.schemaVersion else { throw ConnectionSourceLibraryError.version }
            sources = try c.decode([ConnectionSource].self, forKey: .sources)
            do { selectedSourceId = try c.decode(String.self, forKey: .selectedSourceId) }
            catch { throw ConnectionSourceLibraryError.selection }
            try validate()
        } catch let error as ConnectionSourceLibraryError { throw error }
        catch let error as ConnectionContractError { throw error }
        catch { throw ConnectionSourceLibraryError.sources }
    }
}
