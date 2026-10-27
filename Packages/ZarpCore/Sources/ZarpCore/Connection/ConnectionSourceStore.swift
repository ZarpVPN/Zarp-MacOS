import Foundation

/// Token-bearing source URLs live in a separate restricted document. This store
/// never downloads or changes a live connection when a selection changes.
public final class ConnectionSourceStore: @unchecked Sendable {
    private let file: PrivateConnectionFile
    private let lock = NSLock()

    public init(url: URL) { file = PrivateConnectionFile(url: url, maxBytes: ConnectionSourceLibrary.maxBytes) }

    public func load() throws -> ConnectionSourceLibrary {
        lock.lock(); defer { lock.unlock() }
        return try withFileErrors {
            guard let data = try file.load() else { return try ConnectionSourceLibrary() }
            return try ConnectionSourceLibrary.decode(data)
        }
    }

    public func save(_ library: ConnectionSourceLibrary) throws {
        lock.lock(); defer { lock.unlock() }
        try library.validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data: Data
        do { data = try encoder.encode(library) }
        catch { throw ConnectionSourceLibraryError.sources }
        try withFileErrors { try file.save(data) }
    }

    private func withFileErrors<T>(_ body: () throws -> T) throws -> T {
        do { return try body() }
        catch let error as PrivateConnectionFileError {
            switch error {
            case .location: throw ConnectionSourceLibraryError.location
            case .permissions: throw ConnectionSourceLibraryError.permissions
            case .io: throw ConnectionSourceLibraryError.io
            case .size: throw ConnectionSourceLibraryError.sources
            }
        }
    }
}
