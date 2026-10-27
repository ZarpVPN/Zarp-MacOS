import Foundation

/// Restricted, atomic storage with static errors. Damaged data is preserved.
public final class ServerProfileStore: @unchecked Sendable {
    private let file: PrivateConnectionFile
    private let lock = NSLock()

    public init(url: URL) { file = PrivateConnectionFile(url: url, maxBytes: ServerProfileLibrary.maxBytes) }

    public func load() throws -> ServerProfileLibrary {
        lock.lock(); defer { lock.unlock() }
        return try withFileErrors {
            guard let data = try file.load() else { return try ServerProfileLibrary() }
            return try ServerProfileLibrary.decode(data)
        }
    }

    public func save(_ library: ServerProfileLibrary) throws {
        lock.lock(); defer { lock.unlock() }
        try library.validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data: Data
        do { data = try encoder.encode(library) }
        catch { throw ServerProfileLibraryError.profiles }
        try withFileErrors { try file.save(data) }
    }

    private func withFileErrors<T>(_ body: () throws -> T) throws -> T {
        do { return try body() }
        catch let error as PrivateConnectionFileError {
            switch error {
            case .location: throw ServerProfileLibraryError.location
            case .permissions: throw ServerProfileLibraryError.permissions
            case .io: throw ServerProfileLibraryError.io
            case .size: throw ServerProfileLibraryError.profiles
            }
        }
    }
}
