import Foundation

public enum ServerProfileLibraryError: String, Error, Sendable {
    case version, profiles, selection, location, permissions, io
}

/// A separate collection keeps existing WARP settings/account/history authoritative.
/// A missing collection is the migration from WARP-only builds: no server selection.
public struct ServerProfileLibrary: Codable, Equatable, Sendable, CustomStringConvertible {
    public static let schemaVersion = 1
    public static let maxProfiles = 200
    public static let maxBytes = 2 * 1024 * 1024

    public let version: Int
    public private(set) var profiles: [ServerProfile]
    public private(set) var selectedServerId: String?

    public enum Selection: Equatable, Sendable {
        case automatic
        case available(ServerProfile)
        case unavailable(String)
    }

    public var selection: Selection {
        guard let id = selectedServerId else { return .automatic }
        return profiles.first(where: { $0.id == id }).map(Selection.available) ?? .unavailable(id)
    }

    public var description: String { "ServerProfileLibrary(\(profiles.count) profiles, redacted)" }

    public init(profiles: [ServerProfile] = [], selectedServerId: String? = nil) throws {
        self.version = Self.schemaVersion
        self.profiles = profiles
        self.selectedServerId = selectedServerId
        try validate()
    }

    public func validate() throws {
        guard version == Self.schemaVersion else { throw ServerProfileLibraryError.version }
        guard profiles.count <= Self.maxProfiles, Set(profiles.map(\.id)).count == profiles.count else {
            throw ServerProfileLibraryError.profiles
        }
        for profile in profiles { try profile.validate() }
        if let id = selectedServerId {
            guard id.hasPrefix("server-v1-"), id.utf8.count == 74,
                  id.dropFirst(10).utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                throw ServerProfileLibraryError.selection
            }
        }
    }

    public mutating func upsert(_ profile: ServerProfile) throws {
        try profile.validate()
        if let index = profiles.firstIndex(where: { $0.id == profile.id }) {
            profiles[index] = profile
        } else {
            guard profiles.count < Self.maxProfiles else { throw ServerProfileLibraryError.profiles }
            profiles.append(profile)
        }
    }

    /// Removing a chosen server preserves its ID as unavailable, without substitution.
    public mutating func remove(id: String) { profiles.removeAll { $0.id == id } }

    public mutating func select(id: String?) throws {
        var changed = self
        changed.selectedServerId = id
        try changed.validate()
        self = changed
    }

    public static func decode(_ data: Data) throws -> ServerProfileLibrary {
        guard data.count <= maxBytes else { throw ServerProfileLibraryError.profiles }
        do {
            try StrictContractJSON.validate(data)
            return try JSONDecoder().decode(Self.self, from: data)
        } catch let error as ServerProfileLibraryError { throw error }
        catch let error as ConnectionContractError { throw error }
        catch { throw ServerProfileLibraryError.profiles }
    }

    private enum CodingKeys: String, CodingKey { case version, profiles, selectedServerId }
    private struct Key: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }

    public init(from decoder: Decoder) throws {
        do {
            let raw = try decoder.container(keyedBy: Key.self)
            guard raw.allKeys.allSatisfy({ ["version", "profiles", "selectedServerId"].contains($0.stringValue) }) else {
                throw ServerProfileLibraryError.profiles
            }
            let c = try decoder.container(keyedBy: CodingKeys.self)
            version = try c.decode(Int.self, forKey: .version)
            guard version == Self.schemaVersion else { throw ServerProfileLibraryError.version }
            profiles = try c.decode([ServerProfile].self, forKey: .profiles)
            selectedServerId = try c.decodeIfPresent(String.self, forKey: .selectedServerId)
            try validate()
        } catch let error as ServerProfileLibraryError { throw error }
        catch let error as ConnectionContractError { throw error }
        catch { throw ServerProfileLibraryError.profiles }
    }
}
