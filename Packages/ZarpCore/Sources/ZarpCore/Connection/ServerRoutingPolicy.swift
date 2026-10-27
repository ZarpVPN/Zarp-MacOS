import Foundation

/// Persisted choices and the typed server-routing IPC payload. No system operations.
public struct ServerRoutingPolicy: Codable, Equatable, Sendable {
    public enum ApplicationMode: String, Codable, Sendable, CaseIterable { case all, include, exclude }
    public var version: Int = 1
    public var applicationMode: ApplicationMode = .all
    public var applicationPaths: [String] = []
    public var ipv6: Bool = true
    public var dnsServer: String = "1.1.1.1"

    public init() {}
    public var isDefault: Bool { version == 1 && applicationMode == .all && ipv6 && dnsServer == "1.1.1.1" }
    public var filtersApplications: Bool { applicationMode != .all }

    public func validate() throws {
        guard version == 1, applicationPaths.count <= 128,
              Set(applicationPaths).count == applicationPaths.count,
              applicationPaths.allSatisfy(Self.validApplicationPath),
              applicationMode != .include || !applicationPaths.isEmpty,
              let address = IPAddress(dnsServer), (address.version != 4 || address.description == dnsServer), Self.validDNS(address), ipv6 || address.version == 4,
              let data = try? JSONEncoder().encode(self), data.count <= 32_768 else {
            throw ConnectionContractError(.routing)
        }
    }

    private static func validDNS(_ address: IPAddress) -> Bool {
        let bytes = address.bytes
        guard bytes.contains(where: { $0 != 0 }) else { return false }
        if bytes.count == 4 { return bytes[0] != 127 && bytes[0] < 224 && !(bytes[0] == 169 && bytes[1] == 254) }
        return bytes[0] != 255 && !(bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1) &&
            !(bytes[0] == 254 && bytes[1] & 0xc0 == 0x80) &&
            !(bytes.prefix(10).allSatisfy { $0 == 0 } && bytes[10] == 255 && bytes[11] == 255)
    }

    public static func validApplicationPath(_ path: String) -> Bool {
        path.hasPrefix("/") && path != "/" && path.utf8.count <= 1024 &&
            !path.hasSuffix("/") && !path.contains("//") &&
            !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) &&
            path.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
    }

    public func matchesApplication(executable: String) -> Bool {
        applicationPaths.contains { path in
            executable == path || (path.lowercased().hasSuffix(".app") && executable.hasPrefix(path + "/"))
        }
    }

    /// Corrupt stored routing must refuse a connection, rather than become an all-app tunnel.
    public static var invalid: ServerRoutingPolicy {
        var policy = ServerRoutingPolicy(); policy.version = 0; return policy
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version, applicationMode, applicationPaths, ipv6, dnsServer
    }

    public init(from decoder: Decoder) throws {
        let raw = try decoder.container(keyedBy: AnyKey.self)
        guard raw.allKeys.allSatisfy({ Set(CodingKeys.allCases.map(\.rawValue)).contains($0.stringValue) }) else {
            throw ConnectionContractError(.routing)
        }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        applicationMode = try c.decode(ApplicationMode.self, forKey: .applicationMode)
        applicationPaths = try c.decode([String].self, forKey: .applicationPaths)
        ipv6 = try c.decode(Bool.self, forKey: .ipv6)
        dnsServer = try c.decode(String.self, forKey: .dnsServer)
    }

    private struct AnyKey: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
}
