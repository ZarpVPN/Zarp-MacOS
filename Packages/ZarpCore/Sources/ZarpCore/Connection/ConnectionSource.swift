import Foundation

/// Source URLs can contain subscription tokens. Encode only into restricted storage.
/// This contract never downloads, refreshes, registers an account or starts a runtime.
public struct ConnectionSource: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public enum Kind: String, Codable, Sendable { case warp, manual, subscription }
    public static let maxURLBytes = 8192
    public static let maxBytes = 16_384
    public let kind: Kind
    public let label: String
    public let subscriptionURL: String?

    public var mode: ConnectionMode { kind == .warp ? .warp : .server }
    public var id: String {
        // Bind to the exact validated original URL, including tokens and query order.
        // A refresh redirect cannot silently rebind this source to its final URL.
        "source-v1-" + Strategy.fingerprint(["connection-source-v1", kind.rawValue, subscriptionURL ?? ""])
    }
    public var description: String { "ConnectionSource(\(kind.rawValue), redacted)" }
    public var debugDescription: String { description }

    public init(kind: Kind, label: String = "", subscriptionURL: String? = nil) throws {
        self.kind = kind; self.label = label; self.subscriptionURL = subscriptionURL
        try validate()
    }

    public func validate() throws {
        guard label.utf8.count <= 128, label.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw ConnectionContractError(.label)
        }
        if kind == .subscription {
            guard let subscriptionURL, Self.validHTTPSURL(subscriptionURL) else { throw ConnectionContractError(.sourceURL) }
        } else if subscriptionURL != nil { throw ConnectionContractError(.sourceURL) }
    }

    private static func validHTTPSURL(_ value: String) -> Bool {
        let punctuation = "-._~:/?@!$&'()*+,;=%[]".utf8
        guard !value.isEmpty, value.utf8.count <= maxURLBytes, value.utf8.allSatisfy({
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || punctuation.contains($0)
        }), let decoded = value.removingPercentEncoding,
            decoded.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }),
            let components = URLComponents(string: value, encodingInvalidCharacters: false),
            components.scheme?.lowercased() == "https", components.user == nil, components.password == nil,
            components.fragment == nil, let rawHost = components.percentEncodedHost, !rawHost.contains("%"),
            components.url != nil, let separator = value.range(of: "://") else { return false }
        let authority = value[separator.upperBound...].prefix(while: { $0 != "/" && $0 != "?" })
        guard authority.last != ":", components.port.map({ (1...65535).contains($0) }) ?? true,
              !components.percentEncodedPath.contains(where: { $0 == "[" || $0 == "]" }),
              !(components.percentEncodedQuery ?? "").contains(where: { $0 == "[" || $0 == "]" }) else { return false }
        if rawHost.hasPrefix("[") && rawHost.hasSuffix("]") {
            return IPAddress(String(rawHost.dropFirst().dropLast()))?.version == 6
        }
        return ServerProfile.hostIsValid(rawHost)
    }

    public static func decode(_ data: Data) throws -> Self {
        guard data.count <= maxBytes else { throw ConnectionContractError(.source) }
        do {
            try StrictContractJSON.validate(data)
            return try JSONDecoder().decode(Self.self, from: data)
        } catch let error as ConnectionContractError { throw error }
        catch { throw ConnectionContractError(.source) }
    }

    private enum CodingKeys: String, CodingKey { case kind, label, subscriptionURL }
    private struct Key: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
    public init(from decoder: Decoder) throws {
        let raw = try decoder.container(keyedBy: Key.self)
        guard raw.allKeys.allSatisfy({ ["kind", "label", "subscriptionURL"].contains($0.stringValue) }) else {
            throw ConnectionContractError(.parameters)
        }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind: Kind
        let label: String
        let url: String?
        do { kind = try c.decode(Kind.self, forKey: .kind) } catch { throw ConnectionContractError(.source) }
        do { label = try c.decodeIfPresent(String.self, forKey: .label) ?? "" } catch { throw ConnectionContractError(.label) }
        do { url = try c.decodeIfPresent(String.self, forKey: .subscriptionURL) } catch { throw ConnectionContractError(.sourceURL) }
        try self.init(kind: kind, label: label, subscriptionURL: url)
    }
}
