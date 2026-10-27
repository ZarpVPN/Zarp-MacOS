import Foundation

public enum SubscriptionError: String, Error, Sendable {
    case source, size, encoding, empty, html, json, redirect, timeout, cancelled, network, tls, http, busy
}

/// Counts name only categories. Raw links, tokens and refused field values are
/// never retained in diagnostics. Accepted profiles use the shared strict import.
public struct SubscriptionResult: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public enum Format: String, Codable, Sendable { case links, html, json }
    public let profiles: [ServerProfile]
    public let unsupported: Int
    public let refused: Int
    public let excess: Int
    public let format: Format
    public var description: String {
        "SubscriptionResult(\(profiles.count) profiles, unsupported=\(unsupported), refused=\(refused), excess=\(excess), \(format.rawValue))"
    }
    public var debugDescription: String { description }

    public func requiringProfiles() throws -> Self {
        guard !profiles.isEmpty else {
            switch format {
            case .html: throw SubscriptionError.html
            case .json: throw SubscriptionError.json
            case .links: throw SubscriptionError.empty
            }
        }
        return self
    }
}

/// Pure bounded list import. No DNS, HTTP, account, runtime or filesystem work.
/// Input is the response body after decompression, never arbitrary client JSON.
public enum SubscriptionParser {
    public static let maxBytes = 2 * 1024 * 1024
    public static let maxProfiles = 200

    public static func parse(_ data: Data) throws -> SubscriptionResult {
        guard data.count <= maxBytes else { throw SubscriptionError.size }
        guard let body = String(data: data, encoding: .utf8) else { throw SubscriptionError.encoding }
        var text = cleaned(body)
        if !text.split(whereSeparator: \.isNewline).contains(where: { scheme(cleaned(String($0))) != nil }),
           let decoded = decodedBase64(text) {
            text = cleaned(decoded)
        }
        if text.hasPrefix("{") || text.hasPrefix("[") {
            return SubscriptionResult(profiles: [], unsupported: 0, refused: 0, excess: 0, format: .json)
        }
        if text.lowercased().hasPrefix("<!doctype") || text.lowercased().hasPrefix("<html") {
            return SubscriptionResult(profiles: [], unsupported: 0, refused: 0, excess: 0, format: .html)
        }
        var profiles: [ServerProfile] = []
        var seen = Set<String>()
        var unsupported = 0, refused = 0, excess = 0
        for raw in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            let line = cleaned(String(raw))
            if line.isEmpty || line.hasPrefix("#") { continue }
            guard let name = scheme(line), ["vless", "trojan", "hy2", "hysteria2"].contains(name) else {
                unsupported += 1
                continue
            }
            let profile: ServerProfile
            do { profile = try ServerLinkImporter.parse(line) }
            catch { refused += 1; continue }
            guard seen.insert(profile.id).inserted else { continue }
            if profiles.count == maxProfiles { excess += 1; continue }
            profiles.append(profile)
        }
        return SubscriptionResult(profiles: profiles, unsupported: unsupported, refused: refused, excess: excess, format: .links)
    }

    private static func cleaned(_ text: String) -> String {
        var result = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if result.hasPrefix("\u{feff}") { result.removeFirst() }
        return result.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func scheme(_ text: String) -> String? {
        guard let separator = text.range(of: "://") else { return nil }
        let bytes = Array(text[..<separator.lowerBound].utf8)
        guard let first = bytes.first, (65...90).contains(first) || (97...122).contains(first),
              bytes.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [43, 45, 46].contains($0) }) else { return nil }
        return text[..<separator.lowerBound].lowercased()
    }

    private static func decodedBase64(_ text: String) -> String? {
        let compact = text.utf8.filter { ![9, 10, 13, 32].contains($0) }
        guard compact.count >= 8 else { return nil }
        let padding = compact.reversed().prefix(while: { $0 == 61 }).count
        guard padding <= 2 else { return nil }
        let raw = compact.dropLast(padding)
        guard raw.count % 4 != 1,
              raw.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [43, 47, 45, 95].contains($0) }) else { return nil }
        let required = (4 - raw.count % 4) % 4
        guard padding == 0 || padding == required else { return nil }
        let normalized = String(decoding: raw.map { $0 == 45 ? 43 : ($0 == 95 ? 47 : $0) }, as: UTF8.self) + String(repeating: "=", count: required)
        guard let data = Data(base64Encoded: normalized), data.count <= maxBytes,
              data.base64EncodedString() == normalized, let decoded = String(data: data, encoding: .utf8) else { return nil }
        let clean = cleaned(decoded)
        guard clean.contains("://") || clean.hasPrefix("{") || clean.hasPrefix("[") ||
              clean.lowercased().hasPrefix("<!doctype") || clean.lowercased().hasPrefix("<html") else { return nil }
        return decoded
    }
}
