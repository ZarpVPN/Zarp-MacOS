import Foundation

/// Numeric control endpoint, never resolved using DNS. The daemon applies its own validation
/// and the WARP certificate pin to every custom address.
public struct WarpEndpoint: Hashable, Sendable, CustomStringConvertible {
    public let address: IPAddress
    public let port: UInt16

    public init?(_ text: String) {
        let host: String
        let portText: String
        if text.hasPrefix("["), let end = text.firstIndex(of: "]"), text[text.index(after: end)...].hasPrefix(":") {
            host = String(text[text.index(after: text.startIndex)..<end])
            portText = String(text[text.index(end, offsetBy: 2)...])
            guard let ip = IPAddress(host), ip.version == 6 else { return nil }
        } else {
            let parts = text.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 2 else { return nil }
            host = String(parts[0]); portText = String(parts[1])
        }
        guard let ip = IPAddress(host), !portText.isEmpty,
              portText.utf8.allSatisfy({ (48...57).contains($0) }),
              let port = UInt16(portText), port > 0 else { return nil }
        // Reject special, private, link-local and multicast destinations in the custom contract.
        let b = ip.bytes
        if ip.version == 4 {
            guard b[0] != 0, b[0] != 10, b[0] != 127, b[0] < 224,
                  !(b[0] == 169 && b[1] == 254), !(b[0] == 172 && (16...31).contains(b[1])),
                  !(b[0] == 192 && b[1] == 168), !(b[0] == 100 && (64...127).contains(b[1])) else { return nil }
        } else {
            guard (0x20...0x3f).contains(b[0]) else { return nil }
        }
        self.address = ip; self.port = port
    }

    public var description: String {
        address.version == 6 ? "[\(address)]:\(port)" : "\(address):\(port)"
    }

    /// Internal provider token. IPC sends a numeric endpoint plus an explicit custom policy.
    public var requestToken: String { "custom:" + description }

    public static let maxCount = 64

    public static func parseList(_ text: String) throws -> [WarpEndpoint] {
        guard text.utf8.count <= 16_384 else { throw ListError(line: 0) }
        let lines = text.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n")
        var list: [WarpEndpoint] = []
        var seen = Set<WarpEndpoint>()
        for (index, raw) in lines.components(separatedBy: "\n").enumerated() {
            let value = raw.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]
                .trimmingCharacters(in: .whitespaces)
            if value.isEmpty { continue }
            guard let endpoint = WarpEndpoint(value) else { throw ListError(line: index + 1) }
            if seen.insert(endpoint).inserted { list.append(endpoint) }
            guard list.count <= maxCount else { throw ListError(line: index + 1) }
        }
        return list
    }

    public struct ListError: Error, Sendable { public let line: Int }
}
