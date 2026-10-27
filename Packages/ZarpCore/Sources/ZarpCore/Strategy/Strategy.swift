import Foundation
import CryptoKit

/// WARP strategy names affect the outer ClientHello only. The enrolled
/// Cloudflare public key remains mandatory; these names are never resolved.
public enum WarpTLSName: String, CaseIterable, Sendable {
    case google = "www.google.com"
    case vk = "vk.com"
}

/// A WARP strategy: tunnel transport + the handshake-desync steps it asks for, written in
/// zapret2's `winws2` profile argument syntax — the same syntax Windows Zarp and Android Zarp
/// use. A usable product strategy must contain an executable outer desync step.
public struct Strategy: Identifiable, Hashable, Sendable {
    public let id: String
    /// Localization key for built-in strategies, resolved at display time so the name follows
    /// language changes (Windows `Strategy.NameKey`). `nil` for custom strategies, which keep the
    /// name the user typed in `strategies.txt`.
    public let nameKey: String?
    private let literalName: String
    var fallbackName: String { literalName }
    public let transport: Transport
    /// winws2-style profile arguments, e.g.
    /// `--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=6`.
    public let args: String
    public let isCustom: Bool
    public let countries: Set<StrategyCountry>
    public let legacyId: String?
    public let serverProfile: ServerProfile?
    public let sourceID: String?
    public let warpTLSName: WarpTLSName?
    public var mode: ConnectionMode { serverProfile == nil ? .warp : .server }
    public var transportTitle: String {
        serverProfile.map { $0.serverProtocol.rawValue + " / " + $0.transport.rawValue + " / " + $0.outerTransport.rawValue.uppercased() } ?? transport.title
    }

    /// Versioned, length-delimited executable input. Country tags and display names are excluded.
    public var configurationFingerprint: String {
        if let serverProfile {
            return Self.fingerprint(["server-config-v1", sourceID ?? "", serverProfile.id, transport.rawValue, args])
        }
        let version = transport == .masqueH2 ? "warp-config-h2-v3" : "warp-config-v3"
        var fields = [version, transport.rawValue, args]
        if let warpTLSName { fields += ["tls-name-v1", warpTLSName.rawValue] }
        return Self.fingerprint(fields)
    }

    static func fingerprint(_ fields: [String]) -> String {
        let bytes = fields.map { "\($0.utf8.count):\($0)" }.joined()
        return SHA256.hash(data: Data(bytes.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    public init(id: String, name: String, transport: Transport, args: String, isCustom: Bool = false, nameKey: String? = nil,
                countries: Set<StrategyCountry> = [], legacyId: String? = nil,
                serverProfile: ServerProfile? = nil, sourceID: String? = nil, warpTLSName: WarpTLSName? = nil) {
        self.id = id
        self.nameKey = nameKey
        self.literalName = name
        self.transport = transport
        self.args = args
        self.isCustom = isCustom
        self.countries = countries
        self.legacyId = legacyId
        self.serverProfile = serverProfile
        self.sourceID = sourceID
        self.warpTLSName = warpTLSName
    }

    /// Display name: translated by `nameKey` for built-ins, the literal typed name for custom
    /// strategies — same rule as Windows `Strategy.Name`.
    public func name(using loc: Localization) -> String {
        let base = nameKey.map { loc.string($0) } ?? literalName
        return serverProfile.map { base + " @ " + ($0.label.isEmpty ? $0.host : $0.label) } ?? base
    }

    /// Whether arguments request a strategy. Readiness also requires an executable step.
    public var requiresDesync: Bool { !args.trimmingCharacters(in: .whitespaces).isEmpty }

    /// What `args` asks for. Parsing only describes the request — see `StrategyReadiness` for
    /// whether macOS can currently carry any of it out.
    public var plan: DesyncPlan { StrategyArgsParser.parse(transport: transport, args: args) }

    /// Whether this port can perform what the strategy asks for. Derived, not looked up: WireGuard
    /// has no daemon support yet, and anything `StrategyArgsParser` flagged (raw-socket tricks,
    /// unknown syntax) cannot be expressed as a fake-packet send or a TCP split.
    public var readiness: StrategyReadiness {
        if transport == .wireGuard { return .unsupported(Msg("strategy.wgUnsupported")) }
        let requested = plan
        if let issue = requested.parseIssue { return .unsupported(issue) }
        if requested.isDirect { return .unsupported(Msg("strategy.required")) }
        if serverProfile != nil && warpTLSName != nil {
            return .unsupported(Msg("strategy.unknownFeature", "WARP TLS name in server mode"))
        }
        return .available
    }

    /// Why the strategy can't run here, or `nil` if it can.
    public var unsupportedReason: Msg? {
        if case .unsupported(let reason) = readiness { return reason }
        return nil
    }

    // Identity is by id: two `Strategy` values with the same id are the same strategy even if one
    // is a freshly-reloaded copy with identical fields — matches how results/selection are keyed.
    public static func == (a: Strategy, b: Strategy) -> Bool { a.id == b.id }
    public func hash(into hasher: inout Hasher) { hasher.combine(id) }
}
