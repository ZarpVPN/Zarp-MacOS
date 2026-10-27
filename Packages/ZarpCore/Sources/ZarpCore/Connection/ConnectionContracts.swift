import Foundation

/// Describes a requested mode, not evidence that its runtime is available.
public enum ConnectionMode: String, Codable, Sendable, CaseIterable {
    case warp, server

    public var probeKind: ProbeKind { self == .warp ? .warpTrace : .serverHTTPS }
    public var requiresWarpAccount: Bool { self == .warp }
}

public enum ProbeKind: String, Codable, Sendable {
    case warpTrace, serverHTTPS
}

/// Validation errors contain field names only. Never attach an input URI or credential.
public struct ConnectionContractError: Error, Sendable, Equatable, CustomStringConvertible {
    public enum Field: String, Sendable {
        case version, mode, profile, parameters, label, host, port, credential
        case serverProtocol, transport, security, serverName, alpn, flow
        case path, hostHeader, serviceName, timeout, routing, plain, capabilities, probeKind, strategyId
        case scheme, query, encryption, insecure, fingerprint, publicKey, shortId, ech, obfs, obfsPassword
        case modeOptions, extra, padding, certificatePin, certificateName
        case source, sourceURL
    }
    public let field: Field
    public init(_ field: Field) { self.field = field }
    public var description: String { "invalid connection field: " + field.rawValue }
}

public struct ConnectionOptions: Codable, Equatable, Sendable {
    public var dialTimeoutMs: Int
    public var probeTimeoutMs: Int
    public var persistent: Bool
    public var routeAll: Bool
    public var overrideDNS: Bool
    /// An explicit opt-in. It is never inferred from an unsupported strategy.
    public var allowPlain: Bool

    public init(dialTimeoutMs: Int = 15_000, probeTimeoutMs: Int = 15_000,
                persistent: Bool = false, routeAll: Bool = false, overrideDNS: Bool = false,
                allowPlain: Bool = false) {
        self.dialTimeoutMs = dialTimeoutMs; self.probeTimeoutMs = probeTimeoutMs
        self.persistent = persistent; self.routeAll = routeAll; self.overrideDNS = overrideDNS
        self.allowPlain = allowPlain
    }

    public func validate(mode: ConnectionMode) throws {
        guard (1...120_000).contains(dialTimeoutMs), (1...120_000).contains(probeTimeoutMs) else {
            throw ConnectionContractError(.timeout)
        }
        guard (!routeAll || persistent), (!overrideDNS || routeAll) else { throw ConnectionContractError(.routing) }
        guard mode == .server || !allowPlain else { throw ConnectionContractError(.plain) }
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case dialTimeoutMs, probeTimeoutMs, persistent, routeAll, overrideDNS, allowPlain
    }

    public init(from decoder: Decoder) throws {
        let raw = try decoder.container(keyedBy: ContractCodingKey.self)
        let known = Set(CodingKeys.allCases.map(\.rawValue))
        guard raw.allKeys.allSatisfy({ known.contains($0.stringValue) }) else { throw ConnectionContractError(.parameters) }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        do {
            self.init(dialTimeoutMs: try c.decodeIfPresent(Int.self, forKey: .dialTimeoutMs) ?? 15_000,
                      probeTimeoutMs: try c.decodeIfPresent(Int.self, forKey: .probeTimeoutMs) ?? 15_000,
                      persistent: try c.decodeIfPresent(Bool.self, forKey: .persistent) ?? false,
                      routeAll: try c.decodeIfPresent(Bool.self, forKey: .routeAll) ?? false,
                      overrideDNS: try c.decodeIfPresent(Bool.self, forKey: .overrideDNS) ?? false,
                      allowPlain: try c.decodeIfPresent(Bool.self, forKey: .allowPlain) ?? false)
        } catch {
            throw ConnectionContractError(.parameters)
        }
    }
}

/// Capabilities come from the daemon's runtime inventory. Older and unbundled
/// daemons retain WARP-only capabilities; profiles never grant themselves a mode.
public struct RuntimeCapabilities: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let modes: Set<ConnectionMode>
    public let serverProtocols: Set<ServerProtocol>
    public let outerTransports: Set<OuterTransport>

    public init(schemaVersion: Int = ConnectionContract.schemaVersion, modes: Set<ConnectionMode>,
                serverProtocols: Set<ServerProtocol> = [], outerTransports: Set<OuterTransport>) {
        self.schemaVersion = schemaVersion; self.modes = modes
        self.serverProtocols = serverProtocols; self.outerTransports = outerTransports
    }

    public static let currentWarpOnly = RuntimeCapabilities(modes: [.warp], outerTransports: [.tcp, .udp])

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, modes, serverProtocols, outerTransports
    }

    public init(from decoder: Decoder) throws {
        do {
            let raw = try decoder.container(keyedBy: ContractCodingKey.self)
            let known = Set(CodingKeys.allCases.map(\.rawValue))
            guard raw.allKeys.allSatisfy({ known.contains($0.stringValue) }) else { throw ConnectionContractError(.capabilities) }
            let c = try decoder.container(keyedBy: CodingKeys.self)
            self.init(schemaVersion: try c.decode(Int.self, forKey: .schemaVersion),
                      modes: try c.decode(Set<ConnectionMode>.self, forKey: .modes),
                      serverProtocols: try c.decode(Set<ServerProtocol>.self, forKey: .serverProtocols),
                      outerTransports: try c.decode(Set<OuterTransport>.self, forKey: .outerTransports))
        } catch { throw ConnectionContractError(.capabilities) }
    }

    public func require(mode: ConnectionMode, profile: ServerProfile? = nil) throws {
        guard schemaVersion == ConnectionContract.schemaVersion else { throw ConnectionContractError(.version) }
        guard modes.contains(mode) else { throw ConnectionContractError(.capabilities) }
        if mode == .server {
            guard let profile else { throw ConnectionContractError(.profile) }
            try profile.validate()
            guard serverProtocols.contains(profile.serverProtocol), outerTransports.contains(profile.outerTransport) else {
                throw ConnectionContractError(.capabilities)
            }
        } else if profile != nil {
            throw ConnectionContractError(.profile)
        }
    }
}

/// Versioned pure-data contract. IPC protocol 3 remains compatible; server mode
/// uses a separate capability-checked openServer method.
public enum ConnectionContract {
    public static let schemaVersion = 1
    public static let maxProfileBytes = 16_384
    public static let maxRequestBytes = 65_536

    public static func decodeProfile(_ data: Data) throws -> ServerProfile {
        guard data.count <= maxProfileBytes else { throw ConnectionContractError(.profile) }
        do {
            try StrictContractJSON.validate(data)
            return try JSONDecoder().decode(ServerProfile.self, from: data)
        } catch let error as ConnectionContractError {
            throw error
        } catch {
            // DecodingError descriptions can include an unrecognized secret-bearing value.
            throw ConnectionContractError(.profile)
        }
    }

    public static func decodeRequest(_ data: Data, capabilities: RuntimeCapabilities = .currentWarpOnly) throws -> ConnectionRequest {
        guard data.count <= maxRequestBytes else { throw ConnectionContractError(.parameters) }
        do {
            try StrictContractJSON.validate(data)
            let request = try JSONDecoder().decode(ConnectionRequest.self, from: data)
            try request.validate(capabilities: capabilities)
            return request
        } catch let error as ConnectionContractError {
            throw error
        } catch {
            throw ConnectionContractError(.parameters)
        }
    }
}

/// Draft envelope for a future mode-aware IPC method. No current daemon method accepts it.
public struct ConnectionRequest: Codable, Equatable, Sendable {
    public let version: Int
    public let mode: ConnectionMode
    public let probeKind: ProbeKind
    public let strategyId: String?
    public let profile: ServerProfile?
    public let options: ConnectionOptions

    public init(version: Int = ConnectionContract.schemaVersion, mode: ConnectionMode,
                probeKind: ProbeKind? = nil, strategyId: String? = nil,
                profile: ServerProfile? = nil, options: ConnectionOptions = ConnectionOptions()) {
        self.version = version; self.mode = mode; self.probeKind = probeKind ?? mode.probeKind
        self.strategyId = strategyId; self.profile = profile; self.options = options
    }

    public func validate(capabilities: RuntimeCapabilities) throws {
        guard version == ConnectionContract.schemaVersion else { throw ConnectionContractError(.version) }
        guard probeKind == mode.probeKind else { throw ConnectionContractError(.probeKind) }
        try options.validate(mode: mode)
        guard (mode == .server) == (profile != nil) else { throw ConnectionContractError(.profile) }
        if let strategyId {
            guard !strategyId.isEmpty, strategyId.utf8.count <= 128,
                  strategyId.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw ConnectionContractError(.strategyId)
            }
        } else if mode == .warp || !options.allowPlain {
            throw ConnectionContractError(.plain)
        }
        try capabilities.require(mode: mode, profile: profile)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version, mode, probeKind, strategyId, profile, options
    }

    public init(from decoder: Decoder) throws {
        let raw = try decoder.container(keyedBy: ContractCodingKey.self)
        let known = Set(CodingKeys.allCases.map(\.rawValue))
        guard raw.allKeys.allSatisfy({ known.contains($0.stringValue) }) else { throw ConnectionContractError(.parameters) }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func required<T: Decodable>(_ key: CodingKeys) throws -> T {
            do { return try c.decode(T.self, forKey: key) }
            catch let error as ConnectionContractError { throw error }
            catch { throw ConnectionContractError(ConnectionContractError.Field(rawValue: key.rawValue) ?? .parameters) }
        }
        func optional<T: Decodable>(_ key: CodingKeys) throws -> T? {
            do { return try c.decodeIfPresent(T.self, forKey: key) }
            catch let error as ConnectionContractError { throw error }
            catch { throw ConnectionContractError(ConnectionContractError.Field(rawValue: key.rawValue) ?? .parameters) }
        }
        self.init(version: try required(.version), mode: try required(.mode), probeKind: try required(.probeKind),
                  strategyId: try optional(.strategyId), profile: try optional(.profile), options: try required(.options))
    }
}

public enum ServerProtocol: String, Codable, Sendable, CaseIterable { case vless, trojan, hysteria2 }
public enum OuterTransport: String, Codable, Sendable { case tcp, udp }
public enum ServerTransport: String, Codable, Sendable { case tcp, ws, grpc, httpUpgrade, quic, xhttp }
public enum ServerSecurity: String, Codable, Sendable { case none, tls, reality }
public enum ServerFlow: String, Codable, Sendable { case none, vision }
public enum TLSFingerprint: String, Codable, Sendable {
    case chrome, firefox, edge, safari, ios, android, random, randomized, qq
    case browser360 = "360"
    case chromePSK = "chrome_psk", chromePSKShuffle = "chrome_psk_shuffle"
    case chromePaddingPSKShuffle = "chrome_padding_psk_shuffle", chromePQ = "chrome_pq", chromePQPSK = "chrome_pq_psk"
}
public enum ServerObfuscation: String, Codable, Sendable { case salamander }

public struct ServerCredential: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public enum Kind: String, Codable, Sendable { case uuid, password }
    public let kind: Kind
    public let value: String
    public init(kind: Kind, value: String) { self.kind = kind; self.value = value }
    public var description: String { "ServerCredential(redacted)" }
    public var debugDescription: String { description }

    func validate(for serverProtocol: ServerProtocol) throws {
        guard !value.isEmpty, value.utf8.count <= 4096,
              value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw ConnectionContractError(.credential)
        }
        switch serverProtocol {
        case .vless:
            guard kind == .uuid, value.utf8.count == 36, UUID(uuidString: value) != nil else {
                throw ConnectionContractError(.credential)
            }
        case .trojan, .hysteria2:
            guard kind == .password else { throw ConnectionContractError(.credential) }
        }
    }

    private enum CodingKeys: String, CodingKey { case kind, value }

    public init(from decoder: Decoder) throws {
        do {
            let raw = try decoder.container(keyedBy: ContractCodingKey.self)
            guard raw.allKeys.allSatisfy({ ["kind", "value"].contains($0.stringValue) }) else {
                throw ConnectionContractError(.credential)
            }
            let c = try decoder.container(keyedBy: CodingKeys.self)
            self.init(kind: try c.decode(Kind.self, forKey: .kind), value: try c.decode(String.self, forKey: .value))
        } catch {
            throw ConnectionContractError(.credential)
        }
    }
}

/// Bounded structured profile contract with pinned-engine transport options.
/// Encoding includes credentials for restricted storage/IPC only. Display/debug output is redacted.
public struct ServerProfile: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let label: String
    public let host: String
    public let port: Int
    public let serverProtocol: ServerProtocol
    public let credential: ServerCredential
    public let transport: ServerTransport
    public let security: ServerSecurity
    public let serverName: String?
    public let alpn: [String]
    public let flow: ServerFlow
    public let path: String?
    public let hostHeader: String?
    public let serviceName: String?
    public let fingerprint: TLSFingerprint?
    public let publicKey: String?
    public let shortId: String?
    public let obfs: ServerObfuscation?
    public let obfsPassword: String?
    public let xhttpMode: String?
    public let xhttpExtra: String?
    public let xhttpPadding: String?
    public let echConfig: String?
    public let certificatePins: [String]
    public let certificateNames: [String]
    public let spiderX: String?
    public let mldsaVerify: String?

    public init(label: String = "", host: String, port: Int, serverProtocol: ServerProtocol,
                credential: ServerCredential, transport: ServerTransport = .tcp, security: ServerSecurity = .tls,
                serverName: String? = nil, alpn: [String] = [], flow: ServerFlow = .none,
                path: String? = nil, hostHeader: String? = nil, serviceName: String? = nil,
                fingerprint: TLSFingerprint? = nil, publicKey: String? = nil, shortId: String? = nil,
                obfs: ServerObfuscation? = nil, obfsPassword: String? = nil,
                xhttpMode: String? = nil, xhttpExtra: String? = nil, xhttpPadding: String? = nil, echConfig: String? = nil,
                certificatePins: [String] = [], certificateNames: [String] = [], spiderX: String? = nil, mldsaVerify: String? = nil) throws {
        self.label = label; self.host = host; self.port = port; self.serverProtocol = serverProtocol
        self.credential = credential; self.transport = transport; self.security = security
        self.serverName = serverName; self.alpn = alpn; self.flow = flow
        self.path = path; self.hostHeader = hostHeader; self.serviceName = serviceName
        self.fingerprint = fingerprint; self.publicKey = publicKey; self.shortId = shortId
        self.obfs = obfs; self.obfsPassword = obfsPassword
        self.xhttpMode = xhttpMode; self.xhttpExtra = xhttpExtra; self.xhttpPadding = xhttpPadding; self.echConfig = echConfig
        self.certificatePins = certificatePins; self.certificateNames = certificateNames
        self.spiderX = spiderX; self.mldsaVerify = mldsaVerify
        try validate()
    }

    public var outerTransport: OuterTransport {
        serverProtocol == .hysteria2 || (transport == .xhttp && alpn == ["h3"]) ? .udp : .tcp
    }

    /// Label and source are presentation/provenance, not executable configuration.
    public var id: String {
        var fields = [
            serverProtocol.rawValue, host.lowercased(), String(port), credential.kind.rawValue, credential.value,
            transport.rawValue, security.rawValue, serverName ?? "", String(alpn.count)
        ] + alpn + [flow.rawValue, path ?? "", hostHeader ?? "", serviceName ?? ""]
        // Existing schema 1 identities and saved selections remain stable when options are absent.
        if fingerprint != nil || publicKey != nil || shortId != nil || obfs != nil || obfsPassword != nil {
            fields += ["server-options-v1", fingerprint?.rawValue ?? "", publicKey ?? "", shortId ?? "",
                       obfs?.rawValue ?? "", obfsPassword ?? ""]
        }
        if hasTransportOptions { fields += transportOptionIdentity }
        return "server-v1-" + Strategy.fingerprint(fields)
    }

    public var description: String { "ServerProfile(\(serverProtocol.rawValue), redacted)" }
    public var debugDescription: String { description }

    public func validate() throws {
        try validateTransportOptions()
        guard Self.text(label, max: 128) else { throw ConnectionContractError(.label) }
        guard Self.hostIsValid(host) else { throw ConnectionContractError(.host) }
        guard (1...65535).contains(port) else { throw ConnectionContractError(.port) }
        try credential.validate(for: serverProtocol)
        if let serverName, !Self.hostIsValid(serverName) { throw ConnectionContractError(.serverName) }
        guard alpn.count <= 8, alpn.allSatisfy({ !$0.isEmpty && Self.text($0, max: 255) }) else {
            throw ConnectionContractError(.alpn)
        }
        // These describe admissible configurations, not backend traffic support.
        switch serverProtocol {
        case .hysteria2:
            guard transport == .quic else { throw ConnectionContractError(.transport) }
            guard security == .tls else { throw ConnectionContractError(.security) }
        case .trojan:
            guard transport != .quic else { throw ConnectionContractError(.transport) }
            guard security == .tls else { throw ConnectionContractError(.security) }
        case .vless:
            guard transport != .quic else { throw ConnectionContractError(.transport) }
        }
        guard flow == .none || (serverProtocol == .vless && transport == .tcp && security != .none) else {
            throw ConnectionContractError(.flow)
        }
        guard security != .none || (serverName == nil && alpn.isEmpty) else { throw ConnectionContractError(.security) }
        if security == .reality {
            guard serverProtocol == .vless, [.tcp, .xhttp].contains(transport) else { throw ConnectionContractError(.security) }
            guard let serverName, IPAddress(serverName) == nil else { throw ConnectionContractError(.serverName) }
            guard fingerprint != nil else { throw ConnectionContractError(.fingerprint) }
            guard let publicKey, Self.realityKeyIsValid(publicKey) else { throw ConnectionContractError(.publicKey) }
            if let shortId, !Self.shortIdIsValid(shortId) { throw ConnectionContractError(.shortId) }
        } else {
            guard publicKey == nil else { throw ConnectionContractError(.publicKey) }
            guard shortId == nil else { throw ConnectionContractError(.shortId) }
        }
        if fingerprint != nil && (security == .none || serverProtocol == .hysteria2) {
            throw ConnectionContractError(.fingerprint)
        }
        if obfs != nil {
            guard serverProtocol == .hysteria2 else { throw ConnectionContractError(.obfs) }
            guard let obfsPassword, !obfsPassword.isEmpty, Self.text(obfsPassword, max: 4096) else {
                throw ConnectionContractError(.obfsPassword)
            }
        } else if obfsPassword != nil { throw ConnectionContractError(.obfsPassword) }
        if let path {
            guard [.ws, .httpUpgrade, .xhttp].contains(transport), path.hasPrefix("/"), Self.text(path, max: 2048) else {
                throw ConnectionContractError(.path)
            }
        }
        if let hostHeader {
            guard [.ws, .httpUpgrade, .xhttp].contains(transport), Self.hostIsValid(hostHeader) else {
                throw ConnectionContractError(.hostHeader)
            }
        }
        if let serviceName {
            guard transport == .grpc, Self.text(serviceName, max: 256), !serviceName.isEmpty else {
                throw ConnectionContractError(.serviceName)
            }
        }
    }

    private static func text(_ value: String, max: Int) -> Bool {
        value.utf8.count <= max && value.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
    }

    private static func realityKeyIsValid(_ value: String) -> Bool {
        guard value.utf8.count == 43, value.utf8.allSatisfy({
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95
        }), let data = Data(base64Encoded: value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + "="),
            data.count == 32 else { return false }
        return data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") == value
    }

    private static func shortIdIsValid(_ value: String) -> Bool {
        value.utf8.count <= 16 && value.utf8.count.isMultiple(of: 2) && value.utf8.allSatisfy {
            (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
        }
    }

    static func hostIsValid(_ value: String) -> Bool {
        if let address = IPAddress(value) {
            // A leading-zero IPv4 literal must not become a DNS name in another runtime.
            return address.version == 6 || address.description == value
        }
        guard !value.isEmpty, value.utf8.count <= 253, !value.contains(":"), !value.contains("%") else { return false }
        let pieces = value.split(separator: ".", omittingEmptySubsequences: false)
        if pieces.count == 4 && pieces.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy({ (48...57).contains($0) }) }) {
            return false // A malformed numeric IPv4 literal must not silently become a DNS name.
        }
        return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            guard !label.isEmpty, label.utf8.count <= 63, label.first != "-", label.last != "-" else { return false }
            return label.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }
        }
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case label, host, port, serverProtocol, credential, transport, security, serverName, alpn, flow, path, hostHeader, serviceName
        case fingerprint, publicKey, shortId, obfs, obfsPassword
        case xhttpMode, xhttpExtra, xhttpPadding, echConfig, certificatePins, certificateNames, spiderX, mldsaVerify
    }

    public init(from decoder: Decoder) throws {
        let raw = try decoder.container(keyedBy: ContractCodingKey.self)
        let known = Set(CodingKeys.allCases.map(\.rawValue))
        guard raw.allKeys.allSatisfy({ known.contains($0.stringValue) }) else { throw ConnectionContractError(.parameters) }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func required<T: Decodable>(_ key: CodingKeys) throws -> T {
            do { return try c.decode(T.self, forKey: key) }
            catch { throw ConnectionContractError(ConnectionContractError.Field(rawValue: key.rawValue) ?? .profile) }
        }
        func optional<T: Decodable>(_ key: CodingKeys) throws -> T? {
            do { return try c.decodeIfPresent(T.self, forKey: key) }
            catch { throw ConnectionContractError(ConnectionContractError.Field(rawValue: key.rawValue) ?? .profile) }
        }
        try self.init(label: optional(.label) ?? "", host: required(.host), port: required(.port),
                      serverProtocol: required(.serverProtocol), credential: required(.credential),
                      transport: required(.transport), security: required(.security),
                      serverName: optional(.serverName), alpn: optional(.alpn) ?? [], flow: optional(.flow) ?? .none,
                      path: optional(.path), hostHeader: optional(.hostHeader), serviceName: optional(.serviceName),
                      fingerprint: optional(.fingerprint), publicKey: optional(.publicKey), shortId: optional(.shortId),
                      obfs: optional(.obfs), obfsPassword: optional(.obfsPassword),
                      xhttpMode: optional(.xhttpMode), xhttpExtra: optional(.xhttpExtra), xhttpPadding: optional(.xhttpPadding), echConfig: optional(.echConfig),
                      certificatePins: optional(.certificatePins) ?? [], certificateNames: optional(.certificateNames) ?? [],
                      spiderX: optional(.spiderX), mldsaVerify: optional(.mldsaVerify))
    }
}

private struct ContractCodingKey: CodingKey {
    var stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}
