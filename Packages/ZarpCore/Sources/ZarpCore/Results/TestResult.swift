import Foundation

/// Result of testing one strategy: same shape as Windows Zarp's `TestResult`
/// (`Core/AppConfig.cs`) and Android Zarp's `TestResult.kt`, so the scoring and double-verification
/// rules match both.
public struct TestResult: Hashable, Sendable, Codable {
    public var strategyId: String
    public var ok: Bool = false
    public var connectMs: Int = 0
    public var pingMs: Int = 0
    /// Error text as-is, when there is no translation key for it (e.g. a raw message from the
    /// networking layer).
    public var error: String?
    /// Error as a translation key + arguments, shown in the current language.
    public var errorKey: String?
    public var errorArgs: [String] = []
    /// The failure happened on the second fresh connection.
    public var rechecked: Bool = false
    /// Passed two fresh connections. Endpoint independence is recorded separately.
    public var confirmed: Bool = false
    public var independent: Bool = false
    public var endpointReused: Bool = false
    public var firstEndpoint: String?
    public var configurationFingerprint: String?
    public var endpointListFingerprint: String?
    public var networkIdentity: String?
    /// The WARP endpoint this test used, for diagnostics (Android Zarp records this too; Windows
    /// only logs it).
    public var endpoint: String?
    public var timestamp: Date = Date()

    public init(strategyId: String, ok: Bool = false, connectMs: Int = 0, pingMs: Int = 0,
                error: String? = nil, errorKey: String? = nil, errorArgs: [String] = [],
                rechecked: Bool = false, confirmed: Bool = false, endpoint: String? = nil,
                timestamp: Date = Date(), independent: Bool = false, endpointReused: Bool = false,
                firstEndpoint: String? = nil, configurationFingerprint: String? = nil, endpointListFingerprint: String? = nil,
                networkIdentity: String? = nil) {
        self.strategyId = strategyId
        self.ok = ok
        self.connectMs = connectMs
        self.pingMs = pingMs
        self.error = error
        self.errorKey = errorKey
        self.errorArgs = errorArgs
        self.rechecked = rechecked
        self.confirmed = confirmed
        self.endpoint = endpoint
        self.timestamp = timestamp
        self.independent = independent
        self.endpointReused = endpointReused
        self.firstEndpoint = firstEndpoint
        self.configurationFingerprint = configurationFingerprint
        self.endpointListFingerprint = endpointListFingerprint
        self.networkIdentity = networkIdentity
    }

    private enum CodingKeys: String, CodingKey {
        case strategyId, ok, connectMs, pingMs, error, errorKey, errorArgs, rechecked, confirmed, endpoint, timestamp
        case independent, endpointReused, firstEndpoint, configurationFingerprint, endpointListFingerprint, networkIdentity
    }

    /// Lenient: only `strategyId` is required. A result written by an older build, or with one
    /// field damaged, is still a result — and a field added later never invalidates saved ones.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        strategyId = try c.decode(String.self, forKey: .strategyId)
        ok = (try? c.decodeIfPresent(Bool.self, forKey: .ok)) ?? false
        connectMs = (try? c.decodeIfPresent(Int.self, forKey: .connectMs)) ?? 0
        pingMs = (try? c.decodeIfPresent(Int.self, forKey: .pingMs)) ?? 0
        error = (try? c.decodeIfPresent(String.self, forKey: .error)) ?? nil
        errorKey = (try? c.decodeIfPresent(String.self, forKey: .errorKey)) ?? nil
        errorArgs = (try? c.decodeIfPresent([String].self, forKey: .errorArgs)) ?? []
        rechecked = (try? c.decodeIfPresent(Bool.self, forKey: .rechecked)) ?? false
        confirmed = (try? c.decodeIfPresent(Bool.self, forKey: .confirmed)) ?? false
        endpoint = (try? c.decodeIfPresent(String.self, forKey: .endpoint)) ?? nil
        firstEndpoint = (try? c.decodeIfPresent(String.self, forKey: .firstEndpoint)) ?? nil
        configurationFingerprint = (try? c.decodeIfPresent(String.self, forKey: .configurationFingerprint)) ?? nil
        endpointListFingerprint = (try? c.decodeIfPresent(String.self, forKey: .endpointListFingerprint)) ?? nil
        networkIdentity = (try? c.decodeIfPresent(String.self, forKey: .networkIdentity)) ?? nil
        endpointReused = (try? c.decodeIfPresent(Bool.self, forKey: .endpointReused)) ?? false
        let first = firstEndpoint.flatMap(WarpEndpoint.init)
        let last = endpoint.flatMap(WarpEndpoint.init)
        independent = confirmed && first != nil && last != nil && first != last
        endpointReused = first != nil && last != nil && first == last
        timestamp = (try? c.decodeIfPresent(Date.self, forKey: .timestamp)) ?? Date(timeIntervalSince1970: 0)
    }

    /// Lower is better. Ping weighs 4×: it affects every request after connecting, connecting
    /// happens once — same weighting as Windows `TestResult.Score` / Android `TestResult.score`.
    public static let latencyRange = 0...120_000
    public var validLatencies: Bool { Self.latencyRange.contains(connectMs) && Self.latencyRange.contains(pingMs) }
    public var score: Int { ok && validLatencies ? connectMs + pingMs * 4 : Int.max }

    public var errorMsg: Msg? { errorKey.map { Msg(key: $0, args: errorArgs) } }

    public func errorText(using loc: Localization) -> String {
        errorMsg?.text(using: loc) ?? error ?? ""
    }

    /// Text for the strategy list / log: adds "not confirmed" framing when the failure happened on
    /// the independent re-check (Windows `TestResult.DisplayError`).
    public func displayError(using loc: Localization) -> String {
        let text = errorText(using: loc)
        return rechecked ? loc.string("result.notConfirmed", [text]) : text
    }

    public static func failed(strategyId: String, error: Msg, timestamp: Date = Date(), endpoint: String? = nil) -> TestResult {
        TestResult(strategyId: strategyId, ok: false, errorKey: error.key, errorArgs: error.args, endpoint: endpoint, timestamp: timestamp)
    }

    public static func failedRaw(strategyId: String, error: String, timestamp: Date = Date(), endpoint: String? = nil) -> TestResult {
        TestResult(strategyId: strategyId, ok: false, error: error, endpoint: endpoint, timestamp: timestamp)
    }

    /// Double-verification merge: the slower (more pessimistic) connect time, the average ping —
    /// same rule as Windows `Engine.SearchAndApplyAsync` / Android `TestResult.confirmed`.
    public static func confirmed(_ first: TestResult, _ second: TestResult) -> TestResult {
        let valid = first.ok && second.ok && first.validLatencies && second.validLatencies && first.strategyId == second.strategyId
            && first.configurationFingerprint == second.configurationFingerprint && first.endpointListFingerprint == second.endpointListFingerprint
            && first.networkIdentity == second.networkIdentity
        let firstAddress = first.endpoint.flatMap(WarpEndpoint.init)
        let secondAddress = second.endpoint.flatMap(WarpEndpoint.init)
        let actual = firstAddress != nil && secondAddress != nil
        return TestResult(strategyId: second.strategyId, ok: valid, connectMs: valid ? max(first.connectMs, second.connectMs) : 0,
                   pingMs: valid ? (first.pingMs + second.pingMs) / 2 : 0, confirmed: valid, endpoint: second.endpoint,
                   timestamp: second.timestamp, independent: valid && actual && firstAddress != secondAddress,
                   endpointReused: actual && firstAddress == secondAddress, firstEndpoint: first.endpoint,
                   configurationFingerprint: second.configurationFingerprint, endpointListFingerprint: second.endpointListFingerprint,
                   networkIdentity: second.networkIdentity)
    }
}
