import Foundation

public struct SubscriptionHTTPResponse: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let status: Int
    public let location: String?
    public let body: Data
    public init(status: Int, location: String? = nil, body: Data = Data()) {
        self.status = status; self.location = location; self.body = body
    }
    public var description: String { "SubscriptionHTTPResponse(\(status), redacted)" }
    public var debugDescription: String { description }
}

public struct SubscriptionHTTPError: Error, Equatable, Sendable, CustomStringConvertible {
    public let status: Int
    public var description: String { "subscription: HTTP \(status)" }
}

/// Implementations stream a bounded, decompressed body and must observe task
/// cancellation. Production URLSession lives in the separate ZarpSubscriptions
/// target; pure core tests inject a fake transport without making requests.
public protocol SubscriptionHTTPTransport: Sendable {
    func get(url: URL, userAgent: String, deadline: ContinuousClock.Instant) async throws -> SubscriptionHTTPResponse
}

/// HTTPS redirect policy and both user-agent attempts share one monotonic budget.
/// No account, tunnel or active-pair operation is available from this boundary.
public struct SubscriptionDownloader: Sendable {
    private let transport: any SubscriptionHTTPTransport
    private let timeout: Duration

    public init(transport: any SubscriptionHTTPTransport) { self.transport = transport; timeout = .seconds(25) }

    init(transport: any SubscriptionHTTPTransport, timeout: Duration) {
        precondition(timeout > .zero && timeout <= .seconds(25))
        self.transport = transport; self.timeout = timeout
    }

    public func load(source: ConnectionSource) async throws -> SubscriptionResult {
        do { try source.validate() } catch { throw SubscriptionError.source }
        guard source.kind == .subscription, let original = source.subscriptionURL, let url = URL(string: original) else {
            throw SubscriptionError.source
        }
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        do {
            try Task.checkCancellation()
            return try await withThrowingTaskGroup(of: SubscriptionResult.self) { group in
                group.addTask { try await attempts(url: url, deadline: deadline) }
                group.addTask {
                    try await clock.sleep(until: deadline)
                    throw SubscriptionError.timeout
                }
                defer { group.cancelAll() }
                guard let result = try await group.next() else { throw SubscriptionError.network }
                try Task.checkCancellation()
                guard clock.now < deadline else { throw SubscriptionError.timeout }
                return result
            }
        } catch is CancellationError { throw SubscriptionError.cancelled }
        catch let error as SubscriptionError { throw error }
        catch let error as SubscriptionHTTPError { throw error }
        catch { throw SubscriptionError.network }
    }

    private func attempts(url: URL, deadline: ContinuousClock.Instant) async throws -> SubscriptionResult {
        let first = try await attempt(url: url, userAgent: "Zarp/1.0", deadline: deadline)
        if !first.profiles.isEmpty { return first }
        do {
            let second = try await attempt(url: url, userAgent: "v2rayN/7.0", deadline: deadline)
            return second.profiles.isEmpty ? first : second
        } catch is CancellationError { throw SubscriptionError.cancelled }
        catch let error as SubscriptionError where error == .cancelled || error == .timeout { throw error }
        catch { return first } // Preserve the first format diagnosis after retry failure.
    }

    private func attempt(url original: URL, userAgent: String, deadline: ContinuousClock.Instant) async throws -> SubscriptionResult {
        var url = original
        for hop in 0...5 {
            try Task.checkCancellation()
            guard ContinuousClock.now < deadline else { throw SubscriptionError.timeout }
            let response = try await transport.get(url: url, userAgent: userAgent, deadline: deadline)
            try Task.checkCancellation()
            guard ContinuousClock.now < deadline else { throw SubscriptionError.timeout }
            if [301, 302, 303, 307, 308].contains(response.status) {
                guard hop < 5, let location = response.location, validLocation(location),
                      let next = URL(string: location, relativeTo: url)?.absoluteURL,
                      (try? ConnectionSource(kind: .subscription, subscriptionURL: next.absoluteString)) != nil else {
                    throw SubscriptionError.redirect
                }
                url = next
                continue
            }
            guard response.status == 200 else {
                guard (100...599).contains(response.status) else { throw SubscriptionError.http }
                throw SubscriptionHTTPError(status: response.status)
            }
            return try SubscriptionParser.parse(response.body)
        }
        throw SubscriptionError.redirect
    }

    private func validLocation(_ value: String) -> Bool {
        let punctuation = "-._~:/?@!$&'()*+,;=%[]".utf8
        return !value.isEmpty && value.utf8.count <= ConnectionSource.maxURLBytes && value.removingPercentEncoding != nil &&
            value.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || punctuation.contains($0) })
    }
}
