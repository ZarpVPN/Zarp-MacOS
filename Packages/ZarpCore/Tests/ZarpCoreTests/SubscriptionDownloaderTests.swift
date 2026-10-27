import XCTest
@testable import ZarpCore

private actor ScriptedSubscriptionTransport: SubscriptionHTTPTransport {
    enum Step: Sendable {
        case response(SubscriptionHTTPResponse)
        case failure(SubscriptionError)
        case rawFailure
    }
    struct Request: Sendable { let url: URL; let agent: String; let deadline: ContinuousClock.Instant }
    private var steps: [Step]
    private let delay: UInt64
    private(set) var requests: [Request] = []
    init(_ steps: [Step], delay: UInt64 = 0) { self.steps = steps; self.delay = delay }
    func get(url: URL, userAgent: String, deadline: ContinuousClock.Instant) async throws -> SubscriptionHTTPResponse {
        requests.append(Request(url: url, agent: userAgent, deadline: deadline))
        if delay > 0 { try await Task.sleep(nanoseconds: delay) }
        guard !steps.isEmpty else { throw SubscriptionError.network }
        switch steps.removeFirst() {
        case .response(let response): return response
        case .failure(let error): throw error
        case .rawFailure: throw NSError(domain: "private-token.example.test", code: 1, userInfo: [NSLocalizedDescriptionKey: "private-token"])
        }
    }
}

final class SubscriptionDownloaderTests: XCTestCase {
    private let good = Data("trojan://private-test-password@server.example.test:443".utf8)
    private func source() throws -> ConnectionSource {
        try ConnectionSource(kind: .subscription, subscriptionURL: "https://subscription.example.test/list?token=private-token")
    }

    func testGoodListHasNoUserAgentRetryAndOriginalSourceIdentityIsUnchanged() async throws {
        let source = try source()
        let transport = ScriptedSubscriptionTransport([.response(.init(status: 200, body: good))])
        let result = try await SubscriptionDownloader(transport: transport).load(source: source)
        XCTAssertEqual(result.profiles.count, 1)
        let requests = await transport.requests
        XCTAssertEqual(requests.map(\.agent), ["Zarp/1.0"])
        XCTAssertEqual(requests.first?.url.absoluteString, source.subscriptionURL)
        XCTAssertEqual(source.id, try self.source().id)
    }

    func testHTMLJSONAndUnsupportedListsRetryOnlyAsTheSecondUserAgent() async throws {
        for body in ["<html>private-token</html>", "[{\"private-token\":1}]", "vmess://private-token"] {
            let transport = ScriptedSubscriptionTransport([.response(.init(status: 200, body: Data(body.utf8))), .response(.init(status: 200, body: good))])
            let result = try await SubscriptionDownloader(transport: transport).load(source: source())
            XCTAssertEqual(result.profiles.count, 1)
            let requests = await transport.requests
            XCTAssertEqual(requests.map(\.agent), ["Zarp/1.0", "v2rayN/7.0"])
            XCTAssertEqual(requests[0].deadline, requests[1].deadline)
        }
        let transport = ScriptedSubscriptionTransport([.response(.init(status: 200, body: Data("[{\"private-token\":1}]".utf8))), .failure(.network)])
        let result = try await SubscriptionDownloader(transport: transport).load(source: source())
        XCTAssertEqual(result.format, .json)
        XCTAssertTrue(result.profiles.isEmpty)
    }

    func testNetworkTLSStatusAndOversizeFailuresDoNotTriggerFormatRetry() async throws {
        let cases: [ScriptedSubscriptionTransport.Step] = [.failure(.network), .failure(.tls), .rawFailure,
            .response(.init(status: 403)), .response(.init(status: 200, body: Data(repeating: 32, count: 2 * 1024 * 1024 + 1)))]
        for first in cases {
            let transport = ScriptedSubscriptionTransport([first, .response(.init(status: 200, body: good))])
            do {
                _ = try await SubscriptionDownloader(transport: transport).load(source: source())
                XCTFail("ordinary failure was retried or accepted")
            } catch {
                XCTAssertFalse(String(describing: error).contains("private-token"))
                if case .response(let response) = first, response.status == 403 {
                    XCTAssertEqual((error as? SubscriptionHTTPError)?.status, 403)
                }
            }
            let requests = await transport.requests
            XCTAssertEqual(requests.count, 1)
        }
    }

    func testExactlyFiveHTTPSRedirectsShareTheSameDeadlineAndSourceHash() async throws {
        let transport = ScriptedSubscriptionTransport((1...5).map { .response(.init(status: 302, location: "/hop/\($0)")) } + [.response(.init(status: 200, body: good))])
        let original = try source()
        let result = try await SubscriptionDownloader(transport: transport).load(source: original)
        XCTAssertEqual(result.profiles.count, 1)
        let requests = await transport.requests
        XCTAssertEqual(requests.count, 6)
        XCTAssertEqual(requests.last?.url.absoluteString, "https://subscription.example.test/hop/5")
        XCTAssertTrue(requests.allSatisfy { $0.deadline == requests[0].deadline })
        XCTAssertEqual(original.id, try source().id)
    }

    func testUnsafeMissingAndExcessRedirectsAreNeverFollowed() async throws {
        for location in [nil, "http://redirect.example.test/list", "https://user:private-token@redirect.example.test/list",
                         "https://redirect.example.test/list#private-token", "https://redirect.example.test/%ZZ", " /private-token"] as [String?] {
            let transport = ScriptedSubscriptionTransport([.response(.init(status: 302, location: location)), .response(.init(status: 200, body: good))])
            do {
                _ = try await SubscriptionDownloader(transport: transport).load(source: source())
                XCTFail("unsafe redirect followed")
            } catch { XCTAssertEqual(error as? SubscriptionError, .redirect) }
            let requests = await transport.requests
            XCTAssertEqual(requests.count, 1)
        }
        let transport = ScriptedSubscriptionTransport(Array(repeating: .response(.init(status: 302, location: "/loop")), count: 7))
        do {
            _ = try await SubscriptionDownloader(transport: transport).load(source: source())
            XCTFail("sixth redirect followed")
        } catch { XCTAssertEqual(error as? SubscriptionError, .redirect) }
        let requests = await transport.requests
        XCTAssertEqual(requests.count, 6)
    }

    func testOneDeadlineCoversBothUserAgentAttemptsAndCancellationStopsWork() async throws {
        let transport = ScriptedSubscriptionTransport([.response(.init(status: 200, body: Data("<html>test</html>".utf8))), .response(.init(status: 200, body: good))], delay: 70_000_000)
        let downloader = SubscriptionDownloader(transport: transport, timeout: .milliseconds(100))
        let started = ContinuousClock.now
        do {
            _ = try await downloader.load(source: source())
            XCTFail("user-agent retry received a fresh time budget")
        } catch { XCTAssertEqual(error as? SubscriptionError, .timeout) }
        XCTAssertLessThan(started.duration(to: .now), .seconds(1))
        let requests = await transport.requests
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(requests[0].deadline, requests[1].deadline)
        let delayed = ScriptedSubscriptionTransport([.response(.init(status: 200, body: good))], delay: 5_000_000_000)
        let source = try source()
        let pending = Task { try await SubscriptionDownloader(transport: delayed).load(source: source) }
        for _ in 0..<100 {
            if !(await delayed.requests).isEmpty { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        pending.cancel()
        do { _ = try await pending.value; XCTFail("cancelled request returned a list") }
        catch { XCTAssertEqual(error as? SubscriptionError, .cancelled) }
    }
}
