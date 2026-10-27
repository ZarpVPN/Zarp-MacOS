import XCTest
import ZarpCore
@testable import ZarpSubscriptions

private final class FixtureProtocol: URLProtocol {
    struct Reply {
        var status = 200
        var headers: [String: String] = [:]
        var chunks: [Data] = []
        var error: URLError?
        var stall = false
    }
    static let lock = NSLock()
    static var reply = Reply()
    static var requests: [URLRequest] = []
    static var stops = 0

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.lock.lock()
        Self.requests.append(request)
        let reply = Self.reply
        Self.lock.unlock()
        if reply.stall { return }
        if let error = reply.error { client?.urlProtocol(self, didFailWithError: error); return }
        guard let url = request.url, let response = HTTPURLResponse(url: url, statusCode: reply.status, httpVersion: "HTTP/1.1", headerFields: reply.headers) else { return }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        for data in reply.chunks { client?.urlProtocol(self, didLoad: data) }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {
        Self.lock.lock(); Self.stops += 1; Self.lock.unlock()
    }
    static func configure(_ reply: Reply) {
        lock.lock(); defer { lock.unlock() }
        Self.reply = reply; requests = []; stops = 0
    }
    static func observedRequests() -> [URLRequest] { lock.lock(); defer { lock.unlock() }; return requests }
    static func observedStops() -> Int { lock.lock(); defer { lock.unlock() }; return stops }
}

final class FoundationSubscriptionTransportTests: XCTestCase {
    private let url = URL(string: "https://subscription.example.test/list?token=private-token")!
    private func transport() -> FoundationSubscriptionTransport {
        FoundationSubscriptionTransport {
            let configuration = FoundationSubscriptionTransport.privateConfiguration()
            configuration.protocolClasses = [FixtureProtocol.self]
            return configuration
        }
    }

    func testStreamingBodyAndPrivateSessionHaveNoPersistentState() async throws {
        FixtureProtocol.configure(.init(chunks: [Data("trojan://private-".utf8), Data("password@server.example.test:443".utf8)]))
        let response = try await transport().get(url: url, userAgent: "Zarp/1.0", deadline: .now.advanced(by: .seconds(2)))
        XCTAssertEqual(try SubscriptionParser.parse(response.body).profiles.count, 1)
        let request = try XCTUnwrap(FixtureProtocol.observedRequests().first)
        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertEqual(request.value(forHTTPHeaderField: "User-Agent"), "Zarp/1.0")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Accept-Encoding"), "gzip")
        let configuration = FoundationSubscriptionTransport.privateConfiguration()
        XCTAssertNil(configuration.httpCookieStorage)
        XCTAssertNil(configuration.urlCredentialStorage)
        XCTAssertNil(configuration.urlCache)
        XCTAssertNil(configuration.connectionProxyDictionary)
        XCTAssertFalse(configuration.httpShouldSetCookies)
        XCTAssertFalse(configuration.waitsForConnectivity)
        XCTAssertFalse(String(reflecting: response).contains("private-"))
    }

    func testStreamingAndHeaderOversizeFailBeforeReturningABody() async throws {
        for reply in [FixtureProtocol.Reply(chunks: [Data(repeating: 32, count: 1024 * 1024), Data(repeating: 32, count: 1024 * 1024 + 1)]),
                      FixtureProtocol.Reply(headers: ["Content-Length": "2097153"], chunks: [Data("private-token".utf8)])] {
            FixtureProtocol.configure(reply)
            do { _ = try await transport().get(url: url, userAgent: "Zarp/1.0", deadline: .now.advanced(by: .seconds(2))); XCTFail("oversized body accepted") }
            catch { XCTAssertEqual(error as? SubscriptionError, .size) }
        }
    }

    func testRedirectAndStatusResponsesReturnWithoutImportingTheirBody() async throws {
        for status in [302, 403] {
            FixtureProtocol.configure(.init(status: status, headers: ["Location": "http://unsafe.example.test/private-token"], chunks: [Data("private-ignored-body".utf8)]))
            let response = try await transport().get(url: url, userAgent: "Zarp/1.0", deadline: .now.advanced(by: .seconds(2)))
            XCTAssertEqual(response.status, status)
            XCTAssertEqual(response.location, "http://unsafe.example.test/private-token")
            XCTAssertTrue(response.body.isEmpty)
            XCTAssertEqual(FixtureProtocol.observedRequests().count, 1)
            XCTAssertFalse(String(reflecting: response).contains("private-"))
        }
    }

    func testRawTLSNetworkAndTimeoutErrorsAreSanitized() async throws {
        for (code, expected) in [(URLError.Code.serverCertificateUntrusted, SubscriptionError.tls), (.secureConnectionFailed, .tls), (.cannotFindHost, .network), (.timedOut, .timeout)] {
            FixtureProtocol.configure(.init(error: URLError(code, userInfo: [NSURLErrorFailingURLStringErrorKey: url.absoluteString, NSLocalizedDescriptionKey: "private-token"])))
            do { _ = try await transport().get(url: url, userAgent: "Zarp/1.0", deadline: .now.advanced(by: .seconds(2))); XCTFail("failed request accepted") }
            catch {
                XCTAssertEqual(error as? SubscriptionError, expected)
                XCTAssertFalse(String(reflecting: error).contains("private-token"))
                XCTAssertFalse(String(reflecting: error).contains("example.test"))
            }
        }
    }

    func testCancellationInterruptsAStalledSessionAndExpiredDeadlineDoesNotStart() async throws {
        FixtureProtocol.configure(.init(stall: true))
        let transport = transport(), url = self.url
        let pending = Task { try await transport.get(url: url, userAgent: "Zarp/1.0", deadline: .now.advanced(by: .seconds(2))) }
        for _ in 0..<100 {
            if !FixtureProtocol.observedRequests().isEmpty { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTAssertEqual(FixtureProtocol.observedRequests().count, 1)
        pending.cancel()
        do { _ = try await pending.value; XCTFail("cancelled session returned data") }
        catch { XCTAssertEqual(error as? SubscriptionError, .cancelled) }
        for _ in 0..<100 {
            if FixtureProtocol.observedStops() > 0 { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTAssertGreaterThan(FixtureProtocol.observedStops(), 0)
        FixtureProtocol.configure(.init())
        do { _ = try await transport.get(url: url, userAgent: "Zarp/1.0", deadline: .now.advanced(by: .seconds(-1))); XCTFail("expired request started") }
        catch { XCTAssertEqual(error as? SubscriptionError, .timeout) }
        XCTAssertTrue(FixtureProtocol.observedRequests().isEmpty)
    }
}
