import XCTest
@testable import ZarpCore

private actor RepositoryTransport: SubscriptionHTTPTransport {
    let delay: UInt64
    let error: SubscriptionError?
    let body: Data
    private(set) var calls = 0
    init(delay: UInt64 = 0, error: SubscriptionError? = nil, body: Data) { self.delay = delay; self.error = error; self.body = body }
    func get(url: URL, userAgent: String, deadline: ContinuousClock.Instant) async throws -> SubscriptionHTTPResponse {
        calls += 1
        if delay > 0 { try await Task.sleep(nanoseconds: delay) }
        if let error { throw error }
        return SubscriptionHTTPResponse(status: 200, body: body)
    }
}

final class SubscriptionRepositoryTests: XCTestCase {
    private var directory: URL!
    private let date = Date(timeIntervalSince1970: 1_000_000)
    private let firstBody = Data("trojan://first-test-password@server.example.test:443#First".utf8)
    private let secondBody = Data("trojan://second-test-password@server.example.test:443#Second".utf8)
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("zarp-refresh-repository-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }
    private func source(token: String = "private-token") throws -> ConnectionSource {
        try ConnectionSource(kind: .subscription, subscriptionURL: "https://subscription.example.test/list?token=\(token)")
    }
    private func started(_ transport: RepositoryTransport) async throws {
        for _ in 0..<100 {
            if await transport.calls > 0 { return }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTFail("controlled refresh did not enter transport")
    }

    func testFreshOfflineCacheDoesNotMakeARequest() async throws {
        let cache = SubscriptionCache(directory: directory), source = try source(), date = self.date
        let first = try cache.replace(source: source, result: SubscriptionParser.parse(firstBody), updatedAt: date).snapshot
        let transport = RepositoryTransport(error: .network, body: Data())
        let repository = SubscriptionRepository(cache: cache, downloader: SubscriptionDownloader(transport: transport), now: { date.addingTimeInterval(1) })
        let outcome = try await repository.refreshIfNeeded(source: source)
        if case .fresh(let snapshot) = outcome { XCTAssertEqual(snapshot, first) } else { XCTFail("fresh offline cache was fetched") }
        let calls = await transport.calls
        XCTAssertEqual(calls, 0)
        await repository.close()
    }

    func testStaleNetworkTLSSizeAndFormatFailureRetainExplicitOfflineSelection() async throws {
        let source = try source(), date = self.date
        for (error, body) in [(SubscriptionError.network, Data()), (.tls, Data()), (.size, Data()), (.timeout, Data()),
                              (.html, Data("<html>private-token</html>".utf8)), (.json, Data("[{\"private-token\":1}]".utf8))] {
            let cache = SubscriptionCache(directory: directory)
            let first = try cache.replace(source: source, result: SubscriptionParser.parse(firstBody), updatedAt: date).snapshot
            let id = first.library.profiles[0].id
            try cache.select(serverId: id, source: source)
            let old = try cache.load(source: source)
            let transport = RepositoryTransport(error: body.isEmpty ? error : nil, body: body)
            let repository = SubscriptionRepository(cache: cache, downloader: SubscriptionDownloader(transport: transport), now: { date.addingTimeInterval(12 * 60 * 60) })
            if case .cached(let snapshot, let notice) = try await repository.refreshIfNeeded(source: source) {
                XCTAssertEqual(snapshot, old)
                XCTAssertEqual(notice.reason, error)
                XCTAssertNil(notice.httpStatus)
            } else { XCTFail("stale valid cache was discarded after refresh failure") }
            XCTAssertEqual(try cache.load(source: source), old)
            await repository.close()
        }
    }

    func testSelectionDuringRefreshIsPreservedAndRemovedIDBecomesUnavailable() async throws {
        let cache = SubscriptionCache(directory: directory), source = try source(), date = self.date
        let first = try cache.replace(source: source, result: SubscriptionParser.parse(firstBody), updatedAt: date).snapshot
        let transport = RepositoryTransport(delay: 70_000_000, body: secondBody)
        let repository = SubscriptionRepository(cache: cache, downloader: SubscriptionDownloader(transport: transport), now: { date.addingTimeInterval(1) })
        let pending = Task { try await repository.refresh(source: source) }
        try await started(transport)
        let id = first.library.profiles[0].id
        try await repository.select(serverId: id, source: source)
        let update = try await pending.value
        XCTAssertEqual(update.snapshot.library.selection, .unavailable(id))
        XCTAssertEqual(update.removedServerIds, [id])
        XCTAssertEqual(try cache.load(source: source)?.library.selection, .unavailable(id))
        await repository.close()
    }

    func testDeleteDuringRefreshCannotRecreateCacheOrDeleteAnotherSource() async throws {
        let cache = SubscriptionCache(directory: directory), source = try source(), other = try self.source(token: "other-test-token"), date = self.date
        _ = try cache.replace(source: source, result: SubscriptionParser.parse(firstBody), updatedAt: date)
        let otherSnapshot = try cache.replace(source: other, result: SubscriptionParser.parse(firstBody), updatedAt: date).snapshot
        let transport = RepositoryTransport(delay: 5_000_000_000, body: secondBody)
        let repository = SubscriptionRepository(cache: cache, downloader: SubscriptionDownloader(transport: transport), now: { date.addingTimeInterval(1) })
        let pending = Task { try await repository.refresh(source: source) }
        try await started(transport)
        try await repository.delete(source: source)
        do { _ = try await pending.value; XCTFail("deleted refresh published a late result") }
        catch { XCTAssertEqual(error as? SubscriptionError, .cancelled) }
        XCTAssertNil(try cache.load(source: source))
        XCTAssertEqual(try cache.load(source: other), otherSnapshot)
        await repository.close()
    }

    func testDuplicateAdmissionCancellationAndCloseRetainOldCache() async throws {
        let cache = SubscriptionCache(directory: directory), source = try source(), date = self.date
        let first = try cache.replace(source: source, result: SubscriptionParser.parse(firstBody), updatedAt: date).snapshot
        let transport = RepositoryTransport(delay: 5_000_000_000, body: secondBody)
        let repository = SubscriptionRepository(cache: cache, downloader: SubscriptionDownloader(transport: transport), now: { date.addingTimeInterval(1) })
        let pending = Task { try await repository.refresh(source: source) }
        try await started(transport)
        do { _ = try await repository.refresh(source: source); XCTFail("duplicate refresh admitted") }
        catch { XCTAssertEqual(error as? SubscriptionError, .busy) }
        pending.cancel()
        do { _ = try await pending.value; XCTFail("cancelled refresh wrote a cache") }
        catch { XCTAssertEqual(error as? SubscriptionError, .cancelled) }
        XCTAssertEqual(try cache.load(source: source), first)
        let second = Task { try await repository.refresh(source: source) }
        for _ in 0..<100 {
            if await transport.calls >= 2 { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        await repository.close()
        do { _ = try await second.value; XCTFail("closed repository wrote a cache") }
        catch { XCTAssertEqual(error as? SubscriptionError, .cancelled) }
        XCTAssertEqual(try cache.load(source: source), first)
        do { _ = try await repository.refresh(source: source); XCTFail("closed repository restarted") }
        catch { XCTAssertEqual(error as? SubscriptionError, .cancelled) }
    }
}
