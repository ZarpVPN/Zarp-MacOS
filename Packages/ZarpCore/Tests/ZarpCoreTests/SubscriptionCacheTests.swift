import XCTest
import Darwin
@testable import ZarpCore

final class SubscriptionCacheTests: XCTestCase {
    private var directory: URL!
    private var cacheDirectory: URL { directory.appendingPathComponent("cache") }
    private let date = Date(timeIntervalSince1970: 1_000_000)

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("zarp-subscription-cache-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }
    private func source(token: String = "private-source-token", label: String = "Test") throws -> ConnectionSource {
        try ConnectionSource(kind: .subscription, label: label, subscriptionURL: "https://subscription.example.test/list?token=\(token)")
    }
    private func result(password: String = "private-server-password", label: String = "Test") throws -> SubscriptionResult {
        try SubscriptionParser.parse(Data("trojan://\(password)@server.example.test:443#\(label)".utf8))
    }
    private func path(_ source: ConnectionSource) -> URL { cacheDirectory.appendingPathComponent(source.id + ".json") }

    func testPrivateOfflineRestartAndSourceBindingPreserveSelection() throws {
        let cache = SubscriptionCache(directory: cacheDirectory)
        let original = try source()
        XCTAssertNil(try cache.load(source: original))
        XCTAssertFalse(FileManager.default.fileExists(atPath: cacheDirectory.path))
        let update = try cache.replace(source: original, result: result(), updatedAt: date)
        let id = try XCTUnwrap(update.snapshot.library.profiles.first?.id)
        try cache.select(serverId: id, source: original)
        let restarted = SubscriptionCache(directory: cacheDirectory)
        XCTAssertEqual(try restarted.load(source: original)?.library.selectedServerId, id)
        XCTAssertEqual(try restarted.load(source: source(label: "Rename"))?.sourceId, original.id)
        XCTAssertNil(try restarted.load(source: source(token: "different-private-token")))
        for (url, mode) in [(cacheDirectory, 0o700), (path(original), 0o600)] {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, mode)
        }
        let raw = try String(decoding: Data(contentsOf: path(original)), as: UTF8.self)
        XCTAssertTrue(raw.contains("private-server-password"))
        XCTAssertFalse(raw.contains("private-source-token"))
        for text in [String(describing: update.snapshot), String(reflecting: update.snapshot)] {
            XCTAssertFalse(text.contains("private-"))
            XCTAssertFalse(text.contains("example.test"))
        }
    }

    func testRefreshPreservesRemovedSelectionAndReportsOnlyRemovedIDs() throws {
        let cache = SubscriptionCache(directory: cacheDirectory)
        let source = try source()
        let first = try cache.replace(source: source, result: result(), updatedAt: date).snapshot
        let id = first.library.profiles[0].id
        try cache.select(serverId: id, source: source)
        let rename = try cache.replace(source: source, result: result(label: "Renamed"), updatedAt: date.addingTimeInterval(1))
        XCTAssertTrue(rename.removedServerIds.isEmpty)
        XCTAssertEqual(rename.snapshot.library.selection, .available(rename.snapshot.library.profiles[0]))
        let replacement = try cache.replace(source: source, result: result(password: "replacement-test-password"), updatedAt: date.addingTimeInterval(2))
        XCTAssertEqual(replacement.removedServerIds, [id])
        XCTAssertEqual(replacement.snapshot.library.selection, .unavailable(id))
        XCTAssertEqual(try cache.load(source: source)?.library.selection, .unavailable(id))
        try cache.select(serverId: nil, source: source)
        XCTAssertEqual(try cache.load(source: source)?.library.selection, .automatic)
    }

    func testFailedEmptyOrOlderRefreshRetainsLastDocument() throws {
        let cache = SubscriptionCache(directory: cacheDirectory)
        let source = try source()
        _ = try cache.replace(source: source, result: result(), updatedAt: date)
        let before = try Data(contentsOf: path(source))
        for body in ["", "<html>private-token</html>", "[{\"private\":\"token\"}]", "trojan://private-invalid"] {
            XCTAssertThrowsError(try cache.replace(source: source, result: SubscriptionParser.parse(Data(body.utf8)), updatedAt: date.addingTimeInterval(1)))
            XCTAssertEqual(try Data(contentsOf: path(source)), before)
        }
        XCTAssertThrowsError(try cache.replace(source: source, result: result(password: "older-test-password"), updatedAt: date.addingTimeInterval(-1))) {
            XCTAssertEqual($0 as? SubscriptionCacheError, .stale)
        }
        XCTAssertEqual(try Data(contentsOf: path(source)), before)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: cacheDirectory.path), [source.id + ".json"])
    }

    func testFreshnessRejectsClockRegressionAndTwelveHourBoundary() throws {
        let snapshot = try SubscriptionSnapshot(source: source(), result: result(), updatedAt: date)
        XCTAssertTrue(snapshot.isFresh(at: date))
        XCTAssertTrue(snapshot.isFresh(at: date.addingTimeInterval(12 * 60 * 60 - 0.001)))
        XCTAssertFalse(snapshot.isFresh(at: date.addingTimeInterval(12 * 60 * 60)))
        XCTAssertFalse(snapshot.isFresh(at: date.addingTimeInterval(-0.001)))
        XCTAssertFalse(snapshot.isFresh(at: Date(timeIntervalSince1970: .infinity)))
    }

    func testMalformedDuplicateCrossSourceAndOversizedCacheArePreserved() throws {
        let cache = SubscriptionCache(directory: cacheDirectory)
        let original = try source()
        _ = try cache.replace(source: original, result: result(), updatedAt: date)
        let valid = try String(decoding: Data(contentsOf: path(original)), as: UTF8.self)
        for text in [valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":99"),
                     valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1"),
                     valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"command\":\"private-value\""),
                     valid.replacingOccurrences(of: original.id, with: try source(token: "other-test-token").id),
                     valid.replacingOccurrences(of: "\"unsupported\":0", with: "\"unsupported\":-1"),
                     String(repeating: " ", count: SubscriptionSnapshot.maxBytes + 1)] {
            try Data(text.utf8).write(to: path(original))
            let before = try Data(contentsOf: path(original))
            XCTAssertThrowsError(try cache.load(source: original)) { XCTAssertFalse(String(describing: $0).contains("private-")) }
            XCTAssertThrowsError(try cache.replace(source: original, result: result(), updatedAt: date.addingTimeInterval(1)))
            XCTAssertEqual(try Data(contentsOf: path(original)), before)
        }
    }

    func testDeleteIsSourceSpecificAndUnsafeFilesAreRefused() throws {
        let cache = SubscriptionCache(directory: cacheDirectory)
        let original = try source()
        let other = try source(token: "second-test-token")
        _ = try cache.replace(source: original, result: result(), updatedAt: date)
        _ = try cache.replace(source: other, result: result(), updatedAt: date)
        try cache.delete(source: original)
        XCTAssertNil(try cache.load(source: original))
        XCTAssertNotNil(try cache.load(source: other))
        try cache.delete(source: original)
        let marker = directory.appendingPathComponent("marker.json")
        try Data("private-marker".utf8).write(to: marker)
        try FileManager.default.createSymbolicLink(at: path(original), withDestinationURL: marker)
        XCTAssertThrowsError(try cache.delete(source: original))
        XCTAssertThrowsError(try cache.load(source: original))
        XCTAssertEqual(try Data(contentsOf: marker), Data("private-marker".utf8))
        try FileManager.default.removeItem(at: path(original))
        XCTAssertEqual(mkfifo(path(original).path, 0o600), 0)
        XCTAssertThrowsError(try cache.delete(source: original))
        XCTAssertThrowsError(try cache.load(source: original))
        XCTAssertNotNil(try cache.load(source: other))
    }
}
