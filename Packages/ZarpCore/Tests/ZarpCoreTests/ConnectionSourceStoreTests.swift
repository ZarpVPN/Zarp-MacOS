import XCTest
import Darwin
@testable import ZarpCore

final class ConnectionSourceStoreTests: XCTestCase {
    private var directory: URL!
    private var url: URL { directory.appendingPathComponent("sources/sources.json") }

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("zarp-private-sources-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
    }

    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }

    private func subscription(label: String = "Test", token: String = "private-source-token") throws -> ConnectionSource {
        try ConnectionSource(kind: .subscription, label: label, subscriptionURL: "https://subscription.example.test/list?token=\(token)")
    }

    func testMissingSourcesMigrateToWarpWithoutChangingOtherDocuments() throws {
        let settingsURL = directory.appendingPathComponent("zarp.json")
        let settings = JSONFileSettingsStore(url: settingsURL)
        var preferences = AppSettings()
        preferences.language = "de"
        preferences.autoConnectOnStart = true
        preferences.warpTermsAccepted = true
        preferences.selectedStrategyId = "warp-q-google6"
        settings.save(preferences)
        let accountURL = directory.appendingPathComponent("account-marker.json")
        let profilesURL = directory.appendingPathComponent("profile-marker.json")
        try Data("private-account-marker".utf8).write(to: accountURL)
        try Data("private-profile-marker".utf8).write(to: profilesURL)
        let before = try [settingsURL, accountURL, profilesURL].map { try Data(contentsOf: $0) }
        let store = ConnectionSourceStore(url: url)
        let library = try store.load()
        XCTAssertEqual(library.selection, .available(try ConnectionSource(kind: .warp)))
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.deletingLastPathComponent().path))
        try store.save(library)
        XCTAssertEqual(try store.load(), library)
        XCTAssertEqual(try [settingsURL, accountURL, profilesURL].map { try Data(contentsOf: $0) }, before)
        XCTAssertEqual(settings.load(), preferences)
    }

    func testPrivateOfflineRoundTripPreservesTokensAndSelection() throws {
        let source = try subscription()
        var library = try ConnectionSourceLibrary()
        try library.upsert(source)
        try library.select(id: source.id)
        let store = ConnectionSourceStore(url: url)
        try store.save(library)
        XCTAssertEqual(try ConnectionSourceStore(url: url).load(), library)
        XCTAssertEqual(try store.load().selection, .available(source))
        XCTAssertTrue(String(decoding: try Data(contentsOf: url), as: UTF8.self).contains("private-source-token"))
        for (path, expected) in [(url.deletingLastPathComponent(), 0o700), (url, 0o600)] {
            let attributes = try FileManager.default.attributesOfItem(atPath: path.path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, expected)
        }
        for value in [String(describing: library), String(reflecting: library), String(reflecting: library.selection)] {
            XCTAssertFalse(value.contains("private-source-token"))
            XCTAssertFalse(value.contains("subscription.example.test"))
        }
        for i in 0..<8 {
            try library.upsert(subscription(label: "Renamed \(i)"))
            try store.save(library)
        }
        XCTAssertEqual(library.sources.count, 2)
        XCTAssertEqual(try store.load().selectedSourceId, source.id)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: url.deletingLastPathComponent().path), ["sources.json"])
    }

    func testSourceRemovalAndURLChangeNeverRebindSelectedIdentity() throws {
        let original = try subscription()
        let replacement = try subscription(token: "changed-test-token")
        var library = try ConnectionSourceLibrary()
        try library.upsert(original)
        try library.select(id: original.id)
        try library.remove(id: original.id)
        try library.upsert(replacement)
        XCTAssertEqual(library.selection, .unavailable(original.id))
        XCTAssertNotEqual(original.id, replacement.id)
        let store = ConnectionSourceStore(url: url)
        try store.save(library)
        XCTAssertEqual(try store.load().selection, .unavailable(original.id))
        try library.select(id: replacement.id)
        XCTAssertEqual(library.selection, .available(replacement))
        let warp = try ConnectionSource(kind: .warp)
        XCTAssertThrowsError(try library.remove(id: warp.id))
        XCTAssertTrue(library.sources.contains(warp))
    }

    func testInvalidDuplicateOrOverLimitEditsAreTransactional() throws {
        let warp = try ConnectionSource(kind: .warp)
        let source = try subscription()
        XCTAssertThrowsError(try ConnectionSourceLibrary(sources: [source], selectedSourceId: source.id))
        XCTAssertThrowsError(try ConnectionSourceLibrary(sources: [warp, source, subscription(label: "Rename")]))
        var library = try ConnectionSourceLibrary()
        for i in 0..<(ConnectionSourceLibrary.maxSources - 1) {
            try library.upsert(subscription(token: "test-only-\(i)"))
        }
        let before = library
        XCTAssertThrowsError(try library.upsert(subscription(token: "extra-test-only")))
        XCTAssertThrowsError(try library.select(id: "private-source-token"))
        XCTAssertEqual(library, before)
        let store = ConnectionSourceStore(url: url)
        try store.save(before)
        XCTAssertEqual(try store.load(), before)
    }

    func testMalformedUnknownDuplicateAndOversizedFilesArePreserved() throws {
        let store = ConnectionSourceStore(url: url)
        try store.save(ConnectionSourceLibrary())
        let valid = try String(decoding: Data(contentsOf: url), as: UTF8.self)
        let documents = [
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":99"),
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1"),
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"command\":\"private-source-token\""),
            valid.replacingOccurrences(of: "\"kind\":\"warp\"", with: "\"kind\":\"warp\",\"subscriptionURL\":\"https://private-source-token.example\""),
            "{private-source-token-invalid-json",
            String(repeating: " ", count: ConnectionSourceLibrary.maxBytes + 1)
        ]
        for text in documents {
            try Data(text.utf8).write(to: url)
            let before = try Data(contentsOf: url)
            XCTAssertThrowsError(try store.load()) { error in
                XCTAssertFalse(String(describing: error).contains("private-source-token"))
            }
            XCTAssertEqual(try Data(contentsOf: url), before)
        }
    }

    func testSymlinksAndFifosAreRefusedWithoutChangingTargets() throws {
        let target = directory.appendingPathComponent("target.json")
        let marker = Data("private-target-marker".utf8)
        try marker.write(to: target)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        try FileManager.default.createSymbolicLink(at: url, withDestinationURL: target)
        let store = ConnectionSourceStore(url: url)
        XCTAssertThrowsError(try store.load())
        XCTAssertThrowsError(try store.save(ConnectionSourceLibrary()))
        XCTAssertEqual(try Data(contentsOf: target), marker)
        try FileManager.default.removeItem(at: url)
        XCTAssertEqual(mkfifo(url.path, 0o600), 0)
        XCTAssertThrowsError(try store.load())
        XCTAssertThrowsError(try store.save(ConnectionSourceLibrary()))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: url.deletingLastPathComponent().path), ["sources.json"])
    }

    func testPublicPermissionsAndDirectorySymlinksAreRefused() throws {
        let store = ConnectionSourceStore(url: url)
        try store.save(ConnectionSourceLibrary())
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
        XCTAssertThrowsError(try store.load())
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.deletingLastPathComponent().path)
        XCTAssertThrowsError(try store.load())
        XCTAssertThrowsError(try store.save(ConnectionSourceLibrary()))
        try FileManager.default.removeItem(at: url.deletingLastPathComponent())
        let destination = directory.appendingPathComponent("different-private-directory")
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createSymbolicLink(at: url.deletingLastPathComponent(), withDestinationURL: destination)
        XCTAssertThrowsError(try store.load())
        XCTAssertThrowsError(try store.save(ConnectionSourceLibrary()))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: destination.path).isEmpty)
    }
}
