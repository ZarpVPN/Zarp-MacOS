import XCTest
import Darwin
@testable import ZarpCore

final class ServerProfileStoreTests: XCTestCase {
    private var directory: URL!
    private var url: URL { directory.appendingPathComponent("servers/profiles.json") }

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("zarp-private-profiles-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }

    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }

    private func profile(label: String = "Test", password: String = "test-only-password") throws -> ServerProfile {
        try ServerProfile(label: label, host: "proxy.example", port: 443, serverProtocol: .trojan,
                          credential: .init(kind: .password, value: password))
    }

    func testMissingCollectionMigratesWithoutTouchingWarpPreferences() throws {
        let settingsURL = directory.appendingPathComponent("zarp.json")
        let settingsStore = JSONFileSettingsStore(url: settingsURL)
        var original = AppSettings()
        original.language = "fr"
        original.autoConnectOnStart = true
        original.warpTermsAccepted = true
        original.selectedStrategyId = "warp-q-google6"
        original.results["warp-q-google6"] = .init(strategyId: "warp-q-google6", ok: true, connectMs: 20, pingMs: 4,
                                                 confirmed: true, timestamp: Date(timeIntervalSince1970: 1_791_282_600),
                                                 configurationFingerprint: StrategyCatalog.builtIn.first!.configurationFingerprint)
        settingsStore.save(original)
        let before = try Data(contentsOf: settingsURL)
        let store = ServerProfileStore(url: url)
        let missing = try store.load()
        XCTAssertEqual(missing.selection, .automatic)
        XCTAssertTrue(missing.profiles.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.deletingLastPathComponent().path))
        try store.save(ServerProfileLibrary(profiles: [profile()]))
        XCTAssertEqual(try Data(contentsOf: settingsURL), before)
        XCTAssertEqual(settingsStore.load(), original)
    }

    func testRestrictedAtomicRoundTripAndOfflineSelection() throws {
        let p = try profile()
        let library = try ServerProfileLibrary(profiles: [p], selectedServerId: p.id)
        let store = ServerProfileStore(url: url)
        try store.save(library)
        XCTAssertEqual(try store.load(), library)
        XCTAssertEqual(try store.load().selection, .available(p))
        for (path, expected) in [(url.deletingLastPathComponent(), 0o700), (url, 0o600)] {
            let attributes = try FileManager.default.attributesOfItem(atPath: path.path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, expected)
        }
        for i in 0..<10 {
            try store.save(ServerProfileLibrary(profiles: [profile(label: "Rename \(i)")], selectedServerId: p.id))
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: url.deletingLastPathComponent().path), ["profiles.json"])
        XCTAssertEqual(try store.load().profiles.first?.label, "Rename 9")
    }

    func testAdvancedSecretsAndSelectionsSurviveRestrictedStorage() throws {
        let reality = try ServerLinkImporter.parse("vless://11111111-2222-4333-a444-555555555555@proxy.example:443?security=reality&sni=front.example&pbk=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&sid=abcd&flow=xtls-rprx-vision#First")
        let salamander = try ServerLinkImporter.parse("hy2://test-only-password@proxy.example?obfs=salamander&obfs-password=private-obfs-secret")
        var library = try ServerProfileLibrary(profiles: [reality, salamander], selectedServerId: reality.id)
        let store = ServerProfileStore(url: url)
        try store.save(library)
        XCTAssertEqual(try store.load(), library)
        let stored = try Data(contentsOf: url)
        XCTAssertTrue(String(decoding: stored, as: UTF8.self).contains("private-obfs-secret"))
        for value in [String(describing: salamander), String(reflecting: salamander), String(reflecting: library)] {
            XCTAssertFalse(value.contains("private-obfs-secret"))
        }
        let renamed = try ServerLinkImporter.parse("vless://11111111-2222-4333-a444-555555555555@proxy.example:443?sid=abcd&pbk=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&security=reality&sni=front.example&flow=xtls-rprx-vision#Second")
        XCTAssertEqual(renamed.id, reality.id)
        try library.upsert(renamed)
        XCTAssertEqual(library.profiles.count, 2)
        XCTAssertEqual(library.selection, .available(renamed))
        library.remove(id: reality.id)
        try store.save(library)
        XCTAssertEqual(try store.load().selection, .unavailable(reality.id))
    }

    func testRenamingUpdatesOneIdentityAndRemovedSelectionDoesNotBecomeAutomatic() throws {
        let p = try profile()
        var library = try ServerProfileLibrary(profiles: [p], selectedServerId: p.id)
        let renamed = try profile(label: "Renamed")
        try library.upsert(renamed)
        XCTAssertEqual(library.profiles, [renamed])
        XCTAssertEqual(library.selection, .available(renamed))
        library.remove(id: p.id)
        XCTAssertEqual(library.selection, .unavailable(p.id))
        try library.upsert(profile(password: "different-test-only"))
        XCTAssertEqual(library.selection, .unavailable(p.id))
        let store = ServerProfileStore(url: url)
        try store.save(library)
        XCTAssertEqual(try store.load().selection, .unavailable(p.id))
        try library.select(id: nil)
        XCTAssertEqual(library.selection, .automatic)
    }

    func testCountDuplicateIdentityAndInvalidSelectionFailTransactionally() throws {
        let p = try profile()
        XCTAssertThrowsError(try ServerProfileLibrary(profiles: [p, profile(label: "Rename")]))
        let profiles = try (0..<ServerProfileLibrary.maxProfiles).map { try profile(password: "test-only-\($0)") }
        var library = try ServerProfileLibrary(profiles: profiles)
        XCTAssertThrowsError(try library.upsert(profile(password: "extra-test-only")))
        XCTAssertEqual(library.profiles, profiles)
        XCTAssertThrowsError(try library.select(id: "private-secret"))
        XCTAssertEqual(library.selection, .automatic)
    }

    func testCorruptUnknownAndDuplicateDataIsPreservedAndErrorsAreSafe() throws {
        let store = ServerProfileStore(url: url)
        try store.save(ServerProfileLibrary(profiles: [profile()]))
        for text in [#"{"version":99,"profiles":[]}"#,
                     #"{"version":1,"profiles":[],"command":"private-secret"}"#,
                     #"{"version":1,"profiles":[],"profiles":["private-secret"]}"#,
                     "{private-secret-not-json"] {
            try Data(text.utf8).write(to: url)
            let before = try Data(contentsOf: url)
            XCTAssertThrowsError(try store.load()) {
                XCTAssertFalse(String(describing: $0).contains("private-secret"))
            }
            XCTAssertEqual(try Data(contentsOf: url), before)
        }
    }

    func testSymlinkAndFifoRefusalNeverChangesTargets() throws {
        let target = directory.appendingPathComponent("target.json")
        let marker = Data("private-target-marker".utf8)
        try marker.write(to: target)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        try FileManager.default.createSymbolicLink(at: url, withDestinationURL: target)
        let store = ServerProfileStore(url: url)
        XCTAssertThrowsError(try store.load())
        XCTAssertThrowsError(try store.save(ServerProfileLibrary(profiles: [profile()])))
        XCTAssertEqual(try Data(contentsOf: target), marker)
        try FileManager.default.removeItem(at: url)
        XCTAssertEqual(mkfifo(url.path, 0o600), 0)
        XCTAssertThrowsError(try store.load())
        XCTAssertThrowsError(try store.save(ServerProfileLibrary(profiles: [profile()])))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: url.deletingLastPathComponent().path), ["profiles.json"])
    }

    func testPublicPermissionsAndDirectorySymlinkAreRefused() throws {
        let store = ServerProfileStore(url: url)
        try store.save(ServerProfileLibrary(profiles: [profile()]))
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
        XCTAssertThrowsError(try store.load())
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.deletingLastPathComponent().path)
        XCTAssertThrowsError(try store.save(ServerProfileLibrary()))
        XCTAssertThrowsError(try store.load())
        try FileManager.default.removeItem(at: url.deletingLastPathComponent())
        let destination = directory.appendingPathComponent("different-private-directory")
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createSymbolicLink(at: url.deletingLastPathComponent(), withDestinationURL: destination)
        XCTAssertThrowsError(try store.load())
        XCTAssertThrowsError(try store.save(ServerProfileLibrary()))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: destination.path).isEmpty)
    }
}
