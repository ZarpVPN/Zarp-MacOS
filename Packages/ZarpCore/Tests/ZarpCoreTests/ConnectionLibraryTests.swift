import Foundation
import XCTest
@testable import ZarpCore

final class ConnectionLibraryTests: XCTestCase {
    private var directory: URL!
    private let first = "trojan://private-secret@first.example:443?security=tls&type=tcp&sni=first.example#First"
    private let second = "trojan://another-secret@second.example:443?security=tls&type=tcp&sni=second.example#Second"

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("zarp-library-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        if FileManager.default.fileExists(atPath: directory.path) { try FileManager.default.removeItem(at: directory) }
    }

    func testOpeningAndImportingNeverFetchOrReplaceWarpSelection() async throws {
        let transport = LibraryTransport(body: first)
        let library = ConnectionLibrary(directory: directory, transport: transport)
        let initial = try await library.snapshot()
        XCTAssertEqual(initial.sources.sources.map(\.kind), [.warp])
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.path))
        let result = try await library.importLinks(first + "\n" + first + "\nss://unsupported")
        XCTAssertEqual(result.profiles.count, 1)
        XCTAssertEqual(result.unsupported, 1)
        let imported = try await library.snapshot()
        XCTAssertEqual(imported.manual.profiles.count, 1)
        XCTAssertEqual(imported.sources.selectedSourceId, initial.sources.selectedSourceId)
        let calls = await transport.calls
        XCTAssertEqual(calls, 0)
        await library.close()
    }

    func testManualSelectionAndMissingServerSurviveRestartWithoutSubstitution() async throws {
        let transport = LibraryTransport(body: first)
        let library = ConnectionLibrary(directory: directory, transport: transport)
        _ = try await library.importLinks(first + "\n" + second)
        let sourceId = try ConnectionSource(kind: .manual).id
        let state = try await library.snapshot()
        let selected = state.manual.profiles[0].id
        try await library.selectServer(id: selected, sourceId: sourceId)
        try await library.removeManualServer(id: selected)
        await library.close()
        let reopened = ConnectionLibrary(directory: directory, transport: transport)
        let saved = try await reopened.snapshot()
        XCTAssertEqual(saved.manual.selection, .unavailable(selected))
        XCTAssertEqual(saved.manual.profiles.count, 1)
        try await reopened.selectServer(id: nil, sourceId: sourceId)
        let automatic = try await reopened.snapshot()
        XCTAssertEqual(automatic.manual.selection, .automatic)
        await reopened.close()
    }

    func testRefreshFailureKeepsCachedSelectionAndUrlIdentity() async throws {
        let transport = LibraryTransport(body: first + "\n" + second)
        let library = ConnectionLibrary(directory: directory, transport: transport)
        let source = try await library.saveSubscription(label: "My source", url: "https://subscription.example/list?token=private")
        let beforeRefreshCalls = await transport.calls
        XCTAssertEqual(beforeRefreshCalls, 0)
        let downloaded = try await library.refresh(sourceId: source.id)
        let selected = downloaded.snapshot.library.profiles[0].id
        try await library.selectServer(id: selected, sourceId: source.id)
        let renamed = try await library.saveSubscription(label: "Renamed", url: source.subscriptionURL!)
        XCTAssertEqual(renamed.id, source.id)
        let prior = try await library.snapshot()
        await transport.fail()
        do { _ = try await library.refresh(sourceId: source.id); XCTFail("failed fetch was accepted") }
        catch { XCTAssertEqual(error as? SubscriptionError, .network) }
        let after = try await library.snapshot()
        XCTAssertEqual(after.subscriptions[source.id], prior.subscriptions[source.id])
        XCTAssertEqual(after.subscriptions[source.id]?.library.selectedServerId, selected)
        let newUrl = try await library.saveSubscription(label: "Other", url: "https://subscription.example/list?token=changed")
        XCTAssertNotEqual(newUrl.id, source.id)
        let beforeDelete = try await library.snapshot()
        XCTAssertNil(beforeDelete.subscriptions[newUrl.id])
        try await library.deleteSubscription(sourceId: source.id)
        let afterDelete = try await library.snapshot()
        XCTAssertNil(afterDelete.subscriptions[source.id])
        XCTAssertFalse(afterDelete.sources.sources.contains(where: { $0.id == source.id }))
        XCTAssertTrue(afterDelete.sources.sources.contains(where: { $0.id == newUrl.id }))
        await library.close()
    }

    func testCapacityFailureDoesNotPartiallyImportProfiles() async throws {
        let transport = LibraryTransport(body: "")
        let library = ConnectionLibrary(directory: directory, transport: transport)
        let links = (0..<ServerProfileLibrary.maxProfiles).map { "trojan://secret\($0)@server.example:443#Server\($0)" }.joined(separator: "\n")
        _ = try await library.importLinks(links)
        let before = try await library.snapshot()
        do { _ = try await library.importLinks(first); XCTFail("over-capacity import was accepted") }
        catch { XCTAssertEqual(error as? ServerProfileLibraryError, .profiles) }
        let after = try await library.snapshot()
        XCTAssertEqual(after.manual, before.manual)
        await library.close()
    }

    func testDamagedSubscriptionDoesNotBlockOtherSourcesOrDeleteItsEvidenceOnLoad() async throws {
        let library = ConnectionLibrary(directory: directory, transport: LibraryTransport(body: first))
        let source = try await library.saveSubscription(label: "Damaged", url: "https://subscription.example/list")
        _ = try await library.refresh(sourceId: source.id)
        let cache = directory.appendingPathComponent("subscriptions/" + source.id + ".json")
        let damaged = Data("{broken private cache".utf8)
        try damaged.write(to: cache)
        _ = try await library.importLinks(second)
        let state = try await library.snapshot()
        XCTAssertEqual(state.unreadableSourceIds, [source.id])
        XCTAssertEqual(state.manual.profiles.count, 1)
        XCTAssertNil(state.subscriptions[source.id])
        XCTAssertEqual(try Data(contentsOf: cache), damaged)
        try await library.deleteSubscription(sourceId: source.id)
        XCTAssertFalse(FileManager.default.fileExists(atPath: cache.path))
        await library.close()
    }
}

private actor LibraryTransport: SubscriptionHTTPTransport {
    private let body: Data
    private var failed = false
    private(set) var calls = 0
    init(body: String) { self.body = Data(body.utf8) }
    func fail() { failed = true }
    func get(url: URL, userAgent: String, deadline: ContinuousClock.Instant) async throws -> SubscriptionHTTPResponse {
        calls += 1
        if failed { throw SubscriptionError.network }
        return SubscriptionHTTPResponse(status: 200, body: body)
    }
}
