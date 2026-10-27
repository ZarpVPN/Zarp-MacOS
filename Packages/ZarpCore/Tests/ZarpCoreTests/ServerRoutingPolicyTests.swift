import XCTest
@testable import ZarpCore

final class ServerRoutingPolicyTests: XCTestCase {
    func testApplicationBundlesIncludeInternalHelpersButNotSimilarlyNamedBundles() throws {
        var policy = ServerRoutingPolicy()
        policy.applicationMode = .include
        policy.applicationPaths = ["/Applications/Browser.app", "/usr/bin/curl"]
        try policy.validate()
        XCTAssertTrue(policy.matchesApplication(executable: "/Applications/Browser.app/Contents/Frameworks/Browser Helper.app/Contents/MacOS/Browser Helper"))
        XCTAssertTrue(policy.matchesApplication(executable: "/usr/bin/curl"))
        XCTAssertFalse(policy.matchesApplication(executable: "/Applications/Browser.app.evil/Contents/MacOS/Browser"))
        XCTAssertFalse(policy.matchesApplication(executable: "/usr/bin/curl-other"))
        XCTAssertEqual(try JSONDecoder().decode(ServerRoutingPolicy.self, from: JSONEncoder().encode(policy)), policy)
    }

    func testCorruptSavedPolicyCannotBecomeAnUnrestrictedTunnel() throws {
        let missing = try JSONDecoder().decode(AppSettings.self, from: Data("{}".utf8))
        XCTAssertTrue(missing.serverRouting.isDefault)
        for value in ["null", "true", "{}", "\"bad\""] {
            let settings = try JSONDecoder().decode(AppSettings.self, from: Data(("{\"serverRouting\":" + value + "}").utf8))
            XCTAssertThrowsError(try settings.serverRouting.validate())
            XCTAssertFalse(settings.serverRouting.isDefault)
        }
    }

    func testUnsafePathsEmptyIncludeAndInvalidDNSAreRefused() throws {
        for path in ["/", "relative.app", "/Applications/../Browser.app", "/Applications//Browser.app", "/Applications/Browser.app/", "/Applications/Bad\n.app"] {
            var policy = ServerRoutingPolicy(); policy.applicationPaths = [path]
            XCTAssertThrowsError(try policy.validate(), path)
        }
        var policy = ServerRoutingPolicy(); policy.applicationMode = .include
        XCTAssertThrowsError(try policy.validate())
        policy.applicationMode = .all
        for dns in ["127.0.0.1", "::1", "0.0.0.0", "ff00::1", "fe80::1", "::ffff:7f00:1", "01.1.1.1", "1.1.1.1:53", "resolver.example"] {
            policy.dnsServer = dns
            XCTAssertThrowsError(try policy.validate(), dns)
        }
        policy.ipv6 = false; policy.dnsServer = "2606:4700:4700::1111"
        XCTAssertThrowsError(try policy.validate())
    }

    func testCompactEditorReplacesManualLinksAndRefusesPartialInvalidLists() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = EditorTransport(body: "trojan://fixture@subscription.example:443?security=tls")
        let library = ConnectionLibrary(directory: directory, transport: transport)
        let first = try await library.configureServer(input: "trojan://fixture@first.example:443?security=tls", existingSourceID: nil)
        let next = try await library.configureServer(input: "trojan://fixture@second.example:443?security=tls", existingSourceID: first.id)
        var snapshot = try await library.snapshot()
        XCTAssertEqual(snapshot.manual.profiles.map(\.host), ["second.example"])
        XCTAssertEqual(snapshot.sources.selectedSourceId, try ConnectionSource(kind: .warp).id)
        do {
            _ = try await library.configureServer(input: "trojan://fixture@third.example:443?security=tls\nmalformed-private-link", existingSourceID: next.id)
            XCTFail("partially invalid list replaced saved servers")
        } catch { XCTAssertEqual(error as? ConnectionLibraryError, .source) }
        snapshot = try await library.snapshot()
        XCTAssertEqual(snapshot.manual.profiles.map(\.host), ["second.example"])
        let retained = try await library.configureServer(input: "", existingSourceID: next.id)
        XCTAssertEqual(retained.id, next.id)
        let calls = await transport.calls
        XCTAssertEqual(calls, 0)
        await library.close()
    }

    func testSubscriptionEditorRefreshesBeforeReturningAndNeverActivatesFailedData() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = EditorTransport(body: "trojan://fixture@subscription.example:443?security=tls")
        let library = ConnectionLibrary(directory: directory, transport: transport)
        let source = try await library.configureServer(input: "https://subscription.example/list", existingSourceID: nil)
        let snapshot = try await library.snapshot()
        XCTAssertEqual(snapshot.subscriptions[source.id]?.library.profiles.count, 1)
        let calls = await transport.calls
        XCTAssertEqual(calls, 1)
        await transport.fail()
        do { _ = try await library.configureServer(input: "https://other.example/list", existingSourceID: nil); XCTFail("failed download accepted") }
        catch { XCTAssertEqual(error as? SubscriptionError, .network) }
        let after = try await library.snapshot()
        XCTAssertEqual(after.sources.selectedSourceId, try ConnectionSource(kind: .warp).id)
        XCTAssertEqual(after.subscriptions[source.id], snapshot.subscriptions[source.id])
        await library.close()
    }
}

private actor EditorTransport: SubscriptionHTTPTransport {
    let body: String
    private(set) var calls = 0
    private var failing = false
    init(body: String) { self.body = body }
    func fail() { failing = true }
    func get(url: URL, userAgent: String, deadline: ContinuousClock.Instant) async throws -> SubscriptionHTTPResponse {
        calls += 1
        if failing { throw SubscriptionError.network }
        return SubscriptionHTTPResponse(status: 200, body: Data(body.utf8))
    }
}
