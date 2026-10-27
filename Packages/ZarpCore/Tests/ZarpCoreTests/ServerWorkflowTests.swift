import XCTest
@testable import ZarpCore

final class ServerWorkflowTests: XCTestCase {
    private let tcp = "trojan://private-test@server.example:443?security=tls#Test"
    private let udp = "hy2://private-test@quic.example:443?sni=quic.example#QUIC"

    func testWarpNameVariantsNeverChangeAnImportedServersTLSName() throws {
        let profiles = try [ServerLinkImporter.parse(tcp), ServerLinkImporter.parse(udp)]
        let variants = StrategyCatalog.builtIn.filter { $0.warpTLSName != nil }
        XCTAssertTrue(ServerPairs.build(strategies: variants, profiles: profiles, sourceID: "source").isEmpty)
        let existing = StrategyCatalog.builtIn.filter { $0.warpTLSName == nil }
        XCTAssertEqual(ServerPairs.build(strategies: existing, profiles: profiles, sourceID: "source").count, 14)
    }

    func testCompactConfigurationActivatesServerWithoutConnectingAndRoutingReachesOnlyPersistentOpen() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let library = ConnectionLibrary(directory: directory, transport: WorkflowTransport())
        let provider = WorkflowProvider(), store = InMemorySettingsStore()
        let engine = ZarpEngine(settingsStore: store, strategyStore: InMemoryCustomStrategyStore(), connections: provider, probe: provider,
                                network: UnimplementedNetworkInspector(), log: LogBus(), localization: Localization(tables: [:]), connectionLibrary: library, timing: .immediate)
        await engine.load()
        var policy = ServerRoutingPolicy(); policy.applicationMode = .include; policy.applicationPaths = ["/Applications/Browser.app"]
        try await engine.configureConnection(useServer: true, input: tcp, source: nil, endpoints: [], policy: policy)
        let configured = await engine.snapshot(), before = await provider.opens
        XCTAssertEqual(configured.mode, .server); XCTAssertTrue(before.isEmpty)
        XCTAssertEqual(store.load().serverRouting, policy)
        let pair = try XCTUnwrap(configured.strategies.first)
        _ = await engine.use(pair); await engine.waitUntilIdle()
        _ = await engine.disconnect(); await engine.waitUntilIdle()
        _ = await engine.testStrategies([pair]); await engine.waitUntilIdle()
        let routes = await provider.routes, accounts = await provider.accountCalls
        XCTAssertTrue(routes.contains { $0.persistent && $0.routing.serverPolicy == policy })
        XCTAssertTrue(routes.contains { !$0.persistent })
        XCTAssertTrue(routes.filter { !$0.persistent }.allSatisfy { $0.routing.serverPolicy == nil && !$0.routing.routeAll })
        XCTAssertEqual(accounts, 0)
        do { try await engine.configureConnection(useServer: false, input: "", source: nil, endpoints: [], policy: policy); XCTFail("active tunnel was replaced by configuration") }
        catch { XCTAssertEqual(error as? ConnectionLibraryError, .busy) }
        _ = await engine.disconnect(); await engine.waitUntilIdle()
        try await engine.configureConnection(useServer: false, input: "", source: nil, endpoints: [], policy: policy)
        let warp = await engine.snapshot()
        XCTAssertEqual(warp.mode, .warp)
        await library.close()
    }

    func testEmptyServerConfigurationCannotSilentlySwitchToWarp() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let library = ConnectionLibrary(directory: directory, transport: WorkflowTransport())
        let provider = WorkflowProvider()
        let engine = ZarpEngine(settingsStore: InMemorySettingsStore(), strategyStore: InMemoryCustomStrategyStore(), connections: provider, probe: provider,
                                network: UnimplementedNetworkInspector(), log: LogBus(), localization: Localization(tables: [:]), connectionLibrary: library, timing: .immediate)
        await engine.load()
        do { try await engine.configureConnection(useServer: true, input: "", source: nil, endpoints: [], policy: ServerRoutingPolicy()); XCTFail("empty server accepted") }
        catch { XCTAssertEqual(error as? ConnectionLibraryError, .emptyConfiguration) }
        let snapshot = await engine.snapshot(), opens = await provider.opens
        XCTAssertEqual(snapshot.mode, .warp); XCTAssertFalse(snapshot.isBusy); XCTAssertTrue(opens.isEmpty)
        await library.close()
    }

    func testPairsUseStrategyMajorOrderingAndTheActualOuterTransport() throws {
        let a = try ServerLinkImporter.parse(tcp), b = try ServerLinkImporter.parse(udp)
        let source = try ConnectionSource(kind: .manual)
        let strategies = [Strategy(id: "tcp", name: "Split", transport: .masqueH2, args: "--lua-desync=multisplit:pos=1"),
                          Strategy(id: "direct", name: "Direct", transport: .masqueH2, args: ""),
                          Strategy(id: "udp", name: "Fake", transport: .masqueH3, args: "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=2")]
        let pairs = ServerPairs.build(strategies: strategies, profiles: [a, b], sourceID: source.id)
        XCTAssertEqual(pairs.map(\.id), ["tcp@" + a.id, "udp@" + b.id])
        XCTAssertTrue(pairs.allSatisfy { $0.requiresDesync && $0.sourceID == source.id })
        XCTAssertEqual(pairs.first?.name(using: Localization(tables: [:])), "Split @ Test")
        let other = ServerPairs.build(strategies: strategies, profiles: [a], sourceID: "other")[0]
        XCTAssertNotEqual(pairs[0].configurationFingerprint, other.configurationFingerprint)
    }

    func testServerConnectionNeverEnrollsWarpAndCannotSwitchSourceWhileConnected() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let library = ConnectionLibrary(directory: directory, transport: WorkflowTransport())
        _ = try await library.importLinks(tcp)
        let source = try ConnectionSource(kind: .manual)
        try await library.selectSource(id: source.id)
        let provider = WorkflowProvider(), store = InMemorySettingsStore()
        let engine = ZarpEngine(settingsStore: store, strategyStore: InMemoryCustomStrategyStore(), connections: provider, probe: provider,
                                network: UnimplementedNetworkInspector(), log: LogBus(), localization: Localization(tables: [:]), connectionLibrary: library, timing: .immediate)
        await engine.load()
        let before = await engine.snapshot()
        XCTAssertEqual(before.mode, .server)
        let pair = try XCTUnwrap(before.strategies.first)
        let started = await engine.use(pair)
        XCTAssertTrue(started)
        await engine.waitUntilIdle()
        let connected = await engine.snapshot()
        XCTAssertEqual(connected.state, .connected)
        XCTAssertEqual(connected.mode, .server)
        let accountCalls = await provider.accountCalls, opens = await provider.opens
        XCTAssertEqual(accountCalls, 0)
        XCTAssertEqual(opens, [pair.id])
        let warp = try ConnectionSource(kind: .warp)
        let switchedWhileConnected = await engine.selectSource(warp.id)
        XCTAssertFalse(switchedWhileConnected)
        _ = await engine.disconnect(); await engine.waitUntilIdle()
        let switched = await engine.selectSource(warp.id)
        XCTAssertTrue(switched)
        let warpState = await engine.snapshot()
        XCTAssertTrue(warpState.strategies.allSatisfy { $0.mode == .warp })
        let switchedBack = await engine.selectSource(source.id)
        XCTAssertTrue(switchedBack)
        let restored = await engine.snapshot()
        XCTAssertEqual(restored.selectedStrategyId, pair.id)
        await library.close()
    }

    func testDeletingSelectedServerFailsClosedWithoutOpeningWarpOrAnotherServer() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let library = ConnectionLibrary(directory: directory, transport: WorkflowTransport())
        let imported = try await library.importLinks(tcp + "\n" + udp)
        let source = try ConnectionSource(kind: .manual), selected = imported.profiles[0].id
        try await library.selectSource(id: source.id)
        try await library.selectServer(id: selected, sourceId: source.id)
        try await library.removeManualServer(id: selected)
        let provider = WorkflowProvider()
        let engine = ZarpEngine(settingsStore: InMemorySettingsStore(), strategyStore: InMemoryCustomStrategyStore(), connections: provider,
                                probe: provider, network: UnimplementedNetworkInspector(), log: LogBus(), localization: Localization(tables: [:]), connectionLibrary: library, timing: .immediate)
        await engine.load()
        _ = await engine.connect(); await engine.waitUntilIdle()
        let after = await engine.snapshot(), opens = await provider.opens, accountCalls = await provider.accountCalls
        XCTAssertEqual(after.mode, .server)
        XCTAssertEqual(after.state, .idle)
        XCTAssertTrue(after.strategies.isEmpty)
        XCTAssertTrue(opens.isEmpty)
        XCTAssertEqual(accountCalls, 0)
        await library.close()
    }

    func testIdenticalServerFromDifferentSubscriptionsKeepsSeparateResults() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let library = ConnectionLibrary(directory: directory, transport: WorkflowTransport(body: tcp))
        let a = try await library.saveSubscription(label: "A", url: "https://a.example/subscription")
        let b = try await library.saveSubscription(label: "B", url: "https://b.example/subscription")
        _ = try await library.refresh(sourceId: a.id)
        _ = try await library.refresh(sourceId: b.id)
        try await library.selectSource(id: a.id)
        var settings = AppSettings(); settings.stopAfterWorking = 1
        let store = InMemorySettingsStore(settings), provider = WorkflowProvider()
        let engine = ZarpEngine(settingsStore: store, strategyStore: InMemoryCustomStrategyStore(), connections: provider,
                                probe: provider, network: UnimplementedNetworkInspector(), log: LogBus(), localization: Localization(tables: [:]), connectionLibrary: library, timing: .immediate)
        await engine.load()
        _ = await engine.search(full: false); await engine.waitUntilIdle()
        let scanned = await engine.snapshot()
        XCTAssertEqual(scanned.state, .connected)
        XCTAssertEqual(scanned.results.count, 1)
        XCTAssertTrue(store.load().results.keys.allSatisfy { $0.hasPrefix(a.id + "|") })
        _ = await engine.disconnect(); await engine.waitUntilIdle()
        _ = await engine.selectSource(b.id)
        let other = await engine.snapshot()
        XCTAssertTrue(other.results.isEmpty)
        XCTAssertNil(other.selectedStrategyId)
        _ = await engine.selectSource(a.id)
        let restored = await engine.snapshot()
        XCTAssertEqual(restored.results, scanned.results)
        XCTAssertEqual(restored.selectedStrategyId, scanned.selectedStrategyId)
        await library.close()
    }
}

private struct WorkflowTransport: SubscriptionHTTPTransport {
    var body: String? = nil
    func get(url: URL, userAgent: String, deadline: ContinuousClock.Instant) async throws -> SubscriptionHTTPResponse {
        guard let body else { throw SubscriptionError.network }
        return SubscriptionHTTPResponse(status: 200, body: Data(body.utf8))
    }
}
private struct WorkflowHandle: WarpConnectionHandle {
    let id: String
    let mode: ConnectionMode
    let connectMs = 10
    let endpoint: String? = "192.0.2.1:443"
    func close() async {}
}
private actor WorkflowProvider: WarpConnectionProvider, WarpProbe {
    private(set) var accountCalls = 0
    private(set) var opens: [String] = []
    private(set) var routes: [(persistent: Bool, routing: TunnelRouting)] = []
    func isAccountRegistered() async throws -> Bool { accountCalls += 1; return false }
    func registerAccount() async throws { accountCalls += 1; throw WarpConnectionError("unexpected WARP registration") }
    func connectionSnapshot() async throws -> ConnectionSnapshot { ConnectionSnapshot(live: nil) }
    func open(strategy: Strategy, endpoint: String?, timeoutMs: Int, persistent: Bool, routing: TunnelRouting) async throws -> any WarpConnectionHandle {
        guard strategy.mode == .server, endpoint == nil, strategy.requiresDesync else { throw WarpConnectionError("incorrect server operation") }
        opens.append(strategy.id)
        routes.append((persistent, routing))
        return WorkflowHandle(id: String(opens.count), mode: .server)
    }
    func measure(connection: any WarpConnectionHandle, samples: Int) async throws -> WarpMeasurement { .ok(pingMs: 5, warp: "off") }
}
