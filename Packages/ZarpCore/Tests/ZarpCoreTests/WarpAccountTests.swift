import XCTest
@testable import ZarpCore

final class WarpAccountTests: XCTestCase {
    private let key = "aB123456-abcdefgh-87654321"

    private func engine(_ provider: AccountTestProvider, store: InMemorySettingsStore = InMemorySettingsStore()) -> ZarpEngine {
        ZarpEngine(settingsStore: store, strategyStore: InMemoryCustomStrategyStore(), connections: provider,
                   probe: provider, network: UnimplementedNetworkInspector(), log: LogBus(), localization: Localization(tables: [:]), timing: .immediate)
    }

    func testReferenceLicenseFormatAndSecretResponseRejection() throws {
        XCTAssertTrue(WarpLicense.isValid(key))
        for invalid in [key + "\n", "private-secret", "12345678_abcdefgh_87654321", "１２３４５６７８-abcdefgh-87654321"] {
            XCTAssertFalse(WarpLicense.isValid(invalid))
        }
        do {
            _ = try JSONDecoder().decode(WarpAccountStatus.self, from: Data(#"{"accountType":"private-secret","licenseApplied":true}"#.utf8))
            XCTFail("unknown account type was accepted")
        } catch { XCTAssertFalse(String(describing: error).contains("private-secret")) }
    }

    func testCombinedSetupRequiresConsentOrdersTLSCandidatesAndKeepsTunnelResults() async throws {
        let provider = SetupTestProvider()
        await provider.base.setRegistered(false)
        var settings = AppSettings()
        settings.selectedStrategyId = "warp-t-disorder"
        let confirmed = try XCTUnwrap(StrategyCatalog.builtIn.first { $0.id == "warp-t-split-endhost" })
        settings.results[confirmed.id] = TestResult(strategyId: confirmed.id, ok: true, connectMs: 10, pingMs: 3,
            confirmed: true, configurationFingerprint: confirmed.configurationFingerprint)
        let store = InMemorySettingsStore(settings)
        let engine = ZarpEngine(settingsStore: store, strategyStore: InMemoryCustomStrategyStore(), connections: provider,
            probe: provider.base, network: UnimplementedNetworkInspector(), log: LogBus(), localization: Localization(tables: [:]), timing: .immediate)
        await engine.load()
        do { _ = try await engine.applyWarpLicense(key); XCTFail("setup ran without terms consent") }
        catch { XCTAssertEqual((error as? WarpConnectionError)?.code, "cancelled") }
        let denied = await provider.calls
        XCTAssertTrue(denied.isEmpty)
        await engine.setHooks(EngineHooks(askAcceptWarpTerms: { true }))
        let before = await engine.snapshot()
        let status = try await engine.applyWarpLicense(key)
        let calls = await provider.calls
        XCTAssertEqual(calls.count, 1)
        XCTAssertEqual(calls.first?.0, "license")
        XCTAssertEqual(Array(calls[0].1.prefix(2)), ["warp-t-disorder", confirmed.id])
        XCTAssertTrue(calls[0].1.allSatisfy { id in StrategyCatalog.builtIn.contains { $0.id == id && $0.transport == .masqueH2 && $0.requiresDesync } })
        XCTAssertEqual(status.accountType, .plus)
        let after = await engine.snapshot()
        XCTAssertEqual(after.results, before.results, "API success must not certify a tunnel strategy")
        XCTAssertEqual(after.selectedStrategyId, before.selectedStrategyId)
        let legacy = await provider.legacyCalls
        let opens = await provider.base.opens
        XCTAssertEqual(legacy, 0)
        XCTAssertEqual(opens, 0)
    }

    func testCombinedSetupUsesNoPhysicalFallbackWithAnAdoptedTunnel() async throws {
        let provider = SetupTestProvider()
        let engine = ZarpEngine(settingsStore: InMemorySettingsStore(), strategyStore: InMemoryCustomStrategyStore(), connections: provider,
            probe: provider.base, network: UnimplementedNetworkInspector(), log: LogBus(), localization: Localization(tables: [:]), timing: .immediate)
        await engine.load()
        await engine.adoptExistingConnection()
        _ = try await engine.applyWarpLicense(key)
        let calls = await provider.calls
        XCTAssertEqual(calls.count, 1)
        XCTAssertTrue(calls[0].1.isEmpty)
        let closes = await provider.base.handle.closes
        XCTAssertEqual(closes, 0)
        let snapshot = await engine.snapshot()
        XCTAssertEqual(snapshot.state, .connected)
    }

    func testApplyingLicensePreservesAdoptedTunnelStrategyAndPreferences() async throws {
        let provider = AccountTestProvider()
        let store = InMemorySettingsStore()
        let engine = engine(provider, store: store)
        await engine.load()
        await engine.adoptExistingConnection()
        let before = await engine.snapshot()
        let settings = store.load()
        let result = try await engine.applyWarpLicense(key)
        let after = await engine.snapshot()
        XCTAssertEqual(result, WarpAccountStatus(accountType: .plus, licenseApplied: true))
        XCTAssertEqual(before.state, .connected)
        XCTAssertEqual(after.state, .connected)
        XCTAssertEqual(after.selectedStrategyId, before.selectedStrategyId)
        XCTAssertEqual(store.load().warpEndpoints, settings.warpEndpoints)
        let opens = await provider.opens
        let closes = await provider.handle.closes
        XCTAssertEqual(opens, 0)
        XCTAssertEqual(closes, 0)
        XCTAssertFalse(String(data: try JSONEncoder().encode(store.load()), encoding: .utf8)!.contains(key))
    }

    func testRegistrationForLicenseNeedsTermsButDoesNotConnect() async throws {
        let provider = AccountTestProvider()
        await provider.setRegistered(false)
        let engine = engine(provider)
        await engine.load()
        do { _ = try await engine.applyWarpLicense(key); XCTFail("registration happened without consent") }
        catch { XCTAssertEqual((error as? WarpConnectionError)?.code, "cancelled") }
        let deniedRegistrations = await provider.registrations
        XCTAssertEqual(deniedRegistrations, 0)
        await engine.setHooks(EngineHooks(askAcceptWarpTerms: { true }))
        _ = try await engine.applyWarpLicense(key)
        let registrations = await provider.registrations
        let opens = await provider.opens
        XCTAssertEqual(registrations, 1)
        XCTAssertEqual(opens, 0)
    }

    func testCancellationAndConcurrentRequestsPreserveLiveTunnel() async throws {
        let provider = AccountTestProvider()
        await provider.setBlocking(true)
        let engine = engine(provider)
        await engine.load()
        await engine.adoptExistingConnection()
        let request = Task { try await engine.applyWarpLicense(key) }
        for _ in 0..<1000 {
            if await provider.entered { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        let entered = await provider.entered
        XCTAssertTrue(entered)
        do { _ = try await engine.readWarpAccount(); XCTFail("concurrent account operation accepted") }
        catch { XCTAssertEqual((error as? WarpConnectionError)?.code, "busy") }
        request.cancel()
        do { _ = try await request.value; XCTFail("cancelled account request succeeded") } catch {}
        await engine.waitUntilIdle()
        let after = await engine.snapshot()
        let closes = await provider.handle.closes
        XCTAssertFalse(after.isBusy)
        XCTAssertEqual(after.state, .connected)
        XCTAssertEqual(closes, 0)
    }
}

private actor SetupTestProvider: WarpConnectionProvider, WarpAccountProvider, WarpAccountSetupProvider {
    let base = AccountTestProvider()
    private(set) var calls: [(String, [String])] = []
    private(set) var legacyCalls = 0
    func isAccountRegistered() async throws -> Bool { try await base.isAccountRegistered() }
    func connectionSnapshot() async throws -> ConnectionSnapshot { try await base.connectionSnapshot() }
    func open(strategy: Strategy, endpoint: String?, timeoutMs: Int, persistent: Bool, routing: TunnelRouting) async throws -> any WarpConnectionHandle {
        try await base.open(strategy: strategy, endpoint: endpoint, timeoutMs: timeoutMs, persistent: persistent, routing: routing)
    }
    func registerAccount() async throws { legacyCalls += 1; throw WarpConnectionError("legacy setup invoked") }
    func readWarpAccount() async throws -> WarpAccountStatus { legacyCalls += 1; throw WarpConnectionError("legacy status invoked") }
    func applyWarpLicense(_ key: String) async throws -> WarpAccountStatus { legacyCalls += 1; throw WarpConnectionError("legacy license invoked") }
    func registerAccount(strategies: [Strategy]) async throws { calls.append(("register", strategies.map(\.id))); await base.setRegistered(true) }
    func readWarpAccount(strategies: [Strategy]) async throws -> WarpAccountStatus { calls.append(("status", strategies.map(\.id))); return WarpAccountStatus(accountType: .free) }
    func applyWarpLicense(_ key: String, strategies: [Strategy]) async throws -> WarpAccountStatus {
        calls.append(("license", strategies.map(\.id))); await base.setRegistered(true)
        return WarpAccountStatus(accountType: .plus, licenseApplied: true)
    }
}

private actor AccountTestHandle: WarpConnectionHandle {
    let id = "private-test-handle"
    let connectMs = 20
    let endpoint: String? = "162.159.198.1:443"
    private(set) var closes = 0
    func close() async { closes += 1 }
}

private actor AccountTestProvider: WarpConnectionProvider, WarpAccountProvider, WarpProbe {
    let handle = AccountTestHandle()
    private var registered = true
    private var blocking = false
    private(set) var entered = false
    private(set) var registrations = 0
    private(set) var opens = 0
    func setRegistered(_ value: Bool) { registered = value }
    func setBlocking(_ value: Bool) { blocking = value }
    func isAccountRegistered() async throws -> Bool { registered }
    func registerAccount() async throws { registrations += 1; registered = true }
    func readWarpAccount() async throws -> WarpAccountStatus { WarpAccountStatus(accountType: .free) }
    func applyWarpLicense(_ key: String) async throws -> WarpAccountStatus {
        entered = true
        if blocking { try await Task.sleep(nanoseconds: 60_000_000_000) }
        return WarpAccountStatus(accountType: .plus, licenseApplied: true)
    }
    func connectionSnapshot() async throws -> ConnectionSnapshot {
        ConnectionSnapshot(live: LiveConnectionStatus(handle: handle, strategyId: "warp-q-google6", routeAll: true))
    }
    func open(strategy: Strategy, endpoint: String?, timeoutMs: Int, persistent: Bool, routing: TunnelRouting) async throws -> any WarpConnectionHandle {
        opens += 1; throw WarpConnectionError("unexpected test open")
    }
    func measure(connection: any WarpConnectionHandle, samples: Int) async throws -> WarpMeasurement { .ok(pingMs: 10, warp: "plus") }
}
