import XCTest
@testable import ZarpCore

// Test-only doubles for `WarpConnectionProvider`/`WarpProbe`, used to verify the scan/self-heal
// state machine in isolation from real networking. These must never appear outside this test
// target — the production code's only stand-ins are the always-failing `Unimplemented*` types in
// `EngineProtocols.swift`, which do not pretend anything works.

private final class FakeHandle: WarpConnectionHandle, @unchecked Sendable {
    let id: String
    let connectMs: Int
    let endpoint: String?
    let warnings: [String]
    private let lock = NSLock()
    private var _closeCount = 0
    private let onClose: (@Sendable (String) -> Void)?

    init(id: String, connectMs: Int, endpoint: String?, warnings: [String] = [], onClose: (@Sendable (String) -> Void)? = nil) {
        self.id = id
        self.connectMs = connectMs
        self.endpoint = endpoint
        self.warnings = warnings
        self.onClose = onClose
    }

    var closeCount: Int { lock.lock(); defer { lock.unlock() }; return _closeCount }

    func close() async {
        lock.withLock { _closeCount += 1 }
        onClose?(id)
    }
}

private actor OneShotGate {
    private var opened = false
    private var continuation: CheckedContinuation<Void, Never>?
    private var arrived = false
    private var arrivedContinuation: CheckedContinuation<Void, Never>?

    func wait() async {
        if opened { return }
        arrived = true
        arrivedContinuation?.resume()
        arrivedContinuation = nil
        await withCheckedContinuation { continuation = $0 }
    }

    func open() {
        opened = true
        continuation?.resume()
        continuation = nil
    }

    /// Suspends until some call to `wait()` has actually parked on the gate. Lets a test know the
    /// background task reached this exact point deterministically, instead of racing it — spawning
    /// the task only guarantees it was scheduled, not that it has run yet.
    func waitUntilArrived() async {
        if arrived { return }
        await withCheckedContinuation { arrivedContinuation = $0 }
    }
}

private struct OpenCall: Equatable {
    let id: String
    let endpoint: String?
    let persistent: Bool
    let routing: TunnelRouting
}

private final class ScriptedConnectionProvider: WarpConnectionProvider, @unchecked Sendable {
    enum Outcome {
        case ok(connectMs: Int)
        case fail(timedOut: Bool = false)
        case error(WarpConnectionError)
    }

    private let lock = NSLock()
    private var scripts: [String: [Outcome]]
    private var nextHandleId = 1
    private(set) var calls: [OpenCall] = []
    private(set) var handles: [FakeHandle] = []
    /// Every open and close in the order it happened: "open:<strategy>" / "close:<handle id>".
    private(set) var events: [String] = []
    var openedIds: [String] { calls.map(\.id) }

    /// If set, the first `open(strategy:)` call whose id matches waits on this gate before
    /// returning — lets a test hold a scan "in progress" to exercise `cancel()`.
    var gateForId: (id: String, gate: OneShotGate)?
    /// Makes every `open` wait until the surrounding task is cancelled (a dial that never ends),
    /// then throw `CancellationError` like a real cancellation-aware backend.
    var openHangsUntilCancelled = false
    var openWarnings: [String] = []
    var fixedEndpoint: String?

    /// What `connectionSnapshot()` answers; swap it between calls to simulate the backend's state
    /// changing underneath the engine.
    var snapshot: Result<ConnectionSnapshot, Error> = .success(ConnectionSnapshot(live: nil))
    var snapshotGate: OneShotGate?
    var accountRegistered = true
    var registerError: Error?
    private(set) var registerCalls = 0

    init(_ scripts: [String: [Outcome]] = [:]) {
        self.scripts = scripts
    }

    func open(strategy: Strategy, endpoint: String?, timeoutMs: Int, persistent: Bool, routing: TunnelRouting) async throws -> WarpConnectionHandle {
        if let g = gateForId, g.id == strategy.id { await g.gate.wait() }
        if openHangsUntilCancelled {
            while !Task.isCancelled { try? await Task.sleep(nanoseconds: 5_000_000) }
            throw CancellationError()
        }
        let outcome: Outcome = lock.withLock {
            calls.append(OpenCall(id: strategy.id, endpoint: endpoint, persistent: persistent, routing: routing))
            events.append("open:\(strategy.id)")
            var list = scripts[strategy.id] ?? [.fail()]
            let next = list.count > 1 ? list.removeFirst() : list[0]
            scripts[strategy.id] = list
            return next
        }
        switch outcome {
        case .ok(let ms):
            return lock.withLock {
                let handle = FakeHandle(id: "h\(nextHandleId)", connectMs: ms, endpoint: fixedEndpoint ?? Self.actualEndpoint(endpoint),
                                        warnings: openWarnings) { [weak self] id in
                    self?.lock.withLock { self?.events.append("close:\(id)") }
                }
                nextHandleId += 1
                handles.append(handle)
                return handle
            }
        case .fail(let timedOut):
            throw WarpConnectionError("scripted failure", timedOut: timedOut)
        case .error(let error):
            throw error
        }
    }

    private static func actualEndpoint(_ value: String?) -> String {
        guard let value else { return "162.159.198.1:443" }
        if value.hasPrefix("custom:") { return String(value.dropFirst(7)) }
        if value.hasPrefix("isolated-"), let n = Int(value.dropFirst(9)) { return "162.159.198.\(n % 2 + 1):443" }
        return value
    }

    func connectionSnapshot() async throws -> ConnectionSnapshot {
        if let gate = snapshotGate { await gate.wait() }
        return try snapshot.get()
    }

    func isAccountRegistered() async throws -> Bool { accountRegistered }

    func registerAccount() async throws {
        registerCalls += 1
        if let registerError { throw registerError }
        accountRegistered = true
    }
}

private extension NSLock {
    func withLock<T>(_ body: () -> T) -> T {
        lock(); defer { unlock() }
        return body()
    }
}

private final class ScriptedProbe: WarpProbe, @unchecked Sendable {
    var result: Result<WarpMeasurement, Error> = .success(.ok(pingMs: 50, warp: "on"))
    private let lock = NSLock()
    private(set) var measuredHandleIds: [String] = []
    var gateOnMeasurement: (Int, OneShotGate)?
    var outcomes: [Int: WarpMeasurement] = [:]
    var failures: [Int: WarpConnectionError] = [:]

    func measure(connection: WarpConnectionHandle, samples: Int) async throws -> WarpMeasurement {
        lock.withLock { measuredHandleIds.append(connection.id) }
        if let (count, gate) = gateOnMeasurement, measuredHandleIds.count == count { await gate.wait() }
        if let error = failures[measuredHandleIds.count] { throw error }
        return try outcomes[measuredHandleIds.count] ?? result.get()
    }
}

private struct FixedInspector: NetworkInspector {
    let names: [String]
    func foreignVPNInterfaceNames() -> [String] { names }
}

@MainActor
final class ZarpEngineTests: XCTestCase {
    private func makeEngine(
        connections: WarpConnectionProvider,
        probe: WarpProbe = ScriptedProbe(),
        network: NetworkInspector = UnimplementedNetworkInspector(),
        log: LogBus = LogBus(),
        store: InMemorySettingsStore? = nil,
        customStore: InMemoryCustomStrategyStore = InMemoryCustomStrategyStore(),
        timing: EngineTiming = .immediate,
        backoff: [Double] = [0],
        settings: AppSettings = {
            var s = AppSettings(); s.stopAfterWorking = 1; return s
        }()
    ) -> ZarpEngine {
        ZarpEngine(
            settingsStore: store ?? InMemorySettingsStore(settings),
            strategyStore: customStore,
            connections: connections,
            probe: probe,
            network: network,
            log: log,
            localization: Localization(tables: ["en": Localization.parseTable(Self.minimalEnglish)]),
            reconnectBackoff: backoff, timing: timing
        )
    }

    /// Just enough English text for `Msg`/log formatting not to matter to these assertions —
    /// full key coverage is `LocalizationTests`' job, not this file's. Unknown keys render as the
    /// key itself, which is what most assertions below match on.
    private static let minimalEnglish = """
    detail.strategy = Strategy: {0}
    detail.cancelled = Cancelled
    err.peerKeyMismatch = Server key mismatch at {0}. This endpoint could not be verified.
    """

    private func waitUntil(_ what: String, timeout: TimeInterval = 5, _ condition: @escaping () async -> Bool) async {
        let deadline = Date().addingTimeInterval(timeout)
        while !(await condition()) {
            if Date() > deadline { XCTFail("timed out waiting for \(what)"); return }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
    }

    private func logText(_ log: LogBus) -> String { log.snapshot().map(\.text).joined(separator: "\n") }

    // MARK: - Scan and connect

    func testRemovedPlainWarpSelectionAndResultsCannotReturnAfterRestart() async throws {
        let warpSource = try ConnectionSource(kind: .warp).id
        let otherSource = "source-v1-" + String(repeating: "b", count: 64)
        let pair = "split@server-v1-" + String(repeating: "c", count: 64)
        let otherKey = otherSource + "|" + pair
        var settings = AppSettings()
        settings.selectedStrategyId = "direct"
        settings.sourceSelections = [warpSource: "direct-h2", otherSource: pair]
        settings.results["direct"] = TestResult(strategyId: "direct", ok: true, confirmed: true)
        settings.results["old-network-plain"] = TestResult(strategyId: "direct-h2", ok: true, confirmed: true,
                                                          networkIdentity: "older-network")
        settings.results[otherKey] = TestResult(strategyId: pair, ok: true, confirmed: true)
        let store = InMemorySettingsStore(settings)
        let provider = ScriptedConnectionProvider()
        let engine = makeEngine(connections: provider, store: store)
        await engine.load()
        let selected = await engine.selected
        let catalog = await engine.eligibleStrategies
        XCTAssertNil(selected)
        XCTAssertTrue(catalog.allSatisfy { !$0.plan.isDirect })
        let saved = store.load()
        XCTAssertNil(saved.selectedStrategyId)
        XCTAssertNil(saved.sourceSelections[warpSource])
        XCTAssertNil(saved.results["direct"])
        XCTAssertNil(saved.results["old-network-plain"])
        XCTAssertEqual(saved.sourceSelections[otherSource], pair)
        XCTAssertEqual(saved.results[otherKey]?.strategyId, pair)
        XCTAssertTrue(provider.calls.isEmpty)
    }

    func testCustomEndpointCacheSurvivesRestartButRejectsAnAddressOutsideItsBoundList() async {
        var settings = AppSettings()
        settings.warpEndpoints = ["162.159.198.1:443"]
        let store = InMemorySettingsStore(settings)
        let engine = makeEngine(connections: ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]]), store: store)
        await engine.load()
        _ = await engine.testStrategies([StrategyCatalog.builtIn[0]])
        await engine.waitUntilIdle()
        let restarted = makeEngine(connections: ScriptedConnectionProvider(), store: store)
        await restarted.load()
        let cached = await restarted.results["warp-q-google6"]
        XCTAssertEqual(cached?.confirmed, true)
        var altered = store.load()
        altered.results["warp-q-google6"]?.endpoint = "162.159.198.2:443"
        store.save(altered)
        await restarted.load()
        let rejected = await restarted.results["warp-q-google6"]
        XCTAssertNil(rejected)
    }


    func testRepeatedH2AddressIsNotIndependentEvenWithUniqueIsolationTokens() async {
        let provider = ScriptedConnectionProvider(["warp-t-split-host": [.ok(connectMs: 100)]])
        provider.fixedEndpoint = "162.159.198.2:443"
        let engine = makeEngine(connections: provider)
        await engine.load()
        let strategy = StrategyCatalog.builtIn.first { $0.id == "warp-t-split-host" }!
        _ = await engine.testStrategies([strategy])
        await engine.waitUntilIdle()
        XCTAssertNotEqual(provider.calls[0].endpoint, provider.calls[1].endpoint)
        let result = await engine.results[strategy.id]
        XCTAssertEqual(result?.confirmed, true)
        XCTAssertEqual(result?.independent, false)
        XCTAssertEqual(result?.endpointReused, true)
    }


    func testSingleCustomEndpointConfirmsWithoutIndependenceAndIsPinnedForConnect() async {
        var settings = AppSettings()
        settings.warpEndpoints = ["162.159.198.1:8443"]
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let engine = makeEngine(connections: provider, settings: settings)
        await engine.load()
        _ = await engine.testStrategies([StrategyCatalog.builtIn[0]])
        await engine.waitUntilIdle()
        let result = await engine.results["warp-q-google6"]
        XCTAssertEqual(result?.confirmed, true)
        XCTAssertEqual(result?.independent, false)
        XCTAssertEqual(result?.endpointReused, true)
        XCTAssertEqual(provider.calls.map(\.endpoint), Array(repeating: "custom:162.159.198.1:8443", count: 3))
    }

    func testCustomListRotatesAndChangingItInvalidatesSavedResults() async {
        var settings = AppSettings()
        settings.warpEndpoints = ["162.159.198.1:443", "[2606:4700::1]:443"]
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let engine = makeEngine(connections: provider, settings: settings)
        await engine.load()
        _ = await engine.testStrategies([StrategyCatalog.builtIn[0]])
        await engine.waitUntilIdle()
        let result = await engine.results["warp-q-google6"]
        XCTAssertEqual(result?.independent, true)
        XCTAssertEqual(provider.calls.map(\.endpoint), ["custom:162.159.198.1:443", "custom:[2606:4700::1]:443", "custom:[2606:4700::1]:443"])
        settings.warpEndpoints = ["162.159.198.2:443"]
        await engine.updateSettings(settings)
        let invalidated = await engine.results
        XCTAssertTrue(invalidated.isEmpty)
    }

    func testInvalidStoredEndpointListRefusesInsteadOfDefaulting() async {
        var settings = AppSettings()
        settings.warpEndpoints = ["not-an-address"]
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let engine = makeEngine(connections: provider, settings: settings)
        await engine.load()
        _ = await engine.connect()
        await engine.waitUntilIdle()
        XCTAssertTrue(provider.calls.isEmpty)
        let detail = await engine.detail
        XCTAssertEqual(detail.key, "err.endpointList")
    }


    func testQuickScanContinuesPastFailedRechecksUntilThreeConfirmations() async {
        var settings = AppSettings()
        settings.stopAfterWorking = 3
        let provider = ScriptedConnectionProvider([
            "warp-q-google6": [.ok(connectMs: 100), .fail()],
            "warp-q-google3": [.ok(connectMs: 100), .fail()],
            "warp-q-vk6": [.ok(connectMs: 100)],
            "warp-q-google-vk": [.ok(connectMs: 120)],
            "warp-q-google10": [.ok(connectMs: 140)],
        ])
        let engine = makeEngine(connections: provider, settings: settings)
        await engine.load()
        _ = await engine.search(full: false)
        await engine.waitUntilIdle()
        let results = await engine.results
        XCTAssertEqual(results.values.filter(\.confirmed).count, 3)
        XCTAssertTrue(provider.openedIds.contains("warp-q-google10"))
        XCTAssertFalse(provider.openedIds.contains("warp-q-google11"))
        XCTAssertEqual(results["warp-q-google6"]?.rechecked, true)
    }

    func testCountryFilterAppliesToSavedSelectionFallbackAndSelectedTestsWithoutErasingHistory() async {
        var settings = AppSettings()
        settings.strategyCountries = "cn"
        settings.selectedStrategyId = "warp-q-vk6"
        settings.results["warp-q-vk6"] = TestResult(strategyId: "warp-q-vk6", ok: true, confirmed: true)
        settings.results["warp-q-google6"] = TestResult(strategyId: "warp-q-google6", ok: true, confirmed: true)
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let engine = makeEngine(connections: provider, settings: settings)
        await engine.load()
        let hidden = StrategyCatalog.builtIn.first { $0.id == "warp-q-vk6" }!
        let testedHidden = await engine.testStrategies([hidden])
        let usedHidden = await engine.use(hidden)
        XCTAssertFalse(testedHidden)
        XCTAssertFalse(usedHidden)
        _ = await engine.connect()
        await engine.waitUntilIdle()
        XCTAssertEqual(provider.openedIds, ["warp-q-google6"])
        let history = await engine.results
        XCTAssertTrue(history[hidden.id]?.confirmed == true)
    }

    func testSelectedFailureDoesNotApplyUnrelatedSavedSuccess() async {
        var settings = AppSettings()
        settings.results["warp-q-vk6"] = TestResult(strategyId: "warp-q-vk6", ok: true, confirmed: true)
        let provider = ScriptedConnectionProvider(["warp-q-vk6": [.ok(connectMs: 100)]])
        let engine = makeEngine(connections: provider, settings: settings)
        await engine.load()
        let strategy = StrategyCatalog.builtIn.first { $0.id == "warp-q-google6" }!
        _ = await engine.testStrategies([strategy])
        await engine.waitUntilIdle()
        XCTAssertEqual(provider.openedIds, [strategy.id])
        let state = await engine.state
        XCTAssertEqual(state, .idle)
    }

    func testLegacyCustomSelectionMigratesOnlyWhenUnambiguousAndDoesNotCertifyUnknownArguments() async {
        var settings = AppSettings()
        settings.selectedStrategyId = "custom-same"
        settings.results["custom-same"] = TestResult(strategyId: "custom-same", ok: true, confirmed: true)
        let line = "Same | h3 | --payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=3"
        let engine = makeEngine(connections: ScriptedConnectionProvider(),
                                customStore: InMemoryCustomStrategyStore(line), settings: settings)
        await engine.load()
        let selected = await engine.selectedStrategyId
        let results = await engine.results
        XCTAssertEqual(selected, CustomStrategyFile.parse(line)[0].id)
        XCTAssertTrue(results.isEmpty)
        let ambiguous = makeEngine(connections: ScriptedConnectionProvider(),
                                   customStore: InMemoryCustomStrategyStore(line + "\n" + line.replacingOccurrences(of: "repeats=3", with: "repeats=6")), settings: settings)
        await ambiguous.load()
        let ambiguousSelection = await ambiguous.selectedStrategyId
        XCTAssertNil(ambiguousSelection)
    }

    func testCancelDuringRecheckPreservesPriorConfirmedResult() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let probe = ScriptedProbe()
        let gate = OneShotGate()
        var settings = AppSettings()
        let prior = TestResult(strategyId: "warp-q-google6", ok: true, connectMs: 300, pingMs: 20, confirmed: true,
                               configurationFingerprint: StrategyCatalog.builtIn[0].configurationFingerprint)
        settings.results[prior.strategyId] = prior
        let engine = makeEngine(connections: provider, probe: probe, settings: settings)
        await engine.load()
        probe.gateOnMeasurement = (2, gate)
        _ = await engine.testStrategies([StrategyCatalog.builtIn[0]])
        await gate.waitUntilArrived()
        await engine.cancel()
        await gate.open()
        await engine.waitUntilIdle()
        let preserved = await engine.results[prior.strategyId]
        XCTAssertEqual(preserved, prior)
        XCTAssertTrue(provider.handles.allSatisfy { $0.closeCount == 1 })
    }


    func testQuickScanStopsAfterFirstWorkingAndConnectsWithIt() async {
        // First in the built-in catalog (see StrategyCatalogTests), scripted to succeed on all
        // three calls a full happy path needs: phase-1 test, phase-2 recheck, final apply.
        let provider = ScriptedConnectionProvider([
            "warp-q-google6": [.ok(connectMs: 120), .ok(connectMs: 130), .ok(connectMs: 110)],
        ])
        let engine = makeEngine(connections: provider)
        await engine.load()

        let started = await engine.search(full: false)
        XCTAssertTrue(started)
        await engine.waitUntilIdle()

        let state = await engine.state
        let selected = await engine.selectedStrategyId
        XCTAssertEqual(state, .connected)
        XCTAssertEqual(selected, "warp-q-google6")
        XCTAssertEqual(provider.openedIds, ["warp-q-google6", "warp-q-google6", "warp-q-google6"])
    }

    func testTestsUseFreshEndpointsAndTheFinalConnectionDoesNot() async {
        let provider = ScriptedConnectionProvider([
            "warp-q-google6": [.ok(connectMs: 120), .ok(connectMs: 130), .ok(connectMs: 110)],
        ])
        let engine = makeEngine(connections: provider)
        await engine.load()
        _ = await engine.search(full: false)
        await engine.waitUntilIdle()

        // The daemon maps each token onto a different endpoint, so a test and the independent
        // re-check right after it never share one; the persistent connection takes the account's.
        XCTAssertEqual(provider.calls.map(\.endpoint), ["isolated-0", "isolated-1", "162.159.198.2:443"])
        XCTAssertEqual(provider.calls.map(\.persistent), [false, false, true])
        XCTAssertEqual(provider.calls[0].routing, .testRouteOnly)
        XCTAssertEqual(provider.calls[1].routing, .testRouteOnly)
    }

    func testPersistentConnectionCarriesAllTrafficPerSettingsAndTestsNever() async {
        var settings = AppSettings()
        settings.routeAllTraffic = true
        settings.overrideDNS = true
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let engine = makeEngine(connections: provider, settings: settings)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()
        XCTAssertEqual(provider.calls.last?.routing, TunnelRouting(routeAll: true, overrideDNS: true))

        // The same strategy with the diagnostic mode chosen: nothing but the test route.
        var narrow = settings
        narrow.routeAllTraffic = false
        await engine.updateSettings(narrow)
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()
        XCTAssertEqual(provider.calls.last?.routing, TunnelRouting(routeAll: false, overrideDNS: false))
        let detail = await engine.detail
        XCTAssertEqual(detail.key, "detail.strategyTestRoute", "a connection that tunnels only a test route must not read as a normal Connected")
    }

    func testDNSOverrideIsNeverRequestedWithoutRouteAll() {
        XCTAssertFalse(TunnelRouting(routeAll: false, overrideDNS: true).overrideDNS)
    }

    func testSelfHealFallsBackToOtherConfirmedStrategyWhenSavedFails() async {
        // "warp-q-google6" is saved but broken; "warp-q-vk6" is already confirmed from an earlier
        // scan. Connect must try the saved one, mark it failed, then fall back — without
        // re-testing the already-confirmed one first (matches Windows `Engine.ConnectAsync`).
        var settings = AppSettings()
        settings.selectedStrategyId = "warp-q-google6"
        settings.results = ["warp-q-vk6": TestResult(strategyId: "warp-q-vk6", ok: true, connectMs: 200, pingMs: 60, confirmed: true)]

        let provider = ScriptedConnectionProvider([
            "warp-q-vk6": [.ok(connectMs: 90)],
        ])
        let engine = makeEngine(connections: provider, settings: settings)
        await engine.load()

        let started = await engine.connect()
        XCTAssertTrue(started)
        await engine.waitUntilIdle()

        let state = await engine.state
        let selected = await engine.selectedStrategyId
        let results = await engine.results
        XCTAssertEqual(state, .connected)
        XCTAssertEqual(selected, "warp-q-vk6")
        XCTAssertEqual(results["warp-q-google6"]?.ok, false)
        XCTAssertEqual(provider.openedIds, ["warp-q-google6", "warp-q-vk6"])
    }

    func testSecondCallWhileBusyIsRefused() async {
        let provider = ScriptedConnectionProvider([:]) // everything fails instantly, doesn't matter here
        let engine = makeEngine(connections: provider)
        await engine.load()

        let first = await engine.search(full: false)
        let second = await engine.search(full: true)
        XCTAssertTrue(first)
        XCTAssertFalse(second, "a second operation must not start while the engine is busy")

        await engine.waitUntilIdle()
        let busyAfter = await engine.isBusy
        XCTAssertFalse(busyAfter)
    }

    func testTimedOutTestsAreReportedAsTimeouts() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.fail(timedOut: true)]])
        let engine = makeEngine(connections: provider)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.testStrategies([strategy])
        await engine.waitUntilIdle()
        let result = await engine.results["warp-q-google6"]
        XCTAssertEqual(result?.ok, false)
        XCTAssertEqual(result?.errorKey, "err.timeout")
    }

    func testNotWarpIsRecordedWithoutDoublingTheLabel() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let probe = ScriptedProbe()
        probe.result = .success(.notWarp("off")) // the raw value, as the daemon now sends it
        let engine = makeEngine(connections: provider, probe: probe)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.testStrategies([strategy])
        await engine.waitUntilIdle()
        let result = await engine.results["warp-q-google6"]
        XCTAssertEqual(result?.error, "warp=off", "was displayed as 'warp=warp=off'")
        XCTAssertEqual(provider.handles.first?.closeCount, 1, "the test connection must be closed")
    }

    func testMeasurementsAreScopedToTheConnectionJustOpened() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let probe = ScriptedProbe()
        let engine = makeEngine(connections: provider, probe: probe)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.testStrategies([strategy])
        await engine.waitUntilIdle()
        XCTAssertEqual(probe.measuredHandleIds.first, provider.handles.first?.id)
    }

    func testBackendWarningsReachTheLog() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        provider.openWarnings = ["DNS was not overridden: boom"]
        let log = LogBus()
        let engine = makeEngine(connections: provider, log: log)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()
        XCTAssertTrue(logText(log).contains("zarpd: DNS was not overridden: boom"))
    }

    // MARK: - Strategies this port cannot perform

    func testUnsupportedStrategiesNeverReachTheBackend() async {
        // Before this guard, a strategy the parser flagged (badsum, tcp_md5, seqovl, WireGuard...)
        // was sent to the daemon as an empty plan — a plain direct connection — and recorded as
        // "works ✔✔" under its own name.
        let provider = ScriptedConnectionProvider([:])
        let engine = makeEngine(connections: provider)
        await engine.load()
        let all = StrategyCatalog.unavailable
        let unsupported = all.filter { $0.unsupportedReason != nil }
        XCTAssertEqual(Set(unsupported.map(\.id)), [
            "warp-q-google-bad", "warp-t-google-md5", "warp-t-seqovl", "warp-t-vk-seq", "warp-t-hostfake",
            "warp-wg-google6", "warp-wg-stun", "warp-wg-vk10", "warp-wg-google-ttl",
        ])

        _ = await engine.testStrategies(unsupported)
        await engine.waitUntilIdle()

        XCTAssertTrue(provider.openedIds.isEmpty, "unsupported strategies must not open connections, got \(provider.openedIds)")
        let results = await engine.results
        for s in unsupported {
            XCTAssertNil(results[s.id], "historical unavailable profiles are outside the primary scan")
        }
    }

    func testResultsAnOlderBuildRecordedForUnsupportedStrategiesAreDropped() async {
        // Old builds ran these as direct connections and saved "works ✔✔" for them.
        var settings = AppSettings()
        settings.selectedStrategyId = "warp-t-seqovl"
        settings.results = [
            "warp-t-seqovl": TestResult(strategyId: "warp-t-seqovl", ok: true, connectMs: 100, pingMs: 20, confirmed: true),
            "warp-t-hostfake": TestResult(strategyId: "warp-t-hostfake", ok: true, connectMs: 90, pingMs: 25, confirmed: true),
            "warp-q-google6": TestResult(strategyId: "warp-q-google6", ok: true, connectMs: 120, pingMs: 30, confirmed: true),
        ]
        let engine = makeEngine(connections: ScriptedConnectionProvider(), settings: settings)
        await engine.load()
        let results = await engine.results
        let selected = await engine.selectedStrategyId
        let confirmed = await engine.confirmedStrategies(except: nil).map(\.id)
        XCTAssertEqual(Set(results.keys), ["warp-q-google6"], "false positives must not survive an update")
        XCTAssertNil(selected)
        XCTAssertEqual(confirmed, ["warp-q-google6"], "self-heal must never pick an unsupported strategy")
    }

    func testUsingAnUnsupportedStrategyFailsClearlyWithoutConnecting() async {
        let provider = ScriptedConnectionProvider([:])
        let engine = makeEngine(connections: provider)
        await engine.load()
        let custom = "Unsupported | h2 | --payload=tls_client_hello --lua-desync=multisplit:pos=2:seqovl=681"
        _ = try? await engine.saveCustomStrategies(custom)
        let strategy = await engine.strategies.last!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()
        let detail = await engine.detail
        let state = await engine.state
        let selected = await engine.selectedStrategyId
        XCTAssertEqual(state, .idle)
        XCTAssertEqual(detail.key, "detail.unsupported")
        XCTAssertNil(selected, "an unsupported strategy must never become the saved one")
        XCTAssertTrue(provider.openedIds.isEmpty)
    }

    func testAScanOverAllStrategiesOnlyOpensSupportedOnes() async {
        let provider = ScriptedConnectionProvider([:]) // everything fails
        let engine = makeEngine(connections: provider)
        await engine.load()
        _ = await engine.search(full: true)
        await engine.waitUntilIdle()
        let all = await engine.strategies
        let supportedIds = Set(all.filter { $0.unsupportedReason == nil && $0.requiresDesync }.map(\.id))
        XCTAssertEqual(Set(provider.openedIds), supportedIds)
    }

    // MARK: - Leaks and ordering

    func testTrustFailurePreservesResolvedEndpointAndPhase() async {
        let context = ConnectionFailureContext(endpoint: "162.159.198.2:443", transport: "masqueH2", phase: "tls", strategyId: "warp-t-split")
        let error = WarpConnectionError("remote endpoint has a different public key", code: "peer_key_mismatch", connection: context)
        let provider = ScriptedConnectionProvider(["warp-t-split": [.error(error)]])
        let log = LogBus()
        let engine = makeEngine(connections: provider, log: log)
        await engine.load()
        let strategy = StrategyCatalog.builtIn.first { $0.id == "warp-t-split" }!
        _ = await engine.testStrategies([strategy])
        await engine.waitUntilIdle()
        let result = await engine.results[strategy.id]
        XCTAssertEqual(result?.endpoint, context.endpoint)
        XCTAssertEqual(result?.error, "Server key mismatch at 162.159.198.2:443. This endpoint could not be verified.")
        XCTAssertTrue(logText(log).contains("phase=tls code=peer_key_mismatch"))
        XCTAssertEqual(provider.calls.count, 1)
        XCTAssertTrue(provider.handles.isEmpty)
    }

    func testDelayedResetReasonReachesScanResultAndClosesOwnedHandle() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let probe = ScriptedProbe()
        let context = ConnectionFailureContext(endpoint: "162.159.198.2:443", transport: "masqueH3", phase: "traffic", connectionId: "h1")
        probe.failures[2] = WarpConnectionError("connection #h1 ended: connect-ip read: received a stateless reset", code: "connection_lost", connection: context)
        let engine = makeEngine(connections: provider, probe: probe)
        await engine.load()
        _ = await engine.testStrategies([StrategyCatalog.builtIn[0]])
        await engine.waitUntilIdle()
        let result = await engine.results["warp-q-google6"]
        XCTAssertEqual(result?.ok, false)
        XCTAssertTrue(result?.error?.contains("stateless reset") == true)
        XCTAssertFalse(result?.error?.contains("no open connection") == true)
        XCTAssertEqual(provider.handles.count, 1)
        XCTAssertEqual(provider.handles[0].closeCount, 1)
    }

    func testOldH2PoolEvidenceCannotPinThePreviousHttp3Destination() async {
        let strategy = StrategyCatalog.builtIn.first { $0.id == "warp-t-split" }!
        let legacy = Strategy.fingerprint(["warp-config-v1", strategy.transport.rawValue, strategy.args])
        for fingerprint in [nil, legacy] as [String?] {
            var settings = AppSettings()
            settings.results[strategy.id] = TestResult(strategyId: strategy.id, ok: true, confirmed: true,
                endpoint: "162.159.198.1:443", configurationFingerprint: fingerprint)
            let provider = ScriptedConnectionProvider([strategy.id: [.ok(connectMs: 100)]])
            provider.fixedEndpoint = "162.159.198.2:443"
            let engine = makeEngine(connections: provider, settings: settings)
            await engine.load()
            let cached = await engine.results[strategy.id]
            XCTAssertNil(cached)
            _ = await engine.use(strategy)
            await engine.waitUntilIdle()
            XCTAssertNil(provider.calls.first?.endpoint)
        }
    }

    func testAFailedMeasurementAfterOpenDoesNotLeaveTheConnectionOpen() async {
        // apply() opened a persistent connection, then the measurement call threw (the backend
        // hiccuped). The handle used to be dropped on the floor — the daemon kept the tunnel and its
        // routes, and every later connect failed until the daemon restarted.
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let probe = ScriptedProbe()
        probe.result = .failure(WarpConnectionError("read(): connection reset"))
        let engine = makeEngine(connections: provider, probe: probe)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()

        XCTAssertEqual(provider.handles.count, 1)
        XCTAssertEqual(provider.handles[0].closeCount, 1, "the connection that came up must be closed when measuring it fails")
        let state = await engine.state
        XCTAssertEqual(state, .idle)
    }

    func testAScanFirstDisconnectsTheActiveConnection() async {
        // Only one tunnel can exist (every connection shares one route), so a scan started while
        // connected has to drop the connection first — Windows' TestAsync starts with a disconnect.
        let provider = ScriptedConnectionProvider([
            "warp-q-google6": [.ok(connectMs: 100), .ok(connectMs: 100), .ok(connectMs: 100), .ok(connectMs: 100)],
        ])
        let engine = makeEngine(connections: provider)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()
        let connectedHandle = provider.handles[0].id

        _ = await engine.search(full: false)
        await engine.waitUntilIdle()

        let events = provider.events
        let closeAt = events.firstIndex(of: "close:\(connectedHandle)")
        let secondOpenAt = events.indices.filter { events[$0] == "open:warp-q-google6" }.dropFirst().first
        XCTAssertNotNil(closeAt)
        XCTAssertNotNil(secondOpenAt)
        if let closeAt, let secondOpenAt {
            XCTAssertLessThan(closeAt, secondOpenAt, "the old connection must be closed before the scan opens its first test: \(events)")
        }
    }

    func testAScanAlsoClosesATunnelTheDaemonStillHoldsFromAnEarlierSession() async {
        let provider = ScriptedConnectionProvider([:])
        let leftover = FakeHandle(id: "old", connectMs: 1, endpoint: nil) { _ in }
        provider.snapshot = .success(ConnectionSnapshot(live: LiveConnectionStatus(handle: leftover, strategyId: "warp-q-google6")))
        let engine = makeEngine(connections: provider)
        await engine.load()
        _ = await engine.search(full: false)
        await engine.waitUntilIdle()
        XCTAssertEqual(leftover.closeCount, 1, "an unadopted tunnel would hold the shared route and make every test fail")
    }

    // MARK: - Cancellation

    func testCancelStopsAScanBeforeLaterStrategiesAreTried() async {
        let gate = OneShotGate()
        let provider = ScriptedConnectionProvider([
            "warp-q-google6": [.ok(connectMs: 100)],
        ])
        provider.gateForId = (id: "warp-q-google6", gate: gate)
        let engine = makeEngine(connections: provider)
        await engine.load()

        let started = await engine.search(full: true) // full scan so it would otherwise walk the whole catalog
        XCTAssertTrue(started)
        // Order matters: request cancellation *while the background task is still parked on the
        // gate*, before releasing it. That guarantees `stopRequested` is already true by the time
        // the in-flight attempt finishes and the loop checks it again — no race with the
        // background task racing ahead to a second strategy between "release" and "cancel".
        // `search` only guarantees the background Task was scheduled, not that it has actually run
        // yet, so wait for it to really reach the gate before cancelling.
        await gate.waitUntilArrived()
        await engine.cancel()
        await gate.open()
        await engine.waitUntilIdle()

        let detail = await engine.detail
        XCTAssertEqual(detail.key, "detail.cancelled")
        // The one attempt already in flight when cancel() landed is allowed to finish; no second
        // strategy id may ever be opened after that.
        XCTAssertEqual(provider.openedIds, ["warp-q-google6"])
        XCTAssertEqual(provider.handles.first?.closeCount, 1, "the test connection that was in flight must be closed")
    }

    func testCancelDuringAConnectIsHonored() async {
        // Cancel used to be ignored by apply(): the connect ran to completion (and ended up
        // Connected) no matter what the user pressed.
        let provider = ScriptedConnectionProvider()
        provider.openHangsUntilCancelled = true
        let log = LogBus()
        let engine = makeEngine(connections: provider, log: log)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await waitUntil("the connect to start") { await engine.state == .connecting }

        await engine.cancel()
        await engine.waitUntilIdle()

        let state = await engine.state
        let detail = await engine.detail
        let selected = await engine.selectedStrategyId
        XCTAssertEqual(state, .idle)
        XCTAssertEqual(detail.key, "detail.cancelled")
        XCTAssertNil(selected, "a cancelled connect must not save the strategy")
        XCTAssertTrue(logText(log).contains("log.cancelled"))
    }

    func testCancelLandingJustAfterAConnectionCameUpClosesIt() async {
        let gate = OneShotGate()
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        provider.gateForId = (id: "warp-q-google6", gate: gate)
        let engine = makeEngine(connections: provider)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await gate.waitUntilArrived()
        await engine.cancel()
        await gate.open() // the dial completes right after the user pressed Cancel
        await engine.waitUntilIdle()

        let state = await engine.state
        XCTAssertEqual(state, .idle)
        XCTAssertEqual(provider.handles.first?.closeCount, 1, "a connection nobody wants any more must not be kept")
    }

    func testCancelledTestDoesNotOverwriteWhatWasAlreadyKnown() async {
        var settings = AppSettings()
        let known = TestResult(strategyId: "warp-q-google6", ok: true, connectMs: 100, pingMs: 20, confirmed: true,
                               configurationFingerprint: StrategyCatalog.builtIn[0].configurationFingerprint)
        settings.results = ["warp-q-google6": known]
        let provider = ScriptedConnectionProvider()
        provider.openHangsUntilCancelled = true
        let engine = makeEngine(connections: provider, settings: settings)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.testStrategies([strategy])
        await waitUntil("the test to start") { await engine.state == .searching }
        await engine.cancel()
        await engine.waitUntilIdle()
        let results = await engine.results
        XCTAssertEqual(results["warp-q-google6"], known, "a test that never finished must not leave a failure behind")
    }

    // MARK: - Settings

    func testUpdateSettingsDoesNotClobberResultsOrSelectedStrategy() async {
        // AppViewModel's `settings` is a snapshot the UI captures at launch and mutates locally —
        // it is never refreshed from the engine as scans discover new results. A Settings-screen
        // toggle firing after a scan therefore calls `updateSettings` with a whole `AppSettings`
        // struct whose embedded `results`/`selectedStrategyId` can be stale relative to what the
        // engine has since discovered — that must not roll the engine's live state backwards.
        let provider = ScriptedConnectionProvider([
            "warp-q-google6": [.ok(connectMs: 120), .ok(connectMs: 130), .ok(connectMs: 110)],
        ])
        let store = InMemorySettingsStore({ var s = AppSettings(); s.stopAfterWorking = 1; return s }())
        let engine = makeEngine(connections: provider, store: store)
        await engine.load()

        let started = await engine.search(full: false)
        XCTAssertTrue(started)
        await engine.waitUntilIdle()

        let resultsAfterScan = await engine.results
        let selectedAfterScan = await engine.selectedStrategyId
        XCTAssertEqual(selectedAfterScan, "warp-q-google6")
        XCTAssertFalse(resultsAfterScan.isEmpty)

        // A stale snapshot from before the scan ran, with one real preference change on it —
        // exactly what a toggle flip on an out-of-date `AppViewModel.settings` would send.
        var stale = AppSettings()
        stale.isolateTests = false
        await engine.updateSettings(stale)

        let resultsAfterUpdate = await engine.results
        let selectedAfterUpdate = await engine.selectedStrategyId
        let settingsAfterUpdate = await engine.currentSettings
        XCTAssertEqual(resultsAfterUpdate, resultsAfterScan, "a preference-only settings update must not erase scan results")
        XCTAssertEqual(selectedAfterUpdate, selectedAfterScan, "a preference-only settings update must not erase the selected strategy")
        XCTAssertEqual(settingsAfterUpdate.isolateTests, false, "the actual preference change must still take effect")
        // ...and what reached disk is the live state too, not the stale copy.
        XCTAssertEqual(store.load().results, resultsAfterScan)
        XCTAssertEqual(store.load().selectedStrategyId, selectedAfterScan)
    }

    func testAStaleSettingsCopyCannotUnAcceptTheTerms() async {
        var accepted = AppSettings()
        accepted.warpTermsAccepted = true
        let engine = makeEngine(connections: ScriptedConnectionProvider(), settings: accepted)
        await engine.load()
        await engine.updateSettings(AppSettings()) // warpTermsAccepted == false
        let now = await engine.currentSettings
        XCTAssertTrue(now.warpTermsAccepted)
    }

    func testUpdateSettingsClampsHandEditedValues() async {
        let engine = makeEngine(connections: ScriptedConnectionProvider())
        await engine.load()
        var wild = AppSettings()
        wild.testTimeoutSec = 100_000
        wild.stopAfterWorking = 0
        await engine.updateSettings(wild)
        let s = await engine.currentSettings
        XCTAssertEqual(s.testTimeoutSec, 60)
        XCTAssertEqual(s.stopAfterWorking, 1)
    }

    // MARK: - Adopting and watching the backend's connection

    func testAdoptExistingConnectionReflectsAnAlreadyLiveDaemonTunnel() async {
        // Simulates a GUI crash/relaunch: zarpd already has a real persistent connection open
        // that this fresh engine instance never itself opened.
        let provider = ScriptedConnectionProvider([:])
        provider.snapshot = .success(ConnectionSnapshot(live: LiveConnectionStatus(
            handle: FakeHandle(id: "7", connectMs: 150, endpoint: "162.159.198.2"), strategyId: "warp-q-google6")))
        let engine = makeEngine(connections: provider)
        await engine.load()

        let stateBefore = await engine.state
        XCTAssertEqual(stateBefore, .idle, "must not claim connected before reconciling")
        await engine.adoptExistingConnection()

        let state = await engine.state
        let selected = await engine.selectedStrategyId
        XCTAssertEqual(state, .connected)
        XCTAssertEqual(selected, "warp-q-google6")
        // Adopting must not itself open or close anything — it only reflects what's already there.
        XCTAssertTrue(provider.openedIds.isEmpty)
    }

    func testAdoptingATestRouteOnlyTunnelSaysSo() async {
        let provider = ScriptedConnectionProvider([:])
        provider.snapshot = .success(ConnectionSnapshot(live: LiveConnectionStatus(
            handle: FakeHandle(id: "7", connectMs: 150, endpoint: nil), strategyId: "warp-q-google6", routeAll: false)))
        let engine = makeEngine(connections: provider)
        await engine.load()
        await engine.adoptExistingConnection()
        let detail = await engine.detail
        XCTAssertEqual(detail.key, "detail.strategyTestRoute")
    }

    func testAdoptExistingConnectionDoesNothingWhenEngineAlreadyKnowsItsConnected() async {
        // A real connection the engine opened itself must never be silently replaced by whatever
        // a subsequent reconciliation call happens to see.
        let provider = ScriptedConnectionProvider([
            "warp-q-google6": [.ok(connectMs: 100), .ok(connectMs: 100), .ok(connectMs: 100)],
        ])
        let engine = makeEngine(connections: provider)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()
        let stateAfterUse = await engine.state
        XCTAssertEqual(stateAfterUse, .connected)

        provider.snapshot = .success(ConnectionSnapshot(live: LiveConnectionStatus(
            handle: FakeHandle(id: "999", connectMs: 999, endpoint: "should-not-be-adopted"), strategyId: "warp-q-vk6")))
        await engine.adoptExistingConnection()

        // Still the strategy the engine itself connected with, not the one reconciliation saw.
        let selected = await engine.selectedStrategyId
        XCTAssertEqual(selected, "warp-q-google6")
    }

    func testAdoptIsNotFooledByAConnectThatStartsWhileItWaitsForTheBackend() async {
        // adopt() awaits the backend; actors are re-entrant, so a connect can start in that gap.
        // The answer is then stale and must be dropped, not applied on top of the new operation.
        let gate = OneShotGate()
        let provider = ScriptedConnectionProvider(["warp-q-vk6": [.ok(connectMs: 80)]])
        provider.snapshotGate = gate
        provider.snapshot = .success(ConnectionSnapshot(live: LiveConnectionStatus(
            handle: FakeHandle(id: "old", connectMs: 1, endpoint: nil), strategyId: "warp-q-google6")))
        let engine = makeEngine(connections: provider)
        await engine.load()

        let adopting = Task { await engine.adoptExistingConnection() }
        await gate.waitUntilArrived()
        // Meanwhile the user connects with a different strategy — and that connect runs to
        // completion while adopt is still waiting for its answer. (prepare() asks the backend too,
        // so the gate is removed first: the point is only the interleaving.)
        let strategy = await engine.strategies.first { $0.id == "warp-q-vk6" }!
        provider.snapshotGate = nil
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()
        await gate.open() // the stale answer ("a tunnel for google6 exists") finally arrives
        await adopting.value

        let selected = await engine.selectedStrategyId
        let state = await engine.state
        XCTAssertEqual(selected, "warp-q-vk6", "the stale snapshot overwrote the connection the user just made")
        XCTAssertEqual(state, .connected)
    }

    func testAdoptDropsAStaleAnswerEvenWhenTheEngineIsIdleAgainByThen() async {
        // Same interleaving, but by the time the stale "a tunnel exists" answer arrives the user has
        // connected *and disconnected*: the engine is idle, exactly as before the question, so
        // neither `busy` nor `state` can tell the answer is out of date — only the epoch can.
        let gate = OneShotGate()
        let provider = ScriptedConnectionProvider(["warp-q-vk6": [.ok(connectMs: 80)]])
        provider.snapshotGate = gate
        provider.snapshot = .success(ConnectionSnapshot(live: LiveConnectionStatus(
            handle: FakeHandle(id: "old", connectMs: 1, endpoint: nil), strategyId: "warp-q-google6")))
        let engine = makeEngine(connections: provider)
        await engine.load()

        let adopting = Task { await engine.adoptExistingConnection() }
        await gate.waitUntilArrived()
        provider.snapshotGate = nil
        let strategy = await engine.strategies.first { $0.id == "warp-q-vk6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()
        _ = await engine.disconnect()
        await engine.waitUntilIdle()
        // The leftover "old" tunnel was closed by use()'s prepare(); the snapshot provider still
        // describes it, as a stale answer would.
        await gate.open()
        await adopting.value

        let state = await engine.state
        let selected = await engine.selectedStrategyId
        XCTAssertEqual(state, .idle, "a tunnel that no longer exists was adopted from a stale answer")
        XCTAssertEqual(selected, "warp-q-vk6")
    }

    func testAStaleSnapshotFromBeforeAReconnectDoesNotDeclareTheNewTunnelLost() async {
        // reconcile() asks the backend "is there a tunnel?" and the answer ("no") is already out of
        // date when it arrives, because the user disconnected and connected again in between.
        // Checking `busy` afterwards is not enough: the new connect has *finished* by then.
        var settings = AppSettings()
        settings.reconnectOnLoss = false
        let gate = OneShotGate()
        let provider = ScriptedConnectionProvider([
            "warp-q-google6": [.ok(connectMs: 100)], "warp-q-vk6": [.ok(connectMs: 90)],
        ])
        let engine = makeEngine(connections: provider, settings: settings)
        await engine.load()
        let first = await engine.strategies.first { $0.id == "warp-q-google6" }!
        let second = await engine.strategies.first { $0.id == "warp-q-vk6" }!
        _ = await engine.use(first)
        await engine.waitUntilIdle()

        provider.snapshot = .success(ConnectionSnapshot(live: nil))
        provider.snapshotGate = gate
        let reconciling = Task { await engine.reconcileConnection() }
        await gate.waitUntilArrived()

        provider.snapshotGate = nil
        _ = await engine.use(second) // closes the first tunnel, opens another — all while reconcile waits
        await engine.waitUntilIdle()
        await gate.open()
        let outcome = await reconciling.value

        XCTAssertEqual(outcome, .unchanged)
        let state = await engine.state
        let selected = await engine.selectedStrategyId
        XCTAssertEqual(state, .connected, "a stale 'no tunnel' answer must not tear down the display of the tunnel that is up")
        XCTAssertEqual(selected, "warp-q-vk6")
    }

    func testReconcileNoticesALostTunnelAndGoesIdle() async {
        var settings = AppSettings()
        settings.reconnectOnLoss = false
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let log = LogBus()
        let engine = makeEngine(connections: provider, log: log, settings: settings)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()
        let held = provider.handles[0].id
        provider.snapshot = .success(ConnectionSnapshot(live: LiveConnectionStatus(
            handle: provider.handles[0], strategyId: "warp-q-google6")))
        let steady = await engine.reconcileConnection()
        XCTAssertEqual(steady, .unchanged)

        // The daemon tore the tunnel down (the MASQUE session died) and says why.
        provider.snapshot = .success(ConnectionSnapshot(live: nil, lastLoss: ConnectionLoss(connectionId: held, reason: "no recent network activity")))
        let outcome = await engine.reconcileConnection()

        XCTAssertEqual(outcome, .lost("no recent network activity"))
        let state = await engine.state
        let detail = await engine.detail
        XCTAssertEqual(state, .idle, "a dead tunnel must stop being displayed as Connected")
        XCTAssertEqual(detail.key, "detail.connectionLost")
        XCTAssertTrue(logText(log).contains("log.connectionLost"))
        XCTAssertEqual(provider.calls.count, 1, "with auto-reconnect off nothing may be reopened")
    }

    func testALostTunnelIsReconnectedWithTheSameStrategyWithoutRescanning() async {
        let provider = ScriptedConnectionProvider([
            "warp-q-google6": [.ok(connectMs: 100), .ok(connectMs: 90)],
        ])
        let engine = makeEngine(connections: provider) // reconnectOnLoss defaults to true
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()
        let resultsBefore = await engine.results

        provider.snapshot = .success(ConnectionSnapshot(live: nil, lastLoss: ConnectionLoss(connectionId: "x", reason: "network changed")))
        _ = await engine.reconcileConnection()
        await engine.waitUntilIdle()

        let state = await engine.state
        XCTAssertEqual(state, .connected)
        XCTAssertEqual(provider.openedIds, ["warp-q-google6", "warp-q-google6"], "same strategy again, no scan")
        XCTAssertEqual(provider.calls.last?.persistent, true)
        let resultsAfter = await engine.results
        XCTAssertEqual(resultsAfter, resultsBefore, "the network dropping is not a failure of the strategy")
    }

    func testAFailedReconnectRetriesThenGivesUpWithoutBlamingTheStrategy() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100), .fail()]])
        let log = LogBus()
        let engine = makeEngine(connections: provider, log: log)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()
        let resultsBefore = await engine.results

        provider.snapshot = .success(ConnectionSnapshot(live: nil))
        _ = await engine.reconcileConnection()
        await engine.waitUntilIdle()

        XCTAssertEqual(provider.openedIds.filter { $0 == strategy.id }.count, 1 + 3)
        XCTAssertLessThanOrEqual(provider.openedIds.count, 1 + 3 + 8, "retries and alternative candidates are bounded")
        let state = await engine.state
        XCTAssertEqual(state, .idle)
        let resultsAfter = await engine.results
        XCTAssertEqual(resultsAfter, resultsBefore, "failed reconnects must not overwrite the strategy's good result")
        XCTAssertTrue(logText(log).contains("log.reconnectGiveUp"))
    }

    func testAFlappingTunnelDoesNotReconnectForever() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]]) // every open succeeds
        let log = LogBus()
        let engine = makeEngine(connections: provider, log: log)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()

        for _ in 0..<6 {
            provider.snapshot = .success(ConnectionSnapshot(live: nil)) // it drops again every time
            _ = await engine.reconcileConnection()
            await engine.waitUntilIdle()
        }
        // One immediate retry, then bounded alternatives. Short successes do not
        // create a fresh retry episode or repeat the original pair indefinitely.
        XCTAssertEqual(provider.openedIds.filter { $0 == strategy.id }.count, 2)
        XCTAssertLessThanOrEqual(provider.openedIds.count, 1 + 1 + 8)
        XCTAssertTrue(logText(log).contains("log.reconnectGiveUp"))
    }

    func testOneMissedAnswerIsAHiccupTwoMeanTheBackendIsGone() async {
        var settings = AppSettings()
        settings.reconnectOnLoss = false
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let engine = makeEngine(connections: provider, settings: settings)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()

        provider.snapshot = .failure(WarpConnectionError("connect(): no such file"))
        let first = await engine.reconcileConnection()
        XCTAssertEqual(first, .daemonUnreachable)
        let stillConnected = await engine.state
        XCTAssertEqual(stillConnected, .connected)

        let second = await engine.reconcileConnection()
        XCTAssertEqual(second, .lost(nil))
        let state = await engine.state
        XCTAssertEqual(state, .idle)
    }

    func testAnAnsweredCallResetsTheMissedCount() async {
        var settings = AppSettings()
        settings.reconnectOnLoss = false
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let engine = makeEngine(connections: provider, settings: settings)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()
        let live = LiveConnectionStatus(handle: provider.handles[0], strategyId: "warp-q-google6")

        for _ in 0..<3 { // alternate miss / answer: never two misses in a row
            provider.snapshot = .failure(WarpConnectionError("timeout"))
            _ = await engine.reconcileConnection()
            provider.snapshot = .success(ConnectionSnapshot(live: live))
            _ = await engine.reconcileConnection()
        }
        let state = await engine.state
        XCTAssertEqual(state, .connected)
    }

    func testReconcileAdoptsAConnectionTheBackendReplacedItWith() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let engine = makeEngine(connections: provider)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()

        provider.snapshot = .success(ConnectionSnapshot(live: LiveConnectionStatus(
            handle: FakeHandle(id: "replacement", connectMs: 5, endpoint: nil), strategyId: "warp-q-vk6")))
        let outcome = await engine.reconcileConnection()
        XCTAssertEqual(outcome, .adopted)
        let selected = await engine.selectedStrategyId
        XCTAssertEqual(selected, "warp-q-vk6")
    }

    func testReconcileLeavesABusyEngineAlone() async {
        let gate = OneShotGate()
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        provider.gateForId = (id: "warp-q-google6", gate: gate)
        let engine = makeEngine(connections: provider)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await gate.waitUntilArrived()

        provider.snapshot = .success(ConnectionSnapshot(live: nil))
        let outcome = await engine.reconcileConnection()
        XCTAssertEqual(outcome, .unchanged, "while a connect is in flight the backend legitimately has nothing yet")
        await gate.open()
        await engine.waitUntilIdle()
        let state = await engine.state
        XCTAssertEqual(state, .connected)
    }

    // MARK: - Preparing: other VPNs and the WARP account

    func testAnotherVPNCanBeDeclined() async {
        let provider = ScriptedConnectionProvider([:])
        let seen = LockedBox<[String]>([])
        let engine = makeEngine(connections: provider, network: FixedInspector(names: ["utun28"]))
        await engine.load()
        await engine.setHooks(EngineHooks(askContinueWithVPN: { names in seen.set(names); return false }))
        _ = await engine.search(full: false)
        await engine.waitUntilIdle()
        let detail = await engine.detail
        XCTAssertEqual(detail.key, "detail.vpnOff")
        XCTAssertEqual(seen.value, [])
        XCTAssertTrue(provider.openedIds.isEmpty, "nothing may be tested through someone else's tunnel")
    }

    func testAnotherVPNAlwaysRefusesAndPreservesSavedHistory() async {
        for hook in [true, false] {
            let provider = ScriptedConnectionProvider([:])
            let engine = makeEngine(connections: provider, network: FixedInspector(names: ["utun28"]))
            await engine.load()
            if hook { await engine.setHooks(EngineHooks(askContinueWithVPN: { _ in true })) }
            _ = await engine.search(full: false)
            await engine.waitUntilIdle()
            XCTAssertTrue(provider.openedIds.isEmpty, "foreign VPN must not be bypassed by a hook")
        }
    }

    func testRegistrationNeedsTheUsersConsentFirst() async {
        let provider = ScriptedConnectionProvider([:])
        provider.accountRegistered = false
        let asked = LockedBox(0)
        let engine = makeEngine(connections: provider)
        await engine.load()
        await engine.setHooks(EngineHooks(askAcceptWarpTerms: { asked.set(asked.value + 1); return false }))
        _ = await engine.search(full: false)
        await engine.waitUntilIdle()
        let detail = await engine.detail
        XCTAssertEqual(detail.key, "detail.termsDeclined")
        XCTAssertEqual(provider.registerCalls, 0, "nothing registers with Cloudflare before the user agrees")
        XCTAssertTrue(provider.openedIds.isEmpty)
        XCTAssertEqual(asked.value, 1)
    }

    func testNoConsentHookMeansNoRegistration() async {
        let provider = ScriptedConnectionProvider([:])
        provider.accountRegistered = false
        let engine = makeEngine(connections: provider)
        await engine.load()
        _ = await engine.search(full: false)
        await engine.waitUntilIdle()
        XCTAssertEqual(provider.registerCalls, 0)
    }

    func testAcceptedTermsRegisterOnceAndAreRemembered() async {
        let provider = ScriptedConnectionProvider([:])
        provider.accountRegistered = false
        let asked = LockedBox(0)
        let store = InMemorySettingsStore()
        let engine = makeEngine(connections: provider, store: store)
        await engine.load()
        await engine.setHooks(EngineHooks(askAcceptWarpTerms: { asked.set(asked.value + 1); return true }))
        _ = await engine.search(full: false)
        await engine.waitUntilIdle()
        XCTAssertEqual(provider.registerCalls, 1)
        XCTAssertEqual(asked.value, 1)
        XCTAssertTrue(store.load().warpTermsAccepted, "the acceptance must be saved")

        // Account gone again (config deleted): re-registers without asking a second time.
        provider.accountRegistered = false
        _ = await engine.search(full: false)
        await engine.waitUntilIdle()
        XCTAssertEqual(provider.registerCalls, 2)
        XCTAssertEqual(asked.value, 1)
    }

    func testRegistrationFailureIsReportedAndStopsTheOperation() async {
        let provider = ScriptedConnectionProvider([:])
        provider.accountRegistered = false
        provider.registerError = WarpConnectionError("network is down")
        let log = LogBus()
        let engine = makeEngine(connections: provider, log: log)
        await engine.load()
        await engine.setHooks(EngineHooks(askAcceptWarpTerms: { true }))
        _ = await engine.search(full: false)
        await engine.waitUntilIdle()
        let detail = await engine.detail
        XCTAssertEqual(detail.key, "detail.registerFailed")
        XCTAssertTrue(provider.openedIds.isEmpty)
        XCTAssertTrue(logText(log).contains("log.warpRegisterFailed"))
    }

    func testAnUnreachableBackendIsReportedInsteadOfHanging() async {
        let provider = ScriptedConnectionProvider([:])
        let engine = makeEngine(connections: FailingRegistrationCheck(base: provider))
        await engine.load()
        _ = await engine.search(full: false)
        await engine.waitUntilIdle()
        let detail = await engine.detail
        let state = await engine.state
        XCTAssertEqual(detail.key, "detail.error")
        XCTAssertEqual(state, .idle)
    }

    // MARK: - Custom strategies

    func testSavingCustomStrategiesReloadsThemAndReportsBadLines() async throws {
        let custom = InMemoryCustomStrategyStore()
        let engine = makeEngine(connections: ScriptedConnectionProvider(), customStore: custom)
        await engine.load()
        let skipped = try await engine.saveCustomStrategies("""
        My QUIC | h3 | --payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=8
        this line is broken
        """)
        XCTAssertEqual(skipped, ["this line is broken"])
        let ids = await engine.strategies.map(\.id)
        XCTAssertTrue(ids.contains { $0.hasPrefix("custom-v2-") })
        XCTAssertEqual(custom.loadText().contains("My QUIC"), true, "the text must really be saved")
        let text = await engine.customStrategiesText()
        XCTAssertTrue(text.contains("My QUIC"))
    }

    func testRemovingACustomStrategyDropsItsResultAndSelection() async throws {
        let custom = InMemoryCustomStrategyStore("Mine | h3 | --payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=2\n")
        var settings = AppSettings()
        settings.selectedStrategyId = "custom-mine"
        settings.results = ["custom-mine": TestResult(strategyId: "custom-mine", ok: true, confirmed: true)]
        let engine = makeEngine(connections: ScriptedConnectionProvider(), customStore: custom, settings: settings)
        await engine.load()
        let selectedBefore = await engine.selectedStrategyId
        XCTAssertEqual(selectedBefore, CustomStrategyFile.parse(custom.loadText()).first?.id)

        try await engine.saveCustomStrategies("# nothing here any more\n")

        let results = await engine.results
        let selected = await engine.selectedStrategyId
        XCTAssertNil(results["custom-mine"])
        XCTAssertNil(selected)
    }

    func testPersistentConnectionRequiresSeparatedTrafficChecks() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 10)]])
        let probe = ScriptedProbe(), waits = LockedBox<[Double]>([])
        let timing = EngineTiming(sleep: { seconds in waits.set(waits.value + [seconds]) })
        let engine = makeEngine(connections: provider, probe: probe, timing: timing)
        await engine.load()
        _ = await engine.use(StrategyCatalog.builtIn[0]); await engine.waitUntilIdle()
        let state = await engine.state
        XCTAssertEqual(state, .connected)
        XCTAssertEqual(waits.value, [2, 2])
        XCTAssertEqual(probe.measuredHandleIds, Array(repeating: provider.handles[0].id, count: 3))
    }

    func testAnInitialTrafficBurstCannotPublishADeadConnectionAsConnected() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 10)]])
        let probe = ScriptedProbe()
        probe.outcomes[2] = .noTraffic(lastError: "received a stateless reset")
        let engine = makeEngine(connections: provider, probe: probe)
        await engine.load()
        _ = await engine.use(StrategyCatalog.builtIn[0]); await engine.waitUntilIdle()
        let state = await engine.state
        XCTAssertEqual(state, .idle)
        XCTAssertEqual(provider.handles[0].closeCount, 1)
        XCTAssertEqual(provider.calls.count, 1)
    }

    func testCancellingDuringStabilityWaitClosesTheOwnedHandle() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 10)]])
        let gate = OneShotGate()
        let timing = EngineTiming(sleep: { _ in await gate.wait(); try Task.checkCancellation() })
        let engine = makeEngine(connections: provider, timing: timing)
        await engine.load()
        _ = await engine.use(StrategyCatalog.builtIn[0])
        await gate.waitUntilArrived()
        let pending = await engine.snapshot()
        XCTAssertEqual(pending.state, .connecting)
        XCTAssertEqual(pending.detail.key, "detail.verifying")
        await engine.cancel()
        await gate.open()
        await engine.waitUntilIdle()
        XCTAssertEqual(provider.handles[0].closeCount, 1)
        let ended = await engine.snapshot()
        XCTAssertEqual(ended.detail.key, "detail.cancelled")
    }

    func testQuickSearchContinuesAfterItsConfirmedCandidateFailsPersistentVerification() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 10)], "warp-t-split": [.ok(connectMs: 20)]])
        let probe = ScriptedProbe()
        probe.outcomes[6] = .noTraffic(lastError: "received a stateless reset")
        let engine = makeEngine(connections: provider, probe: probe)
        await engine.load()
        _ = await engine.search(full: false); await engine.waitUntilIdle()
        let snapshot = await engine.snapshot()
        XCTAssertEqual(snapshot.state, .connected)
        XCTAssertEqual(snapshot.selectedStrategyId, "warp-t-split")
        XCTAssertEqual(snapshot.results["warp-q-google6"]?.ok, false)
        XCTAssertFalse(provider.openedIds.contains("direct-h2"))
    }

    func testRapidLossRetainsBackoffAndPrefersVerifiedTLSAlternatives() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 10)], "warp-t-split": [.ok(connectMs: 20)]])
        let waits = LockedBox<[Double]>([])
        let timing = EngineTiming(sleep: { seconds in waits.set(waits.value + [seconds]) })
        let engine = makeEngine(connections: provider, timing: timing, backoff: [2, 10, 30])
        await engine.load()
        _ = await engine.use(StrategyCatalog.builtIn[0]); await engine.waitUntilIdle()
        for _ in 0..<2 {
            provider.snapshot = .success(ConnectionSnapshot(live: nil))
            _ = await engine.reconcileConnection(); await engine.waitUntilIdle()
        }
        let snapshot = await engine.snapshot()
        XCTAssertEqual(snapshot.selectedStrategyId, "warp-t-split")
        XCTAssertEqual(snapshot.state, .connected)
        XCTAssertEqual(provider.openedIds, ["warp-q-google6", "warp-q-google6", "warp-t-split", "warp-t-split", "warp-t-split"])
        XCTAssertTrue(waits.value.contains(10), "a momentary success must not reset the delay to two seconds")
        XCTAssertEqual(Array(provider.events.suffix(5).prefix(4)), ["open:warp-t-split", "close:h3", "open:warp-t-split", "close:h4"])
    }

    func testAllBrieflySuccessfulAlternativesStillExhaustOneBoundedEpisode() async {
        let scripts = Dictionary(uniqueKeysWithValues: StrategyCatalog.builtIn.map { ($0.id, [ScriptedConnectionProvider.Outcome.ok(connectMs: 10)]) })
        let provider = ScriptedConnectionProvider(scripts)
        let engine = makeEngine(connections: provider)
        await engine.load()
        _ = await engine.use(StrategyCatalog.builtIn[0]); await engine.waitUntilIdle()
        for _ in 0..<14 {
            provider.snapshot = .success(ConnectionSnapshot(live: nil))
            _ = await engine.reconcileConnection(); await engine.waitUntilIdle()
        }
        let state = await engine.state
        XCTAssertEqual(state, .idle)
        XCTAssertEqual(provider.openedIds.filter { $0 == "warp-q-google6" }.count, 2)
        XCTAssertLessThanOrEqual(provider.calls.count, 1 + 1 + 8 * 3)
        XCTAssertFalse(provider.openedIds.contains("direct"))
        XCTAssertFalse(provider.openedIds.contains("direct-h2"))
    }

    func testRecoveryStopsBeforeOpeningAnythingThroughAForeignVPN() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 10)], "warp-t-split": [.ok(connectMs: 20)]])
        let network = MutablePathInspector("wifi")
        let engine = makeEngine(connections: provider, network: network)
        await engine.load()
        _ = await engine.use(StrategyCatalog.builtIn[0]); await engine.waitUntilIdle()
        network.names.set(["utun99"])
        provider.snapshot = .success(ConnectionSnapshot(live: nil))
        _ = await engine.reconcileConnection(); await engine.waitUntilIdle()
        XCTAssertEqual(provider.calls.count, 1)
        let snapshot = await engine.snapshot()
        XCTAssertEqual(snapshot.detail.key, "detail.vpnOff")
    }

    func testPathChangeDuringScanDiscardsOldEvidenceAndRestartsOnce() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 10)]])
        let network = MutablePathInspector("wifi")
        let timing = EngineTiming(sleep: { _ in network.identity.set("hotspot") })
        let engine = makeEngine(connections: provider, network: network, timing: timing)
        await engine.load()
        _ = await engine.search(full: false); await engine.waitUntilIdle()
        let snapshot = await engine.snapshot()
        XCTAssertEqual(snapshot.state, .connected)
        XCTAssertEqual(provider.calls.count, 4)
        XCTAssertEqual(provider.handles.first?.closeCount, 1)
        XCTAssertEqual(snapshot.results["warp-q-google6"]?.networkIdentity, "hotspot")
        XCTAssertEqual(snapshot.results["warp-q-google6"]?.confirmed, true)
    }

    func testRepeatedPathChangesCannotRestartAScanForever() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 10)]])
        let network = MutablePathInspector("wifi")
        let timing = EngineTiming(sleep: { _ in network.identity.set(network.identity.value == "wifi" ? "hotspot" : "wifi") })
        let engine = makeEngine(connections: provider, network: network, timing: timing)
        await engine.load()
        _ = await engine.search(full: false); await engine.waitUntilIdle()
        let snapshot = await engine.snapshot()
        XCTAssertEqual(snapshot.state, .idle)
        XCTAssertEqual(snapshot.detail.key, "detail.networkChanged")
        XCTAssertTrue(snapshot.results.isEmpty)
        XCTAssertEqual(provider.calls.count, 2)
        XCTAssertTrue(provider.handles.allSatisfy { $0.closeCount == 1 })
    }

    func testOnlyAMatureConnectionStartsAFreshRecoveryEpisode() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 10)], "warp-t-split": [.ok(connectMs: 20)]])
        let now = LockedBox(Date(timeIntervalSince1970: 1_000))
        let timing = EngineTiming(now: { now.value }, sleep: { _ in try Task.checkCancellation() })
        let engine = makeEngine(connections: provider, timing: timing)
        await engine.load()
        _ = await engine.use(StrategyCatalog.builtIn[0]); await engine.waitUntilIdle()
        provider.snapshot = .success(ConnectionSnapshot(live: nil))
        _ = await engine.reconcileConnection(); await engine.waitUntilIdle()
        now.set(now.value.addingTimeInterval(31))
        _ = await engine.reconcileConnection(); await engine.waitUntilIdle()
        XCTAssertEqual(provider.openedIds, Array(repeating: "warp-q-google6", count: 3))
        let state = await engine.state
        XCTAssertEqual(state, .connected)
    }

    func testCancellingAnAlternativeCannotOpenTheNextCandidate() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 10), .fail()], "warp-t-split": [.ok(connectMs: 20)]])
        let gate = OneShotGate()
        provider.gateForId = ("warp-t-split", gate)
        let engine = makeEngine(connections: provider)
        await engine.load()
        _ = await engine.use(StrategyCatalog.builtIn[0]); await engine.waitUntilIdle()
        provider.snapshot = .success(ConnectionSnapshot(live: nil))
        _ = await engine.reconcileConnection()
        await gate.waitUntilArrived()
        await engine.cancel()
        await gate.open()
        await engine.waitUntilIdle()
        XCTAssertEqual(provider.openedIds.suffix(1), ["warp-t-split"])
        XCTAssertEqual(provider.handles.last?.closeCount, 1)
        let detail = await engine.detail
        XCTAssertEqual(detail.key, "detail.cancelled")
    }

    func testHeartbeatPathChangeClosesOnlyTheOwnedTunnelAndRechecksTheNewPath() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 10)]])
        let network = MutablePathInspector("wifi")
        let engine = makeEngine(connections: provider, network: network)
        await engine.load()
        _ = await engine.use(StrategyCatalog.builtIn[0]); await engine.waitUntilIdle()
        network.identity.set("hotspot")
        await engine.observeNetworkChange(); await engine.waitUntilIdle()
        let state = await engine.state
        XCTAssertEqual(state, .connected)
        XCTAssertEqual(provider.calls.count, 2)
        XCTAssertEqual(provider.handles[0].closeCount, 1)
        XCTAssertEqual(provider.handles[1].closeCount, 0)
    }

    func testRecoveryDeadlineCannotBeExtendedByBackoff() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 10)]])
        let now = LockedBox(Date(timeIntervalSince1970: 1_000))
        let expiring = LockedBox(false)
        let timing = EngineTiming(now: { now.value }, sleep: { _ in
            if expiring.value { now.set(now.value.addingTimeInterval(181)) }
        })
        let engine = makeEngine(connections: provider, timing: timing)
        await engine.load()
        _ = await engine.use(StrategyCatalog.builtIn[0]); await engine.waitUntilIdle()
        expiring.set(true)
        provider.snapshot = .success(ConnectionSnapshot(live: nil))
        _ = await engine.reconcileConnection(); await engine.waitUntilIdle()
        XCTAssertEqual(provider.calls.count, 1)
        let state = await engine.state
        XCTAssertEqual(state, .idle)
    }

    func testSavedWifiEvidenceDoesNotPinOrCertifyTheHotspot() async {
        let strategy = StrategyCatalog.builtIn[0]
        var settings = AppSettings()
        let cached = TestResult(strategyId: strategy.id, ok: true, confirmed: true, endpoint: "162.159.198.2:4500",
                                configurationFingerprint: strategy.configurationFingerprint, networkIdentity: "wifi")
        settings.results[strategy.id] = cached
        let store = InMemorySettingsStore(settings)
        let provider = ScriptedConnectionProvider([strategy.id: [.ok(connectMs: 10)]])
        let network = MutablePathInspector("hotspot")
        let engine = makeEngine(connections: provider, network: network, store: store)
        await engine.load()
        let before = await engine.results
        XCTAssertTrue(before.isEmpty)
        _ = await engine.use(strategy); await engine.waitUntilIdle()
        XCTAssertNil(provider.calls.first?.endpoint)
        network.identity.set("wifi")
        let restored = makeEngine(connections: ScriptedConnectionProvider(), network: network, store: store)
        await restored.load()
        let prior = await restored.results[strategy.id]
        XCTAssertEqual(prior, cached)
    }

    // MARK: - Snapshot

    func testSnapshotIsConsistentWithTheLiveProperties() async {
        let provider = ScriptedConnectionProvider(["warp-q-google6": [.ok(connectMs: 100)]])
        let engine = makeEngine(connections: provider)
        await engine.load()
        let strategy = await engine.strategies.first { $0.id == "warp-q-google6" }!
        _ = await engine.use(strategy)
        await engine.waitUntilIdle()
        let snap = await engine.snapshot()
        let state = await engine.state
        let selected = await engine.selectedStrategyId
        let busy = await engine.isBusy
        XCTAssertEqual(snap.state, state)
        XCTAssertEqual(snap.selectedStrategyId, selected)
        XCTAssertEqual(snap.isBusy, busy)
        XCTAssertEqual(snap.strategies.count, StrategyCatalog.builtIn.count)
    }
}

/// A tiny thread-safe cell for values the `@Sendable` hooks need to record.
private final class LockedBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: T
    init(_ initial: T) { stored = initial }
    var value: T { lock.lock(); defer { lock.unlock() }; return stored }
    func set(_ new: T) { lock.lock(); stored = new; lock.unlock() }
}

/// A provider whose very first question — "is there an account?" — fails, like a daemon that isn't
/// installed or running.
private struct FailingRegistrationCheck: WarpConnectionProvider {
    let base: WarpConnectionProvider
    func open(strategy: Strategy, endpoint: String?, timeoutMs: Int, persistent: Bool, routing: TunnelRouting) async throws -> WarpConnectionHandle {
        try await base.open(strategy: strategy, endpoint: endpoint, timeoutMs: timeoutMs, persistent: persistent, routing: routing)
    }
    func connectionSnapshot() async throws -> ConnectionSnapshot { try await base.connectionSnapshot() }
    func isAccountRegistered() async throws -> Bool { throw WarpConnectionError("connect(/var/run/zarpd.sock): No such file or directory — is zarpd running?") }
    func registerAccount() async throws { try await base.registerAccount() }
}

private struct MutablePathInspector: NetworkInspector {
    let identity: LockedBox<String?>
    let names = LockedBox<[String]>([])
    init(_ identity: String) { self.identity = LockedBox(identity) }
    func connectionPathIdentity() -> String? { identity.value }
    func foreignVPNInterfaceNames() -> [String] { names.value }
}
