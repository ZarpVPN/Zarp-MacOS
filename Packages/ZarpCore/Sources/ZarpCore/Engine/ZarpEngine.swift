import Foundation

/// Things only the UI layer can do, which the engine needs an answer to mid-operation (Windows
/// `Engine.AskContinueWithVpn` and its siblings). Both are optional: with no hook the engine takes
/// the conservative default (don't continue / don't accept).
public struct EngineHooks: Sendable {
    /// Legacy callback retained for source compatibility. VPN conflicts now always refuse
    /// testing and connection attempts, so this callback is never invoked.
    public var askContinueWithVPN: (@Sendable ([String]) async -> Bool)?
    /// Zarp needs a WARP account and has none: ask the user to accept Cloudflare's terms before one
    /// is registered on their behalf. Return `true` if they accept.
    public var askAcceptWarpTerms: (@Sendable () async -> Bool)?

    public init(askContinueWithVPN: (@Sendable ([String]) async -> Bool)? = nil,
                askAcceptWarpTerms: (@Sendable () async -> Bool)? = nil) {
        self.askContinueWithVPN = askContinueWithVPN
        self.askAcceptWarpTerms = askAcceptWarpTerms
    }
}

/// Everything the UI shows, captured in one actor hop so the pieces are consistent with each other
/// (reading them with seven separate `await`s can straddle a state change).
public struct EngineSnapshot: Sendable {
    public let state: EngineState
    public let detail: Msg
    public let progressDone: Int
    public let progressTotal: Int
    public let strategies: [Strategy]
    public let results: [String: TestResult]
    public let selectedStrategyId: String?
    public let isBusy: Bool
    public let sources: [ConnectionSource]
    public let sourceID: String
    public let mode: ConnectionMode
}

/// What `reconcileConnection()` found.
public enum ReconcileOutcome: Sendable, Equatable {
    case unchanged
    /// A tunnel the engine didn't know about is now shown as connected.
    case adopted
    /// The tunnel the engine believed in is gone; the engine is idle again (the associated value
    /// is the reason, if the backend gave one).
    case lost(String?)
    /// The backend couldn't be asked.
    case daemonUnreachable
}

/// Strategy scan/connect/self-heal state machine. Direct port of Windows Zarp's `Engine`
/// (`Core/Engine.cs`) and Android Zarp's `ZarpEngine` (`core/ZarpEngine.kt`): same states, same
/// inline double verification, same scoring, same self-healing order (saved strategy → other confirmed strategies,
/// best first → Quick Scan).
///
/// This type knows nothing about how a WARP connection actually gets made — that is entirely
/// `WarpConnectionProvider`'s job (see `EngineProtocols.swift`).
///
/// Cancellation follows Windows' model (`CancellationToken` threaded through every step): `cancel()`
/// is honored by *every* operation — mid-dial, mid-connect, between strategies — and a cancelled
/// operation always ends by tearing down whatever it had opened and reporting "Cancelled".
public actor ZarpEngine {
    public private(set) var state: EngineState = .idle
    public private(set) var detail: Msg = Msg("detail.noStrategy")
    public private(set) var progressDone: Int = 0
    public private(set) var progressTotal: Int = 0
    public private(set) var strategies: [Strategy] = StrategyCatalog.builtIn
    public private(set) var results: [String: TestResult] = [:]
    public private(set) var selectedStrategyId: String?

    /// Called after any state/detail/progress/results change, from whatever task is running —
    /// same role as Windows `Engine.Changed`. UI layers hop back to the main actor themselves.
    public var onChanged: (@Sendable () -> Void)?

    private static let warpSource = try! ConnectionSource(kind: .warp)
    private let connectionLibrary: ConnectionLibrary?
    private var sourceSnapshot: ConnectionLibrarySnapshot?
    public private(set) var sources: [ConnectionSource] = [warpSource]
    public private(set) var sourceID: String = warpSource.id
    public var mode: ConnectionMode { sources.first { $0.id == sourceID }?.mode ?? .server }
    private var resultPrefix: String { mode == .warp ? "" : sourceID + "|" }
    private func resultKey(_ id: String) -> String { resultPrefix + id }

    private let settingsStore: SettingsStore
    private let strategyStore: CustomStrategyStore
    private let connections: WarpConnectionProvider
    private let probe: WarpProbe
    private let network: NetworkInspector
    private let log: LogBus
    private let loc: Localization
    private let timing: EngineTiming
    private var networkIdentity: String?
    private var networkChanged = false
    private var connectedAt: Date?

    private var settings: AppSettings
    private var hooks = EngineHooks()
    private var endpointSeq: Int = 0
    private var endpointListFingerprint: String? {
        mode == .server || settings.warpEndpoints.isEmpty ? nil : Strategy.fingerprint(["warp-endpoints-v1"] + settings.warpEndpoints)
    }
    private var activeConnection: WarpConnectionHandle?
    private var runningTask: Task<Void, Never>?
    private var accountTask: Task<WarpAccountStatus, Error>?
    private var busy = false
    private var stopRequested = false
    /// Bumped on every state transition and every operation start/finish. An answer from the
    /// backend is only valid if the epoch is unchanged since the question was asked: actors are
    /// re-entrant, so while `adoptExistingConnection`/`reconcileConnection` wait for the backend a
    /// whole connect can start *and finish* — checking `busy` afterwards would not notice, and the
    /// stale answer would overwrite the newer state.
    private var epoch = 0

    /// Consecutive failed attempts to reach the backend while the engine believes it is connected.
    private var unreachableCount = 0
    /// When automatic reconnect cycles began, newest last — a limit against a tunnel that keeps
    /// dying (flapping network) turning into an endless connect loop.
    private var reconnectCycles: [Date] = []
    private let reconnectBackoff: [Double]
    private static let reconnectAttemptsPerCycle = 3
    private static let maxRecoveryAlternatives = 8
    private static let stableConnectionLifetime: TimeInterval = 30
    private struct RecoveryEpisode {
        let primary: Strategy
        let sourceID: String
        let startedAt: Date
        var attempts = 0
        var losses: [String: Int] = [:]
        var alternatives = Set<String>()
        var exhausted = false
    }
    private var recovery: RecoveryEpisode?
    private static let reconnectCyclesPerWindow = 3
    private static let reconnectWindow: TimeInterval = 600

    /// - Parameter reconnectBackoff: seconds to wait before each automatic reconnect attempt
    ///   (the first, then the second, ...). Tests pass zeros.
    public init(settingsStore: SettingsStore, strategyStore: CustomStrategyStore,
                connections: WarpConnectionProvider, probe: WarpProbe, network: NetworkInspector,
                log: LogBus, localization: Localization, reconnectBackoff: [Double] = [2, 10, 30],
                connectionLibrary: ConnectionLibrary? = nil, timing: EngineTiming = EngineTiming()) {
        self.connectionLibrary = connectionLibrary
        self.settingsStore = settingsStore
        self.strategyStore = strategyStore
        self.connections = connections
        self.probe = probe
        self.network = network
        self.log = log
        self.loc = localization
        self.timing = timing
        self.reconnectBackoff = reconnectBackoff.isEmpty ? [0] : reconnectBackoff
        self.settings = settingsStore.load()
    }

    // MARK: - Lifecycle

    /// Loads settings and the strategy list. Call once at startup (Windows `Engine`'s constructor
    /// + Android `ZarpEngine.load`).
    public func load() async {
        settings = settingsStore.load()
        // Removed plain WARP entries cannot survive as a saved selection or
        // cached success. Other sources and their strategy/server pairs remain.
        let removedPlainIDs: Set<String> = ["direct", "direct-h2"]
        if let id = settings.selectedStrategyId, removedPlainIDs.contains(id) {
            settings.selectedStrategyId = nil
        }
        if let id = settings.sourceSelections[Self.warpSource.id], removedPlainIDs.contains(id) {
            settings.sourceSelections[Self.warpSource.id] = nil
        }
        settings.results = settings.results.filter { !removedPlainIDs.contains($0.value.strategyId) }
        networkIdentity = network.connectionPathIdentity()
        await readSources()
        reloadStrategies()
        restoreCurrentResults()
        detail = selected.map { Msg("detail.strategy", $0.name(using: loc)) } ?? Msg("detail.noStrategy")
        notify()
    }

    private func restoreCurrentResults() {
        selectedStrategyId = settings.sourceSelections[sourceID] ?? (mode == .warp && settings.selectedStrategyId?.contains("@") != true ? settings.selectedStrategyId : nil)
        results = [:]
        let legacyGroups = Dictionary(grouping: strategies.filter { $0.legacyId != nil }, by: { $0.legacyId! })
        if let old = selectedStrategyId, let matches = legacyGroups[old] {
            selectedStrategyId = matches.count == 1 ? matches[0].id : nil
        }
        for strategy in strategies {
            var result = settings.results[resultKey(strategy.id)]
            if mode == .warp, result == nil, let legacy = strategy.legacyId, legacyGroups[legacy]?.count == 1 {
                result = settings.results[legacy]
                result?.strategyId = strategy.id
            }
            guard var r = result, r.strategyId == strategy.id, r.validLatencies else { continue }
            // Built-in legacy arguments are unchanged at this migration. A legacy custom name
            // provides no evidence of which arguments were tested, so it cannot certify them.
            if mode == .warp && r.configurationFingerprint == nil && !strategy.isCustom && strategy.transport != .masqueH2 {
                r.configurationFingerprint = strategy.configurationFingerprint
            }
            guard r.configurationFingerprint == strategy.configurationFingerprint,
                  r.endpointListFingerprint == endpointListFingerprint, r.networkIdentity == networkIdentity else { continue }
            if mode == .warp && r.ok && !settings.warpEndpoints.isEmpty {
                guard let endpoint = r.endpoint.flatMap(WarpEndpoint.init), settings.warpEndpoints.contains(endpoint.description) else { continue }
            }
            results[strategy.id] = r
        }
        if !strategies.contains(where: { $0.id == selectedStrategyId }) { selectedStrategyId = nil }
        settings.selectedStrategyId = selectedStrategyId
        // An older build sent strategies it couldn't perform to the daemon as plain direct
        // connections and recorded them as working. Those results (and a saved selection of such a
        // strategy) are wrong; they must not stay in the table or be picked by self-healing.
        for s in strategies where s.unsupportedReason != nil {
            results[s.id] = nil
            if selectedStrategyId == s.id {
                selectedStrategyId = nil
                settings.selectedStrategyId = nil
            }
        }
        saveResults()
    }

    private func readSources() async {
        guard let connectionLibrary else { return }
        do {
            let value = try await connectionLibrary.snapshot()
            sourceSnapshot = value
            sources = value.sources.sources
            sourceID = value.sources.selectedSourceId
        } catch {
            sourceSnapshot = nil
            sources = []
            sourceID = "unavailable"
        }
    }

    /// Configuration changes never replace a connected or in-flight pair.
    public func refreshSources() async {
        guard !busy, activeConnection == nil, state != .connected else { return }
        busy = true
        defer { busy = false; epoch += 1; notify() }
        saveResults()
        await readSources()
        reloadStrategies()
        restoreCurrentResults()
    }

    @discardableResult
    public func selectSource(_ id: String) async -> Bool {
        guard !busy, activeConnection == nil, state != .connected, let connectionLibrary else { return false }
        busy = true
        defer { busy = false; epoch += 1; notify() }
        do {
            saveResults()
            try await connectionLibrary.selectSource(id: id)
            await readSources()
            reloadStrategies()
            restoreCurrentResults()
            detail = selected.map { Msg("detail.strategy", $0.name(using: loc)) } ?? Msg("detail.noStrategy")
            return true
        } catch { return false }
    }

    /// Configuration is committed only after validation/import/refresh succeeds. No tunnel opens.
    public func configureConnection(useServer: Bool, input: String, source: String?, endpoints: [String], policy: ServerRoutingPolicy) async throws {
        guard !busy, activeConnection == nil, state != .connected, let connectionLibrary else { throw ConnectionLibraryError.busy }
        let parsed = try WarpEndpoint.parseList(endpoints.joined(separator: "\n")).map(\.description)
        if useServer { try policy.validate() }
        busy = true
        stopRequested = false
        notify()
        defer { busy = false; epoch += 1; notify() }
        let target = useServer ? try await connectionLibrary.configureServer(input: input, existingSourceID: source) : Self.warpSource
        try Task.checkCancellation()
        if cancelled { throw CancellationError() }
        saveResults()
        try await connectionLibrary.selectSource(id: target.id)
        if parsed != settings.warpEndpoints { settings.results = settings.results.filter { $0.key.contains("|") } }
        if policy != settings.serverRouting { settings.results = settings.results.filter { !$0.key.contains("|") } }
        settings.warpEndpoints = parsed
        settings.serverRouting = policy
        settingsStore.save(settings)
        await readSources()
        reloadStrategies()
        restoreCurrentResults()
        detail = selected.map { Msg("detail.strategy", $0.name(using: loc)) } ?? Msg("detail.noStrategy")
    }

    /// Installs the UI callbacks the engine may need mid-operation.
    public func setHooks(_ hooks: EngineHooks) {
        self.hooks = hooks
    }

    /// Reconciles with a tunnel the backend already has open that this engine instance didn't
    /// itself start — most concretely, the GUI crashed or was quit and relaunched while `zarpd`
    /// (a fully independent daemon) kept running. Without this, a freshly-launched engine has no
    /// way to tell "genuinely idle" apart from "a real tunnel is up, I just don't know about it
    /// yet," and would show Disconnected while traffic keeps flowing underneath — worse, a user
    /// pressing Connect in that state would open a *second* tunnel alongside the first rather than
    /// using or replacing it.
    ///
    /// A no-op if this engine already knows about an active connection (`state == .connected`) or
    /// is busy with something else — never overwrites a connection the engine itself is already
    /// tracking, and never races a scan/connect. Errors (the backend isn't reachable at all) are
    /// swallowed: this is best-effort reconciliation, not a user-facing action.
    public func adoptExistingConnection() async {
        guard !busy, state != .connected else { return }
        let asked = epoch
        guard let snapshot = try? await connections.connectionSnapshot(), let live = snapshot.live else { return }
        // An actor method that awaits can be re-entered: a connect/scan may have started (and even
        // finished) while the backend was being asked. The answer is only valid if nothing changed
        // in the meantime.
        guard epoch == asked, !busy, state != .connected else { return }
        await adopt(live)
    }

    /// Compares what the engine believes with what the backend reports and corrects the engine —
    /// the UI calls this every few seconds. This is what makes a dead tunnel stop being displayed
    /// as "Connected": the daemon tears a tunnel down when its data plane dies, and the next call
    /// here notices, returns to idle, and (if the user wants it) starts a reconnect.
    @discardableResult
    public func reconcileConnection() async -> ReconcileOutcome {
        guard !busy else { return .unchanged }
        let asked = epoch
        let snapshot: ConnectionSnapshot
        do {
            snapshot = try await connections.connectionSnapshot()
        } catch {
            // A failure that arrives after something else already happened says nothing about
            // the engine's current state.
            guard epoch == asked, !busy else { return .unchanged }
            unreachableCount += 1
            // One missed answer is a hiccup; two in a row while "connected" means the daemon
            // (and with it the tunnel) is gone — a restart closes every tunnel.
            guard state == .connected, unreachableCount >= 2 else { return .daemonUnreachable }
            await connectionLost(reason: loc.string("err.daemonGone"), closeHandle: false)
            return .lost(nil)
        }
        // A snapshot taken before a connect/scan/disconnect that has since run is stale — even if
        // that operation already finished (busy is false again).
        guard epoch == asked, !busy else { return .unchanged }
        unreachableCount = 0

        switch (state, snapshot.live) {
        case (.connected, .some(let live)):
            if live.handle.id != activeConnection?.id {
                await adopt(live)
                return .adopted
            }
            return .unchanged
        case (.connected, .none):
            let reason = snapshot.lastLoss?.reason
            await connectionLost(reason: reason ?? loc.string("err.unknownLoss"), closeHandle: false)
            return .lost(reason)
        case (.idle, .some(let live)):
            await adopt(live)
            return .adopted
        default:
            return .unchanged
        }
    }

    public func reloadStrategies() {
        strategyStore.writeTemplateIfMissing()
        let base = StrategyCatalog.load(customText: strategyStore.loadText()) { [log, loc] line in
            log.write(loc.string("log.customSkipped", [CustomStrategyFile.fileName, line]))
        }
        if mode == .warp { strategies = base; return }
        guard let library = sourceSnapshot?.library(sourceId: sourceID) else { strategies = []; return }
        let profiles: [ServerProfile]
        switch library.selection {
        case .automatic: profiles = library.profiles
        case .available(let profile): profiles = [profile]
        case .unavailable: profiles = []
        }
        strategies = ServerPairs.build(strategies: base, profiles: profiles, sourceID: sourceID)
    }

    /// The user's `strategies.txt` as it is now (the template, if it didn't exist yet).
    public func customStrategiesText() -> String {
        strategyStore.writeTemplateIfMissing()
        return strategyStore.loadText()
    }

    /// Saves the in-app editor's text to `strategies.txt` and reloads the list. Returns the lines
    /// that were skipped as malformed (so the editor can tell the user right away); throws if the
    /// file couldn't be written.
    @discardableResult
    public func saveCustomStrategies(_ text: String) throws -> [String] {
        try strategyStore.saveText(text)
        var skipped: [String] = []
        _ = CustomStrategyFile.parse(text) { skipped.append($0) }
        reloadStrategies()
        // A custom strategy that was removed or renamed no longer has a meaningful result.
        let known = Set(strategies.map(\.id))
        results = results.filter { known.contains($0.key) }
        if let id = selectedStrategyId, !known.contains(id) {
            selectedStrategyId = nil
            settings.selectedStrategyId = nil
        }
        saveResults()
        notify()
        return skipped
    }

    public var selected: Strategy? { eligibleStrategies.first { $0.id == selectedStrategyId } }
    public var eligibleStrategies: [Strategy] {
        strategies.filter { StrategyFilter.matches($0, value: settings.strategyCountries) }
    }

    // API reachability is separate from tunnel confirmation. Only portable TLS
    // strategies can protect the fixed HTTPS registration origin.
    private var registrationStrategies: [Strategy] {
        let selectedID = settings.sourceSelections[Self.warpSource.id] ?? settings.selectedStrategyId
        let endpoints = settings.warpEndpoints.isEmpty ? nil : Strategy.fingerprint(["warp-endpoints-v1"] + settings.warpEndpoints)
        return Array(StrategyCatalog.load(customText: strategyStore.loadText()).enumerated()
            .filter { _, s in
                s.mode == .warp && s.transport == .masqueH2 && s.unsupportedReason == nil && s.warpTLSName == nil &&
                s.plan.tcpDesync != nil && StrategyFilter.matches(s, value: settings.strategyCountries)
            }
            .sorted { lhs, rhs in
                func rank(_ s: Strategy) -> Int {
                    if s.id == selectedID { return 0 }
                    if let saved = mode == .warp ? results[s.id] : settings.results[s.id],
                       saved.ok && saved.confirmed && saved.configurationFingerprint == s.configurationFingerprint &&
                       saved.endpointListFingerprint == endpoints { return 1 }
                    return 2
                }
                let l = rank(lhs.element), r = rank(rhs.element)
                return l == r ? lhs.offset < rhs.offset : l < r
            }.prefix(32).map(\.element))
    }
    public var isBusy: Bool { busy }
    /// Quick Scan stops after this many working strategies (Windows `Engine.QuickStopAfter`).
    public var quickStopAfter: Int { max(1, settings.stopAfterWorking) }
    public var currentSettings: AppSettings { settings }

    /// A consistent view of everything the UI displays.
    public func snapshot() -> EngineSnapshot {
        EngineSnapshot(state: state, detail: detail, progressDone: progressDone, progressTotal: progressTotal,
                       strategies: eligibleStrategies, results: results, selectedStrategyId: selectedStrategyId, isBusy: busy,
                       sources: sources, sourceID: sourceID, mode: activeConnection?.mode ?? mode)
    }

    /// `new` comes from the UI's own `AppSettings` snapshot, which only ever changes user
    /// preference fields — so the scan state (`results`, `selectedStrategyId`) is taken from the
    /// engine's own live values rather than accepted from `new`. Otherwise any Settings-screen
    /// toggle after a scan would silently roll discovered/verified strategy state back to whatever
    /// it was when the UI last saw it, even though nothing scan- or connection-related was being
    /// changed. Likewise the saved acceptance of Cloudflare's terms is never un-set by a stale copy.
    public func updateSettings(_ new: AppSettings) {
        guard !busy || (new.warpEndpoints == settings.warpEndpoints && new.strategyCountries == settings.strategyCountries && new.serverRouting == settings.serverRouting) else { return }
        if new.warpEndpoints != settings.warpEndpoints {
            guard let endpoints = try? WarpEndpoint.parseList(new.warpEndpoints.joined(separator: "\n")),
                  endpoints.map(\.description) == new.warpEndpoints else { return }
            settings.results = settings.results.filter { $0.key.contains("|") }
            if mode == .warp { results.removeAll() }
        }
        if new.serverRouting != settings.serverRouting {
            settings.results = settings.results.filter { !$0.key.contains("|") }
            if mode == .server { results.removeAll() }
        }
        saveResults()
        var merged = new.normalized()
        merged.results = settings.results
        merged.sourceSelections = settings.sourceSelections
        merged.selectedStrategyId = selectedStrategyId
        merged.warpTermsAccepted = new.warpTermsAccepted || settings.warpTermsAccepted
        settings = merged
        settingsStore.save(settings)
        notify()
    }

    /// Registers the change callback (Windows `Engine.Changed`), replacing any previous one. A
    /// method rather than exposing `onChanged` for direct cross-actor assignment, so callers have
    /// one unambiguous `await engine.setOnChanged { ... }` call site.
    public func setOnChanged(_ callback: @escaping @Sendable () -> Void) {
        onChanged = callback
    }

    // MARK: - Top-level actions (each returns `false` if the engine was already busy)

    /// Main button: connect with the saved strategy, fall back to other confirmed strategies, then
    /// to a Quick Scan — same order as Windows `Engine.ConnectAsync`.
    @discardableResult
    public func connect() -> Bool {
        run { [self] in
            guard await prepare() else { return }
            if let s = await selected {
                switch await apply(s) {
                case .connected: return
                case .cancelled: await cancelledExit(); return
                case .failed: break
                }
                if await searchAfterNetworkChange() { return }
                await markFailed(s)
                let others = await confirmedStrategies(except: s)
                if !others.isEmpty {
                    log.write(loc.string("log.savedFailed", [s.name(using: loc)]))
                    switch await applyFirstWorking(others) {
                    case .connected: return
                    case .cancelled: await cancelledExit(); return
                    case .failed: break
                    }
                }
                if await searchAfterNetworkChange() { return }
                log.write(loc.string("log.verifiedFailed"))
            }
            let list = await eligibleStrategies.filter(\.requiresDesync)
            let others = await confirmedStrategies(except: nil)
            if !others.isEmpty {
                switch await applyFirstWorking(others) {
                case .connected: return
                case .cancelled: await cancelledExit(); return
                case .failed: break
                }
            }
            if await searchAfterNetworkChange() { return }
            await searchAndApply(list, stopAfter: quickStopAfter,
                                  title: loc.string("log.searchQuick", [String(list.count), String(quickStopAfter)]))
        }
    }

    /// Quick Scan stops after `quickStopAfter` working strategies; Full Scan tests all of them —
    /// same as Windows `Engine.SearchAsync`.
    @discardableResult
    public func search(full: Bool) -> Bool {
        run { [self] in
            guard await prepare() else { return }
            let list = await eligibleStrategies.filter(\.requiresDesync)
            if full {
                await searchAndApply(list, stopAfter: 0, title: loc.string("log.searchFull", [String(list.count)]))
            } else {
                await searchAndApply(list, stopAfter: quickStopAfter,
                                      title: loc.string("log.searchQuick", [String(list.count), String(quickStopAfter)]))
            }
        }
    }

    /// Tests only the given strategies, all of them, no early stop (Windows `Engine.TestStrategiesAsync`).
    @discardableResult
    public func testStrategies(_ only: [Strategy]) -> Bool {
        let ids = Set(only.map(\.id))
        let list = eligibleStrategies.filter { ids.contains($0.id) }
        guard !list.isEmpty else { return false }
        return run { [self] in
            guard await prepare() else { return }
            let current = await eligibleStrategies.filter { candidate in list.contains { $0.id == candidate.id && $0.configurationFingerprint == candidate.configurationFingerprint } }
            await searchAndApply(current, stopAfter: 0, title: loc.string("log.searchSelected", [String(current.count)]))
        }
    }

    /// Connects with a specific strategy and remembers it (Windows `Engine.UseStrategyAsync`).
    @discardableResult
    public func use(_ strategy: Strategy) -> Bool {
        guard let current = eligibleStrategies.first(where: { $0.id == strategy.id }) else { return false }
        let strategy = current
        return run { [self] in
            guard await prepare() else { return }
            switch await apply(strategy) {
            case .connected: await saveSelected(strategy)
            case .cancelled: await cancelledExit()
            case .failed:
                if await networkChanged, await prepare(resetRecovery: false) {
                    if case .connected = await apply(strategy) { await saveSelected(strategy) }
                }
            }
        }
    }

    @discardableResult
    public func disconnect() -> Bool {
        run { [self] in
            await resetRecoveryState()
            await setState(.disconnecting, Msg("detail.disconnecting"))
            await stopAll()
            await setState(.idle, Msg("detail.disconnected"))
        }
    }

    /// Cancels the running operation, if any. Honored everywhere: loop bodies check it between
    /// steps, and real Swift task cancellation reaches whatever `connections.open`/`probe.measure`
    /// are waiting on. Whatever the operation had opened is torn down and the engine ends up idle
    /// with "Cancelled".
    public func cancel() {
        stopRequested = true
        runningTask?.cancel()
        accountTask?.cancel()
    }

    /// Waits for the current operation, if any, to finish. Windows Zarp waits the same way before
    /// quitting (`Engine.FinishShutdownAsync`'s `_busy.WaitAsync()`), so a shutdown never races a
    /// scan that's mid-flight; returns immediately if nothing is running.
    public func waitUntilIdle() async {
        await runningTask?.value
        _ = try? await accountTask?.value
    }

    public func readWarpAccount() async throws -> WarpAccountStatus {
        try await accountOperation(license: nil)
    }

    public func applyWarpLicense(_ value: String) async throws -> WarpAccountStatus {
        let key = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard WarpLicense.isValid(key) else { throw WarpConnectionError("invalid WARP+ license format", code: "bad_request") }
        return try await accountOperation(license: key)
    }

    private func accountOperation(license: String?) async throws -> WarpAccountStatus {
        guard !busy else { throw WarpConnectionError("another operation is in progress", code: "busy") }
        guard let provider = connections as? any WarpAccountProvider else {
            throw WarpConnectionError("WARP+ is unavailable in this provider", code: "unsupported")
        }
        try Task.checkCancellation()
        busy = true
        epoch += 1
        let task = Task { try await self.performAccountOperation(provider: provider, license: license) }
        accountTask = task
        notify()
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }

    private func performAccountOperation(provider: any WarpAccountProvider, license: String?) async throws -> WarpAccountStatus {
        defer { accountTask = nil; busy = false; epoch += 1; notify() }
        // Account management deliberately skips prepare(): it must not close the
        // active tunnel, reset a strategy or change routes while applying a key.
        if !(try await connections.isAccountRegistered()) {
            guard license != nil else { throw WarpConnectionError("WARP account is not registered", code: "no_account") }
            let accepted: Bool
            if settings.warpTermsAccepted { accepted = true }
            else { accepted = await hooks.askAcceptWarpTerms?() ?? false }
            try Task.checkCancellation()
            guard accepted else { throw WarpConnectionError("WARP terms were not accepted", code: "cancelled") }
            if !(connections is any WarpAccountSetupProvider) { try await connections.registerAccount() }
            settings.warpTermsAccepted = true
            settingsStore.save(settings)
        }
        try Task.checkCancellation()
        if let setup = connections as? any WarpAccountSetupProvider {
            let candidates = activeConnection == nil ? registrationStrategies : []
            if let license { return try await setup.applyWarpLicense(license, strategies: candidates) }
            return try await setup.readWarpAccount(strategies: candidates)
        }
        if let license { return try await provider.applyWarpLicense(license) }
        return try await provider.readWarpAccount()
    }

    // MARK: - Task orchestration

    /// Runs `body` if nothing else is running; returns whether it started. Matches the
    /// "one operation at a time" rule from Windows `Engine.Run` (`SemaphoreSlim(1,1)`) and Android
    /// `ZarpEngine.launchOp` (`Mutex.tryLock`).
    private func run(_ body: @escaping @Sendable () async -> Void) -> Bool {
        guard !busy else { return false }
        busy = true
        epoch += 1
        stopRequested = false
        runningTask = Task { [weak self] in
            await body()
            await self?.finishRun()
        }
        return true
    }

    private func finishRun() {
        progressTotal = 0
        progressDone = 0
        busy = false
        epoch += 1
        runningTask = nil
        notify()
    }

    /// True once the user asked to stop — through `cancel()` or through Swift task cancellation.
    private var cancelled: Bool { stopRequested || Task.isCancelled }

    private func notify() { onChanged?() }

    private func setState(_ s: EngineState, _ d: Msg? = nil) {
        epoch += 1
        state = s
        if let d { detail = d }
        notify()
    }

    private func setProgress(_ done: Int, _ total: Int) {
        progressDone = done
        progressTotal = total
        notify()
    }

    /// The common ending of a cancelled operation (Windows `Run`'s `OperationCanceledException`
    /// handler): close whatever is open, say so, and go idle.
    private func cancelledExit() async {
        await stopAll()
        log.write(loc.string("log.cancelled"))
        setState(.idle, Msg("detail.cancelled"))
    }

    // MARK: - Steps

    /// Checks everything a scan or connect depends on before it starts, and answers `false` — with
    /// the engine back to idle and a reason on screen — if it can't go ahead.
    private func prepare(resetRecovery: Bool = true) async -> Bool {
        if resetRecovery { recovery = nil; reconnectCycles.removeAll() }
        updateNetworkIdentity(network.connectionPathIdentity())
        networkChanged = false
        setState(.preparing, Msg("detail.preparing"))
        if mode == .server {
            guard (try? settings.serverRouting.validate()) != nil else {
                setState(.idle, Msg("routing.invalid")); return false
            }
            if settings.serverRouting.filtersApplications && !settings.routeAllTraffic {
                setState(.idle, Msg("routing.fullTunnelRequired")); return false
            }
        }
        if mode == .warp, (try? WarpEndpoint.parseList(settings.warpEndpoints.joined(separator: "\n")))?.map(\.description) != settings.warpEndpoints {
            setState(.idle, Msg("err.endpointList", "0"))
            return false
        }

        // Scans measure through a tunnel of their own, and only one tunnel can exist: whatever is
        // open — the connection this engine holds, or one the daemon still has from a previous
        // session — has to go first (Windows `TestAsync` also starts with a disconnect). Doing it
        // before the VPN check also keeps Zarp's own tunnel from being reported as a foreign VPN.
        await stopAll()
        if let snapshot = try? await connections.connectionSnapshot(), let live = snapshot.live {
            await live.handle.close()
        }
        if cancelled { await cancelledExit(); return false }

        let destinations: [String]
        if mode == .server {
            destinations = Array(Set(eligibleStrategies.compactMap { $0.serverProfile?.host })).sorted()
        } else {
            destinations = settings.warpEndpoints.isEmpty
                ? ["162.159.198.1", "162.159.197.1", "2606:4700:103::1"]
                : settings.warpEndpoints.compactMap(WarpEndpoint.init).map { $0.address.description }
        }
        let foreign = network.foreignVPNInterfaceNames(destinations: destinations + ["api.cloudflareclient.com"])
        if !foreign.isEmpty {
            for name in foreign { log.write(loc.string("log.otherVpn", [name])) }
            log.write(loc.string("log.vpnAdvice"))
            setState(.idle, Msg("detail.vpnOff"))
            return false
        }

        if mode == .server {
            do {
                if let outcome = try await connectionLibrary?.refreshIfNeeded(sourceId: sourceID), case .cached = outcome {
                    log.write(loc.string("sources.cached"))
                }
                let expectedSource = sourceID
                await readSources()
                guard sourceID == expectedSource, mode == .server else {
                    setState(.idle, Msg("sources.unavailable")); return false
                }
                reloadStrategies()
                restoreCurrentResults()
                guard !eligibleStrategies.isEmpty else { setState(.idle, Msg("sources.unavailable")); return false }
                if cancelled { await cancelledExit(); return false }
                return true
            } catch {
                if cancelled { await cancelledExit(); return false }
                setState(.idle, Msg("sources.refreshFailed"))
                return false
            }
        }
        do {
            if !(try await connections.isAccountRegistered()) {
                // Nothing registers with Cloudflare until the user has accepted its terms.
                let accepted: Bool
                if settings.warpTermsAccepted {
                    accepted = true
                } else if let ask = hooks.askAcceptWarpTerms {
                    accepted = await ask()
                } else {
                    accepted = false
                }
                guard accepted else {
                    setState(.idle, Msg("detail.termsDeclined"))
                    return false
                }
                settings.warpTermsAccepted = true
                settingsStore.save(settings)
                log.write(loc.string("log.warpRegistering"))
                setState(.preparing, Msg("detail.registering"))
                do {
                    if let setup = connections as? any WarpAccountSetupProvider {
                        try await setup.registerAccount(strategies: registrationStrategies)
                    } else { try await connections.registerAccount() }
                } catch {
                    log.write(loc.string("log.warpRegisterFailed", [describe(error)]))
                    setState(.idle, Msg("detail.registerFailed"))
                    return false
                }
                settings.warpTermsAccepted = true
                settingsStore.save(settings)
                log.write(loc.string("log.warpRegistered"))
            }
        } catch {
            // The backend itself couldn't be asked (not installed, not running).
            log.write(loc.string("log.error", [describe(error)]))
            setState(.idle, Msg("detail.error", describe(error)))
            return false
        }
        if cancelled { await cancelledExit(); return false }
        return true
    }

    private enum TestOutcome {
        case result(TestResult)
        case cancelled
    }

    private struct PathChanged: Error {}

    private func updateNetworkIdentity(_ value: String?) {
        guard value != networkIdentity else { return }
        networkIdentity = value
        restoreCurrentResults()
        notify()
    }

    /// Called by the heartbeat. A scan checks its own path at every traffic phase.
    public func observeNetworkChange() async {
        guard !busy else { return }
        let value = network.connectionPathIdentity()
        guard value != networkIdentity else { return }
        updateNetworkIdentity(value)
        log.write(loc.string("log.networkChanged"))
        if state == .connected {
            await connectionLost(reason: loc.string("log.networkChanged"), closeHandle: true)
        }
    }

    private func verifyTraffic(_ handle: any WarpConnectionHandle, samples: Int, followUps: Int) async throws -> WarpMeasurement {
        let path = networkIdentity
        let initial = try await probe.measure(connection: handle, samples: samples)
        try validateTrafficPath(path)
        guard case .ok = initial else { return initial }
        for _ in 0..<followUps {
            try await timing.sleep(2)
            try validateTrafficPath(path)
            let next = try await probe.measure(connection: handle, samples: 1)
            try validateTrafficPath(path)
            guard case .ok = next else { return next }
        }
        return initial
    }

    private func validateTrafficPath(_ path: String?) throws {
        if cancelled { throw CancellationError() }
        let current = network.connectionPathIdentity()
        guard current == path else {
            updateNetworkIdentity(current)
            networkChanged = true
            throw PathChanged()
        }
    }

    private func restartChangedSearch(_ list: [Strategy], stopAfter: Int, title: String, remaining: Int) async {
        await stopAll()
        guard remaining > 0, !cancelled else {
            if cancelled { await cancelledExit() }
            else { setState(.idle, Msg("detail.networkChanged")) }
            return
        }
        log.write(loc.string("log.networkChanged"))
        guard await prepare(resetRecovery: false) else { return }
        let ids = Set(list.map(\.id))
        await searchAndApply(eligibleStrategies.filter { ids.contains($0.id) }, stopAfter: stopAfter, title: title, networkRestarts: remaining - 1)
    }

    private func searchAfterNetworkChange() async -> Bool {
        guard networkChanged else { return false }
        let list = eligibleStrategies.filter(\.requiresDesync)
        await restartChangedSearch(list, stopAfter: quickStopAfter,
            title: loc.string("log.searchQuick", [String(list.count), String(quickStopAfter)]), remaining: 1)
        return true
    }

    /// Tests one strategy on a fresh WARP endpoint so it cannot inherit DPI state from a previous
    /// successful connection (Windows `Engine.TestAsync`, Android `ZarpEngine.test`).
    private func test(_ s: Strategy, avoiding previousEndpoint: String? = nil) async -> TestOutcome {
        let path = networkIdentity
        // A strategy this port can't perform is a failed test, instantly and without touching the
        // network — never a connection that silently runs without its technique and "passes".
        if let reason = s.unsupportedReason {
            return .result(.failed(strategyId: s.id, error: reason))
        }
        // (No tunnel can be open here: prepare() closed whatever was, and every test closes its own
        // connection — so a throwaway test always starts from a clean slate.)
        let endpoint = s.mode == .warp ? nextTestEndpoint(avoiding: previousEndpoint) : nil
        let handle: WarpConnectionHandle
        do {
            handle = try await connections.open(strategy: s, endpoint: endpoint, timeoutMs: settings.testTimeoutSec * 1000,
                                                 persistent: false, routing: .testRouteOnly)
        } catch let error as WarpConnectionError {
            if error.isCancelled || cancelled { return .cancelled }
            try? validateTrafficPath(path)
            logConnectionFailure(error)
            let failedEndpoint = error.connection?.endpoint ?? endpoint
            return error.timedOut
                ? .result(.failed(strategyId: s.id, error: Msg("err.timeout", String(settings.testTimeoutSec)), endpoint: failedEndpoint))
                : .result(.failedRaw(strategyId: s.id, error: describe(error), endpoint: failedEndpoint))
        } catch {
            if cancelled || error is CancellationError { return .cancelled }
            try? validateTrafficPath(path)
            return .result(.failedRaw(strategyId: s.id, error: String(describing: error), endpoint: endpoint))
        }

        if cancelled {
            await handle.close()
            return .cancelled
        }

        let result: TestResult
        do {
            switch try await verifyTraffic(handle, samples: 3, followUps: 1) {
            case .ok(let pingMs, _):
                result = TestResult(strategyId: s.id, ok: true, connectMs: handle.connectMs, pingMs: pingMs, endpoint: handle.endpoint)
            case .notWarp(let warp):
                // Windows doesn't distinguish "connected but not WARP" from "no traffic at all";
                // this port keeps that one user-facing message and records the raw detail for diagnostics.
                var r = TestResult.failed(strategyId: s.id, error: Msg("err.noTraffic"), endpoint: handle.endpoint)
                r.error = "warp=\(warp ?? "?")"
                result = r
            case .noTraffic(let lastError):
                var r = TestResult.failed(strategyId: s.id, error: Msg("err.noTraffic"), endpoint: handle.endpoint)
                r.error = lastError
                result = r
            }
        } catch {
            await handle.close()
            if cancelled || error is CancellationError || (error as? WarpConnectionError)?.isCancelled == true { return .cancelled }
            try? validateTrafficPath(path)
            logConnectionFailure(error)
            return .result(.failedRaw(strategyId: s.id, error: describe(error), endpoint: handle.endpoint))
        }
        await handle.close()
        var verified = result
        verified.networkIdentity = networkIdentity
        return .result(verified)
    }

    /// Stops after N confirmations or list exhaustion. Cancel during either attempt preserves
    /// the previous completed result for this candidate.
    private func searchAndApply(_ list: [Strategy], stopAfter: Int, title: String, networkRestarts: Int = 1,
                                restartScope: [Strategy]? = nil) async {
        let list = list.filter(\.requiresDesync)
        let networkScope = restartScope ?? list
        log.write(title)
        setProgress(0, list.count)
        var confirmedCount = 0
        var initialSuccesses = 0
        var testedIds = Set<String>()
        for (index, strategy) in list.enumerated() {
            if cancelled { break }
            setState(.searching, Msg("detail.testing", String(index + 1), String(list.count), strategy.name(using: loc)))
            guard case .result(var first) = await test(strategy) else { break }
            if networkChanged { break }
            first.networkIdentity = networkIdentity
            first.configurationFingerprint = strategy.configurationFingerprint
            first.endpointListFingerprint = endpointListFingerprint
            var completed = first
            if first.ok {
                initialSuccesses += 1
                log.write(loc.string("log.recheck", ["1"]))
                setState(.searching, Msg("detail.rechecking", String(index + 1), String(list.count), strategy.name(using: loc)))
                guard case .result(var second) = await test(strategy, avoiding: first.endpoint) else { break }
                if networkChanged { break }
                second.networkIdentity = networkIdentity
                second.configurationFingerprint = strategy.configurationFingerprint
                second.endpointListFingerprint = endpointListFingerprint
                if second.ok {
                    completed = TestResult.confirmed(first, second)
                    if completed.confirmed { confirmedCount += 1 }
                    log.write("  " + loc.string("log.recheckOk", [strategy.name(using: loc), String(second.connectMs), String(second.pingMs)]))
                } else {
                    completed = second
                    completed.rechecked = true
                    completed.firstEndpoint = first.endpoint
                }
            }
            if cancelled { break }
            putResult(completed)
            testedIds.insert(strategy.id)
            saveResults()
            setProgress(index + 1, list.count)
            log.write("  " + (completed.ok
                ? loc.string("log.testOk", [strategy.name(using: loc), String(completed.connectMs), String(completed.pingMs)])
                : loc.string("log.testFail", [strategy.name(using: loc), completed.displayError(using: loc)])))
            if stopAfter > 0 && confirmedCount >= stopAfter { break }
        }
        if cancelled { await cancelledExit(); return }
        if networkChanged {
            await restartChangedSearch(networkScope, stopAfter: stopAfter, title: title, remaining: networkRestarts)
            return
        }
        // Selected tests may only apply their own completed candidates. Hidden or previously
        // confirmed candidates outside this operation must not change its outcome.
        let confirmed = confirmedStrategies(except: nil).filter { testedIds.contains($0.id) }
        guard !confirmed.isEmpty else {
            await stopAll()
            log.write(initialSuccesses == 0 ? loc.string("log.noneWorked", [CustomStrategyFile.fileName]) : loc.string("log.candidatesFailed"))
            setState(.idle, Msg("detail.notFound"))
            return
        }
        setProgress(0, 0)
        let best = confirmed[0]
        if let br = results[best.id] {
            log.write(loc.string("log.best", [best.name(using: loc), String(br.connectMs), String(br.pingMs)]))
        }
        switch await applyFirstWorking(confirmed) {
        case .connected: break
        case .cancelled: await cancelledExit()
        case .failed:
            if networkChanged {
                await restartChangedSearch(networkScope, stopAfter: stopAfter, title: title, remaining: networkRestarts)
            } else {
                let remaining = list.filter { !testedIds.contains($0.id) }
                if stopAfter > 0 && !remaining.isEmpty {
                    await searchAndApply(remaining, stopAfter: stopAfter, title: title,
                                         networkRestarts: networkRestarts, restartScope: networkScope)
                } else { setState(.idle, Msg("detail.foundButFailed")) }
            }
        }
    }

    /// Confirmed strategies, best (lowest score) first (Windows `Engine.ConfirmedStrategies`).
    public func confirmedStrategies(except: Strategy?) -> [Strategy] {
        eligibleStrategies
            .filter { $0.unsupportedReason == nil && $0.requiresDesync && results[$0.id]?.configurationFingerprint == $0.configurationFingerprint && results[$0.id]?.endpointListFingerprint == endpointListFingerprint && $0.id != except?.id && (results[$0.id]?.ok ?? false) && (results[$0.id]?.confirmed ?? false) && results[$0.id]?.networkIdentity == networkIdentity }
            .sorted { results[$0.id]!.score < results[$1.id]!.score }
    }

    private enum ApplyOutcome {
        case connected
        case failed
        case cancelled
    }

    /// Connects with the first strategy in the list that actually connects, and remembers it
    /// (Windows `Engine.ApplyFirstWorkingAsync`).
    private func applyFirstWorking(_ ordered: [Strategy]) async -> ApplyOutcome {
        for s in ordered {
            if cancelled { return .cancelled }
            switch await apply(s) {
            case .connected:
                await saveSelected(s)
                return .connected
            case .cancelled:
                return .cancelled
            case .failed:
                if networkChanged { return .failed }
                await markFailed(s)
                log.write(loc.string("log.tryNext", [s.name(using: loc)]))
            }
        }
        return .failed
    }

    private func markFailed(_ s: Strategy) async {
        putResult(.failed(strategyId: s.id, error: Msg("result.applyFailed")))
        saveResults()
    }

    /// What a persistent connection should carry, from the user's settings.
    private var routing: TunnelRouting {
        TunnelRouting(routeAll: settings.routeAllTraffic, overrideDNS: settings.overrideDNS,
                      serverPolicy: mode == .server && !settings.serverRouting.isDefault ? settings.serverRouting : nil)
    }

    private func connectedDetail(_ name: String, routeAll: Bool) -> Msg {
        Msg(routeAll ? "detail.strategy" : "detail.strategyTestRoute", name)
    }

    /// Connects with the given strategy and keeps the connection (Windows `Engine.ApplyAsync`).
    /// Does not record a failure in `results` — whether a failed apply should count against the
    /// strategy is the caller's decision (an automatic reconnect after a network blip must not).
    private func apply(_ s: Strategy) async -> ApplyOutcome {
        let path = networkIdentity
        guard eligibleStrategies.contains(where: { $0.id == s.id && $0.configurationFingerprint == s.configurationFingerprint }) else { return .failed }
        setState(.connecting, Msg("detail.connectingTo", s.name(using: loc)))
        log.write(loc.string("log.connectingWith", [s.name(using: loc)]))
        await stopAll()
        if cancelled { return .cancelled }

        if let reason = s.unsupportedReason {
            log.write(loc.string("log.unsupportedStrategy", [s.name(using: loc), reason.text(using: loc)]))
            setState(.idle, Msg("detail.unsupported"))
            return .failed
        }

        let timeoutMs = max(30, settings.testTimeoutSec * 2) * 1000
        var opened: WarpConnectionHandle?
        do {
            let handle = try await connections.open(strategy: s, endpoint: persistentEndpoint(for: s), timeoutMs: timeoutMs, persistent: true, routing: routing)
            opened = handle
            for warning in handle.warnings { log.write("zarpd: " + warning) }
            if cancelled {
                await handle.close()
                return .cancelled
            }
            setState(.connecting, Msg("detail.verifying"))
            switch try await verifyTraffic(handle, samples: 1, followUps: 2) {
            case .ok:
                activeConnection = handle
                connectedAt = timing.now()
                unreachableCount = 0
                log.write(loc.string("log.warpConnectedIn", [String(handle.connectMs)]))
                setState(.connected, connectedDetail(s.name(using: loc), routeAll: routing.routeAll))
                return .connected
            case .notWarp, .noTraffic:
                await handle.close()
                log.write(loc.string("err.noTraffic"))
            }
        } catch {
            // Reached when the connection came up but measuring it threw (the backend went away
            // mid-call): the connection must not be left behind with nobody holding its handle —
            // it would keep its routes, and block every later connect, until the daemon restarted.
            if let handle = opened { await handle.close() }
            if cancelled || error is CancellationError || (error as? WarpConnectionError)?.isCancelled == true { return .cancelled }
            try? validateTrafficPath(path)
            logConnectionFailure(error)
            log.write(loc.string("log.warpNotConnected"))
            log.write(describe(error))
        }
        setState(.idle, Msg("detail.connectFailed"))
        return .failed
    }

    private func stopAll() async {
        connectedAt = nil
        if let c = activeConnection {
            activeConnection = nil
            await c.close()
        }
    }

    // MARK: - Reconciliation helpers

    private func adopt(_ live: LiveConnectionStatus) async {
        let liveSource = live.handle.mode == .warp ? Self.warpSource.id : (live.sourceID ?? "unavailable")
        if liveSource != sourceID {
            saveResults()
            if let connectionLibrary, sources.contains(where: { $0.id == liveSource }) {
                try? await connectionLibrary.selectSource(id: liveSource)
                await readSources()
            }
            sourceID = liveSource
            reloadStrategies()
            restoreCurrentResults()
        }
        activeConnection = live.handle
        connectedAt = timing.now()
        selectedStrategyId = nil
        if let strategyId = live.strategyId, let match = strategies.first(where: { $0.id == strategyId }) {
            selectedStrategyId = strategyId
            await saveSelected(match)
            setState(.connected, connectedDetail(match.name(using: loc), routeAll: live.routeAll))
        } else {
            setState(.connected, connectedDetail(live.strategyId ?? "?", routeAll: live.routeAll))
        }
    }

    /// The tunnel the engine believed in is gone: say so, go idle, and — if the user wants — start
    /// a quiet reconnect.
    private func connectionLost(reason: String, closeHandle: Bool) async {
        let handle = activeConnection
        activeConnection = nil
        if closeHandle, let handle { await handle.close() }
        log.write(loc.string("log.connectionLost", [reason]))
        setState(.idle, Msg("detail.connectionLost"))
        scheduleReconnect()
    }

    /// Short successful connections remain in the same bounded recovery episode.
    /// Alternatives are verified with the same outer-strategy and traffic path.
    private func scheduleReconnect() {
        guard settings.reconnectOnLoss, let strategy = selected, strategy.unsupportedReason == nil else { return }
        let now = timing.now()
        if let connectedAt, now.timeIntervalSince(connectedAt) >= Self.stableConnectionLifetime { recovery = nil }
        connectedAt = nil
        if recovery?.sourceID != sourceID { recovery = nil }
        if recovery == nil {
            reconnectCycles = reconnectCycles.filter { now.timeIntervalSince($0) < Self.reconnectWindow }
            guard reconnectCycles.count < Self.reconnectCyclesPerWindow else {
                log.write(loc.string("log.reconnectGiveUp")); return
            }
            reconnectCycles.append(now)
            recovery = RecoveryEpisode(primary: strategy, sourceID: sourceID, startedAt: now)
        }
        guard var episode = recovery, !episode.exhausted else {
            log.write(loc.string("log.reconnectGiveUp")); return
        }
        episode.losses[strategy.id, default: 0] += 1
        recovery = episode
        if (strategy.id != episode.primary.id || episode.losses[strategy.id, default: 0] >= 2),
           results[strategy.id] != nil {
            putResult(.failed(strategyId: strategy.id, error: Msg("result.unstable")))
            saveResults()
        }
        _ = run { [self] in await recoverConnection() }
    }

    private func recoverConnection() async {
        guard let episode = recovery else { return }
        let primary = episode.primary
        if episode.losses[primary.id, default: 0] < 2 {
            while let current = recovery, current.attempts < Self.reconnectAttemptsPerCycle {
                let attempt = current.attempts + 1
                recovery?.attempts = attempt
                log.write(loc.string("log.reconnecting", [String(attempt), String(Self.reconnectAttemptsPerCycle), primary.name(using: loc)]))
                guard await waitForRecovery(attempt: attempt) else { return }
                guard await prepare(resetRecovery: false) else { recovery?.exhausted = true; return }
                switch await apply(primary) {
                case .connected: return
                case .cancelled: await cancelledExit(); return
                case .failed: break
                }
            }
        }
        log.write(loc.string("log.recoveryAlternatives"))
        let indexed = eligibleStrategies.enumerated().filter { _, strategy in
            strategy.id != primary.id && strategy.unsupportedReason == nil && strategy.requiresDesync
        }
        let candidates = indexed.sorted { lhs, rhs in
            let leftDifferent = lhs.element.transport != primary.transport
            let rightDifferent = rhs.element.transport != primary.transport
            if leftDifferent != rightDifferent { return leftDifferent }
            let leftScore = results[lhs.element.id]?.confirmed == true ? results[lhs.element.id]!.score : Int.max
            let rightScore = results[rhs.element.id]?.confirmed == true ? results[rhs.element.id]!.score : Int.max
            return leftScore == rightScore ? lhs.offset < rhs.offset : leftScore < rightScore
        }.map(\.element)
        for strategy in candidates {
            guard let current = recovery, current.alternatives.count < Self.maxRecoveryAlternatives else { break }
            if current.alternatives.contains(strategy.id) { continue }
            recovery?.alternatives.insert(strategy.id)
            let attempt = current.attempts + current.alternatives.count + 1
            guard await waitForRecovery(attempt: attempt) else { return }
            guard await prepare(resetRecovery: false) else { recovery?.exhausted = true; return }
            log.write(loc.string("log.recoveryCandidate", [strategy.name(using: loc)]))
            guard case .result(var first) = await test(strategy), !cancelled else { await cancelledExit(); return }
            if networkChanged || !first.ok { continue }
            first.configurationFingerprint = strategy.configurationFingerprint
            first.endpointListFingerprint = endpointListFingerprint
            first.networkIdentity = networkIdentity
            guard case .result(var second) = await test(strategy, avoiding: first.endpoint), !cancelled else { await cancelledExit(); return }
            if networkChanged || !second.ok { continue }
            second.configurationFingerprint = strategy.configurationFingerprint
            second.endpointListFingerprint = endpointListFingerprint
            second.networkIdentity = networkIdentity
            let confirmed = TestResult.confirmed(first, second)
            guard confirmed.confirmed else { continue }
            putResult(confirmed)
            saveResults()
            switch await apply(strategy) {
            case .connected: await saveSelected(strategy); return
            case .cancelled: await cancelledExit(); return
            case .failed: break
            }
        }
        recovery?.exhausted = true
        log.write(loc.string("log.reconnectGiveUp"))
        setState(.idle, Msg("detail.connectFailed"))
    }

    private func waitForRecovery(attempt: Int) async -> Bool {
        guard let recovery, timing.now().timeIntervalSince(recovery.startedAt) < 180 else {
            self.recovery?.exhausted = true
            log.write(loc.string("log.reconnectGiveUp"))
            setState(.idle, Msg("detail.connectFailed"))
            return false
        }
        setState(.connecting, Msg("detail.preparing"))
        do { try await timing.sleep(reconnectBackoff[min(attempt - 1, reconnectBackoff.count - 1)]) }
        catch { await cancelledExit(); return false }
        if cancelled { await cancelledExit(); return false }
        guard timing.now().timeIntervalSince(recovery.startedAt) < 180 else {
            self.recovery?.exhausted = true
            log.write(loc.string("log.reconnectGiveUp"))
            setState(.idle, Msg("detail.connectFailed"))
            return false
        }
        return true
    }

    private func resetRecoveryState() {
        recovery = nil
        reconnectCycles.removeAll()
    }

    // MARK: - State helpers

    private func saveSelected(_ s: Strategy) async {
        selectedStrategyId = s.id
        settings.selectedStrategyId = s.id
        settings.sourceSelections[sourceID] = s.id
        settingsStore.save(settings)
    }

    private func putResult(_ r: TestResult) {
        var r = r
        r.networkIdentity = networkIdentity
        r.configurationFingerprint = strategies.first { $0.id == r.strategyId }?.configurationFingerprint
        r.endpointListFingerprint = endpointListFingerprint
        results[r.strategyId] = r
    }

    private func saveResults() {
        if let selectedStrategyId { settings.sourceSelections[sourceID] = selectedStrategyId }
        if mode == .warp {
            settings.results = settings.results.filter { $0.key.contains("|") || $0.value.networkIdentity != networkIdentity }
        } else {
            settings.results = settings.results.filter { !$0.key.hasPrefix(resultPrefix) || $0.value.networkIdentity != networkIdentity }
        }
        for (key, value) in results { settings.results[resultKey(key)] = value }
        settingsStore.save(settings)
    }

    /// The message to show for a backend error: a localized sentence for the codes the engine
    /// knows, the backend's own text otherwise.
    private func describe(_ error: Error) -> String {
        if error is PathChanged { return loc.string("detail.networkChanged") }
        guard let e = error as? WarpConnectionError else { return String(describing: error) }
        if let message = e.accountSetupMessage { return message.text(using: loc) }
        switch e.code {
        case "foreign_vpn": return loc.string("err.foreignVpn")
        case "no_account": return loc.string("err.noAccount")
        case "peer_key_mismatch": return loc.string("err.peerKeyMismatch", [e.connection?.endpoint ?? "WARP"])
        case "strategy_required": return loc.string("strategy.required")
        default: return e.message
        }
    }

    private func logConnectionFailure(_ error: Error) {
        guard let error = error as? WarpConnectionError, let context = error.connection else { return }
        log.write("Connection failure: transport=\(context.transport ?? "?") endpoint=\(context.endpoint ?? "?") phase=\(context.phase ?? "?") code=\(error.code ?? "?")")
    }

    private func persistentEndpoint(for strategy: Strategy) -> String? {
        guard strategy.mode == .warp else { return nil }
        if let result = results[strategy.id], result.confirmed,
           result.configurationFingerprint == strategy.configurationFingerprint,
           result.endpointListFingerprint == endpointListFingerprint, result.networkIdentity == networkIdentity,
           let value = result.endpoint, let endpoint = WarpEndpoint(value) {
            if settings.warpEndpoints.isEmpty { return endpoint.description }
            if settings.warpEndpoints.contains(endpoint.description) { return endpoint.requestToken }
        }
        return settings.warpEndpoints.first.flatMap(WarpEndpoint.init)?.requestToken
    }

    private func nextTestEndpoint(avoiding previous: String?) -> String? {
        if !settings.warpEndpoints.isEmpty {
            let endpoints = settings.warpEndpoints.compactMap(WarpEndpoint.init)
            let index = endpointSeq % endpoints.count
            endpointSeq = (endpointSeq + 1) % 1_000_000_000
            let candidate = endpoints[index]
            let previousAddress = previous.flatMap(WarpEndpoint.init)
            return (candidate == previousAddress ? endpoints.first { $0 != previousAddress } ?? candidate : candidate).requestToken
        }
        guard settings.isolateTests else { return nil }
        // Adjacent inline rechecks use consecutive pool tokens. Actual returned endpoints decide
        // independence, including finite pools, repeated addresses, and backend limitations.
        defer { endpointSeq = (endpointSeq + 1) % 1_000_000_000 }
        return "isolated-\(endpointSeq)"
    }
}
