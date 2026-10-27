import AppKit
import Foundation
import ServiceManagement
import SwiftUI
import ZarpCore
import ZarpdIPC
import ZarpSubscriptions

/// Bridges the `ZarpEngine` actor (plus `Localization` and `LogBus`) to SwiftUI state, and owns
/// the concrete wiring the App target is responsible for.
///
/// `connections`/`probe` default to `ZarpdClient`, using real IPC to the bundled
/// daemon. AutomaticDaemonCoordinator prepares it through ZarpdInstaller.
/// `network` is SystemNetworkInspector, the foreign-VPN check.
///
/// Besides forwarding the UI's actions, this type runs the app's heartbeat (`monitorTick`, every few
/// seconds): it pings the daemon, lets the engine reconcile what it believes with what the daemon
/// reports — which is how a tunnel that died on its own stops being shown as "Connected" — and pulls
/// the daemon's log lines into the app's own log.
@MainActor
final class AppViewModel: ObservableObject {
    let engine: ZarpEngine
    let localization: Localization
    let log: LogBus
    let serverLibrary: ServerLibraryViewModel

    @Published private(set) var engineState: EngineState = .idle
    var state: EngineState { preparingConnection && engineState == .idle ? .preparing : engineState }
    @Published private(set) var engineDetail: Msg = Msg("detail.noStrategy")
    var detail: Msg {
        if preparingConnection && engineState == .idle { return Msg("connection.preparing") }
        if engineState == .idle, let connectionPreparationNotice { return connectionPreparationNotice }
        return engineDetail
    }
    @Published private(set) var progressDone: Int = 0
    @Published private(set) var progressTotal: Int = 0
    @Published private(set) var strategies: [Strategy] = []
    @Published private(set) var results: [String: TestResult] = [:]
    @Published private(set) var selectedStrategyId: String?
    @Published private(set) var engineBusy = false
    var isBusy: Bool { engineBusy || preparingConnection }
    @Published private(set) var sources: [ConnectionSource] = []
    @Published private(set) var sourceID = ""
    @Published private(set) var connectionMode: ConnectionMode = .warp
    @Published private(set) var settings: AppSettings = AppSettings()
    @Published private(set) var logLines: [LogEntry] = []
    @Published private(set) var languageCode: String = Localization.fallbackCode
    @Published private(set) var isReady = false
    /// Drives `CloseConfirmationView`'s presentation. Kept here (not in `ZarpApp`/AppKit code) so
    /// both the main window and the menu bar item can trigger and observe it without threading an
    /// extra binding through the Scene hierarchy.
    @Published var showingCloseConfirmation = false
    /// Menu and keyboard requests open the separate settings window, then clear this flag.
    @Published var settingsRequested = false

    @Published private(set) var preparingConnection = false
    @Published private(set) var connectionPreparationNotice: Msg?
    @Published private(set) var daemonUnavailable = false
    private var daemonPing: PingResult?
    private var automaticDaemon: AutomaticDaemonCoordinator?
    /// Whether "Start with macOS" is on (`SMAppService.mainApp`).
    @Published private(set) var autostartEnabled = false
    private let zarpdClient: ZarpdClient?

    private var started = false
    private var monitorTask: Task<Void, Never>?
    private var daemonLogCursor: UInt64 = 0
    private var daemonLogPrimed = false

    static let monitorInterval: UInt64 = 4_000_000_000
    /// How long quitting waits for a scan to unwind and the tunnel to close before giving up.
    private static let terminationGrace: UInt64 = 8_000_000_000

    init(
        settingsStore: SettingsStore, strategyStore: CustomStrategyStore, localization: Localization, log: LogBus,
        connections: WarpConnectionProvider = ZarpdClient(), probe: WarpProbe? = nil,
        network: NetworkInspector = SystemNetworkInspector(), connectionLibrary: ConnectionLibrary? = nil
    ) {
        self.localization = localization
        self.log = log
        let library = connectionLibrary ?? ConnectionLibrary(directory: Self.dataDirectory().appendingPathComponent("Connections", isDirectory: true), transport: FoundationSubscriptionTransport())
        self.serverLibrary = ServerLibraryViewModel(library: library)
        // WarpProbe defaults to the same ZarpdClient instance as WarpConnectionProvider when the
        // caller doesn't pass its own (the common case) — one socket-speaking object, not two —
        // but can't share that default with the `connections` parameter above directly since a
        // caller providing a custom `connections` (a fake, in a future test) shouldn't silently
        // still get a real ZarpdClient for probing.
        let resolvedProbe = probe ?? (connections as? ZarpdClient) ?? ZarpdClient()
        self.zarpdClient = (connections as? ZarpdClient) ?? (resolvedProbe as? ZarpdClient)
        self.engine = ZarpEngine(
            settingsStore: settingsStore,
            strategyStore: strategyStore,
            connections: connections,
            probe: resolvedProbe,
            network: network,
            log: log,
            localization: localization,
            connectionLibrary: library
        )
        self.languageCode = localization.currentCode
        self.logLines = log.snapshot()

        log.onAppend = { [weak self] _ in
            Task { @MainActor in self?.refreshLogLines() }
        }
        localization.onChanged = { [weak self] in
            Task { @MainActor in self?.languageCode = localization.currentCode }
        }
        #if !ZARP_APPEARANCE_PREVIEW
        if let client = zarpdClient {
            let adapter = ZarpdInstaller(client: client, expectedVersion: Self.appVersion)
            automaticDaemon = makeAutomaticCoordinator(service: adapter)
        }
        #endif
    }

    private func makeAutomaticCoordinator(service: any AutomaticDaemonService) -> AutomaticDaemonCoordinator {
        AutomaticDaemonCoordinator(service: service, canReplace: { [weak self] in
            guard let self else { return false }
            return self.engineState == .idle && !self.engineBusy
        }, onEvent: { [log, localization] event in
            log.write(event.message, using: localization)
        })
    }

    private func refreshLogLines() {
        logLines = log.snapshot()
    }

    /// Call once at launch (calling it again is a no-op: SwiftUI's `.task` can re-run when a view
    /// reappears).
    func start() async {
        guard !started else { return }
        started = true
        await engine.setOnChanged { [weak self] in
            Task { @MainActor in await self?.refresh() }
        }
        await engine.setHooks(EngineHooks(
            askContinueWithVPN: { [localization] names in await Self.confirmContinueWithVPN(names, localization) },
            askAcceptWarpTerms: { [localization] in await Self.confirmWarpTerms(localization) }
        ))
        await engine.load()
        settings = await engine.currentSettings
        let systemCode = Self.systemLanguageCode()
        localization.setLanguage(localization.resolve(setting: settings.language, systemCode: systemCode))
        log.write(Msg("log.appStarted", Self.appVersion), using: localization)
        await refresh()
        refreshAutostart()
        _ = await ensureConnectionService()
        isReady = true
        startMonitoring()
        if settings.autoConnectOnStart { await autoConnectOnLaunch() }
    }

    /// "Connect when Zarp starts". Only when the daemon is actually answering and nothing else is
    /// going on — an adopted tunnel counts as already connected.
    private func autoConnectOnLaunch() async {
        guard daemonPing != nil else {
            log.write(localization.string("connection.prepareFailed"))
            return
        }
        guard state == .idle, !isBusy else { return }
        _ = await engine.connect()
    }

    // MARK: - Heartbeat

    private func startMonitoring() {
        monitorTask?.cancel()
        monitorTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: Self.monitorInterval)
                guard !Task.isCancelled, let self else { return }
                await self.monitorTick()
            }
        }
    }

    private func monitorTick() async {
        guard !preparingConnection else { return }
        await engine.observeNetworkChange()
        await pingDaemon()
        await engine.reconcileConnection()
        await pullDaemonLogs()
        if (daemonUnavailable || daemonNeedsUpdate), automaticDaemon?.canRepairAutomatically == true,
           engineState == .idle, !engineBusy {
            _ = await ensureConnectionService()
        }
    }

    // MARK: - Automatic connection preparation

    func ensureConnectionService(userInitiated: Bool = false) async -> Bool {
        guard let automaticDaemon else { return !preparingConnection }
        preparingConnection = true
        connectionPreparationNotice = nil
        defer { preparingConnection = false }
        let result = await automaticDaemon.ensureReady(userInitiated: userInitiated)
        switch result {
        case .ready:
            daemonLogPrimed = false
            await pingDaemon()
            return daemonPing != nil
        case .approvalRequired: connectionPreparationNotice = Msg("connection.permissionRequired")
        case .moveToApplications: connectionPreparationNotice = Msg("connection.moveToApplications")
        case .failed: connectionPreparationNotice = Msg("connection.prepareFailed")
        case .deferred: break
        }
        if result != .deferred { daemonUnavailable = true }
        return false
    }

    private func pingDaemon() async {
        guard let zarpdClient else { return }
        let wasResponding = daemonPing != nil
        do {
            daemonPing = try await zarpdClient.ping(timeout: 1)
            daemonUnavailable = false
            connectionPreparationNotice = nil
            if !wasResponding { await engine.adoptExistingConnection() }
        } catch {
            daemonPing = nil
            daemonUnavailable = true
        }
    }

    private var daemonNeedsUpdate: Bool {
        guard let ping = daemonPing else { return false }
        return ping.effectiveProtocol < ZarpdClient.protocolVersion || (ping.version != "dev" && ping.version != Self.appVersion)
    }

    static var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "dev"
    }

    /// Imports the daemon's new log lines into the app's log (prefixed so it's clear where they
    /// came from). The first pull only sets the cursor: what the daemon logged before this session
    /// isn't replayed into the panel. If the daemon restarted, its sequence numbers start over and
    /// the new process's log is imported from the beginning.
    private func pullDaemonLogs() async {
        guard let zarpdClient, daemonPing != nil else { return }
        guard let result = try? await zarpdClient.logs(since: daemonLogCursor) else { return }
        if result.next < daemonLogCursor {
            guard let fresh = try? await zarpdClient.logs(since: 0) else { return }
            importDaemonLogs(fresh)
            daemonLogCursor = fresh.next
            return
        }
        if !daemonLogPrimed {
            daemonLogPrimed = true
            daemonLogCursor = result.next
            return
        }
        importDaemonLogs(result)
        daemonLogCursor = result.next
    }

    private func importDaemonLogs(_ logs: DaemonLogs) {
        for line in logs.lines ?? [] {
            log.write("zarpd: " + line.text, at: Date(timeIntervalSince1970: Double(line.timeMs) / 1000))
        }
    }

    // MARK: - Start with macOS (SMAppService.mainApp)

    func refreshAutostart() {
        #if !ZARP_APPEARANCE_PREVIEW
        let status = SMAppService.mainApp.status
        let on = status == .enabled || status == .requiresApproval
        if autostartEnabled != on { autostartEnabled = on }
        #endif
    }

    func setAutostart(_ enabled: Bool) {
        #if !ZARP_APPEARANCE_PREVIEW
        do {
            if enabled {
                try SMAppService.mainApp.register()
                log.write(localization.string("log.autostartOn"))
            } else {
                try SMAppService.mainApp.unregister()
                log.write(localization.string("log.autostartOff"))
            }
        } catch {
            log.write(localization.string("log.autostartFailed", [error.localizedDescription]))
        }
        refreshAutostart()
        #endif
    }

    // MARK: - Engine state

    /// Waits for whatever operation is in flight to finish — used when the app is quitting
    /// (Windows `Engine.ShutdownAsync`).
    func waitUntilIdle() async {
        await engine.waitUntilIdle()
    }

    private func refresh() async {
        let snapshot = await engine.snapshot()
        engineState = snapshot.state
        engineDetail = snapshot.detail
        progressDone = snapshot.progressDone
        progressTotal = snapshot.progressTotal
        strategies = snapshot.strategies
        results = snapshot.results
        selectedStrategyId = snapshot.selectedStrategyId
        engineBusy = snapshot.isBusy
        sources = snapshot.sources
        sourceID = snapshot.sourceID
        connectionMode = snapshot.mode
    }

    func reloadSources() {
        #if !ZARP_APPEARANCE_PREVIEW
        Task { await engine.refreshSources(); await refresh() }
        #endif
    }
    func selectSource(_ id: String) { Task { _ = await engine.selectSource(id); await refresh() } }

    func configureConnection(useServer: Bool, input: String, source: String?, endpoints: [String], policy: ServerRoutingPolicy) async -> Msg? {
        do {
            try await engine.configureConnection(useServer: useServer, input: input, source: source, endpoints: endpoints, policy: policy)
            await refresh()
            await serverLibrary.load()
            return nil
        } catch is CancellationError {
            await refresh(); return Msg("sources.cancelled")
        } catch let error as ConnectionLibraryError {
            await refresh()
            return Msg(error == .emptyConfiguration ? "connection.noServer" : error == .busy ? "sources.busyError" : "sources.formatError")
        } catch let error as ConnectionContractError {
            await refresh(); return Msg(error.field == .routing ? "routing.invalid" : "sources.formatError")
        } catch {
            await refresh(); return ServerLibraryViewModel.configurationNotice(error)
        }
    }

    // MARK: - Actions (fire-and-forget from the UI's point of view; state updates arrive via `refresh()`)

    func connectButtonTapped() {
        guard !preparingConnection else { return }
        if engineBusy { Task { await engine.cancel() }; return }
        if state == .connected { Task { _ = await engine.disconnect() }; return }
        performConnectionAction { await self.engine.connect() }
    }

    private func performConnectionAction(_ action: @escaping @MainActor () async -> Bool) {
        guard isReady, !isBusy else { return }
        Task {
            guard await ensureConnectionService(userInitiated: true) else { return }
            connectionPreparationNotice = nil
            _ = await action()
        }
    }

    func quickScan() { performConnectionAction { await self.engine.search(full: false) } }
    func fullScan() { performConnectionAction { await self.engine.search(full: true) } }
    func testSelected(_ items: [Strategy]) { performConnectionAction { await self.engine.testStrategies(items) } }
    func use(_ strategy: Strategy) { performConnectionAction { await self.engine.use(strategy) } }
    func cancel() { Task { await engine.cancel() } }

    /// The text for the custom-strategies editor.
    func customStrategiesText() async -> String {
        await engine.customStrategiesText()
    }

    /// Saves the editor's text; returns the lines that were skipped as malformed, or the error that
    /// kept the file from being written.
    func saveCustomStrategies(_ text: String) async -> Result<[String], Error> {
        do {
            let skipped = try await engine.saveCustomStrategies(text)
            await refresh()
            return .success(skipped)
        } catch {
            log.write(localization.string("log.customSaveFailed", [CustomStrategyFile.fileName, error.localizedDescription]))
            return .failure(error)
        }
    }

    func updateSettings(_ mutate: (inout AppSettings) -> Void) {
        var s = settings
        mutate(&s)
        settings = s
        Task { await engine.updateSettings(s); await refresh() }
        if let lang = s.language {
            localization.setLanguage(lang)
        }
    }

    func setLanguage(_ code: String?) {
        updateSettings { $0.language = code }
        localization.setLanguage(code ?? Self.systemLanguageCode())
    }

    // MARK: - Close / quit (Windows `MainForm.OnFormClosing` + `CloseActionForm`)

    /// Call when the user asks to close the window or quit. `hide`/`terminate` are injected so
    /// this type doesn't need AppKit's `NSApp` itself — `ZarpApp.swift` passes `NSApp.hide(nil)` /
    /// `NSApp.terminate(nil)`. Terminating runs `ZarpAppDelegate.applicationShouldTerminate`, which
    /// calls `prepareForTermination()` — so the shutdown sequence is the same however the app is
    /// asked to quit (⌘Q, the menu bar, the Dock's Quit, logging out).
    func requestClose(hide: @escaping () -> Void, terminate: @escaping () -> Void) {
        if settings.askBeforeClose {
            showingCloseConfirmation = true
        } else if settings.minimizeToMenuBar {
            hide()
        } else {
            terminate()
        }
    }

    func confirmClose(minimizeToMenuBar: Bool, remember: Bool, hide: @escaping () -> Void, terminate: @escaping () -> Void) {
        showingCloseConfirmation = false
        if remember {
            updateSettings { s in
                s.askBeforeClose = false
                s.minimizeToMenuBar = minimizeToMenuBar
            }
        }
        if minimizeToMenuBar {
            hide()
        } else {
            terminate()
        }
    }

    func cancelClose() { showingCloseConfirmation = false }

    /// The shutdown sequence (Windows `Engine.FinishShutdownAsync`): cancel whatever might be
    /// running (e.g. a scan) so quitting doesn't sit through it to natural completion, wait for that
    /// cancellation to actually finish tearing down, and only then disconnect if asked to.
    /// `disconnect()`/`cancel()` on the engine only confirm an operation *started* — they are not
    /// themselves awaitable to completion, which is exactly why `waitUntilIdle()` follows each one
    /// here rather than being trusted to have already happened.
    ///
    /// Bounded: a daemon that has stopped answering must not be able to keep the app from quitting
    /// (or a logout from completing), so after a grace period the app goes ahead regardless.
    func prepareForTermination() async {
        await automaticDaemon?.stop()
        monitorTask?.cancel()
        await serverLibrary.close()
        let engine = self.engine
        let disconnect = settings.disconnectOnExit
        let grace = Self.terminationGrace
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            // Two *unstructured* tasks race. A task group would not do: leaving it waits for every
            // child, including the stuck one the timeout exists to abandon.
            let once = OneShot()
            Task {
                await engine.cancel()
                await engine.waitUntilIdle()
                if disconnect {
                    _ = await engine.disconnect()
                    await engine.waitUntilIdle()
                }
                if once.fire() { continuation.resume() }
            }
            Task {
                try? await Task.sleep(nanoseconds: grace)
                if once.fire() { continuation.resume() }
            }
        }
    }

    // MARK: - Dialogs the engine asks for

    /// Windows' `dlg.vpn`: another VPN is on; carrying on means measuring (or fighting) its tunnel.
    /// "Cancel" is the default button — the message itself says turning the VPN off is better.
    private static func confirmContinueWithVPN(_ names: [String], _ loc: Localization) -> Bool {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Zarp"
        alert.informativeText = loc.string("dlg.vpn", [names.joined(separator: "\n")])
        alert.addButton(withTitle: loc.string("btn.cancel"))
        alert.addButton(withTitle: loc.string("dlg.vpnContinue"))
        return alert.runModal() == .alertSecondButtonReturn
    }

    /// Zarp registers an anonymous WARP account with Cloudflare, which means accepting Cloudflare's
    /// terms for the user: that happens only after they say so here.
    private static func confirmWarpTerms(_ loc: Localization) -> Bool {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = loc.string("dlg.termsTitle")
        alert.informativeText = loc.string("dlg.terms")
        alert.addButton(withTitle: loc.string("dlg.termsAccept"))
        alert.addButton(withTitle: loc.string("btn.cancel"))
        return alert.runModal() == .alertFirstButtonReturn
    }

    // MARK: - Licenses

    /// Windows `Licenses.Extract`: puts the notices that must accompany the distributed binaries
    /// (this app's own, the Go components inside `zarpd`, the zapret2 blobs) where the user can
    /// read them, and reveals them.
    func revealLicenses() {
        let fm = FileManager.default
        guard let bundled = Bundle.main.resourceURL?.appendingPathComponent("Licenses", isDirectory: true),
              fm.fileExists(atPath: bundled.path) else {
            log.write(localization.string("log.licenseFailed", ["Licenses", "not found in the app bundle"]))
            return
        }
        let target = Self.dataDirectory().appendingPathComponent("Licenses", isDirectory: true)
        do {
            try? fm.removeItem(at: target)
            try fm.copyItem(at: bundled, to: target)
            NSWorkspace.shared.activateFileViewerSelecting([target.appendingPathComponent("THIRD_PARTY_NOTICES.md")])
        } catch {
            log.write(localization.string("log.licenseFailed", ["Licenses", error.localizedDescription]))
        }
    }

    static func dataDirectory() -> URL {
        let base = (try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true))
            ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("Zarp", isDirectory: true)
    }

    /// Windows follows `CultureInfo.CurrentUICulture`; this is the SwiftUI/Foundation
    /// equivalent — `Locale`, not a networking API.
    private static func systemLanguageCode() -> String {
        Locale.preferredLanguages.first.flatMap { Locale(identifier: $0).language.languageCode?.identifier } ?? Localization.fallbackCode
    }
}

/// Fires exactly once, from whichever caller gets there first.
private final class OneShot: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false

    func fire() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if fired { return false }
        fired = true
        return true
    }
}

#if ZARP_APPEARANCE_PREVIEW
// Compiled only into the isolated appearance fixture, never the app target.
@MainActor
extension AppViewModel {
    func appearanceReportStartupFailure() async -> Bool {
        let previous = automaticDaemon
        defer { automaticDaemon = previous }
        automaticDaemon = makeAutomaticCoordinator(service: AppearanceFailedRegistration())
        return await ensureConnectionService(userInitiated: true)
    }

    func appearanceAutomaticPreparation(_ preparing: Bool, notice: Msg? = nil) {
        preparingConnection = preparing
        connectionPreparationNotice = notice
        daemonUnavailable = preparing || notice != nil
    }

    func appearanceMainState(detail: Msg, selectedStrategyId: String? = nil) {
        self.engineDetail = detail
        self.selectedStrategyId = selectedStrategyId
    }

    func appearanceServerFixture() {
        let source = try! ConnectionSource(kind: .manual)
        let profile = try! ServerLinkImporter.parse("trojan://appearance-fixture@server.example:443?security=tls#Example")
        sources = [try! ConnectionSource(kind: .warp), source]
        sourceID = source.id
        connectionMode = .server
        strategies = ServerPairs.build(strategies: StrategyCatalog.builtIn, profiles: [profile], sourceID: source.id)
        results = [:]
        settings.serverRouting.applicationMode = .include
        settings.serverRouting.applicationPaths = ["/Applications/Example Browser.app"]
    }

    static func appearanceFixture(directory: URL, languages: URL, language: String) -> AppViewModel {
        let localization = Localization.load(languageFilesDirectory: languages)
        localization.setLanguage(language)
        let provider = AppearanceProvider()
        let library = ConnectionLibrary(directory: directory, transport: AppearanceTransport())
        let model = AppViewModel(settingsStore: InMemorySettingsStore(), strategyStore: InMemoryCustomStrategyStore(),
                                 localization: localization, log: LogBus(maxEntries: 20), connections: provider, probe: provider,
                                 network: UnimplementedNetworkInspector(), connectionLibrary: library)
        model.started = true
        model.isReady = true
        model.strategies = StrategyCatalog.builtIn
        let source = try! ConnectionSource(kind: .warp)
        model.sources = [source]
        model.sourceID = source.id
        if let first = model.strategies.first {
            model.results[first.id] = TestResult(strategyId: first.id, ok: true, connectMs: 338, pingMs: 39, confirmed: true)
        }
        if model.strategies.count > 1 {
            let id = model.strategies[1].id
            model.results[id] = .failed(strategyId: id, error: Msg("err.timeout", "15"))
        }
        return model
    }
}

private struct AppearanceTransport: SubscriptionHTTPTransport {
    func get(url: URL, userAgent: String, deadline: ContinuousClock.Instant) async throws -> SubscriptionHTTPResponse { throw SubscriptionError.network }
}
private struct AppearanceProvider: WarpConnectionProvider, WarpProbe, WarpAccountProvider {
    func open(strategy: Strategy, endpoint: String?, timeoutMs: Int, persistent: Bool, routing: TunnelRouting) async throws -> any WarpConnectionHandle { throw WarpConnectionError("appearance fixture has no network") }
    func connectionSnapshot() async throws -> ConnectionSnapshot { ConnectionSnapshot(live: nil) }
    func isAccountRegistered() async throws -> Bool { true }
    func registerAccount() async throws { throw WarpConnectionError("appearance fixture has no account API") }
    func measure(connection: any WarpConnectionHandle, samples: Int) async throws -> WarpMeasurement { throw WarpConnectionError("appearance fixture has no network") }
    func readWarpAccount() async throws -> WarpAccountStatus { WarpAccountStatus(accountType: .free, licenseApplied: false) }
    func applyWarpLicense(_ key: String) async throws -> WarpAccountStatus { throw WarpConnectionError("appearance fixture has no account API") }
}

@MainActor
private final class AppearanceFailedRegistration: AutomaticDaemonService {
    var registrationStatus: DaemonRegistrationStatus = .enabled
    func health() async -> DaemonServiceHealth { .unreachable }
    func validateLocation() throws {}
    func unregisterForRecovery() async throws { registrationStatus = .missing }
    func registerForRecovery() throws { throw NSError(domain: "SMAppServiceErrorDomain", code: 1) }
    func openApprovalSettings() {}
}
#endif
