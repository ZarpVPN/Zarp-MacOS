import AppKit
import SwiftUI
import ZarpCore

// This executable links the actual views with private storage and providers that cannot connect.
// It excludes ZarpApp.swift and its production services, app delegate and launch behavior.
@main
struct AppearancePreviewApp: App {
    @NSApplicationDelegateAdaptor(PreviewDelegate.self) private var delegate
    @StateObject private var vm: AppViewModel

    init() {
        NSApplication.shared.setActivationPolicy(.regular)
        let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let languages = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
        DispatchQueue.global().asyncAfter(deadline: .now() + 28) { exit(2) }
        let model = AppViewModel.appearanceFixture(
            directory: output.appendingPathComponent("private-connections", isDirectory: true),
            languages: languages, language: "ru")
        _vm = StateObject(wrappedValue: model)
    }

    var body: some Scene {
        ZarpWindows(vm: vm, onMainClose: { NSApp.terminate(nil) })
    }
}

@MainActor
final class PreviewDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            func items(_ menu: NSMenu) -> [NSMenuItem] {
                menu.items.flatMap { [$0] + ($0.submenu.map(items) ?? []) }
            }
            let commands = NSApp.mainMenu.map(items) ?? []
            if !NSApp.windows.contains(where: \.isVisible), let main = commands.first(where: { $0.title == "Zarp" && $0.action != nil }) {
                NSApp.sendAction(main.action!, to: main.target, from: main)
            }
            NSApp.activate(ignoringOtherApps: true)
        }
    }
}

@MainActor
struct AppearanceDriver: View {
    @ObservedObject var vm: AppViewModel
    @Binding var isLogExpanded: Bool
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismissWindow) private var dismissWindow
    @Environment(\.layoutDirection) private var layoutDirection
    @State private var started = false
    @State private var observedDirection: LayoutDirection = .leftToRight

    var body: some View {
        Color.clear.frame(width: 1, height: 1).onChange(of: layoutDirection, initial: true) { _, direction in
            observedDirection = direction
        }.task {
            guard !started else { return }
            started = true
            do {
                try await run()
                exit(0)
            } catch {
                try? String(describing: error).write(to: output.appendingPathComponent("preview-failure.txt"), atomically: true, encoding: .utf8)
                fputs("Appearance preview failed: \(error)\n", stderr)
                exit(1)
            }
        }
    }

    private func run() async throws {
        NSApp.activate(ignoringOtherApps: true)
        let main = try await window(title: "Zarp")
        let originalSize = main.frame.size
        try require(originalSize.width == 380 && originalSize.height < 520, "Main window retained empty fixed-height space")
        try capture(main, name: "main-ru")

        // Exercise the actual preparation-to-LogBus-to-view-model path with an
        // inert failing service. Nothing reaches ServiceManagement or real IPC.
        for index in 0..<24 { vm.log.write("Private journal fixture \(index)") }
        let prepared = await vm.appearanceReportStartupFailure()
        try await Task.sleep(for: .milliseconds(200))
        try require(!prepared, "The failing fixture unexpectedly prepared a connection")
        try require(vm.logLines.count == 20, "The log view model lost the bounded snapshot")
        try require(vm.logLines.last?.text.contains("SMAppServiceErrorDomain (1)") == true, "Startup failure left the journal empty")
        let failureSize = main.frame.size

        isLogExpanded = true
        try await Task.sleep(for: .milliseconds(400))
        try require(main.frame.width == failureSize.width && main.frame.height > failureSize.height + 180, "Expanded log did not resize the window")
        try capture(main, name: "main-log-ru")
        let cappedCount = vm.logLines.count
        vm.log.write(DaemonPreparationEvent.failed("startup_timeout").message, using: vm.localization)
        try await Task.sleep(for: .milliseconds(250))
        try require(vm.logLines.count == cappedCount && vm.logLines.last?.text.contains("startup_timeout") == true,
                    "A capped log did not display the latest appended entry")
        try capture(main, name: "main-log-capped-ru")
        isLogExpanded = false
        try await Task.sleep(for: .milliseconds(400))
        try require(main.frame.size == failureSize, "Collapsed log left empty window space")
        vm.appearanceAutomaticPreparation(false)
        try await Task.sleep(for: .milliseconds(200))
        try require(main.frame.size == originalSize, "Clearing the failure retained unused window space")

        vm.appearanceMainState(detail: Msg("detail.vpnOff"), selectedStrategyId: vm.strategies.first?.id)
        try await Task.sleep(for: .milliseconds(200))
        try capture(main, name: "main-vpn-warning-ru")
        vm.localization.setLanguage("en")
        try await Task.sleep(for: .milliseconds(200))
        try capture(main, name: "main-vpn-warning-en")
        vm.localization.setLanguage("ru")
        vm.appearanceMainState(detail: Msg("detail.noStrategy"))
        try await Task.sleep(for: .milliseconds(200))

        // Exercise the same request used by the menu bar and Command-comma.
        vm.settingsRequested = true
        let settings = try await window(title: vm.localization.string("settings.title"))
        settings.setContentSize(NSSize(width: 880, height: 800))
        try await Task.sleep(for: .milliseconds(200))
        try require(settings !== main, "Settings reused the main window")
        try require(settings.sheetParent == nil && main.attachedSheet == nil, "Settings opened as a sheet")
        try require(main.frame.size == originalSize, "Settings resized the main window")
        try capture(settings, name: "settings-ru")

        vm.settingsRequested = true
        try await Task.sleep(for: .milliseconds(250))
        let matching = NSApp.windows.filter { $0.isVisible && $0.title == settings.title }
        try require(matching.count == 1 && matching[0] === settings, "Settings is not single-instance")

        settings.setContentSize(NSSize(width: 820, height: 690))
        try await Task.sleep(for: .milliseconds(250))
        try capture(settings, name: "settings-minimum-ru")
        try require(main.frame.size == originalSize, "Resizing settings changed the main window")
        settings.setContentSize(NSSize(width: 880, height: 800))

        for (id, key) in [("connection", "settings.connection"), ("warp-plus", "warpPlus.title"), ("servers", "sources.title")] {
            openWindow(id: id)
            let child = try await window(title: vm.localization.string(key))
            try require(child.sheetParent == nil, "\(id) opened as a sheet")
            try capture(child, name: "\(id)-ru")
            dismissWindow(id: id)
        }

        vm.localization.setLanguage("en")
        try await Task.sleep(for: .milliseconds(350))
        try capture(settings, name: "settings-en")
        try require(main.frame.width == originalSize.width, "Changing language changed the main width")
        vm.localization.setLanguage("ru")
        vm.appearanceServerFixture()
        try await Task.sleep(for: .milliseconds(250))
        for (id, key) in [("connection", "settings.connection"), ("applications", "apps.title")] {
            openWindow(id: id)
            let child = try await window(title: vm.localization.string(key))
            try require(child.sheetParent == nil, "\(id) opened as a sheet")
            try capture(child, name: id == "connection" ? "server-editor-ru" : "application-routing-ru")
            dismissWindow(id: id)
        }
        try capture(main, name: "main-server-ru")
        let serverSize = main.frame.size
        try require(serverSize.width == originalSize.width && serverSize.height < 540, "Server mode left empty window space")
        vm.localization.setLanguage("fa")
        try await Task.sleep(for: .milliseconds(350))
        try capture(main, name: "main-fa")
        try require(observedDirection == .rightToLeft, "Farsi did not change scene direction")
        try require(main.frame.width == originalSize.width && main.frame.height < 570, "Farsi broke the compact main layout")
        try capture(settings, name: "settings-fa")
        for (id, key) in [("connection", "settings.connection"), ("warp-plus", "warpPlus.title"), ("applications", "apps.title")] {
            openWindow(id: id)
            let child = try await window(title: vm.localization.string(key))
            try capture(child, name: "\(id)-fa")
            dismissWindow(id: id)
        }
        vm.localization.setLanguage("ru")
        try await Task.sleep(for: .milliseconds(350))
        try require(observedDirection == .leftToRight, "Returning from Farsi retained RTL")
        dismissWindow(id: "settings")
        try await Task.sleep(for: .milliseconds(200))
        try require(main.isVisible && main.frame.size == serverSize, "Closing settings closed or resized the main window")

        let visibleBeforePreparation = NSApp.windows.filter(\.isVisible).count
        vm.appearanceAutomaticPreparation(true)
        try await Task.sleep(for: .milliseconds(250))
        try capture(main, name: "main-automatic-preparation-ru")
        vm.connectButtonTapped()
        try await Task.sleep(for: .milliseconds(150))
        try require(NSApp.windows.filter(\.isVisible).count == visibleBeforePreparation, "Preparation opened a maintenance window")
        openWindow(id: "warp-plus")
        let account = try await window(title: vm.localization.string("warpPlus.title"))
        try capture(account, name: "warp-plus-automatic-preparation-ru")
        dismissWindow(id: "warp-plus")
        vm.appearanceAutomaticPreparation(false, notice: Msg("connection.permissionRequired"))
        try await Task.sleep(for: .milliseconds(250))
        try capture(main, name: "main-permission-ru")
        vm.appearanceAutomaticPreparation(false)
        try await Task.sleep(for: .milliseconds(250))
        try require(main.frame.size == serverSize, "Completed preparation left empty main-window space")

        let report: [String: Any] = [
            "status": "PASS", "settings_separate": true, "settings_single_instance": true,
            "main_size_preserved": true, "minimum_settings_size_checked": true,
            "main_content_sized": true, "log_expands_and_collapses": true,
            "startup_failure_written_to_journal": true, "capped_log_receives_latest_entry": true,
            "settings_closes_independently": true,
            "server_editor_checked": true, "application_selector_checked": true,
            "farsi_rtl_and_language_switch_checked": true,
            "automatic_preparation_ui_checked": true,
            "no_maintenance_window_opened": true,
            "network_provider": "inert", "production_services_started": false,
            "main_frame": [originalSize.width, originalSize.height],
            "main_server_frame": [serverSize.width, serverSize.height]
        ]
        let data = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: output.appendingPathComponent("report.json"))
        print(String(decoding: data, as: UTF8.self))
    }

    private var output: URL { URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true) }

    private func window(title: String) async throws -> NSWindow {
        for _ in 0..<40 {
            if let window = NSApp.windows.first(where: { $0.isVisible && $0.title == title }) {
                try await Task.sleep(for: .milliseconds(300))
                return window
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        throw PreviewFailure(message: "Window did not open: \(title)")
    }

    private func capture(_ window: NSWindow, name: String) throws {
        guard let content = window.contentView else { throw PreviewFailure(message: "Missing window content") }
        let view = content.superview ?? content
        view.layoutSubtreeIfNeeded()
        view.displayIfNeeded()
        guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
            throw PreviewFailure(message: "Cannot capture \(name)")
        }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]) else {
            throw PreviewFailure(message: "Cannot encode \(name)")
        }
        try png.write(to: output.appendingPathComponent("\(name).png"))
    }

    private func require(_ condition: Bool, _ message: String) throws {
        if !condition { throw PreviewFailure(message: message) }
    }
}

private struct PreviewFailure: Error, CustomStringConvertible {
    let message: String
    var description: String { message }
}
