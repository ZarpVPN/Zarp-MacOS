import AppKit
import SwiftUI

/// Single-instance windows share the same model and keep independent sizes.
struct ZarpWindows: Scene {
    @ObservedObject var vm: AppViewModel
    let onMainClose: () -> Void

    var body: some Scene {
        Window("Zarp", id: "main") {
            MainWindowView(vm: vm)
                .background(WindowCloseInterceptor(onShouldClose: onMainClose))
                .environment(\.layoutDirection, vm.localization.isRightToLeft ? .rightToLeft : .leftToRight)
                .preferredColorScheme(.dark)
                .tint(Theme.accent)
        }
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .appSettings) {
                Button(vm.localization.string("settings.title")) { vm.settingsRequested = true }
                    .keyboardShortcut(",", modifiers: .command)
            }
        }

        Window(vm.localization.string("settings.title"), id: "settings") {
            SettingsView(vm: vm)
                .background(WindowTitleUpdater(title: vm.localization.string("settings.title")))
                .environment(\.layoutDirection, vm.localization.isRightToLeft ? .rightToLeft : .leftToRight)
                .preferredColorScheme(.dark).tint(Theme.accent)
        }
        .defaultSize(width: 880, height: 800)
        .windowResizability(.contentMinSize)

        Window(vm.localization.string("settings.connection"), id: "connection") {
            ConnectionSettingsView(vm: vm)
                .background(WindowTitleUpdater(title: vm.localization.string("settings.connection")))
                .environment(\.layoutDirection, vm.localization.isRightToLeft ? .rightToLeft : .leftToRight)
                .preferredColorScheme(.dark).tint(Theme.accent)
        }
        .windowResizability(.contentSize)

        Window(vm.localization.string("apps.title"), id: "applications") {
            ApplicationRoutingView(vm: vm)
                .background(WindowTitleUpdater(title: vm.localization.string("apps.title")))
                .environment(\.layoutDirection, vm.localization.isRightToLeft ? .rightToLeft : .leftToRight)
                .preferredColorScheme(.dark).tint(Theme.accent)
        }
        .defaultSize(width: 860, height: 660)
        .windowResizability(.contentMinSize)

        Window(vm.localization.string("sources.title"), id: "servers") {
            ServersView(model: vm.serverLibrary, localization: vm.localization)
                .background(WindowTitleUpdater(title: vm.localization.string("sources.title")))
                .environment(\.layoutDirection, vm.localization.isRightToLeft ? .rightToLeft : .leftToRight)
                .preferredColorScheme(.dark).tint(Theme.accent)
                .onDisappear { vm.reloadSources() }
        }
        .windowResizability(.contentSize)

        Window(vm.localization.string("warpPlus.title"), id: "warp-plus") {
            WarpPlusView(vm: vm)
                .background(WindowTitleUpdater(title: vm.localization.string("warpPlus.title")))
                .environment(\.layoutDirection, vm.localization.isRightToLeft ? .rightToLeft : .leftToRight)
                .preferredColorScheme(.dark).tint(Theme.accent)
        }
        .windowResizability(.contentSize)

    }
}

/// Invisible helper view: on insertion, finds its enclosing `NSWindow` and makes itself that
/// window's delegate purely to intercept `windowShouldClose(_:)`. The window has no other delegate
/// of its own to preserve (plain SwiftUI `Window` scenes don't set one), so this doesn't need to
/// forward other delegate methods anywhere.
private struct WindowCloseInterceptor: NSViewRepresentable {
    let onShouldClose: () -> Void

    func makeNSView(context: Context) -> NSView {
        let view = NSView(frame: .zero)
        DispatchQueue.main.async { context.coordinator.attach(via: view, onShouldClose: onShouldClose) }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        context.coordinator.attach(via: nsView, onShouldClose: onShouldClose)
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator: NSObject, NSWindowDelegate {
        private weak var window: NSWindow?
        private var onShouldClose: (() -> Void)?

        func attach(via view: NSView, onShouldClose: @escaping () -> Void) {
            self.onShouldClose = onShouldClose
            guard let window = view.window, window !== self.window else { return }
            self.window = window
            window.delegate = self
        }

        func windowShouldClose(_ sender: NSWindow) -> Bool {
            onShouldClose?()
            return false
        }
    }
}

// SwiftUI can retain a closed scene's first title across language changes.
// Update the real window when its content is inserted or localized again.
private struct WindowTitleUpdater: NSViewRepresentable {
    let title: String
    func makeNSView(context: Context) -> NSView {
        let view = NSView(frame: .zero)
        update(view)
        return view
    }
    func updateNSView(_ view: NSView, context: Context) { update(view) }
    private func update(_ view: NSView) {
        let title = title
        DispatchQueue.main.async { view.window?.title = title }
    }
}
