import AppKit
import SwiftUI
import ZarpCore

/// The main window: title, power button, status, detail line, progress bar, hint, and a
/// collapsible log — matches Windows Zarp's `MainForm` (`UI/MainForm.cs`), same 380pt compact
/// width and the same element order top to bottom.
///
/// Pressing the power button drives a real `WarpConnectionProvider` (`ZarpdClient`, talking to
/// `zarpd` over IPC — see `AppViewModel`'s doc comment); it fails visibly and honestly if `zarpd`
/// isn't running, rather than silently no-opping.
struct MainWindowView: View {
    @ObservedObject var vm: AppViewModel
    @Environment(\.openWindow) private var openWindow
    @State private var showingLanguageMenu = false
    @State private var isLogExpanded = false

    var body: some View {
        VStack(spacing: 0) {
            header
            if vm.isReady && (vm.sources.count > 1 || !vm.sources.contains(where: { $0.id == vm.sourceID })) {
                sourcePicker
            }

            PowerButton(look: powerLook, action: vm.connectButtonTapped)
                .padding(.top, 28)
                .padding(.bottom, 20)

            Text(statusText)
                .font(Theme.font(18, weight: .bold))
                .foregroundColor(statusColor)

            Text(vm.detail.text(using: vm.localization))
                .font(Theme.font(12))
                .foregroundColor(Theme.textDim)
                .multilineTextAlignment(.center)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 24)
                .padding(.top, 6)
                .frame(minHeight: 34)

            if vm.progressTotal > 0 {
                ProgressBar(fraction: Double(vm.progressDone) / Double(max(1, vm.progressTotal)))
                    .frame(height: 4)
                    .padding(.horizontal, 40)
                    .padding(.top, 10)
            }

            if !vm.preparingConnection {
                Text(hintText)
                    .font(Theme.font(11))
                    .foregroundColor(Theme.textDim)
                    .multilineTextAlignment(.center)
                    .lineLimit(3)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 24)
                    .padding(.top, 14)
            }

            logToggle.padding(.top, 12)

            if isLogExpanded {
                LogView(lines: vm.logLines)
                    .frame(height: 190)
                    .transition(.opacity)
            }
        }
        .padding(.bottom, 12)
        .frame(width: 380)
        .fixedSize(horizontal: false, vertical: true)
        .background(Theme.back)
        .task { await vm.start() }
        // Menu bar and keyboard requests open a separate single-instance window.
        .onChange(of: vm.settingsRequested) { _, requested in
            guard requested else { return }
            openSettings()
            vm.settingsRequested = false
        }
        .sheet(isPresented: $vm.showingCloseConfirmation) {
            CloseConfirmationView(
                localization: vm.localization,
                disconnectOnExit: vm.settings.disconnectOnExit,
                onChoice: { minimizeToMenuBar, remember in
                    vm.confirmClose(minimizeToMenuBar: minimizeToMenuBar, remember: remember,
                                     hide: { NSApp.hide(nil) }, terminate: { NSApp.terminate(nil) })
                },
                onCancel: { vm.cancelClose() }
            )
        }
        .animation(.easeInOut(duration: 0.15), value: isLogExpanded)
        #if ZARP_APPEARANCE_PREVIEW
        .overlay(AppearanceDriver(vm: vm, isLogExpanded: $isLogExpanded))
        #endif
    }

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Zarp")
                    .font(Theme.font(22, weight: .bold))
                    .foregroundColor(Theme.text)
                Text(vm.localization.string(vm.connectionMode == .server ? "sources.subtitle" : "main.subtitle"))
                    .font(Theme.font(11))
                    .foregroundColor(Theme.textDim)
            }
            Spacer()
            HStack(spacing: 6) {
                iconButton(systemName: "globe", help: vm.localization.string("main.languageTip")) {
                    showingLanguageMenu = true
                }
                .popover(isPresented: $showingLanguageMenu) { languageMenu }
                iconButton(systemName: "gearshape", help: vm.localization.string("main.settingsTip")) {
                    openSettings()
                }
            }
        }
        .padding(.top, 18)
        .padding(.horizontal, 22)
    }

    private func openSettings() {
        openWindow(id: "settings")
        NSApp.activate(ignoringOtherApps: true)
    }

    private var sourcePicker: some View {
        HStack {
            Text(vm.localization.string("sources.source"))
            DarkMenu(title: vm.sources.first(where: { $0.id == vm.sourceID }).map(sourceName) ?? vm.localization.string("sources.unavailable"), width: 230) {
                ForEach(vm.sources, id: \.id) { source in
                    Button(sourceName(source)) { vm.selectSource(source.id) }
                }
                Divider()
                Button(vm.localization.string("sources.title")) { openWindow(id: "servers") }
            }
            .disabled(vm.isBusy || vm.state == .connected)
        }
        .font(Theme.font(11.5))
        .padding(.horizontal, 22)
        .padding(.top, 10)
    }

    private func sourceName(_ source: ConnectionSource) -> String {
        switch source.kind {
        case .warp: return "WARP"
        case .manual: return vm.localization.string("sources.manual")
        case .subscription: return source.label.isEmpty ? vm.localization.string("sources.subscription", [String((vm.sources.firstIndex { $0.id == source.id } ?? 0) + 1)]) : source.label
        }
    }

    private func iconButton(systemName: String, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(.system(size: 20, weight: .medium))
                .foregroundColor(Theme.text)
                .frame(width: 40, height: 40)
                .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.border, lineWidth: 1))
        }
        .buttonStyle(.plain)
        .help(help)
    }

    private var languageMenu: some View {
        VStack(alignment: .leading, spacing: 2) {
            languageRow(nativeName: vm.localization.string("lang.system", [systemLanguageNativeName]), code: nil)
            Divider().overlay(Theme.border)
            ForEach(Localization.languages) { language in
                languageRow(nativeName: language.nativeName, code: language.code)
            }
        }
        .padding(6)
        .frame(width: 200)
        .background(Theme.panel)
    }

    private func languageRow(nativeName: String, code: String?) -> some View {
        let isCurrent = code == vm.settings.language || (code == nil && vm.settings.language == nil)
        return Button {
            vm.setLanguage(code)
            showingLanguageMenu = false
        } label: {
            HStack {
                Text(nativeName).font(Theme.font(12.5)).foregroundColor(Theme.text)
                Spacer()
                if isCurrent {
                    Rectangle().fill(Theme.accent).frame(width: 2, height: 14)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var systemLanguageNativeName: String {
        let code = Locale.preferredLanguages.first.flatMap { Locale(identifier: $0).language.languageCode?.identifier } ?? "en"
        return Localization.languages.first { $0.code == code }?.nativeName ?? "English"
    }

    private var logToggle: some View {
        Button {
            isLogExpanded.toggle()
        } label: {
            Text(vm.localization.string(isLogExpanded ? "main.logHide" : "main.logShow"))
                .font(Theme.font(11))
                .foregroundColor(Theme.textDim)
        }
        .buttonStyle(.plain)
        .padding(.leading, 22)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: - Status text/color (Windows `MainForm.UpdateUi`)

    private var powerLook: PowerButton.Look {
        switch vm.state {
        case .connected: return .on
        case .idle, .disconnecting: return vm.isBusy ? .busy : .off
        default: return .busy
        }
    }

    private var statusText: String {
        let key: String
        switch vm.state {
        case .connected: key = "status.connected"
        case .searching: key = "status.searching"
        case .connecting: key = "status.connecting"
        case .preparing: key = "status.preparing"
        case .disconnecting: key = "status.disconnecting"
        case .idle: key = "status.disconnected"
        }
        return vm.localization.string(key)
    }

    private var statusColor: Color {
        switch vm.state {
        case .connected: return Theme.accent
        case .searching, .connecting, .preparing, .disconnecting: return Theme.busy
        case .idle: return Theme.text
        }
    }

    private var hintText: String {
        if vm.isBusy { return vm.localization.string("hint.cancel") }
        if vm.state == .connected { return vm.localization.string("hint.disconnect") }
        if vm.selectedStrategyId == nil {
            return vm.localization.string(vm.connectionMode == .server ? "sources.hintFirstRun" : "hint.firstRun")
        }
        return vm.localization.string("hint.connect")
    }
}

/// Thin determinate progress bar — matches Windows `MainForm.PaintProgress`'s flat fill rectangle.
private struct ProgressBar: View {
    let fraction: Double

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(Theme.panel)
                Capsule().fill(Theme.busy).frame(width: geo.size.width * min(1, max(0, fraction)))
            }
        }
    }
}
