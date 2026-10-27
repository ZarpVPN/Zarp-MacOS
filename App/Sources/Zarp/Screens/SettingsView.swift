import AppKit
import SwiftUI
import ZarpCore
import ZarpdIPC

/// A separate compact window, with the strategy list and two option columns.
struct SettingsView: View {
    @ObservedObject var vm: AppViewModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismissWindow) private var dismissWindow

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    StrategiesView(vm: vm)
                    HStack(spacing: 8) {
                        actionButton(vm.localization.string("settings.connection"), enabled: vm.isReady) { openWindow(id: "connection") }
                        actionButton(vm.localization.string("apps.title"), enabled: vm.isReady) { openWindow(id: "applications") }
                        Spacer()
                    }
                    optionsSection
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack(spacing: 8) {
                Text("Zarp \(appVersion)").font(Theme.font(11)).foregroundColor(Theme.textDim)
                Spacer()
                actionButton(vm.localization.string("btn.licenses")) { vm.revealLicenses() }
                actionButton(vm.localization.string("settings.close")) { dismissWindow(id: "settings") }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
            .background(Theme.back)
        }
        .background(Theme.back)
        .frame(minWidth: 820, minHeight: 690)
        .onAppear { vm.refreshAutostart() }
        .onDisappear { vm.reloadSources() }
    }

    private var optionsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(vm.localization.string("settings.options"))
                .font(Theme.font(15, weight: .bold))
                .foregroundColor(Theme.text)

            HStack(alignment: .top, spacing: 42) {
                VStack(alignment: .leading, spacing: 6) {
                    ToggleSwitchView(title: vm.localization.string("opt.autoConnect"),
                                     isOn: Binding(get: { vm.settings.autoConnectOnStart },
                                                    set: { v in vm.updateSettings { $0.autoConnectOnStart = v } }))
                    ToggleSwitchView(title: vm.localization.string("opt.autostart"),
                                     isOn: Binding(get: { vm.autostartEnabled },
                                                    set: { vm.setAutostart($0) }))

                    HStack(spacing: 10) {
                        Text(vm.localization.string("opt.onClose"))
                            .font(Theme.font(12.5))
                            .foregroundColor(Theme.text)
                        DarkMenu(title: vm.localization.string(closeActionKeys[closeActionBinding.wrappedValue]), width: 220) {
                            ForEach(closeActionKeys.indices, id: \.self) { index in
                                Button(vm.localization.string(closeActionKeys[index])) { closeActionBinding.wrappedValue = index }
                            }
                        }
                        .accessibilityLabel(vm.localization.string("opt.closeAccessible"))
                    }

                    ToggleSwitchView(title: vm.localization.string("opt.disconnectOnExit"),
                                     isOn: Binding(get: { vm.settings.disconnectOnExit },
                                                    set: { v in vm.updateSettings { $0.disconnectOnExit = v } }))
                    ToggleSwitchView(title: vm.localization.string(vm.connectionMode == .server ? "opt.routeAllServer" : "opt.routeAll"),
                                     isOn: Binding(get: { vm.settings.routeAllTraffic },
                                                    set: { v in vm.updateSettings { $0.routeAllTraffic = v } }),
                                     isEnabled: vm.connectionMode != .server || !vm.settings.serverRouting.filtersApplications)
                        .help(vm.localization.string("opt.routeAllTip"))
                    ToggleSwitchView(title: vm.localization.string(vm.connectionMode == .server ? "opt.overrideDNSServer" : "opt.overrideDNS"),
                                     isOn: Binding(get: { vm.settings.overrideDNS && vm.settings.routeAllTraffic },
                                                    set: { v in vm.updateSettings { $0.overrideDNS = v } }),
                                     isEnabled: vm.settings.routeAllTraffic)
                    ToggleSwitchView(title: vm.localization.string("opt.reconnect"),
                                     isOn: Binding(get: { vm.settings.reconnectOnLoss },
                                                    set: { v in vm.updateSettings { $0.reconnectOnLoss = v } }))
                    ToggleSwitchView(title: vm.localization.string("opt.isolate"),
                                     isOn: Binding(get: { vm.settings.isolateTests },
                                                    set: { v in vm.updateSettings { $0.isolateTests = v } }))
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                VStack(alignment: .leading, spacing: 14) {
                    labeledStepper(vm.localization.string("opt.timeout"),
                                   value: Binding(get: { vm.settings.testTimeoutSec },
                                                  set: { v in vm.updateSettings { $0.testTimeoutSec = v } }),
                                   range: 5...60)
                    // Localization already turns the file's literal "\n" into a real newline
                    // (Localization.parseTable); flatten it back to a space for this single-line label.
                    labeledStepper(vm.localization.string("opt.stopAfter").replacingOccurrences(of: "\n", with: " "),
                                   value: Binding(get: { vm.settings.stopAfterWorking },
                                                  set: { v in vm.updateSettings { $0.stopAfterWorking = v } }),
                                   range: 1...100)

                    HStack(spacing: 8) {
                        actionButton(vm.localization.string("btn.dataFolder")) { openDataFolder() }
                        Spacer(minLength: 0)
                    }

                }
                .frame(width: 320, alignment: .leading)

            }
        }
    }

    private func labeledStepper(_ title: String, value: Binding<Int>, range: ClosedRange<Int>) -> some View {
        HStack(spacing: 10) {
            Text(title)
                .font(Theme.font(12.5))
                .foregroundColor(Theme.text)
                .frame(maxWidth: 170, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            NumberStepperView(value: value, range: range)
        }
    }

    private let closeActionKeys = ["opt.closeAsk", "opt.closeTray", "opt.closeExit"]

    private var closeActionBinding: Binding<Int> {
        Binding(
            get: {
                if vm.settings.askBeforeClose { return 0 }
                return vm.settings.minimizeToMenuBar ? 1 : 2
            },
            set: { newValue in
                vm.updateSettings { s in
                    s.askBeforeClose = newValue == 0
                    if !s.askBeforeClose { s.minimizeToMenuBar = newValue == 1 }
                }
            }
        )
    }

    // MARK: - Actions

    private func openDataFolder() {
        NSWorkspace.shared.activateFileViewerSelecting([AppViewModel.dataDirectory()])
    }

    private var appVersion: String { AppViewModel.appVersion }
}
