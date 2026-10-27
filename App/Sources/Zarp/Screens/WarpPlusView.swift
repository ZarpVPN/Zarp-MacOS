import SwiftUI
import ZarpCore

struct WarpPlusView: View {
    @ObservedObject var vm: AppViewModel
    @Environment(\.dismissWindow) private var dismissWindow
    @State private var key = ""
    @State private var account: WarpAccountType = .unknown
    @State private var working = false
    @State private var message: Msg?
    @State private var failed = false
    @State private var request: Task<Void, Never>?
    @State private var initialLoadPending = true

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(vm.localization.string("warpPlus.title")).font(Theme.font(17, weight: .bold))
            Text(vm.localization.string("warpPlus.hint")).fixedSize(horizontal: false, vertical: true)
            Text(vm.localization.string("warpPlus.account", [accountName])).font(Theme.font(13, weight: .bold))
            Text(vm.localization.string("warpPlus.key")).font(Theme.font(11.5)).foregroundColor(Theme.textDim)
            SecureField("", text: $key)
                .environment(\.layoutDirection, .leftToRight)
                .textFieldStyle(.plain)
                .padding(9)
                .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.border, lineWidth: 1))
                .accessibilityLabel(vm.localization.string("warpPlus.key"))
                .disabled(working || vm.isBusy)
            Text(vm.localization.string("warpPlus.privacy"))
                .font(Theme.font(11)).foregroundColor(Theme.textDim)
                .fixedSize(horizontal: false, vertical: true)
            if !key.isEmpty && !WarpLicense.isValid(key.trimmingCharacters(in: .whitespacesAndNewlines)) {
                Text(vm.localization.string("warpPlus.invalid")).foregroundColor(Theme.bad)
            }
            if let message {
                Text(message.text(using: vm.localization)).foregroundColor(failed ? Theme.bad : Theme.textDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                actionButton(vm.localization.string("warpPlus.apply"), primary: true,
                             enabled: !working && !vm.isBusy && WarpLicense.isValid(key.trimmingCharacters(in: .whitespacesAndNewlines))) {
                    run(apply: true, userInitiated: true)
                }
                actionButton(vm.localization.string("warpPlus.refresh"), enabled: !working && !vm.isBusy) { run(apply: false, userInitiated: true) }
                Spacer()
                if working { ProgressView().controlSize(.small) }
                actionButton(vm.localization.string("sources.done")) { request?.cancel(); key = ""; dismissWindow(id: "warp-plus") }
            }
        }
        .foregroundColor(Theme.text)
        .font(Theme.font(12))
        .padding(20)
        .frame(width: 610)
        .background(Theme.back)
        .task {
            if vm.preparingConnection { message = Msg("connection.preparing") }
            else if !vm.isBusy { run(apply: false) }
        }
        .onChange(of: vm.daemonUnavailable) { _, unavailable in
            if unavailable && !vm.preparingConnection { request?.cancel(); failed = true; message = Msg("connection.prepareFailed") }
            else if !unavailable && !working && !vm.isBusy { run(apply: false) }
        }
        .onChange(of: vm.preparingConnection) { _, inProgress in
            if !inProgress && initialLoadPending && !working && !vm.isBusy { run(apply: false) }
        }
        .onDisappear { request?.cancel(); key = "" }
    }

    private var accountName: String {
        let label: String
        switch vm.daemonUnavailable ? .unknown : account {
        case .unknown: label = "warpPlus.unknown"
        case .free: label = "warpPlus.free"
        case .plus: label = "warpPlus.plus"
        case .unlimited: label = "warpPlus.unlimited"
        case .zeroTrust: label = "warpPlus.zerotrust"
        }
        return vm.localization.string(label)
    }

    private func run(apply: Bool, userInitiated: Bool = false) {
        guard !working, !vm.isBusy else { return }
        initialLoadPending = false
        working = true
        failed = false
        message = Msg(apply ? "warpPlus.applying" : "warpPlus.loading")
        let submitted = key
        request = Task {
            defer { working = false; request = nil }
            do {
                guard await vm.ensureConnectionService(userInitiated: userInitiated) else {
                    failed = true
                    message = vm.connectionPreparationNotice ?? Msg("connection.prepareFailed")
                    return
                }
                try Task.checkCancellation()
                let status = try await (apply ? vm.engine.applyWarpLicense(submitted) : vm.engine.readWarpAccount())
                account = status.accountType
                if apply {
                    key = ""
                    message = Msg(status.accountType.isPlus ? "warpPlus.applied" : "warpPlus.unconfirmed")
                    failed = !status.accountType.isPlus
                } else { message = nil }
            } catch {
                guard !Task.isCancelled else {
                    failed = vm.daemonUnavailable
                    message = vm.daemonUnavailable ? Msg("connection.prepareFailed") : nil
                    return
                }
                failed = true
                switch (error as? WarpConnectionError)?.code {
                case "cancelled": failed = false; message = nil
                case "busy": message = Msg("warpPlus.busy")
                case "no_account": message = Msg("warpPlus.noWarp")
                case "unsupported": message = Msg("warpPlus.updateDaemon")
                case "account_timeout": message = Msg("warpPlus.timeout")
                case "bad_request": message = Msg("warpPlus.invalid")
                default: message = (error as? WarpConnectionError)?.accountSetupMessage ?? Msg(apply ? "warpPlus.applyFailed" : "warpPlus.accountFailed")
                }
            }
        }
    }
}
