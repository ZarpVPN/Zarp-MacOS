import SwiftUI
import ZarpCore

struct ConnectionSettingsView: View {
    @ObservedObject var vm: AppViewModel
    @ObservedObject private var library: ServerLibraryViewModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismissWindow) private var dismissWindow
    @State private var useServer = false
    @State private var serverText = ""
    @State private var sourceID = ""
    @State private var endpointText = ""
    @State private var policy = ServerRoutingPolicy()
    @State private var problem: Msg?
    @State private var saving = false
    @State private var saveTask: Task<Void, Never>?

    init(vm: AppViewModel) { self.vm = vm; self.library = vm.serverLibrary }

    private var canEdit: Bool { vm.isReady && !vm.isBusy && !saving && vm.state != .connected }
    private var servers: [ConnectionSource] { vm.sources.filter { $0.kind != .warp } }
    private var selected: ConnectionSource? { servers.first { $0.id == sourceID } }
    private var savedCount: Int { library.snapshot?.library(sourceId: sourceID)?.profiles.count ?? 0 }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(vm.localization.string("settings.connection")).font(Theme.font(15, weight: .bold))
            ToggleSwitchView(title: vm.localization.string("connection.useServer"), isOn: $useServer, isEnabled: canEdit)

            if useServer {
                Text(vm.localization.string("connection.serverHelp"))
                    .font(Theme.font(11.5)).foregroundColor(Theme.textDim)
                    .fixedSize(horizontal: false, vertical: true)
                if !servers.isEmpty {
                    HStack {
                        Text(vm.localization.string("connection.savedSource"))
                        DarkMenu(title: selected.map(sourceName) ?? vm.localization.string("connection.newServer"), width: 330) {
                            ForEach(servers, id: \.id) { source in
                                Button(sourceName(source)) { sourceID = source.id; serverText = source.subscriptionURL ?? "" }
                            }
                            Divider()
                            Button(vm.localization.string("connection.newServer")) { sourceID = ""; serverText = "" }
                            Button(vm.localization.string("sources.title")) { openWindow(id: "servers") }
                        }.disabled(!canEdit)
                        Spacer()
                    }
                }
                editor($serverText).accessibilityLabel(vm.localization.string("connection.serverInput"))
                if savedCount > 0 {
                    Text(vm.localization.string("connection.savedServers", [String(savedCount)]))
                        .font(Theme.font(11)).foregroundColor(Theme.textDim)
                }
                HStack {
                    ToggleSwitchView(title: vm.localization.string("connection.ipv6"), isOn: $policy.ipv6, isEnabled: canEdit)
                    Text(vm.localization.string("connection.dns"))
                    TextField("1.1.1.1", text: $policy.dnsServer)
                        .environment(\.layoutDirection, .leftToRight)
                        .textFieldStyle(.plain).font(Theme.monospaced(11.5))
                        .padding(8).frame(width: 164)
                        .background(RoundedRectangle(cornerRadius: 7).fill(Theme.panel))
                        .overlay(RoundedRectangle(cornerRadius: 7).stroke(Theme.border, lineWidth: 1))
                        .disabled(!canEdit)
                }
                Text(vm.localization.string("connection.serverSaveHelp"))
                    .font(Theme.font(11)).foregroundColor(Theme.textDim)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text(vm.localization.string("settings.endpoints")).font(Theme.font(13, weight: .bold))
                Text(vm.localization.string("settings.endpointHelp"))
                    .font(Theme.font(11.5)).foregroundColor(Theme.textDim)
                    .fixedSize(horizontal: false, vertical: true)
                editor($endpointText).accessibilityLabel(vm.localization.string("settings.endpoints"))
                if vm.settings.warpEndpoints.count == 1 {
                    Text(vm.localization.string("settings.singleEndpoint")).font(Theme.font(11)).foregroundColor(Theme.busy)
                }
                HStack {
                    actionButton(vm.localization.string("btn.resetEndpoints"), enabled: canEdit && !endpointText.isEmpty) { endpointText = ""; problem = nil }
                    Spacer()
                    actionButton(vm.localization.string("warpPlus.title"), enabled: !saving) { openWindow(id: "warp-plus") }
                }
            }
            if let problem {
                Text(problem.text(using: vm.localization)).foregroundColor(Theme.bad)
                    .font(Theme.font(11.5)).fixedSize(horizontal: false, vertical: true)
            }
            if saving {
                HStack {
                    ProgressView().controlSize(.small)
                    Text(vm.localization.string("connection.saving"))
                    actionButton(vm.localization.string("btn.cancel")) { saveTask?.cancel() }
                }
            }
            Text(vm.localization.string("connection.nextConnection"))
                .font(Theme.font(11)).foregroundColor(Theme.textDim)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                Spacer()
                actionButton(vm.localization.string("btn.save"), primary: true, enabled: canEdit, action: save)
                actionButton(vm.localization.string("settings.close")) { dismissWindow(id: "connection") }
            }.padding(.top, 8)
        }
        .foregroundColor(Theme.text).font(Theme.font(12))
        .padding(20).frame(width: 660).background(Theme.back)
        .onAppear {
            useServer = vm.connectionMode == .server
            sourceID = (useServer ? vm.sourceID : servers.first?.id) ?? ""
            serverText = selected?.subscriptionURL ?? ""
            endpointText = vm.settings.warpEndpoints.joined(separator: "\n")
            policy = vm.settings.serverRouting
        }
        .task { await library.load() }
        .onChange(of: vm.sources.map(\.id)) { _, ids in
            if !ids.contains(sourceID) { sourceID = servers.first?.id ?? ""; serverText = selected?.subscriptionURL ?? "" }
        }
        .onDisappear { saveTask?.cancel() }
    }

    private func editor(_ text: Binding<String>) -> some View {
        TextEditor(text: text).environment(\.layoutDirection, .leftToRight).font(Theme.monospaced(11.5)).scrollContentBackground(.hidden)
            .padding(6).frame(height: 145).background(Theme.panel)
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.border, lineWidth: 1))
            .disabled(!canEdit)
    }

    private func save() {
        let endpoints: [String]
        do { endpoints = try WarpEndpoint.parseList(endpointText).map(\.description) }
        catch { problem = Msg("err.endpointList", String((error as? WarpEndpoint.ListError)?.line ?? 0)); return }
        var currentPolicy = vm.settings.serverRouting
        currentPolicy.version = 1
        currentPolicy.ipv6 = policy.ipv6
        currentPolicy.dnsServer = policy.dnsServer.trimmingCharacters(in: .whitespacesAndNewlines)
        problem = nil; saving = true
        let activeServer = useServer, text = serverText, existing = sourceID
        saveTask = Task { @MainActor in
            defer { saving = false; saveTask = nil }
            problem = await vm.configureConnection(useServer: activeServer, input: text, source: existing.isEmpty ? nil : existing, endpoints: endpoints, policy: currentPolicy)
            if problem == nil { dismissWindow(id: "connection") }
        }
    }

    private func sourceName(_ source: ConnectionSource) -> String {
        if source.kind == .manual { return vm.localization.string("sources.manual") }
        return source.label.isEmpty ? vm.localization.string("sources.subscription", [String((servers.firstIndex { $0.id == source.id } ?? 0) + 1)]) : source.label
    }
}
