import AppKit
import SwiftUI
import UniformTypeIdentifiers
import ZarpCore

struct ApplicationRoutingView: View {
    @ObservedObject var vm: AppViewModel
    @StateObject private var inventory = ApplicationInventory()
    @Environment(\.dismissWindow) private var dismissWindow
    @State private var mode: ServerRoutingPolicy.ApplicationMode = .all
    @State private var paths = Set<String>()
    @State private var search = ""
    @State private var problem: Msg?

    private var filtered: [InstalledApplication] {
        inventory.applications.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || $0.path.localizedCaseInsensitiveContains(search) }
    }
    private var hasChanges: Bool { vm.settings.serverRouting.version != 1 || mode != vm.settings.serverRouting.applicationMode || paths != Set(vm.settings.serverRouting.applicationPaths) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(vm.localization.string("apps.title")).font(Theme.font(15, weight: .bold))
            HStack {
                ToggleSwitchView(title: vm.localization.string("apps.enable"), isOn: Binding(
                    get: { mode != .all }, set: { mode = $0 ? .include : .all }
                ))
                if mode != .all {
                    DarkMenu(title: modeTitle(mode), width: 230) {
                        ForEach([ServerRoutingPolicy.ApplicationMode.include, .exclude], id: \.rawValue) { value in
                            Button(modeTitle(value)) { mode = value }
                        }
                    }
                }
            }
            Text(vm.localization.string("apps.help"))
                .font(Theme.font(11.5)).foregroundColor(Theme.textDim).fixedSize(horizontal: false, vertical: true)
            if vm.connectionMode == .warp {
                Text(vm.localization.string("apps.serverOnly"))
                    .font(Theme.font(11.5)).foregroundColor(Theme.busy).fixedSize(horizontal: false, vertical: true)
            }
            TextField(vm.localization.string("apps.search"), text: $search)
                .textFieldStyle(.plain).padding(9).background(RoundedRectangle(cornerRadius: 7).fill(Theme.panel))
                .overlay(RoundedRectangle(cornerRadius: 7).stroke(Theme.border, lineWidth: 1))
            Table(filtered) {
                TableColumn("") { app in
                    Toggle("", isOn: Binding(get: { paths.contains(app.path) }, set: { enabled in
                        if enabled { paths.insert(app.path) } else { paths.remove(app.path) }
                    })).labelsHidden().toggleStyle(.checkbox).disabled(mode == .all)
                        .accessibilityLabel(app.name)
                }.width(26)
                TableColumn(vm.localization.string("apps.application")) { app in
                    HStack(spacing: 7) {
                        Image(nsImage: icon(app)).resizable().frame(width: 18, height: 18)
                        Text(app.name).foregroundColor(app.exists ? Theme.text : Theme.bad).lineLimit(1)
                    }
                }.width(min: 170, ideal: 220)
                TableColumn(vm.localization.string("apps.path")) { app in
                    Text(app.path).font(Theme.font(11)).foregroundColor(Theme.textDim).lineLimit(1).help(app.path)
                }
            }
            .environment(\.layoutDirection, .leftToRight)
            .tableStyle(.inset(alternatesRowBackgrounds: false)).scrollContentBackground(.hidden)
            .background(Theme.panel).overlay(Rectangle().stroke(Theme.border, lineWidth: 1))
            .frame(minHeight: 240, maxHeight: .infinity)
            HStack {
                Text(vm.localization.string("apps.selected", [String(paths.count)])).foregroundColor(Theme.textDim)
                if inventory.loading { ProgressView().controlSize(.small) }
                Spacer()
            }.font(Theme.font(11))
            if let problem { Text(problem.text(using: vm.localization)).font(Theme.font(11.5)).foregroundColor(Theme.bad) }
            Text(vm.localization.string("apps.dnsHelp"))
                .font(Theme.font(11)).foregroundColor(Theme.textDim).fixedSize(horizontal: false, vertical: true)
            Text(vm.localization.string("connection.nextConnection"))
                .font(Theme.font(11)).foregroundColor(Theme.textDim)
            HStack(spacing: 8) {
                actionButton(vm.localization.string("apps.add"), action: add)
                actionButton(vm.localization.string("daemon.refresh"), enabled: !inventory.loading) { Task { await inventory.reload(selected: paths) } }
                Spacer()
                actionButton(vm.localization.string("btn.save"), primary: true, enabled: hasChanges && vm.isReady && !vm.isBusy, action: save)
                actionButton(vm.localization.string("settings.close")) { dismissWindow(id: "applications") }
            }
        }
        .padding(20).font(Theme.font(12)).foregroundColor(Theme.text).background(Theme.back)
        .frame(minWidth: 800, minHeight: 620)
        .task {
            mode = vm.settings.serverRouting.applicationMode
            paths = Set(vm.settings.serverRouting.applicationPaths)
            await inventory.reload(selected: paths)
        }
        .onChange(of: paths) { _, selected in inventory.include(selected) }
    }

    private func modeTitle(_ value: ServerRoutingPolicy.ApplicationMode) -> String {
        switch value {
        case .all: return vm.localization.string("apps.modeAll")
        case .include: return vm.localization.string("apps.modeInclude")
        case .exclude: return vm.localization.string("apps.modeExclude")
        }
    }

    private func icon(_ application: InstalledApplication) -> NSImage {
        #if ZARP_APPEARANCE_PREVIEW
        return NSImage(systemSymbolName: "app", accessibilityDescription: nil) ?? NSImage()
        #else
        return NSWorkspace.shared.icon(forFile: application.path)
        #endif
    }

    private func add() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true; panel.canChooseDirectories = false
        panel.treatsFilePackagesAsDirectories = false; panel.allowsMultipleSelection = true
        panel.allowedContentTypes = [.applicationBundle, .executable]
        panel.begin { response in
            guard response == .OK else { return }
            for url in panel.urls { paths.insert(inventory.add(url)) }
        }
    }

    private func save() {
        var policy = vm.settings.serverRouting
        policy.version = 1; policy.applicationMode = mode; policy.applicationPaths = paths.sorted()
        do { try policy.validate() } catch { problem = Msg(mode == .include && paths.isEmpty ? "apps.choose" : "routing.invalid"); return }
        vm.updateSettings {
            $0.serverRouting = policy
            if policy.filtersApplications { $0.routeAllTraffic = true }
        }
        problem = nil
    }
}
