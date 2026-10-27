import SwiftUI
import ZarpCore

private struct ServerRow: Identifiable {
    let profile: ServerProfile
    var id: String { profile.id }
    var name: String { profile.label.isEmpty ? profile.host : profile.label }
    var address: String {
        let host = profile.host.contains(":") ? "[\(profile.host)]" : profile.host
        return "\(host):\(profile.port)"
    }
    var protocolName: String { profile.serverProtocol.rawValue + " / " + profile.transport.rawValue }
}

/// Edits private configuration without activating a source or changing a connection.
struct ServersView: View {
    @ObservedObject var model: ServerLibraryViewModel
    let localization: Localization
    @Environment(\.dismissWindow) private var dismissWindow
    @State private var sourceId = ""
    @State private var selected = Set<String>()
    @State private var importText = ""
    @State private var subscriptionLabel = ""
    @State private var subscriptionURL = ""
    @State private var deletingSource: String?

    private var sources: [ConnectionSource] {
        model.snapshot?.sources.sources.filter { $0.kind != .warp } ?? []
    }
    private var current: ConnectionSource? { sources.first { $0.id == sourceId } }
    private var library: ServerProfileLibrary? { model.snapshot?.library(sourceId: sourceId) }
    private var rows: [ServerRow] { (library?.profiles ?? []).map { ServerRow(profile: $0) } }
    private var canEdit: Bool { model.snapshot != nil && !model.isWorking }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(localization.string("sources.title")).font(Theme.font(17, weight: .bold))
                Spacer()
                actionButton(localization.string("sources.done")) { dismissWindow(id: "servers") }
            }
            Text(localization.string("sources.runtimePending"))
                .font(Theme.font(11.5)).foregroundColor(Theme.textDim)
                .fixedSize(horizontal: false, vertical: true)

            if sources.isEmpty {
                Text(localization.string("sources.empty")).foregroundColor(Theme.textDim)
            } else {
                sourceControls
                serverTable
                serverControls
            }

            Divider()
            importSection
            subscriptionSection
            notices
        }
        .padding(20)
        .frame(width: 840)
        .background(Theme.back)
        .foregroundColor(Theme.text)
        .task { await model.load(); reconcileSource() }
        .onChange(of: sources.map(\.id)) { _, _ in reconcileSource() }
        .onChange(of: sourceId) { _, _ in selected.removeAll() }
        .onChange(of: library?.profiles.map(\.id)) { _, ids in selected.formIntersection(Set(ids ?? [])) }
        .onChange(of: model.message) { _, notice in
            if notice?.key == "sources.imported" {
                importText = ""
                sourceId = sources.first(where: { $0.kind == .manual })?.id ?? sourceId
            } else if notice?.key == "sources.saved" {
                if let source = try? ConnectionSource(kind: .subscription, subscriptionURL: subscriptionURL) {
                    sourceId = source.id
                }
                subscriptionLabel = ""
                subscriptionURL = ""
            }
        }
        .onDisappear { model.cancel() }
        .alert(localization.string("sources.deleteTitle"), isPresented: Binding(
            get: { deletingSource != nil }, set: { if !$0 { deletingSource = nil } }
        )) {
            Button(localization.string("btn.cancel"), role: .cancel) { deletingSource = nil }
            Button(localization.string("sources.delete"), role: .destructive) {
                if let id = deletingSource { model.deleteSubscription(sourceId: id) }
                deletingSource = nil
            }
        } message: { Text(localization.string("sources.deleteHelp")) }
    }

    private var sourceControls: some View {
        HStack {
            Picker(localization.string("sources.source"), selection: $sourceId) {
                ForEach(sources, id: \.id) { source in
                    Text(sourceName(source)).tag(source.id)
                }
            }
            .frame(maxWidth: .infinity)
            if current?.kind == .subscription {
                actionButton(localization.string("sources.refresh"), enabled: canEdit) {
                    model.refresh(sourceId: sourceId)
                }
                actionButton(localization.string("sources.delete"), enabled: canEdit) {
                    deletingSource = sourceId
                }
            }
        }
        .disabled(model.isWorking)
    }

    private var serverTable: some View {
        Table(rows, selection: $selected) {
            TableColumn("") { row in
                Text(row.id == library?.selectedServerId ? "✔" : "")
                    .foregroundColor(Theme.accent)
            }.width(24)
            TableColumn(localization.string("sources.server")) { row in
                Text(row.name)
            }
            TableColumn(localization.string("sources.address")) { row in
                Text(row.address)
            }
            TableColumn(localization.string("col.protocol")) { row in
                Text(row.protocolName)
            }.width(160)
        }
        .environment(\.layoutDirection, .leftToRight)
        .tableStyle(.inset(alternatesRowBackgrounds: false))
        .scrollContentBackground(.hidden)
        .background(Theme.panel)
        .frame(height: 180)
        .disabled(model.isWorking)
    }

    private var serverControls: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                actionButton(localization.string("sources.select"), enabled: canEdit && selected.count == 1) {
                    model.selectServer(id: selected.first, sourceId: sourceId)
                }
                actionButton(localization.string("sources.automatic"), enabled: canEdit && library != nil) {
                    model.selectServer(id: nil, sourceId: sourceId)
                }
                if current?.kind == .manual {
                    actionButton(localization.string("sources.delete"), enabled: canEdit && selected.count == 1) {
                        if let id = selected.first { model.removeManualServer(id: id) }
                    }
                }
                Spacer()
                if let snapshot = model.snapshot?.subscriptions[sourceId] {
                    Text(localization.string("sources.lastUpdate", [
                        Date(timeIntervalSince1970: Double(snapshot.updatedAtMilliseconds) / 1000)
                            .formatted(date: .abbreviated, time: .shortened)
                    ])).font(Theme.font(11)).foregroundColor(Theme.textDim)
                }
            }
            if case .unavailable = library?.selection {
                Text(localization.string("sources.missingSelection")).foregroundColor(Theme.busy)
            }
        }
    }

    private var importSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(localization.string("sources.importTitle")).font(Theme.font(13, weight: .bold))
            Text(localization.string("sources.importHelp")).font(Theme.font(11)).foregroundColor(Theme.textDim)
            TextEditor(text: $importText)
                .environment(\.layoutDirection, .leftToRight)
                .scrollContentBackground(.hidden)
                .background(Theme.panel).font(Theme.monospaced(11)).frame(height: 65)
                .accessibilityLabel(localization.string("sources.importTitle"))
            actionButton(localization.string("sources.import"), enabled: canEdit && !importText.isEmpty) {
                model.importLinks(importText)
            }
        }
        .disabled(!canEdit)
    }

    private var subscriptionSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(localization.string("sources.subscriptionTitle")).font(Theme.font(13, weight: .bold))
            HStack {
                TextField(localization.string("sources.label"), text: $subscriptionLabel).frame(width: 180)
                SecureField(localization.string("sources.url"), text: $subscriptionURL)
                    .environment(\.layoutDirection, .leftToRight)
                actionButton(localization.string("btn.save"), enabled: canEdit && !subscriptionURL.isEmpty) {
                    model.saveSubscription(label: subscriptionLabel, url: subscriptionURL)
                }
            }
            Text(localization.string("sources.saveHelp")).font(Theme.font(11)).foregroundColor(Theme.textDim)
        }
        .disabled(!canEdit)
    }

    private var notices: some View {
        VStack(alignment: .leading, spacing: 6) {
            if model.isWorking {
                HStack {
                    ProgressView().controlSize(.small)
                    if model.isRefreshing {
                        Text(localization.string("sources.refreshing"))
                        actionButton(localization.string("btn.cancel")) { model.cancel() }
                    }
                }
            }
            if let message = model.message { Text(message.text(using: localization)).foregroundColor(Theme.accent) }
            if let problem = model.problem { Text(problem.text(using: localization)).foregroundColor(Theme.bad) }
            if model.snapshot?.unreadableSourceIds.contains(sourceId) == true {
                Text(localization.string("sources.storageError")).foregroundColor(Theme.bad)
            }
            if model.snapshot == nil && !model.isWorking {
                actionButton(localization.string("daemon.refresh")) { Task { await model.load(); reconcileSource() } }
            }
        }
        .font(Theme.font(11.5))
        .fixedSize(horizontal: false, vertical: true)
    }

    private func sourceName(_ source: ConnectionSource) -> String {
        if !source.label.isEmpty { return source.label }
        if source.kind == .manual { return localization.string("sources.manual") }
        // A URL can contain a secret in the host, path or query. Display only a number.
        return localization.string("sources.subscription", [String((sources.firstIndex(where: { $0.id == source.id }) ?? 0) + 1)])
    }

    private func reconcileSource() {
        if !sources.contains(where: { $0.id == sourceId }) { sourceId = sources.first?.id ?? "" }
    }
}
