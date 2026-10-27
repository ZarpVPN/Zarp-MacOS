import AppKit
import SwiftUI
import ZarpCore

/// One table row: a `Strategy` plus everything about to be displayed, pre-computed so the
/// `Table` column closures stay pure formatting.
private struct StrategyRow: Identifiable {
    let strategy: Strategy
    let displayName: String
    let isCurrent: Bool
    let resultText: String
    let resultColor: Color
    let connectText: String
    let pingText: String
    let tooltip: String
    var id: String { strategy.id }
}

/// The Strategies table: `Strategy | Protocol | Result | Connect, ms | Ping, ms`, with a narrow
/// leading column marking the saved strategy. Visual source of truth: Windows Zarp's
/// `SettingsForm` (`UI/SettingsForm.cs`'s column setup and `FillList`) and the attached screenshot
/// of that window — same column order and widths, same ✔ / ✔✔ convention, same row density.
///
/// Backed by real networking through `zarpd`/`ZarpdClient` (docs/ARCHITECTURE.md §5) — rows read
/// "not tested" until a Test/Use/scan runs. Strategies this port cannot perform (raw-socket tricks,
/// WireGuard) read "not available on macOS" with the reason as a tooltip, and are never attempted.
struct StrategiesView: View {
    @ObservedObject var vm: AppViewModel
    @State private var selection = Set<String>()
    @State private var showingCustomStrategiesSheet = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(vm.localization.string("settings.strategy"))
                    .font(Theme.font(15, weight: .bold)).foregroundColor(Theme.text)
                Spacer()
                countryMenu
            }
            Text(vm.localization.string("settings.explain"))
                .font(Theme.font(11.5)).foregroundColor(Theme.textDim)
                .fixedSize(horizontal: false, vertical: true)

            table

            HStack(spacing: 8) {
                actionButton(vm.localization.string("btn.use"), primary: true,
                             enabled: selection.count == 1 && !vm.isBusy && !selectionIsUnsupported, action: useSelected)
                actionButton(vm.localization.string("btn.testSelected"),
                             enabled: !selection.isEmpty && !vm.isBusy, action: testSelected)
                if vm.isBusy {
                    actionButton(vm.localization.string("btn.cancel")) { vm.cancel() }
                } else {
                    actionButton(vm.localization.string("btn.quickScan")) { vm.quickScan() }
                        .help(vm.localization.string("tip.quickScan", [String(max(1, vm.settings.stopAfterWorking))]))
                    actionButton(vm.localization.string("btn.fullScan")) { vm.fullScan() }
                        .help(vm.localization.string("tip.fullScan", [String(vm.strategies.count)]))
                }
                actionButton(vm.localization.string("btn.custom"), enabled: !vm.isBusy) {
                    showingCustomStrategiesSheet = true
                }
            }

            Text(statusLine)
                .font(Theme.font(11.5))
                .foregroundColor(Theme.textDim)
                .lineLimit(1)
        }
        .background(Theme.back)
        .onChange(of: vm.strategies.map(\.id)) { _, ids in selection.formIntersection(Set(ids)) }
        .sheet(isPresented: $showingCustomStrategiesSheet) {
            CustomStrategiesSheet(vm: vm, isPresented: $showingCustomStrategiesSheet)
        }
    }

    // MARK: - Table

    private var rows: [StrategyRow] {
        vm.strategies.map { s in
            let result = vm.results[s.id]
            if let reason = s.unsupportedReason {
                // Never attempted, so never a result: say plainly that this port can't do it, and
                // why (tooltip) — instead of a "not tested" that suggests pressing Test would help.
                return StrategyRow(
                    strategy: s, displayName: s.name(using: vm.localization),
                    isCurrent: false,
                    resultText: vm.localization.string("result.unavailable"),
                    resultColor: Theme.textDisabled,
                    connectText: "",
                    pingText: "",
                    tooltip: reason.text(using: vm.localization)
                )
            }
            let (text, color) = Self.resultCell(result, using: vm.localization)
            return StrategyRow(
                strategy: s, displayName: s.name(using: vm.localization),
                isCurrent: s.id == vm.selectedStrategyId,
                resultText: text,
                resultColor: color,
                connectText: (result?.ok ?? false) ? "\(result!.connectMs)" : "",
                pingText: (result?.ok ?? false) ? "\(result!.pingMs)" : "",
                tooltip: text + "\n" + (s.requiresDesync ? s.args : vm.localization.string("settings.directTip"))
                    + (result?.confirmed == true ? "\n" + vm.localization.string(result?.independent == true ? "result.independent" : "result.freshOnly") : "")
            )
        }
    }

    /// The single selected strategy is one this port can't run (so "Use" would only fail).
    private var selectionIsUnsupported: Bool {
        guard selection.count == 1, let id = selection.first, let s = vm.strategies.first(where: { $0.id == id }) else { return false }
        return s.unsupportedReason != nil
    }

    private var countryMenu: some View {
        DarkMenu(title: vm.localization.string("strategy.countrySelection", [countrySelection]), width: 218) {
            Button {
                selection.removeAll()
                vm.updateSettings { $0.strategyCountries = "all" }
            } label: {
                Label(vm.localization.string("strategy.allCountries"), systemImage: StrategyFilter.countries(vm.settings.strategyCountries).isEmpty ? "checkmark" : "")
            }
            Divider()
            ForEach(StrategyCountry.allCases, id: \.self) { country in
                Toggle(countryName(country), isOn: Binding(
                    get: { StrategyFilter.countries(vm.settings.strategyCountries).contains(country) },
                    set: { _ in
                        selection.removeAll()
                        vm.updateSettings { $0.strategyCountries = StrategyFilter.toggle($0.strategyCountries, country: country) }
                    }
                ))
            }
        }
        .accessibilityLabel(vm.localization.string("strategy.countries"))
        .disabled(vm.isBusy)
        .help(vm.localization.string("strategy.countryHint"))
    }

    private var countrySelection: String {
        let selected = StrategyFilter.countries(vm.settings.strategyCountries)
        return selected.isEmpty ? vm.localization.string("strategy.allCountries") :
            StrategyCountry.allCases.filter { selected.contains($0) }.map(countryName).joined(separator: ", ")
    }

    private func countryName(_ country: StrategyCountry) -> String {
        switch country {
        case .ru: return vm.localization.string("strategy.countryRU")
        case .ir: return vm.localization.string("strategy.countryIR")
        case .cn: return vm.localization.string("strategy.countryCN")
        }
    }

    private var table: some View {
        StrategyTable(rows: rows, selection: $selection,
                      titles: ["", "col.strategy", "col.protocol", "col.result", "col.connect", "col.ping"].map { $0.isEmpty ? "" : vm.localization.string($0) }) { id in
            guard !vm.isBusy, let strategy = vm.strategies.first(where: { $0.id == id }), strategy.unsupportedReason == nil else { return }
            vm.use(strategy)
        }
        .frame(height: 228)
        .overlay(Rectangle().stroke(Theme.border, lineWidth: 1))
    }

    /// Same rule as Windows `SettingsForm.FillList`: not tested (dim) · works ✔✔ (ok, confirmed)
    /// · works (1 check) (busy, unconfirmed) · the error text (bad).
    private static func resultCell(_ result: TestResult?, using loc: Localization) -> (text: String, color: Color) {
        guard let result else { return (loc.string("result.notTested"), Theme.textDim) }
        if result.ok {
            return result.confirmed
                ? (loc.string("result.works2"), Theme.ok)
                : (loc.string("result.works1"), Theme.busy)
        }
        return (result.displayError(using: loc), Theme.bad)
    }

    private var statusLine: String {
        guard vm.isBusy else { return vm.detail.text(using: vm.localization) }
        let progress = vm.progressTotal > 0 ? " [\(vm.progressDone)/\(vm.progressTotal)]" : ""
        return "⏳ " + vm.detail.text(using: vm.localization) + progress
    }

    private func useSelected() {
        guard selection.count == 1, let id = selection.first, let s = vm.strategies.first(where: { $0.id == id }) else { return }
        vm.use(s)
    }

    private func testSelected() {
        let items = vm.strategies.filter { selection.contains($0.id) }
        guard !items.isEmpty else { return }
        vm.testSelected(items)
    }
}

/// Native table keeps Windows row density while retaining keyboard and VoiceOver navigation.
private struct StrategyTable: NSViewRepresentable {
    let rows: [StrategyRow]
    @Binding var selection: Set<String>
    let titles: [String]
    let onUse: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.borderType = .noBorder
        scroll.drawsBackground = true
        scroll.backgroundColor = NSColor(Theme.panel)
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = false
        scroll.appearance = NSAppearance(named: .darkAqua)
        let table = NSTableView()
        table.userInterfaceLayoutDirection = .leftToRight
        scroll.userInterfaceLayoutDirection = .leftToRight
        table.identifier = NSUserInterfaceItemIdentifier("strategy-table")
        table.backgroundColor = NSColor(Theme.panel)
        table.gridColor = NSColor(Theme.border)
        table.gridStyleMask = .solidVerticalGridLineMask
        table.rowSizeStyle = .custom
        table.usesAutomaticRowHeights = false
        table.rowHeight = 19
        table.intercellSpacing = NSSize(width: 10, height: 0)
        table.usesAlternatingRowBackgroundColors = false
        table.allowsMultipleSelection = true
        table.allowsEmptySelection = true
        table.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        table.dataSource = context.coordinator
        table.delegate = context.coordinator
        table.target = context.coordinator
        table.doubleAction = #selector(Coordinator.useRow(_:))
        let identifiers = ["current", "name", "protocol", "result", "connect", "ping"]
        let widths: [CGFloat] = [24, 250, 126, 220, 78, 64]
        let minimums: [CGFloat] = [24, 190, 108, 150, 78, 64]
        for index in identifiers.indices {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifiers[index]))
            column.headerCell = DarkTableHeaderCell(textCell: titles[index])
            column.headerCell.alignment = index >= 4 ? .right : .left
            column.width = widths[index]
            column.minWidth = minimums[index]
            if index == 0 || index >= 4 {
                column.maxWidth = widths[index]
                column.resizingMask = []
            } else { column.resizingMask = [.autoresizingMask, .userResizingMask] }
            table.addTableColumn(column)
        }
        table.headerView?.frame.size.height = 25
        scroll.documentView = table
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let table = scroll.documentView as? NSTableView else { return }
        let coordinator = context.coordinator
        coordinator.parent = self
        coordinator.syncing = true
        defer { coordinator.syncing = false }
        for (index, column) in table.tableColumns.enumerated() { column.headerCell.stringValue = titles[index] }
        table.reloadData()
        table.selectRowIndexes(IndexSet(rows.indices.filter { selection.contains(rows[$0].id) }), byExtendingSelection: false)
    }

    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate {
        var parent: StrategyTable
        var syncing = false
        init(_ parent: StrategyTable) { self.parent = parent }
        func numberOfRows(in tableView: NSTableView) -> Int { parent.rows.count }
        func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? { DarkTableRowView() }
        func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row index: Int) -> NSView? {
            guard parent.rows.indices.contains(index), let column = tableColumn else { return nil }
            let row = parent.rows[index]
            let cell = tableView.makeView(withIdentifier: column.identifier, owner: self) as? NSTableCellView ?? makeCell(column.identifier)
            guard let field = cell.textField else { return cell }
            var color = Theme.textDim
            field.font = NSFont.systemFont(ofSize: 11.5, weight: .regular)
            field.alignment = .left
            switch column.identifier.rawValue {
            case "current": field.stringValue = row.isCurrent ? "✔" : ""; color = Theme.accent
            case "name":
                field.stringValue = row.displayName
                color = Theme.text
                field.font = NSFont.systemFont(ofSize: 11.5, weight: row.isCurrent ? .semibold : .regular)
            case "protocol": field.stringValue = row.strategy.transportTitle
            case "result": field.stringValue = row.resultText; color = row.resultColor
            case "connect": field.stringValue = row.connectText; field.alignment = .right
            default: field.stringValue = row.pingText; field.alignment = .right
            }
            field.textColor = NSColor(color)
            cell.toolTip = row.tooltip
            return cell
        }

        private func makeCell(_ id: NSUserInterfaceItemIdentifier) -> NSTableCellView {
            let cell = NSTableCellView()
            cell.identifier = id
            let field = NSTextField(labelWithString: "")
            field.translatesAutoresizingMaskIntoConstraints = false
            field.lineBreakMode = .byTruncatingTail
            field.maximumNumberOfLines = 1
            cell.addSubview(field)
            cell.textField = field
            NSLayoutConstraint.activate([
                field.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 2),
                field.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -2),
                field.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
            ])
            return cell
        }

        func tableViewSelectionDidChange(_ notification: Notification) {
            guard !syncing, let table = notification.object as? NSTableView else { return }
            parent.selection = Set(table.selectedRowIndexes.compactMap { parent.rows.indices.contains($0) ? parent.rows[$0].id : nil })
        }
        @objc func useRow(_ table: NSTableView) {
            guard parent.rows.indices.contains(table.clickedRow) else { return }
            parent.onUse(parent.rows[table.clickedRow].id)
        }
    }
}

private final class DarkTableRowView: NSTableRowView {
    override func drawSelection(in dirtyRect: NSRect) {
        NSColor(Theme.panelHover).setFill()
        bounds.fill()
    }
}

private final class DarkTableHeaderCell: NSTableHeaderCell {
    override func draw(withFrame rect: NSRect, in controlView: NSView) {
        NSColor(Theme.back).setFill()
        rect.fill()
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = alignment
        paragraph.lineBreakMode = .byTruncatingTail
        (stringValue as NSString).draw(in: rect.insetBy(dx: 7, dy: 5), withAttributes: [
            .font: NSFont.systemFont(ofSize: 11), .foregroundColor: NSColor(Theme.textDim), .paragraphStyle: paragraph
        ])
    }
}

/// Windows Zarp opens `strategies.txt` in Notepad (`SettingsForm.OpenCustomFile`) and reloads the
/// catalog when the user closes it. This sheet is the SwiftUI-native equivalent: an editable text
/// view over the real file — loaded when the sheet opens, written back by Save (which also reloads
/// the strategy list), and left untouched by Cancel. Malformed lines are reported right after saving,
/// so a typo isn't discovered later as a strategy that silently isn't there.
private struct CustomStrategiesSheet: View {
    @ObservedObject var vm: AppViewModel
    @Binding var isPresented: Bool
    @State private var text = ""
    @State private var loaded = false
    @State private var skippedLines: [String] = []
    @State private var saveError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(vm.localization.string("btn.custom"))
                .font(Theme.font(14, weight: .bold))
                .foregroundColor(Theme.text)
            TextEditor(text: $text)
                .environment(\.layoutDirection, .leftToRight)
                .font(Theme.monospaced(11.5))
                .foregroundColor(Theme.text)
                .scrollContentBackground(.hidden)
                .background(Theme.panel)
                .frame(minWidth: 520, minHeight: 320)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Theme.border, lineWidth: 1))
                .disabled(!loaded)
            if let saveError {
                Text(saveError)
                    .font(Theme.font(11))
                    .foregroundColor(Theme.bad)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !skippedLines.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    Text(vm.localization.string("custom.skipped", [String(skippedLines.count)]))
                        .font(Theme.font(11))
                        .foregroundColor(Theme.busy)
                    ForEach(skippedLines, id: \.self) { line in
                        Text(line)
                            .font(Theme.monospaced(10.5))
                            .foregroundColor(Theme.textDim)
                            .lineLimit(1)
                    }
                }
            }
            HStack {
                Spacer()
                actionButton(vm.localization.string("btn.cancel")) { isPresented = false }
                actionButton(vm.localization.string("btn.save"), primary: true, enabled: loaded, action: save)
            }
        }
        .padding(20)
        .background(Theme.back)
        .task {
            guard !loaded else { return }
            text = await vm.customStrategiesText()
            loaded = true
        }
    }

    private func save() {
        Task {
            switch await vm.saveCustomStrategies(text) {
            case .success(let skipped):
                if skipped.isEmpty {
                    isPresented = false
                } else {
                    // Saved, but some lines were not understood: keep the sheet open to show which.
                    skippedLines = skipped
                    saveError = nil
                }
            case .failure(let error):
                saveError = vm.localization.string("custom.saveFailed", [CustomStrategyFile.fileName, error.localizedDescription])
            }
        }
    }
}
