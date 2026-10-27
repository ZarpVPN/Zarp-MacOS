import AppKit
import Foundation

struct InstalledApplication: Identifiable, Sendable {
    let path: String
    let name: String
    let exists: Bool
    var id: String { path }
}

/// Reads bundle metadata only. Never opens or executes an application.
@MainActor
final class ApplicationInventory: ObservableObject {
    @Published private(set) var applications: [InstalledApplication] = []
    @Published private(set) var loading = false
    private var selectedPaths = Set<String>()

    func include(_ paths: Set<String>) {
        selectedPaths = paths
        let known = Set(applications.map(\.path))
        for path in paths where !known.contains(path) { applications.append(Self.describe(URL(fileURLWithPath: path))) }
        sort()
    }

    func reload(selected: Set<String>) async {
        guard !loading else { return }
        include(selected)
        loading = true
        #if ZARP_APPEARANCE_PREVIEW
        applications = [InstalledApplication(path: "/Applications/Example Browser.app", name: "Example Browser", exists: true),
                        InstalledApplication(path: "/Applications/Example Messenger.app", name: "Example Messenger", exists: true)]
        #else
        applications = await Task.detached(priority: .utility) {
            let fm = FileManager.default
            let roots = ["/Applications", "/System/Applications", NSHomeDirectory() + "/Applications"]
            var found: [String: InstalledApplication] = [:]
            for path in roots {
                let root = URL(fileURLWithPath: path, isDirectory: true)
                guard let entries = fm.enumerator(at: root, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles, .skipsPackageDescendants]) else { continue }
                var count = 0
                for case let url as URL in entries {
                    count += 1
                    if Task.isCancelled || count > 10_000 || found.count >= 2000 { break }
                    if url.pathComponents.count - root.pathComponents.count > 4 { entries.skipDescendants(); continue }
                    if url.pathExtension.lowercased() == "app" {
                        entries.skipDescendants()
                        let app = Self.describe(url.resolvingSymlinksInPath().standardizedFileURL)
                        found[app.path] = app
                    }
                }
            }
            return Array(found.values)
        }.value
        #endif
        include(selectedPaths)
        loading = false
    }

    func add(_ url: URL) -> String {
        let app = Self.describe(url.resolvingSymlinksInPath().standardizedFileURL)
        if !applications.contains(where: { $0.path == app.path }) { applications.append(app); sort() }
        return app.path
    }

    nonisolated private static func describe(_ url: URL) -> InstalledApplication {
        var name = url.deletingPathExtension().lastPathComponent
        if let data = try? Data(contentsOf: url.appendingPathComponent("Contents/Info.plist")),
           let info = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any] {
            name = (info["CFBundleDisplayName"] as? String) ?? (info["CFBundleName"] as? String) ?? name
        }
        return InstalledApplication(path: url.path, name: name, exists: FileManager.default.fileExists(atPath: url.path))
    }

    private func sort() { applications.sort { $0.name.localizedStandardCompare($1.name) == .orderedAscending } }
}
