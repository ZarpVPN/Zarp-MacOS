import Foundation

/// Reject temporary or untrusted locations before privileged registration.
/// Release manifests use an explicit Program under /Applications/Zarp.app.
/// DaemonLaunchConfiguration separately verifies that the actual app copy owns
/// that executable. Debug manifests point to their own build directory.
public enum InstallLocationProblem: Equatable, Sendable {
    case mountedVolume
    case translocated
    /// Not under `/Applications`: the daemon's executable would sit somewhere a non-admin user (or
    /// malware running as them) can write.
    case notInApplications

    /// - Parameters:
    ///   - bundlePath: `Bundle.main.bundleURL.path`.
    ///   - requireSystemApplications: whether to insist on `/Applications` (true for a release
    ///     build; a debug build running from DerivedData passes false).
    public static func detect(bundlePath: String, requireSystemApplications: Bool = false) -> InstallLocationProblem? {
        // Checked first: a translocated path lives under /private/var/folders, never /Volumes, but
        // keeping the more specific signal first means a future path that somehow matched both
        // would still report the more actionable one.
        if bundlePath.contains("/AppTranslocation/") { return .translocated }
        if bundlePath.hasPrefix("/Volumes/") { return .mountedVolume }
        if requireSystemApplications && !isInSystemApplications(bundlePath) { return .notInApplications }
        return nil
    }

    /// `/Applications/Zarp.app` and `/Applications/Utilities/Zarp.app` qualify; `/Applications`
    /// itself and anything that merely starts with the same letters (`/ApplicationsFake/...`) don't.
    private static func isInSystemApplications(_ path: String) -> Bool {
        let standardized = NSString(string: path).standardizingPath
        return standardized.hasPrefix("/Applications/") && standardized.count > "/Applications/".count
    }
}
