import Foundation

/// Release installation has a fixed path. An explicit Program avoids depending
/// on the background-item database resolving a relative executable's container.
public enum DaemonLaunchConfiguration {
    public static let label = "io.github.zarp.mac.zarpd"
    public static let plistName = label + ".plist"
    public static let releaseProgram = "/Applications/Zarp.app/Contents/MacOS/zarpd"

    public enum ValidationError: String, Error {
        case invalidManifest, relativeProgram, mismatchedProgram
    }

    public static func validate(_ data: Data, bundleURL: URL) throws {
        guard data.count <= 16_384,
              let manifest = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              manifest["Label"] as? String == label,
              manifest["BundleProgram"] == nil,
              let program = manifest["Program"] as? String,
              manifest["ProgramArguments"] as? [String] == [program] else {
            throw ValidationError.invalidManifest
        }
        guard program.hasPrefix("/"), NSString(string: program).standardizingPath == program else {
            throw ValidationError.relativeProgram
        }
        guard program == bundleURL.appendingPathComponent("Contents/MacOS/zarpd").standardizedFileURL.path else {
            throw ValidationError.mismatchedProgram
        }
    }
}
