import Foundation
import XCTest
@testable import ZarpCore

final class DaemonLaunchConfigurationTests: XCTestCase {
    private var manifestURL: URL {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        return root.appendingPathComponent("zarpd/cmd/zarpd/io.github.zarp.mac.zarpd.plist")
    }

    private func manifest() throws -> [String: Any] {
        try XCTUnwrap(PropertyListSerialization.propertyList(from: Data(contentsOf: manifestURL), format: nil) as? [String: Any])
    }

    private func data(_ manifest: [String: Any]) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: manifest, format: .xml, options: 0)
    }

    func testReleaseManifestHasAnExplicitExecutableIndependentOfContainerResolution() throws {
        let manifest = try manifest()
        XCTAssertNil(manifest["BundleProgram"])
        XCTAssertEqual(manifest["Program"] as? String, DaemonLaunchConfiguration.releaseProgram)
        XCTAssertNoThrow(try DaemonLaunchConfiguration.validate(data(manifest), bundleURL: URL(fileURLWithPath: "/Applications/Zarp.app")))
    }

    func testRelativeProgramAndLegacyBundleResolutionCannotPassPreflight() throws {
        var manifest = try manifest()
        manifest["Program"] = "Contents/MacOS/zarpd"
        manifest["ProgramArguments"] = ["Contents/MacOS/zarpd"]
        XCTAssertThrowsError(try DaemonLaunchConfiguration.validate(data(manifest), bundleURL: URL(fileURLWithPath: "/Applications/Zarp.app"))) {
            XCTAssertEqual($0 as? DaemonLaunchConfiguration.ValidationError, .relativeProgram)
        }
        manifest = try self.manifest()
        manifest["BundleProgram"] = "Contents/MacOS/zarpd"
        XCTAssertThrowsError(try DaemonLaunchConfiguration.validate(data(manifest), bundleURL: URL(fileURLWithPath: "/Applications/Zarp.app")))
    }

    func testAReleaseCannotRegisterAnotherCopyOrAdditionalArguments() throws {
        var manifest = try manifest()
        XCTAssertThrowsError(try DaemonLaunchConfiguration.validate(data(manifest), bundleURL: URL(fileURLWithPath: "/Applications/Other/Zarp.app"))) {
            XCTAssertEqual($0 as? DaemonLaunchConfiguration.ValidationError, .mismatchedProgram)
        }
        manifest["ProgramArguments"] = [DaemonLaunchConfiguration.releaseProgram, "-config", "/tmp/other-account"]
        XCTAssertThrowsError(try DaemonLaunchConfiguration.validate(data(manifest), bundleURL: URL(fileURLWithPath: "/Applications/Zarp.app")))
    }

    func testDebugManifestMustTargetItsOwnBuildEvenWhenThePathHasSpaces() throws {
        var manifest = try manifest()
        let bundle = URL(fileURLWithPath: "/private/tmp/Private Build/Zarp.app")
        let program = bundle.appendingPathComponent("Contents/MacOS/zarpd").path
        manifest["Program"] = program
        manifest["ProgramArguments"] = [program]
        XCTAssertNoThrow(try DaemonLaunchConfiguration.validate(data(manifest), bundleURL: bundle))
        XCTAssertThrowsError(try DaemonLaunchConfiguration.validate(data(manifest), bundleURL: URL(fileURLWithPath: "/Applications/Zarp.app")))
    }
}
