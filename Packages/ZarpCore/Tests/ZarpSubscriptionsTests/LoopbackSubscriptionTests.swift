import XCTest
import Darwin
import ZarpCore
@testable import ZarpSubscriptions

final class LoopbackSubscriptionTests: XCTestCase {
    func testRealHTTPSGzipRedirectRetryLimitsAndTrustFailure() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("zarp-subscription-https-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/subscription-fixture.go")
        let binary = directory.appendingPathComponent("subscription-fixture")
        let environment = ProcessInfo.processInfo.environment
        let build = Process()
        // Use the compiler selected by the caller, including actions/setup-go.
        // Keep compiler policy explicit without inheriting unrelated settings.
        build.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        build.arguments = ["go", "build", "-trimpath", "-o", binary.path, source.path]
        var buildEnvironment = ["PATH": environment["PATH"] ?? "/usr/bin:/bin",
                             "HOME": environment["HOME"] ?? FileManager.default.homeDirectoryForCurrentUser.path,
                             "GOTOOLCHAIN": "local", "GOENV": "off", "GOFLAGS": "",
                             "GO111MODULE": "off", "GOPROXY": "off", "GOSUMDB": "off", "CGO_ENABLED": "0",
                             "TMPDIR": directory.path]
        if let cache = environment["GOCACHE"] { buildEnvironment["GOCACHE"] = cache }
        build.environment = buildEnvironment
        build.standardOutput = FileHandle.nullDevice; build.standardError = FileHandle.nullDevice
        try build.run()
        defer { if build.isRunning { build.terminate(); build.waitUntilExit() } }
        // A fresh CI image can need to compile the standard library first.
        let buildDeadline = ContinuousClock.now.advanced(by: .seconds(90))
        while build.isRunning && ContinuousClock.now < buildDeadline { try await Task.sleep(nanoseconds: 10_000_000) }
        guard !build.isRunning else { throw FixtureError.build }
        build.waitUntilExit()
        guard build.terminationStatus == 0 else { throw FixtureError.build }
        let input = Pipe(), output = Pipe()
        let child = Process()
        child.executableURL = binary
        child.environment = ["PATH": "/usr/bin:/bin", "TMPDIR": directory.path]
        child.standardInput = input; child.standardOutput = output; child.standardError = FileHandle.nullDevice
        try child.run()
        defer {
            try? input.fileHandleForWriting.close()
            // The fixed fixture stops on EOF and independently after 40 seconds.
            // No numeric PID/group fallback or process-name signal is used.
        }
        var data = Data()
        let metadataDeadline = ContinuousClock.now.advanced(by: .seconds(3))
        var descriptor = pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
        while !data.contains(10) && data.count < 16_384 && ContinuousClock.now < metadataDeadline {
            guard poll(&descriptor, 1, 50) >= 0 else { throw FixtureError.metadata }
            if descriptor.revents & Int16(POLLIN | POLLHUP) != 0 {
                guard let byte = try output.fileHandleForReading.read(upToCount: 1), !byte.isEmpty else { throw FixtureError.metadata }
                data.append(byte)
            }
        }
        guard data.last == 10 else { throw FixtureError.metadata }
        struct Metadata: Decodable { let version: Int; let endpoint: String; let certificate: String }
        let metadata = try JSONDecoder().decode(Metadata.self, from: data)
        let endpoint = try XCTUnwrap(URL(string: metadata.endpoint))
        guard metadata.version == 1, endpoint.host == "127.0.0.1", let port = endpoint.port,
              let certificate = Data(base64Encoded: metadata.certificate) else { throw FixtureError.metadata }
        let transport = FoundationSubscriptionTransport(loopbackTestCertificate: certificate, port: port)
        let downloader = SubscriptionDownloader(transport: transport)
        let cache = SubscriptionCache(directory: directory.appendingPathComponent("cache"))
        for path in ["gzip", "redirect", "agents", "gzip"] {
            let source = try ConnectionSource(kind: .subscription, subscriptionURL: endpoint.appendingPathComponent(path).absoluteString)
            let result = try await downloader.load(source: source)
            XCTAssertEqual(result.profiles.count, 1)
            XCTAssertEqual(result.profiles.first?.label, "Fixture")
        }
        let large = try ConnectionSource(kind: .subscription, subscriptionURL: endpoint.appendingPathComponent("gzip-large").absoluteString)
        let good = try SubscriptionParser.parse(Data("trojan://private-cache-password@server.example.test:443".utf8))
        _ = try cache.replace(source: large, result: good, updatedAt: Date())
        let previous = try cache.load(source: large)
        do { _ = try await downloader.load(source: large); XCTFail("gzip expansion exceeded the delivered-body limit") }
        catch { XCTAssertEqual(error as? SubscriptionError, .size) }
        XCTAssertEqual(try cache.load(source: large), previous)
        let downgrade = try ConnectionSource(kind: .subscription, subscriptionURL: endpoint.appendingPathComponent("downgrade").absoluteString)
        do { _ = try await downloader.load(source: downgrade); XCTFail("real TLS redirect downgraded to HTTP") }
        catch { XCTAssertEqual(error as? SubscriptionError, .redirect) }
        do { _ = try await FoundationSubscriptionTransport().get(url: endpoint.appendingPathComponent("gzip"), userAgent: "Zarp/1.0", deadline: .now.advanced(by: .seconds(2))); XCTFail("system trust accepted the isolated fixture CA") }
        catch { XCTAssertEqual(error as? SubscriptionError, .tls) }
        try input.fileHandleForWriting.close()
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while child.isRunning && ContinuousClock.now < deadline { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertFalse(child.isRunning)
        if !child.isRunning { child.waitUntilExit(); XCTAssertEqual(child.terminationStatus, 0) }
        try output.fileHandleForReading.close()
    }

    private enum FixtureError: Error { case build, metadata }
}
