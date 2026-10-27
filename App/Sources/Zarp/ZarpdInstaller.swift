import Foundation
import ServiceManagement
import ZarpCore
import ZarpdIPC

/// Platform adapter for automatic preparation. Only Zarp's bundled daemon is
/// controlled here. The coordinator owns retries and active-connection guards.
@MainActor
final class ZarpdInstaller: AutomaticDaemonService {
    private static let plistName = DaemonLaunchConfiguration.plistName
    private var service = SMAppService.daemon(plistName: plistName)
    private let client: ZarpdClient
    private let expectedVersion: String
    private enum LocationError: Error { case moveToApplications }

    init(client: ZarpdClient, expectedVersion: String) {
        self.client = client
        self.expectedVersion = expectedVersion
    }

    var registrationStatus: DaemonRegistrationStatus {
        switch service.status {
        case .notRegistered: return .missing
        case .enabled: return .enabled
        case .requiresApproval: return .approvalRequired
        case .notFound: return .unavailable
        @unknown default: return .unavailable
        }
    }

    func health() async -> DaemonServiceHealth {
        guard let ping = try? await client.ping(timeout: 1) else { return .unreachable }
        let outdated = ping.effectiveProtocol < ZarpdClient.protocolVersion || (ping.version != "dev" && ping.version != expectedVersion)
        guard outdated else { return .ready }
        guard (try? await client.isIdleForUpdate()) == true else { return .busy }
        return .outdated
    }

    func validateLocation() throws {
        #if DEBUG
        let requireApplications = false
        #else
        let requireApplications = true
        #endif
        if InstallLocationProblem.detect(bundlePath: Bundle.main.bundleURL.path, requireSystemApplications: requireApplications) != nil {
            throw LocationError.moveToApplications
        }
        let manifest = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LaunchDaemons/" + Self.plistName)
        do {
            try DaemonLaunchConfiguration.validate(Data(contentsOf: manifest), bundleURL: Bundle.main.bundleURL)
        } catch DaemonLaunchConfiguration.ValidationError.mismatchedProgram {
            throw LocationError.moveToApplications
        }
    }

    func registerForRecovery() throws {
        try validateLocation()
        try service.register()
    }

    func unregisterForRecovery() async throws {
        try validateLocation()
        do { try await service.unregister() }
        catch {
            guard (error as NSError).code == kSMErrorJobNotFound, service.status == .notRegistered else { throw error }
        }
        service = SMAppService.daemon(plistName: Self.plistName)
    }

    func openApprovalSettings() { SMAppService.openSystemSettingsLoginItems() }
}
