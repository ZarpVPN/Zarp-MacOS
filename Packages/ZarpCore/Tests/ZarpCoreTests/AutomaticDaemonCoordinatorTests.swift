import XCTest
@testable import ZarpCore

final class AutomaticDaemonCoordinatorTests: XCTestCase {
    @MainActor
    func testNativeFailureProducesOrderedJournalEventsWithoutPrivateErrorDetails() async {
        let service = AutomaticServiceFixture(registration: .enabled)
        service.registrationError = NSError(domain: "SMAppServiceErrorDomain", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "private-license-and-profile", NSFilePathErrorKey: "/private/account/key"])
        var events: [DaemonPreparationEvent] = []
        let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { true }, pause: {}, onEvent: { events.append($0) })
        let result = await coordinator.ensureReady()
        XCTAssertEqual(result, .failed)
        XCTAssertEqual(events, [.checking, .replacing, .registering, .failed("SMAppServiceErrorDomain (1)")])
        let messages = events.map(\.message)
        XCTAssertEqual(messages.last?.key, "log.connectionPreparationFailed")
        XCTAssertEqual(messages.last?.args, ["SMAppServiceErrorDomain (1)"])
        XCTAssertFalse(messages.description.contains("private-license"))
        XCTAssertFalse(messages.description.contains("/private/account"))
    }

    @MainActor
    func testReadinessTimeoutIsReportedOnceInsteadOfLeavingAnEmptyJournal() async {
        let service = AutomaticServiceFixture()
        service.healthAfterRegistration = .unreachable
        var events: [DaemonPreparationEvent] = []
        let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { true }, pause: {}, onEvent: { events.append($0) })
        let result = await coordinator.ensureReady()
        XCTAssertEqual(result, .failed)
        XCTAssertEqual(events, [.checking, .registering, .waiting, .failed("startup_timeout")])
    }

    @MainActor
    func testResponsiveAndBusyServicesAreNeverReplaced() async {
        for health in [DaemonServiceHealth.ready, .busy] {
            let service = AutomaticServiceFixture(health: health)
            let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { true }, pause: {})
            let result = await coordinator.ensureReady()
            XCTAssertEqual(result, .ready)
            XCTAssertEqual(service.events, [])
        }
    }

    @MainActor
    func testFirstLaunchRegistersWithoutUnregisteringAMissingService() async {
        let service = AutomaticServiceFixture()
        let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { true }, pause: {})
        let result = await coordinator.ensureReady()
        XCTAssertEqual(result, .ready)
        XCTAssertEqual(service.events, ["validate", "register"])
    }

    @MainActor
    func testUnreachableRegistrationAndOutdatedIdleServiceAreReplaced() async {
        for health in [DaemonServiceHealth.unreachable, .outdated] {
            let service = AutomaticServiceFixture(health: health, registration: .enabled)
            let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { true }, pause: {})
            let result = await coordinator.ensureReady()
            XCTAssertEqual(result, .ready)
            XCTAssertEqual(service.events, ["validate", "unregister", "removed", "register"])
        }
    }

    @MainActor
    func testTransientLaunchDelayDoesNotReplaceRegistration() async {
        let service = AutomaticServiceFixture(registration: .enabled)
        let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { true }, pause: { service.reportedHealth = .ready })
        let result = await coordinator.ensureReady()
        XCTAssertEqual(result, .ready)
        XCTAssertEqual(service.events, [])
    }

    @MainActor
    func testActiveWorkDefersReplacementWithoutConsumingAutomaticAttempt() async {
        let service = AutomaticServiceFixture(registration: .enabled)
        var idle = false
        let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { idle }, pause: {})
        let deferred = await coordinator.ensureReady()
        XCTAssertEqual(deferred, .deferred)
        XCTAssertEqual(service.events, [])
        XCTAssertTrue(coordinator.canRepairAutomatically)
        idle = true
        let ready = await coordinator.ensureReady()
        XCTAssertEqual(ready, .ready)
        XCTAssertEqual(service.events, ["validate", "unregister", "removed", "register"])
    }

    @MainActor
    func testFailedRegistrationCannotCreateAMonitoringLoopButConnectCanRetry() async {
        let service = AutomaticServiceFixture()
        service.registrationError = FixtureFailure.denied
        let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { true }, pause: {})
        let failed = await coordinator.ensureReady()
        XCTAssertEqual(failed, .failed)
        XCTAssertFalse(coordinator.canRepairAutomatically)
        let observedAgain = await coordinator.ensureReady()
        XCTAssertEqual(observedAgain, .failed)
        XCTAssertEqual(service.events, ["validate", "register"])
        service.registrationError = nil
        let retried = await coordinator.ensureReady(userInitiated: true)
        XCTAssertEqual(retried, .ready)
        XCTAssertEqual(service.events, ["validate", "register", "validate", "register"])
    }

    @MainActor
    func testApprovalOpensSystemSettingsOnceUntilExplicitUserAction() async {
        let service = AutomaticServiceFixture(registration: .approvalRequired)
        let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { true }, pause: {})
        let first = await coordinator.ensureReady()
        let second = await coordinator.ensureReady()
        XCTAssertEqual(first, .approvalRequired)
        XCTAssertEqual(second, .approvalRequired)
        XCTAssertFalse(coordinator.canRepairAutomatically)
        XCTAssertEqual(service.events, ["approval"])
        let explicit = await coordinator.ensureReady(userInitiated: true)
        XCTAssertEqual(explicit, .approvalRequired)
        XCTAssertEqual(service.events, ["approval", "approval"])
        service.reportedHealth = .ready
        service.registrationStatus = .enabled
        let approved = await coordinator.ensureReady()
        XCTAssertEqual(approved, .ready)
        XCTAssertEqual(service.events, ["approval", "approval"])
    }

    @MainActor
    func testApprovalAppearingDuringLaunchWaitPreventsUnregistration() async {
        let service = AutomaticServiceFixture(registration: .enabled)
        let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { true }, pause: { service.registrationStatus = .approvalRequired })
        let result = await coordinator.ensureReady()
        XCTAssertEqual(result, .approvalRequired)
        XCTAssertEqual(service.events, ["approval"])
    }

    @MainActor
    func testInvalidLocationDoesNotRemoveExistingServiceOrRepeatAutomaticPreparation() async {
        let service = AutomaticServiceFixture(registration: .enabled)
        service.locationError = FixtureFailure.location
        let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { true }, pause: {})
        let result = await coordinator.ensureReady()
        XCTAssertEqual(result, .moveToApplications)
        XCTAssertFalse(coordinator.canRepairAutomatically)
        XCTAssertEqual(service.events, ["validate"])
    }

    @MainActor
    func testNonrespondingNewRegistrationHasBoundedReadinessChecks() async {
        let service = AutomaticServiceFixture()
        service.healthAfterRegistration = .unreachable
        var waits = 0
        let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { true }, pause: { waits += 1 })
        let result = await coordinator.ensureReady()
        XCTAssertEqual(result, .failed)
        XCTAssertEqual(service.healthReads, 10)
        XCTAssertEqual(waits, 9)
        XCTAssertEqual(service.events, ["validate", "register"])
        XCTAssertFalse(coordinator.canRepairAutomatically)
    }

    @MainActor
    func testConcurrentStartupAndUserActionJoinTheSameReplacement() async {
        let service = AutomaticServiceFixture(registration: .enabled)
        service.suspendRemoval = true
        let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { true }, pause: {})
        let startup = Task { await coordinator.ensureReady() }
        await service.waitForRemoval()
        var second: Task<ConnectionPreparation, Never>?
        await withCheckedContinuation { started in
            second = Task {
                started.resume()
                return await coordinator.ensureReady(userInitiated: true)
            }
        }
        service.completeRemoval()
        let firstResult = await startup.value
        let secondResult = await second?.value
        XCTAssertEqual(firstResult, .ready)
        XCTAssertEqual(secondResult, .ready)
        XCTAssertEqual(service.healthReads, 3)
        XCTAssertEqual(service.events, ["validate", "unregister", "removed", "register"])
    }

    @MainActor
    func testQuittingJoinsRemovalAndDoesNotRegisterAgain() async {
        let service = AutomaticServiceFixture(registration: .enabled)
        service.suspendRemoval = true
        let coordinator = AutomaticDaemonCoordinator(service: service, canReplace: { true }, pause: {})
        let startup = Task { await coordinator.ensureReady() }
        await service.waitForRemoval()
        var shutdown: Task<Void, Never>?
        await withCheckedContinuation { started in
            shutdown = Task {
                started.resume()
                await coordinator.stop()
            }
        }
        service.completeRemoval()
        await shutdown?.value
        let result = await startup.value
        XCTAssertEqual(result, .failed)
        XCTAssertEqual(service.events, ["validate", "unregister", "removed"])
    }
}

private enum FixtureFailure: Error { case denied, location }

@MainActor
private final class AutomaticServiceFixture: AutomaticDaemonService {
    var registrationStatus: DaemonRegistrationStatus
    var reportedHealth: DaemonServiceHealth
    var healthAfterRegistration: DaemonServiceHealth = .ready
    var registrationError: Error?
    var locationError: Error?
    var suspendRemoval = false
    private(set) var events: [String] = []
    private(set) var healthReads = 0
    private var removal: CheckedContinuation<Void, Never>?
    private var arrival: CheckedContinuation<Void, Never>?

    init(health: DaemonServiceHealth = .unreachable, registration: DaemonRegistrationStatus = .missing) {
        reportedHealth = health
        registrationStatus = registration
    }
    func health() async -> DaemonServiceHealth { healthReads += 1; return reportedHealth }
    func validateLocation() throws {
        events.append("validate")
        if let locationError { throw locationError }
    }
    func registerForRecovery() throws {
        events.append("register")
        if let registrationError { throw registrationError }
        registrationStatus = .enabled
        reportedHealth = healthAfterRegistration
    }
    func unregisterForRecovery() async throws {
        events.append("unregister")
        if suspendRemoval {
            await withCheckedContinuation { continuation in
                removal = continuation
                arrival?.resume()
                arrival = nil
            }
        }
        events.append("removed")
        registrationStatus = .missing
    }
    func openApprovalSettings() { events.append("approval") }
    func waitForRemoval() async {
        if removal != nil { return }
        await withCheckedContinuation { arrival = $0 }
    }
    func completeRemoval() { removal?.resume(); removal = nil }
}
