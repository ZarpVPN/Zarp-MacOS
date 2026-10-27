import XCTest
@testable import ZarpCore

final class DaemonServiceRecoveryTests: XCTestCase {
    @MainActor
    func testRegistrationWaitsForNativeUnregistrationCompletion() async throws {
        let service = SuspendedDaemonRegistration()
        let repair = Task { try await DaemonServiceRecovery.run(service, alreadyRegistered: true) }
        await service.waitForUnregister()
        XCTAssertEqual(service.events, ["unregister"])
        service.completeUnregister()
        try await repair.value
        XCTAssertEqual(service.events, ["unregister", "removed", "register"])
    }

    @MainActor
    func testFailedUnregistrationCannotRaceANewRegistration() async {
        let service = SuspendedDaemonRegistration()
        let repair = Task { try await DaemonServiceRecovery.run(service, alreadyRegistered: true) }
        await service.waitForUnregister()
        service.completeUnregister(error: RecoveryTestError.denied)
        do { try await repair.value; XCTFail("authorization failure was ignored") } catch {}
        XCTAssertEqual(service.events, ["unregister"])
    }

    @MainActor
    func testCancellationJoinsNativeRemovalBeforeSkippingRegistration() async {
        let service = SuspendedDaemonRegistration()
        let repair = Task { try await DaemonServiceRecovery.run(service, alreadyRegistered: true) }
        await service.waitForUnregister()
        repair.cancel()
        XCTAssertEqual(service.events, ["unregister"])
        service.completeUnregister()
        do { try await repair.value; XCTFail("cancelled recovery registered a service") } catch {}
        XCTAssertEqual(service.events, ["unregister", "removed"])
    }
}

private enum RecoveryTestError: Error { case denied }

@MainActor
private final class SuspendedDaemonRegistration: DaemonServiceRegistration {
    private(set) var events: [String] = []
    private var waiting: CheckedContinuation<Void, Error>?
    private var arrival: CheckedContinuation<Void, Never>?

    func unregisterForRecovery() async throws {
        events.append("unregister")
        try await withCheckedThrowingContinuation { continuation in
            waiting = continuation
            arrival?.resume()
            arrival = nil
        }
        events.append("removed")
    }
    func registerForRecovery() throws { events.append("register") }
    func waitForUnregister() async {
        if waiting != nil { return }
        await withCheckedContinuation { arrival = $0 }
    }
    func completeUnregister(error: Error? = nil) {
        if let error { waiting?.resume(throwing: error) } else { waiting?.resume() }
        waiting = nil
    }
}
