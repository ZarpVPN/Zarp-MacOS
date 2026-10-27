import Foundation

public enum DaemonRegistrationStatus: Equatable, Sendable { case missing, enabled, approvalRequired, unavailable }
public enum DaemonServiceHealth: Equatable, Sendable { case ready, outdated, busy, unreachable }
public enum ConnectionPreparation: Equatable, Sendable { case ready, approvalRequired, failed, moveToApplications, deferred }

public enum DaemonPreparationEvent: Equatable, Sendable {
    case checking, replacing, registering, waiting, ready, approvalRequired
    case failed(String)

    public var message: Msg {
        switch self {
        case .checking: return Msg("connection.preparing")
        case .replacing: return Msg("log.connectionReplacing")
        case .registering: return Msg("log.connectionRegistering")
        case .waiting: return Msg("log.connectionWaiting")
        case .ready: return Msg("log.connectionReady")
        case .approvalRequired: return Msg("connection.permissionRequired")
        case .failed(let diagnostic): return Msg("log.connectionPreparationFailed", diagnostic)
        }
    }
}

@MainActor
public protocol AutomaticDaemonService: DaemonServiceRegistration {
    var registrationStatus: DaemonRegistrationStatus { get }
    func health() async -> DaemonServiceHealth
    func validateLocation() throws
    func openApprovalSettings()
}

/// One owner for startup, reconnect and account setup. Monitoring can observe
/// recovery but cannot repeatedly unregister or request authorization.
@MainActor
public final class AutomaticDaemonCoordinator {
    private let service: any AutomaticDaemonService
    private let canReplace: @MainActor () -> Bool
    private let pause: @MainActor () async throws -> Void
    private let onEvent: @MainActor (DaemonPreparationEvent) -> Void
    private var operation: Task<ConnectionPreparation, Never>?
    private var automaticAttemptUsed = false
    private var approvalPresented = false

    public var canRepairAutomatically: Bool { !automaticAttemptUsed && !approvalPresented }

    public init(service: any AutomaticDaemonService, canReplace: @escaping @MainActor () -> Bool,
                pause: @escaping @MainActor () async throws -> Void = { try await Task.sleep(nanoseconds: 400_000_000) },
                onEvent: @escaping @MainActor (DaemonPreparationEvent) -> Void = { _ in }) {
        self.service = service
        self.canReplace = canReplace
        self.pause = pause
        self.onEvent = onEvent
    }

    public func ensureReady(userInitiated: Bool = false) async -> ConnectionPreparation {
        if let operation { return await operation.value }
        let task = Task { await self.prepare(userInitiated: userInitiated) }
        operation = task
        let result = await task.value
        operation = nil
        return result
    }

    public func stop() async {
        operation?.cancel()
        _ = await operation?.value
    }

    private func approval(userInitiated: Bool) -> ConnectionPreparation {
        if !approvalPresented || userInitiated {
            approvalPresented = true
            onEvent(.approvalRequired)
            service.openApprovalSettings()
        }
        return .approvalRequired
    }

    private func prepare(userInitiated: Bool) async -> ConnectionPreparation {
        let health = await service.health()
        if Task.isCancelled { return .failed }
        switch health {
        case .ready, .busy: return .ready
        case .outdated, .unreachable: break
        }
        onEvent(.checking)
        if service.registrationStatus == .approvalRequired { return approval(userInitiated: userInitiated) }
        guard canReplace() else { return .deferred }
        guard !automaticAttemptUsed || userInitiated else { return fail("automatic_attempt_used") }
        // A launchd restart may already be completing. Observe it before
        // replacing registration, including a brief client disconnection.
        if health == .unreachable {
            do { try await pause() } catch { return fail("cancelled") }
            switch await service.health() {
            case .ready, .busy: onEvent(.ready); return .ready
            case .outdated, .unreachable: break
            }
        }
        guard !Task.isCancelled else { return .failed }
        if service.registrationStatus == .approvalRequired { return approval(userInitiated: userInitiated) }
        guard canReplace() else { return .deferred }
        automaticAttemptUsed = true
        do { try service.validateLocation() } catch {
            onEvent(.failed(Self.diagnostic(error)))
            return error is DaemonLaunchConfiguration.ValidationError ? .failed : .moveToApplications
        }
        do {
            let registered = service.registrationStatus != .missing
            if registered { onEvent(.replacing) }
            try await DaemonServiceRecovery.run(service, alreadyRegistered: registered, willRegister: { self.onEvent(.registering) })
            if service.registrationStatus == .approvalRequired { return approval(userInitiated: userInitiated) }
            onEvent(.waiting)
            for _ in 0..<8 {
                try Task.checkCancellation()
                switch await service.health() {
                case .ready, .busy: onEvent(.ready); return .ready
                case .outdated, .unreachable: break
                }
                if service.registrationStatus == .approvalRequired { return approval(userInitiated: userInitiated) }
                try await pause()
            }
        } catch {
            if service.registrationStatus == .approvalRequired { return approval(userInitiated: userInitiated) }
            return fail(Task.isCancelled ? "cancelled" : Self.diagnostic(error))
        }
        return fail("startup_timeout")
    }

    private func fail(_ diagnostic: String) -> ConnectionPreparation {
        onEvent(.failed(diagnostic))
        return .failed
    }

    private static func diagnostic(_ error: Error) -> String {
        if let error = error as? DaemonLaunchConfiguration.ValidationError {
            return "launch_manifest." + error.rawValue
        }
        // UserInfo and localizedDescription can contain paths or private values.
        let error = error as NSError
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        let domain = String(String.UnicodeScalarView(error.domain.unicodeScalars.filter { allowed.contains($0) }.prefix(96)))
        return domain + " (" + String(error.code) + ")"
    }
}
