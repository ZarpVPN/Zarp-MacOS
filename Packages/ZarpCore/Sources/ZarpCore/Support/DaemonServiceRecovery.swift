/// The platform adapter owns authorization and installation location checks.
/// Recovery never uses daemon IPC, which may be precisely what is broken.
@MainActor
public protocol DaemonServiceRegistration {
    func unregisterForRecovery() async throws
    func registerForRecovery() throws
}

public enum DaemonServiceRecovery {
    @MainActor
    public static func run(_ service: any DaemonServiceRegistration, alreadyRegistered: Bool,
                           willRegister: @MainActor () -> Void = {}) async throws {
        if alreadyRegistered { try await service.unregisterForRecovery() }
        try Task.checkCancellation()
        willRegister()
        try service.registerForRecovery()
    }
}
