/// Account API strategies are separate from measured tunnel results.
public protocol WarpAccountSetupProvider: Sendable {
    func registerAccount(strategies: [Strategy]) async throws
    func readWarpAccount(strategies: [Strategy]) async throws -> WarpAccountStatus
    func applyWarpLicense(_ key: String, strategies: [Strategy]) async throws -> WarpAccountStatus
}
