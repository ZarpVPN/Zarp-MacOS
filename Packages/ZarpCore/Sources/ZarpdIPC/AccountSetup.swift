import Foundation
import ZarpCore

extension ZarpdClient {
    public func registerAccount(strategies: [Strategy]) async throws {
        _ = try await accountSetup(operation: "register", strategies: strategies)
    }

    public func readWarpAccount(strategies: [Strategy]) async throws -> WarpAccountStatus {
        try await accountSetup(operation: "status", strategies: strategies)
    }

    public func applyWarpLicense(_ key: String, strategies: [Strategy]) async throws -> WarpAccountStatus {
        guard WarpLicense.isValid(key) else { throw WarpConnectionError("invalid WARP+ license format", code: "bad_request") }
        return try await accountSetup(operation: "license", strategies: strategies, license: key)
    }

    private func accountSetup(operation: String, strategies: [Strategy], license: String? = nil) async throws -> WarpAccountStatus {
        guard try await ping().accountSetupVersion == 1 else {
            throw WarpConnectionError("protected account setup requires an updated daemon", code: "unsupported")
        }
        struct Candidate: Encodable {
            let id: String
            let mode: String
            let positions: [String]
        }
        struct Request: Encodable {
            let version = 1
            let operation: String
            let strategies: [Candidate]
            let license: String?
        }
        let candidates: [Candidate] = try strategies.map { strategy in
            guard strategy.mode == .warp, strategy.transport == .masqueH2, strategy.unsupportedReason == nil,
                  let step = strategy.plan.tcpDesync, step.positions.count <= 16 else {
                throw WarpConnectionError("invalid registration strategy", code: "bad_request")
            }
            return Candidate(id: strategy.id, mode: step.mode.rawValue, positions: step.positions)
        }
        guard candidates.count <= 32 else { throw WarpConnectionError("too many registration strategies", code: "bad_request") }
        return try await call("setupWarpAccount", Request(operation: operation, strategies: candidates, license: license), timeout: 190)
    }
}
