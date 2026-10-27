import Foundation

public enum WarpAccountType: String, Codable, Sendable {
    case unknown, free, plus, unlimited, zeroTrust
    public var isPlus: Bool { self == .plus || self == .unlimited }
}

/// Only bounded public account state crosses IPC. No key or account identifier is returned.
public struct WarpAccountStatus: Codable, Equatable, Sendable {
    public let accountType: WarpAccountType
    public let licenseApplied: Bool
    public init(accountType: WarpAccountType, licenseApplied: Bool = false) {
        self.accountType = accountType; self.licenseApplied = licenseApplied
    }

    private enum CodingKeys: String, CodingKey { case accountType, licenseApplied }
    public init(from decoder: Decoder) throws {
        do {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            accountType = try container.decode(WarpAccountType.self, forKey: .accountType)
            licenseApplied = try container.decode(Bool.self, forKey: .licenseApplied)
        } catch { throw WarpConnectionError("invalid WARP account response", code: "account_request") }
    }
}

public enum WarpLicense {
    public static func isValid(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count == 26, bytes[8] == 45, bytes[17] == 45 else { return false }
        return bytes.enumerated().allSatisfy { index, byte in
            index == 8 || index == 17 || (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte)
        }
    }
}

/// Account operations share the existing WARP account and preserve its tunnel,
/// endpoint policy and zapret strategy. Implementations never persist a license.
public protocol WarpAccountProvider: Sendable {
    func readWarpAccount() async throws -> WarpAccountStatus
    func applyWarpLicense(_ key: String) async throws -> WarpAccountStatus
}

extension WarpConnectionError {
    public var accountSetupMessage: Msg? {
        switch code {
        case "daemon_unreachable", "daemon_timeout": return Msg("connection.prepareFailed")
        case "account_uncertain": return Msg("err.accountUncertain")
        case "account_unavailable", "account_storage": return Msg("err.accountUnavailable")
        case "account_rate_limited": return Msg("err.accountRateLimited")
        case "account_certificate": return Msg("err.accountCertificate")
        case "account_network", "strategy_unapplied": return Msg("err.accountNetwork")
        case "account_rejected", "account_response": return Msg("err.accountRejected")
        case "license_uncertain": return Msg("err.licenseUncertain")
        case "foreign_vpn": return Msg("err.foreignVpn")
        default: return nil
        }
    }
}
