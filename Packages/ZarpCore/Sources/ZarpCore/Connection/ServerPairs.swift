import Foundation

/// Strategy-major ordering matches Windows. Direct WARP controls and techniques
/// that cannot operate on a server's outer transport never become server pairs.
public enum ServerPairs {
    public static func build(strategies: [Strategy], profiles: [ServerProfile], sourceID: String) -> [Strategy] {
        strategies.flatMap { strategy -> [Strategy] in
            guard strategy.transport != .wireGuard, strategy.requiresDesync, strategy.unsupportedReason == nil,
                  strategy.warpTLSName == nil else { return [] }
            return profiles.compactMap { profile in
                guard profile.security != .none,
                      (profile.outerTransport == .tcp && strategy.transport == .masqueH2) ||
                      (profile.outerTransport == .udp && strategy.transport == .masqueH3) else { return nil }
                return Strategy(id: strategy.id + "@" + profile.id, name: strategy.fallbackName, transport: strategy.transport,
                                args: strategy.args, isCustom: strategy.isCustom, nameKey: strategy.nameKey,
                                countries: strategy.countries, serverProfile: profile, sourceID: sourceID)
            }
        }
    }
}
