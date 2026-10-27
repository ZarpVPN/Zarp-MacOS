import Foundation

/// Read-only UI advice. The daemon independently decides whether it can open a
/// tunnel or bind an API socket. Nil is an unknown lookup; empty is no route.
public enum NetworkRouteEvidence {
    public static func foreignInterfaces(candidates: [String], observations: [String?]) -> [String] {
        var found = Set(observations.compactMap { $0 }.filter { $0.hasPrefix("utun") })
        if observations.isEmpty || observations.contains(where: { $0 == nil }) {
            found.formUnion(candidates)
        }
        return found.sorted()
    }
}
