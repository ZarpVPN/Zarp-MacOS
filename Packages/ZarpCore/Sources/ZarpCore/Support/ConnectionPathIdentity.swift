public enum ConnectionPathIdentity {
    public struct Service: Sendable {
        public let key: String
        public let interface: String
        public let router: String
        public let addresses: [String]

        public init(key: String, interface: String, router: String, addresses: [String]) {
            self.key = key
            self.interface = interface
            self.router = router
            self.addresses = addresses
        }
    }

    /// A VPN becoming primary must not change the underlying access identity.
    public static func make(services: [Service]) -> String? {
        let physical = services.filter { service in
            !service.router.isEmpty && !service.addresses.isEmpty && !service.interface.isEmpty &&
            !["utun", "tun", "tap", "ppp", "ipsec", "lo", "awdl", "llw"].contains { service.interface.hasPrefix($0) }
        }.sorted { $0.key < $1.key }
        guard !physical.isEmpty else { return nil }
        let parts = physical.flatMap { [$0.key, $0.interface, $0.router] + $0.addresses.sorted() }
        return make(components: parts)
    }

    /// Store an opaque fingerprint, never access-network addresses or names.
    public static func make(components: [String]) -> String {
        Strategy.fingerprint(["physical-network-v1"] + components)
    }
}
