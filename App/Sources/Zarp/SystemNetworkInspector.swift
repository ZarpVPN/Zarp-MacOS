import Darwin
import Foundation
import SystemConfiguration
import ZarpCore

/// Reads routes for the selected backend and both default families. A dormant
/// interface alone is insufficient when every relevant lookup is conclusive.
/// Failed observations retain the conservative interface warning. The daemon
/// keeps its separate, stricter conflict checks before any network operation.
struct SystemNetworkInspector: NetworkInspector {
    func connectionPathIdentity() -> String? {
        let patterns = ["State:/Network/Service/.*/IPv4", "State:/Network/Service/.*/IPv6"]
        guard let snapshot = SCDynamicStoreCopyMultiple(nil, nil, patterns as CFArray) as? [String: Any] else { return nil }
        let services = snapshot.compactMap { key, value -> ConnectionPathIdentity.Service? in
            guard let state = value as? [String: Any],
                  let interface = state["InterfaceName"] as? String else { return nil }
            return ConnectionPathIdentity.Service(key: key, interface: interface,
                router: state["Router"] as? String ?? "", addresses: state["Addresses"] as? [String] ?? [])
        }
        return ConnectionPathIdentity.make(services: services)
    }

    func foreignVPNInterfaceNames() -> [String] {
        foreignVPNInterfaceNames(destinations: ["162.159.198.1", "2606:4700:103::1", "api.cloudflareclient.com"])
    }

    func foreignVPNInterfaceNames(destinations: [String]) -> [String] {
        let candidates = Self.routedTunnelCandidates()
        var observations = [Self.routeInterface(destination: "default", ipv6: false),
                            Self.routeInterface(destination: "default", ipv6: true)]
        let targets = Array(Set(destinations)).sorted()
        for destination in targets.prefix(8) {
            let families = destination.contains(":") ? [true] : (IPAddress(destination) != nil ? [false] : [false, true])
            for ipv6 in families { observations.append(Self.routeInterface(destination: destination, ipv6: ipv6)) }
        }
        // A truncated automatic server list cannot prove that every target avoids a VPN.
        if targets.count > 8 { observations.append(nil) }
        return NetworkRouteEvidence.foreignInterfaces(candidates: candidates, observations: observations)
    }

    /// Active utun interfaces with IPv4, global IPv6 or unique-local IPv6 addresses.
    static func routedTunnelCandidates() -> [String] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var found = Set<String>()
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            let name = String(cString: entry.pointee.ifa_name)
            guard name.hasPrefix("utun") else { continue }
            let flags = Int32(entry.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_RUNNING != 0 else { continue }
            guard let addr = entry.pointee.ifa_addr else { continue }
            if addr.pointee.sa_family == sa_family_t(AF_INET) {
                let ipv4 = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
                if ipv4 >> 16 != 0xA9FE { found.insert(name) }
            } else if addr.pointee.sa_family == sa_family_t(AF_INET6) {
                let bytes = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                    withUnsafeBytes(of: $0.pointee.sin6_addr) { Array($0) }
                }
                if bytes[0] & 0xe0 == 0x20 || bytes[0] & 0xfe == 0xfc { found.insert(name) }
            }
        }
        return found.sorted()
    }

    // All processes below are owned, read-only route queries. Bound DNS lookup
    // time and join a timed-out query without touching VPN processes or services.
    static func routeInterface(destination: String, ipv6: Bool) -> String? {
        guard !destination.isEmpty, destination.utf8.count <= 253,
              !destination.hasPrefix("-"), !destination.contains(where: { $0.isWhitespace }) else { return nil }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/route")
        process.arguments = ["-n", "get", ipv6 ? "-inet6" : "-inet", destination]
        var environment = ProcessInfo.processInfo.environment
        environment["LC_ALL"] = "C"
        process.environment = environment
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        let completed = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in completed.signal() }
        do { try process.run() } catch { return nil }
        if completed.wait(timeout: .now() + 0.8) == .timedOut {
            process.terminate()
            if completed.wait(timeout: .now() + 0.2) == .timedOut, process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
            process.waitUntilExit()
            return nil
        }
        process.waitUntilExit()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        if process.terminationStatus == 0 { return interface(fromRouteGet: output) }
        if output.contains("not in table") || output.contains("Network is unreachable") { return "" }
        return nil
    }

    /// Pulls `interface: en0` out of `route -n get` output.
    static func interface(fromRouteGet output: String) -> String? {
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("interface:") {
                let value = trimmed.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces)
                return value.isEmpty ? nil : value
            }
        }
        return nil
    }
}
