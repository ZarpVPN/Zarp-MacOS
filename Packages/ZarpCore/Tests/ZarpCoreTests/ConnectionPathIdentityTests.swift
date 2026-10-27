import XCTest
@testable import ZarpCore

final class ConnectionPathIdentityTests: XCTestCase {
    private let wifi = ConnectionPathIdentity.Service(key: "wifi/IPv4", interface: "en0", router: "192.168.1.1", addresses: ["192.168.1.2"])

    func testOwnedAndForeignTunnelServicesCannotChangeThePhysicalIdentity() {
        let tunnel = ConnectionPathIdentity.Service(key: "vpn/IPv4", interface: "utun15", router: "10.0.0.1", addresses: ["10.0.0.2"])
        XCTAssertNotNil(ConnectionPathIdentity.make(services: [wifi]))
        XCTAssertEqual(ConnectionPathIdentity.make(services: [wifi]), ConnectionPathIdentity.make(services: [tunnel, wifi]))
        XCTAssertNil(ConnectionPathIdentity.make(services: [tunnel]))
    }

    func testHotspotChangesAreDetectedEvenOnTheSamePhysicalInterface() {
        let hotspot = ConnectionPathIdentity.Service(key: "wifi/IPv4", interface: "en0", router: "172.20.10.1", addresses: ["172.20.10.2"])
        XCTAssertNotEqual(ConnectionPathIdentity.make(services: [wifi]), ConnectionPathIdentity.make(services: [hotspot]))
    }

    func testServiceOrderAndAddressOrderDoNotCauseFalseNetworkChanges() {
        let ipv6 = ConnectionPathIdentity.Service(key: "wifi/IPv6", interface: "en0", router: "fe80::1", addresses: ["2001:db8::2", "2001:db8::3"])
        let reordered = ConnectionPathIdentity.Service(key: ipv6.key, interface: ipv6.interface, router: ipv6.router, addresses: ipv6.addresses.reversed())
        XCTAssertEqual(ConnectionPathIdentity.make(services: [wifi, ipv6]), ConnectionPathIdentity.make(services: [reordered, wifi]))
    }
}
