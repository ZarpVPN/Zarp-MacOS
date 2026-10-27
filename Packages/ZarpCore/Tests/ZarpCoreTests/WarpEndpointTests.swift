import XCTest
@testable import ZarpCore

final class WarpEndpointTests: XCTestCase {
    func testNumericEndpointsCanonicalizeAndDeduplicateWithComments() throws {
        let endpoints = try WarpEndpoint.parseList("# endpoints\r\n162.159.198.1:443 # first\r\n[2606:4700:0000::1]:8443\r\n[2606:4700::1]:8443\n")
        XCTAssertEqual(endpoints.map(\.description), ["162.159.198.1:443", "[2606:4700::1]:8443"])
        XCTAssertEqual(endpoints[1].address.version, 6)
    }

    func testInvalidEndpointsCannotSilentlyBecomeDefaultPool() {
        for value in ["example.com:443", "162.159.198.1", "162.159.198.1:0", "162.159.198.1:65536",
                      "162.159.198.1:+443", "[::1]:443", "[fe80::1%en0]:443", "10.0.0.1:443",
                      "100.64.0.1:443", "[ff02::1]:443", "2606:4700::1:443", "[2606:4700::1]", "[]:443"] {
            XCTAssertThrowsError(try WarpEndpoint.parseList("# header\n" + value)) { error in
                XCTAssertEqual((error as? WarpEndpoint.ListError)?.line, 2)
            }
        }
    }

    func testFiniteListBounds() throws {
        XCTAssertEqual(try WarpEndpoint.parseList(" # empty\n"), [])
        let lines = (1...65).map { "162.159.198.1:\($0)" }.joined(separator: "\n")
        XCTAssertThrowsError(try WarpEndpoint.parseList(lines))
    }
}
