import XCTest
@testable import ZarpCore

final class NetworkRouteEvidenceTests: XCTestCase {
    func testDormantInterfacesDoNotWarnWhenActualRoutesArePhysical() {
        XCTAssertEqual(NetworkRouteEvidence.foreignInterfaces(candidates: ["utun2"], observations: ["en0", "", "en0"]), [])
    }
    func testIPv6OrSpecificDestinationRouteWarnsWithPhysicalDefault() {
        XCTAssertEqual(NetworkRouteEvidence.foreignInterfaces(candidates: [], observations: ["en0", "en0", "utun8"]), ["utun8"])
    }
    func testUnknownOrTruncatedLookupKeepsConservativeWarning() {
        XCTAssertEqual(NetworkRouteEvidence.foreignInterfaces(candidates: ["utun2"], observations: ["en0", nil]), ["utun2"])
    }
}
