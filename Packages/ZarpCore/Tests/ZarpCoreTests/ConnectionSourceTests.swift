import XCTest
@testable import ZarpCore

final class ConnectionSourceTests: XCTestCase {
    func testSharedSwiftGoSourceVectors() throws {
        struct Vector: Decodable { let name: String; let json: String; let id: String?; let errorField: String? }
        struct Fixture: Decodable { let sources: [Vector] }
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: root.appendingPathComponent("testdata/connection-contracts.json")))
        for vector in fixture.sources {
            if let field = vector.errorField {
                XCTAssertThrowsError(try ConnectionSource.decode(Data(vector.json.utf8)), vector.name) {
                    XCTAssertEqual(($0 as? ConnectionContractError)?.field.rawValue, field, vector.name)
                    XCTAssertFalse(String(describing: $0).contains("private-source-token"))
                }
            } else {
                let source = try ConnectionSource.decode(Data(vector.json.utf8))
                XCTAssertEqual(source.id, vector.id, vector.name)
                XCTAssertEqual(try ConnectionSource.decode(JSONEncoder().encode(source)), source, vector.name)
                XCTAssertFalse(String(describing: source).contains("private-source-token"))
                XCTAssertFalse(String(reflecting: source).contains("private-source-token"))
            }
        }
    }

    func testSourceIdentityBindsOriginalUrlWithoutLabelOrCrossSourceReuse() throws {
        let url = "https://subscriptions.example/list?token=private-source-token"
        let source = try ConnectionSource(kind: .subscription, label: "First", subscriptionURL: url)
        XCTAssertEqual(source.id, try ConnectionSource(kind: .subscription, label: "Renamed", subscriptionURL: url).id)
        XCTAssertNotEqual(source.id, try ConnectionSource(kind: .subscription, subscriptionURL: url + "2").id)
        XCTAssertNotEqual(source.id, try ConnectionSource(kind: .subscription, subscriptionURL: url.replacingOccurrences(of: "/list", with: "/redirected-list")).id)
        XCTAssertNotEqual(try ConnectionSource(kind: .manual).id, try ConnectionSource(kind: .warp).id)
        XCTAssertEqual(try ConnectionSource(kind: .warp).mode, .warp)
        XCTAssertEqual(source.mode, .server)
        XCTAssertFalse(source.mode.requiresWarpAccount)
        XCTAssertEqual(source.subscriptionURL, url)
    }

    func testOversizedMalformedAndDuplicateSourcesNeverExposeTokens() {
        for data in [Data(repeating: 65, count: ConnectionSource.maxBytes + 1), Data("private-source-token".utf8),
                     Data(#"{"kind":"subscription","subscriptionURL":"\ud800"}"#.utf8)] {
            XCTAssertThrowsError(try ConnectionSource.decode(data)) {
                XCTAssertFalse(String(describing: $0).contains("private-source-token"))
            }
        }
    }
}
