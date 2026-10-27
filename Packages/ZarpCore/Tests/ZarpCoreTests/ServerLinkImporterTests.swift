import XCTest
@testable import ZarpCore

final class ServerLinkImporterTests: XCTestCase {
    private struct Vectors: Decodable {
        struct Import: Decodable {
            let name: String
            let link: String
            let profile: ServerProfile?
            let id: String?
            let errorField: String?
        }
        struct Contract: Decodable {
            let name: String
            let json: String
            let id: String?
            let errorField: String?
            let serverCapabilities: Bool?
        }
        let imports: [Import]
        let profiles: [Contract]
        let requests: [Contract]
    }

    private func vectors() throws -> Vectors {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("testdata/connection-contracts.json")))
    }

    func testSharedImportVectors() throws {
        for vector in try vectors().imports {
            if let field = vector.errorField {
                XCTAssertThrowsError(try ServerLinkImporter.parse(vector.link), vector.name) {
                    XCTAssertEqual(($0 as? ConnectionContractError)?.field.rawValue, field, vector.name)
                    XCTAssertFalse(String(describing: $0).contains("test-only-secret"))
                    XCTAssertFalse(String(describing: $0).contains("private-secret"))
                }
            } else {
                let imported = try ServerLinkImporter.parse(vector.link)
                XCTAssertEqual(imported, vector.profile, vector.name)
                XCTAssertEqual(imported.id, vector.id, vector.name)
                XCTAssertEqual(try ConnectionContract.decodeProfile(JSONEncoder().encode(imported)), imported)
            }
        }
    }

    func testSharedProfileAndRequestVectors() throws {
        let fixture = try vectors()
        for vector in fixture.profiles {
            let data = Data(vector.json.utf8)
            if let field = vector.errorField {
                XCTAssertThrowsError(try ConnectionContract.decodeProfile(data), vector.name) {
                    XCTAssertEqual(($0 as? ConnectionContractError)?.field.rawValue, field, vector.name)
                }
            } else {
                XCTAssertEqual(try ConnectionContract.decodeProfile(data).id, vector.id, vector.name)
            }
        }
        let serverCapabilities = RuntimeCapabilities(modes: [.warp, .server], serverProtocols: Set(ServerProtocol.allCases),
                                                     outerTransports: [.tcp, .udp])
        for vector in fixture.requests {
            let capabilities = vector.serverCapabilities == true ? serverCapabilities : .currentWarpOnly
            if let field = vector.errorField {
                XCTAssertThrowsError(try ConnectionContract.decodeRequest(Data(vector.json.utf8), capabilities: capabilities), vector.name) {
                    XCTAssertEqual(($0 as? ConnectionContractError)?.field.rawValue, field, vector.name)
                }
            } else {
                XCTAssertNoThrow(try ConnectionContract.decodeRequest(Data(vector.json.utf8), capabilities: capabilities), vector.name)
            }
        }
    }

    func testLabelAliasesAndQueryOrderDoNotChangeExecutableIdentity() throws {
        let first = try ServerLinkImporter.parse("hy2://test-only-password@proxy.example?sni=front.example&alpn=h3#First")
        let reordered = try ServerLinkImporter.parse("hysteria2://test-only-password@proxy.example:443?alpn=h3&sni=front.example#Second")
        XCTAssertEqual(first.id, reordered.id)
        XCTAssertNotEqual(first.label, reordered.label)
        let changed = try ServerLinkImporter.parse("hy2://different-test-password@proxy.example?alpn=h3&sni=front.example")
        XCTAssertNotEqual(first.id, changed.id)
    }

    func testAdvancedIdentityBindsEveryExecutableOptionAndErrorsRedactSecrets() throws {
        let base = "vless://11111111-2222-4333-a444-555555555555@proxy.example:443?security=reality&sni=front.example&pbk=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
        let original = try ServerLinkImporter.parse(base)
        for changed in [base + "&sid=abcd", base + "&fp=firefox", base + "&flow=xtls-rprx-vision",
                        base.replacingOccurrences(of: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", with: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI")] {
            XCTAssertNotEqual(try ServerLinkImporter.parse(changed).id, original.id)
        }
        let hy2 = "hy2://test-only-password@proxy.example?obfs=salamander&obfs-password=private-obfs-secret"
        XCTAssertNotEqual(try ServerLinkImporter.parse(hy2).id,
                          try ServerLinkImporter.parse(hy2.replacingOccurrences(of: "private-obfs-secret", with: "different-obfs-secret")).id)
        for link in [base + "&sid=private-obfs-secret", hy2 + "&fp=private-obfs-secret",
                     hy2.replacingOccurrences(of: "salamander", with: "private-obfs-secret")] {
            XCTAssertThrowsError(try ServerLinkImporter.parse(link)) {
                XCTAssertFalse(String(describing: $0).contains("private-obfs-secret"))
                XCTAssertFalse(String(describing: $0).contains("test-only-password"))
            }
        }
    }

    func testMalformedEncodingBoundsAndDeepJsonFailWithoutInputLeak() throws {
        for link in [String(repeating: "private-value", count: 1000),
                     "trojan://test-only-password@proxy.example:443?sni=%00",
                     "trojan://test-only-password@proxy.example:443?%GG=private-value"] {
            XCTAssertThrowsError(try ServerLinkImporter.parse(link)) {
                XCTAssertFalse(String(describing: $0).contains("private-value"))
                XCTAssertFalse(String(describing: $0).contains("test-only-password"))
            }
        }
        let deep = String(repeating: "[", count: 40) + "0" + String(repeating: "]", count: 40)
        let invalidUTF8 = Data([123, 34, 120, 34, 58, 34, 255, 34, 125])
        for data in [Data(deep.utf8), invalidUTF8, Data(#"{"unknown":"\udc00"}"#.utf8)] {
            XCTAssertThrowsError(try ConnectionContract.decodeProfile(data))
            XCTAssertThrowsError(try ConnectionContract.decodeRequest(data))
        }
    }

    func testValidUnicodeSurrogatePairAndUtf8IdentityRemainExact() throws {
        let imported = try ServerLinkImporter.parse("trojan://test-%F0%9F%98%80@proxy.example:443")
        let encoded = try JSONEncoder().encode(imported)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        var escaped = String(decoding: try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]), as: UTF8.self)
        escaped = escaped.replacingOccurrences(of: "😀", with: #"\ud83d\ude00"#)
        XCTAssertEqual(try ConnectionContract.decodeProfile(Data(escaped.utf8)).id, imported.id)
        XCTAssertFalse(String(reflecting: imported).contains(imported.credential.value))
    }
}
