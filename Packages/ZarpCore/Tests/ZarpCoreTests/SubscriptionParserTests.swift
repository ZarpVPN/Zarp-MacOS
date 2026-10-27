import XCTest
@testable import ZarpCore

final class SubscriptionParserTests: XCTestCase {
    private let trojan = "trojan://private-test-password@server.example.test:443#ÿ"
    private let vless = "vless://11111111-2222-4333-a444-555555555555@vless.example.test:443?security=tls#Test"

    func testPlainStandardURLSafeAndUnpaddedListsAgree() throws {
        let body = "\u{feff}  # test comment\r\n\(trojan)\r\n\(vless)\n"
        let expected = try SubscriptionParser.parse(Data(body.utf8))
        XCTAssertEqual(expected.profiles.count, 2)
        let standard = Data(body.utf8).base64EncodedString()
        let urlSafe = standard.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        for encoded in [standard, urlSafe, standard.trimmingCharacters(in: CharacterSet(charactersIn: "=")), urlSafe.trimmingCharacters(in: CharacterSet(charactersIn: "="))] {
            XCTAssertEqual(try SubscriptionParser.parse(Data(encoded.utf8)), expected)
            let wrapped = encoded.enumerated().map { $0.offset % 16 == 0 ? "\n " + String($0.element) : String($0.element) }.joined()
            XCTAssertEqual(try SubscriptionParser.parse(Data(wrapped.utf8)), expected)
        }
        XCTAssertEqual(try expected.requiringProfiles(), expected)
        XCTAssertEqual(try XCTUnwrap(expected.profiles.first).label, "ÿ")
    }

    func testDuplicateConfigurationKeepsFirstLabelAndCountsRejectedEntries() throws {
        let body = [trojan, trojan.replacingOccurrences(of: "#ÿ", with: "#Renamed"),
                    "vmess://private-unsupported", "wg://private-unsupported", "private garbage",
                    "vless://private-refused@server.example.test:443?security=tls", trojan + "?unknown=private-value",
                    "# comment", ""].joined(separator: "\n")
        // Unknown query must precede the fragment to be a refused URI parameter.
        let actual = body.replacingOccurrences(of: trojan + "?unknown=private-value", with: "trojan://private-test-password@server.example.test:443?unknown=private-value")
        let result = try SubscriptionParser.parse(Data(actual.utf8))
        XCTAssertEqual(result.profiles.count, 1)
        XCTAssertEqual(result.profiles[0].label, "ÿ")
        XCTAssertEqual(result.unsupported, 3)
        XCTAssertEqual(result.refused, 2)
        XCTAssertEqual(result.excess, 0)
        for text in [String(describing: result), String(reflecting: result)] {
            XCTAssertFalse(text.contains("private-"))
            XCTAssertFalse(text.contains("server.example.test"))
        }
    }

    func testDistinctLimitCountsExcessOnceWithoutChangingAcceptedOrder() throws {
        var lines = (0..<205).map { "trojan://test-password-\($0)@server.example.test:443#Server \($0)" }
        lines += [lines[0], lines[204].replacingOccurrences(of: "#Server 204", with: "#Rename")]
        let result = try SubscriptionParser.parse(Data(lines.joined(separator: "\n").utf8))
        XCTAssertEqual(result.profiles.count, 200)
        XCTAssertEqual(result.excess, 5)
        XCTAssertEqual(result.unsupported, 0)
        XCTAssertEqual(result.refused, 0)
        XCTAssertEqual(result.profiles.first?.label, "Server 0")
        XCTAssertEqual(result.profiles.last?.label, "Server 199")
    }

    func testHTMLJSONAndMalformedBodiesNeverBecomeProfiles() throws {
        for (body, format, error) in [(" \u{feff}<HTML>private-token</HTML>", SubscriptionResult.Format.html, SubscriptionError.html),
                                     ("[{\"token\":\"private-token\"}]", .json, .json)] {
            for data in [Data(body.utf8), Data(Data(body.utf8).base64EncodedString().utf8)] {
                let result = try SubscriptionParser.parse(data)
                XCTAssertEqual(result.format, format)
                XCTAssertTrue(result.profiles.isEmpty)
                XCTAssertThrowsError(try result.requiringProfiles()) { XCTAssertEqual($0 as? SubscriptionError, error) }
            }
        }
        let encoded = Data(trojan.utf8).base64EncodedString()
        for body in [encoded + "=", encoded + "===", "private invalid base64!", "", "# comment only"] {
            let result = try SubscriptionParser.parse(Data(body.utf8))
            XCTAssertTrue(result.profiles.isEmpty)
            XCTAssertThrowsError(try result.requiringProfiles()) { XCTAssertEqual($0 as? SubscriptionError, .empty) }
        }
        XCTAssertThrowsError(try SubscriptionParser.parse(Data([0xff, 0xfe]))) { XCTAssertEqual($0 as? SubscriptionError, .encoding) }
    }

    func testBodyAndIndividualLinkBoundsAreEnforced() throws {
        let exact = Data(repeating: 32, count: 2 * 1024 * 1024)
        XCTAssertTrue(try SubscriptionParser.parse(exact).profiles.isEmpty)
        XCTAssertThrowsError(try SubscriptionParser.parse(exact + Data([32]))) { XCTAssertEqual($0 as? SubscriptionError, .size) }
        let tooLong = "trojan://" + String(repeating: "private", count: 1400) + "@server.example.test:443"
        let result = try SubscriptionParser.parse(Data(tooLong.utf8))
        XCTAssertEqual(result.refused, 1)
        XCTAssertTrue(result.profiles.isEmpty)
    }
}
