import XCTest
@testable import ZarpCore

final class XHTTPOptionsTests: XCTestCase {
    private let prefix = "vless://00000000-0000-4000-a000-000000000001@server.example:443?security=tls&type=xhttp&sni=server.example"

    func testAllModesExtraAndExactH3SelectionSurviveStorage() throws {
        for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
            let extra = #"{"xPaddingBytes":"10-20","xmux":{"maxConcurrency":"16-32"}}"#
            var allowed = CharacterSet.urlQueryAllowed; allowed.remove(charactersIn: "&=+#")
            let profile = try ServerLinkImporter.parse(prefix + "&mode=" + mode + "&path=%2Ftest&extra=" + extra.addingPercentEncoding(withAllowedCharacters: allowed)!)
            XCTAssertEqual(profile.xhttpMode, mode)
            XCTAssertEqual(profile.xhttpExtra, extra)
            XCTAssertEqual(profile.outerTransport, .tcp)
            XCTAssertEqual(try ConnectionContract.decodeProfile(JSONEncoder().encode(profile)), profile)
        }
        XCTAssertEqual(try ServerLinkImporter.parse(prefix + "&alpn=h3").outerTransport, .udp)
        XCTAssertEqual(try ServerLinkImporter.parse(prefix + "&alpn=h2,h3").outerTransport, .tcp)
    }

    func testDownloadLegCannotEscapeRelayOrChangeOuterTransport() throws {
        func parse(_ extra: String) throws -> ServerProfile {
            var allowed = CharacterSet.urlQueryAllowed; allowed.remove(charactersIn: "&=+#")
            return try ServerLinkImporter.parse(prefix + "&alpn=h2&extra=" + extra.addingPercentEncoding(withAllowedCharacters: allowed)!)
        }
        XCTAssertNoThrow(try parse(#"{"downloadSettings":{"address":"server.example","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"server.example","alpn":["h2"]},"xhttpSettings":{"mode":"packet-up","path":"/download"}}}"#))
        for extra in [#"{"downloadSettings":{"address":"another.example"}}"#, #"{"downloadSettings":{"sockopt":{"dialerProxy":"direct"}}}"#,
                      #"{"downloadSettings":{"tlsSettings":{"alpn":["h3"]}}}"#, #"{"sockopt":{"dialerProxy":"direct"}}"#,
                      #"{"headers":{"Host":"ignored.example"}}"#, #"{"scMaxEachPostBytes":16777216,"scMaxBufferedPosts":64}"#,
                      #"{"xmux":{"maxConcurrency":32,"maxConnections":10}}"#, #"{"xPaddingBytes":false}"#] {
            XCTAssertThrowsError(try parse(extra)) { XCTAssertEqual(($0 as? ConnectionContractError)?.field, .extra) }
        }
    }

    func testECHAndCertificateOptionsAreBoundIntoIdentity() throws {
        let base = try ServerLinkImporter.parse(prefix)
        let ech = Data([0, 4, 0xfe, 0x0d, 0, 0]).base64EncodedString()
        let pin = String(repeating: "ab", count: 32)
        let profile = try ServerLinkImporter.parse(prefix + "&ech=" + ech + "&pcs=" + pin + "&vcn=server.example")
        XCTAssertEqual(profile.echConfig, ech)
        XCTAssertEqual(profile.certificatePins, [pin])
        XCTAssertNotEqual(profile.id, base.id)
        XCTAssertThrowsError(try ServerLinkImporter.parse(prefix + "&ech=invalid"))
    }
}
