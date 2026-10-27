import XCTest
@testable import ZarpCore

final class ConnectionContractTests: XCTestCase {
    private func profile(label: String = "Test", password: String = "test-only-password",
                         transport: ServerTransport = .tcp, path: String? = nil) throws -> ServerProfile {
        try ServerProfile(label: label, host: "server.example", port: 443, serverProtocol: .trojan,
                          credential: ServerCredential(kind: .password, value: password),
                          transport: transport, path: path)
    }

    private func encoded(_ profile: ServerProfile) throws -> Data { try JSONEncoder().encode(profile) }

    private func modified(_ profile: ServerProfile, edit: (inout [String: Any]) -> Void) throws -> Data {
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded(profile)) as? [String: Any])
        edit(&object)
        return try JSONSerialization.data(withJSONObject: object)
    }

    func testServerLabelDoesNotAffectIdentityButCredentialsAndTransportDo() throws {
        let first = try profile()
        XCTAssertEqual(first.id, try profile(label: "Renamed").id)
        XCTAssertNotEqual(first.id, try profile(password: "different-test-password").id)
        XCTAssertNotEqual(first.id, try profile(transport: .ws, path: "/socket").id)
        XCTAssertNotEqual(try profile(transport: .ws, path: "/one").id,
                          try profile(transport: .ws, path: "/two").id)
    }

    func testStructuredProfileRoundTripsWithoutLosingCredentials() throws {
        let original = try profile(transport: .ws, path: "/socket")
        let decoded = try ConnectionContract.decodeProfile(encoded(original))
        XCTAssertEqual(decoded, original)
        XCTAssertEqual(decoded.id, original.id)
        XCTAssertFalse(String(describing: original).contains(original.credential.value))
        XCTAssertFalse(String(reflecting: original.credential).contains(original.credential.value))
    }

    func testModeSeparatesAccountRequirementsAndProbeKinds() {
        XCTAssertTrue(ConnectionMode.warp.requiresWarpAccount)
        XCTAssertFalse(ConnectionMode.server.requiresWarpAccount)
        XCTAssertEqual(ConnectionMode.warp.probeKind, .warpTrace)
        XCTAssertEqual(ConnectionMode.server.probeKind, .serverHTTPS)
        XCTAssertFalse(ConnectionOptions().allowPlain)
    }

    func testCurrentCapabilitiesRefuseServerModeWithoutBackendEvidence() throws {
        XCTAssertThrowsError(try RuntimeCapabilities.currentWarpOnly.require(mode: .server, profile: profile())) {
            XCTAssertEqual($0 as? ConnectionContractError, ConnectionContractError(.capabilities))
        }
        XCTAssertNoThrow(try RuntimeCapabilities.currentWarpOnly.require(mode: .warp))
        XCTAssertThrowsError(try RuntimeCapabilities.currentWarpOnly.require(mode: .warp, profile: profile()))
    }

    func testWrongProbeCannotCertifyAnotherMode() {
        let request = ConnectionRequest(mode: .warp, probeKind: .serverHTTPS, strategyId: "direct")
        XCTAssertThrowsError(try request.validate(capabilities: .currentWarpOnly)) {
            XCTAssertEqual($0 as? ConnectionContractError, ConnectionContractError(.probeKind))
        }
    }

    func testRequestVersionAndRoutingAreStrict() throws {
        let valid = ConnectionRequest(mode: .warp, strategyId: "warp-q-google6")
        XCTAssertEqual(try ConnectionContract.decodeRequest(JSONEncoder().encode(valid)), valid)
        for invalid in [ConnectionRequest(version: 99, mode: .warp, strategyId: "direct"),
                        ConnectionRequest(mode: .warp, strategyId: "direct", options: .init(routeAll: true)),
                        ConnectionRequest(mode: .warp, strategyId: "direct", options: .init(overrideDNS: true)),
                        ConnectionRequest(mode: .warp, strategyId: "direct", options: .init(dialTimeoutMs: Int.max)),
                        ConnectionRequest(mode: .warp, strategyId: "direct", options: .init(allowPlain: true)),
                        ConnectionRequest(mode: .warp)] {
            XCTAssertThrowsError(try ConnectionContract.decodeRequest(JSONEncoder().encode(invalid)))
        }
    }

    func testUnknownExecutableFieldsAreRejectedAtEveryEnvelopeLevel() throws {
        let valid = ConnectionRequest(mode: .warp, strategyId: "direct")
        let data = try JSONEncoder().encode(valid)
        let original = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        for key in ["command", "argv", "binaryPath", "configPath"] {
            var changed = original
            changed[key] = "ignored-input-must-be-refused"
            XCTAssertThrowsError(try ConnectionContract.decodeRequest(JSONSerialization.data(withJSONObject: changed))) {
                XCTAssertEqual($0 as? ConnectionContractError, ConnectionContractError(.parameters))
            }
            var nested = original
            var options = try XCTUnwrap(nested["options"] as? [String: Any])
            options[key] = "ignored-input-must-be-refused"
            nested["options"] = options
            XCTAssertThrowsError(try ConnectionContract.decodeRequest(JSONSerialization.data(withJSONObject: nested)))
        }
    }

    func testCredentialAndDecodeErrorsNameTheFieldWithoutItsValue() throws {
        let secret = "test-value-that-must-never-appear-in-errors"
        let valid = try profile()
        for (field, edit) in [
            (ConnectionContractError.Field.transport, { (object: inout [String: Any]) in object["transport"] = secret }),
            (.security, { (object: inout [String: Any]) in object["security"] = secret }),
            (.port, { (object: inout [String: Any]) in object["port"] = secret }),
            (.credential, { (object: inout [String: Any]) in object["credential"] = ["kind": secret, "value": secret] })
        ] {
            XCTAssertThrowsError(try ConnectionContract.decodeProfile(modified(valid, edit: edit))) {
                XCTAssertEqual(($0 as? ConnectionContractError)?.field, field)
                XCTAssertFalse(String(describing: $0).contains(secret))
            }
        }
    }

    func testUnknownProfileAndCredentialFieldsCannotBeSilentlyDiscarded() throws {
        let valid = try profile()
        let unsupported = try modified(valid) { $0["ech"] = "test-only-unsupported-value" }
        XCTAssertThrowsError(try ConnectionContract.decodeProfile(unsupported)) {
            XCTAssertEqual(($0 as? ConnectionContractError)?.field, .parameters)
        }
        let credentialExtra = try modified(valid) {
            $0["credential"] = ["kind": "password", "value": "test-only-password", "binaryPath": "/tmp/untrusted"]
        }
        XCTAssertThrowsError(try ConnectionContract.decodeProfile(credentialExtra))
    }

    func testInapplicableProtocolFieldsAndInvalidLiteralsFail() throws {
        let valid = try profile()
        for host in ["999.999.999.999", "server.example/secret", "[::1]", "fe80::1%en0", "-bad.example"] {
            XCTAssertThrowsError(try ConnectionContract.decodeProfile(modified(valid) { $0["host"] = host }))
        }
        for (field, value) in [("transport", "quic"), ("flow", "vision"), ("security", "none"), ("path", "/ignored")] {
            XCTAssertThrowsError(try ConnectionContract.decodeProfile(modified(valid) { $0[field] = value }))
        }
    }

    func testHysteriaUsesUdpAndMixedAlpnDoesNotTurnTcpIntoQuic() throws {
        let hy2 = try ServerProfile(host: "server.example", port: 443, serverProtocol: .hysteria2,
                                   credential: .init(kind: .password, value: "test-only"), transport: .quic)
        XCTAssertEqual(hy2.outerTransport, .udp)
        let tls = try ServerProfile(host: "server.example", port: 443, serverProtocol: .trojan,
                                   credential: .init(kind: .password, value: "test-only"), alpn: ["h3", "h2"])
        XCTAssertEqual(tls.outerTransport, .tcp)
    }

    func testOversizedMalformedDataNeverLeaksInputIntoErrors() {
        for data in [Data("private-test-input".utf8), Data(repeating: 65, count: ConnectionContract.maxProfileBytes + 1)] {
            XCTAssertThrowsError(try ConnectionContract.decodeProfile(data)) {
                XCTAssertFalse(String(describing: $0).contains("private-test-input"))
            }
        }
        XCTAssertThrowsError(try ConnectionContract.decodeRequest(Data(repeating: 65, count: ConnectionContract.maxRequestBytes + 1)))
    }
}
