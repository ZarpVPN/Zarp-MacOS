import Darwin
import XCTest
import ZarpCore
@testable import ZarpdIPC

/// The client is the only thing standing between the engine and the daemon, and it used to have no
/// tests at all. These run the real `ZarpdClient` over real Unix sockets against `FakeDaemon`, whose
/// canned answers are byte-for-byte what `zarpd/ipc` produces (`json.Marshal` of the Go structs in
/// `protocol.go`) — so a field renamed on either side breaks a test here instead of the running app.
final class ZarpdClientTests: XCTestCase {
    private var daemons: [FakeDaemon] = []

    override func tearDown() {
        daemons.forEach { $0.stop() }
        daemons = []
        super.tearDown()
    }

    private func makeDaemon(_ behavior: @escaping @Sendable (FakeDaemon.Request) -> FakeDaemon.Behavior) throws -> FakeDaemon {
        let d = try FakeDaemon(behavior: behavior)
        daemons.append(d)
        return d
    }

    private func client(_ d: FakeDaemon, scale: Double = 1) -> ZarpdClient {
        ZarpdClient(socketPath: d.path, timeoutScale: scale)
    }

    private func strategy(_ id: String) -> Strategy {
        (StrategyCatalog.builtIn + StrategyCatalog.unavailable).first { $0.id == id }!
    }

    // MARK: - Decoding what zarpd really sends

    func testServiceReplacementRequiresExplicitIdleAndDisconnectedStatus() async throws {
        let replies: [(String, Bool)] = [
            (#"{"daemonRunning":true,"connected":false,"networkBusy":false}"#, true),
            (#"{"daemonRunning":true,"connected":false,"networkBusy":true}"#, false),
            (#"{"daemonRunning":true,"connected":true,"networkBusy":false}"#, false),
            (#"{"daemonRunning":true,"connected":false}"#, false),
            (#"{"daemonRunning":false,"connected":false,"networkBusy":false}"#, false),
        ]
        for (reply, expected) in replies {
            let daemon = try makeDaemon { _ in .reply(result: reply) }
            let idle = try await client(daemon).isIdleForUpdate()
            XCTAssertEqual(idle, expected)
            XCTAssertEqual(daemon.requests.map(\.method), ["status"])
        }
    }

    func testProtectedAccountSetupRequiresCapabilityBeforeSendingLicense() async throws {
        let d = try makeDaemon { _ in .reply(result: #"{"version":"old","pid":1,"protocol":3,"warpPlusSupported":true}"#) }
        do {
            _ = try await client(d).applyWarpLicense("aB123456-abcdefgh-87654321", strategies: [strategy("warp-t-split")])
            XCTFail("license sent to an older setup implementation")
        } catch { XCTAssertEqual((error as? WarpConnectionError)?.code, "unsupported") }
        XCTAssertEqual(d.requests.map(\.method), ["ping"])
    }

    func testProtectedSetupHasBoundedTypedCandidatesAndSingleCombinedRequest() async throws {
        let d = try makeDaemon { request in
            if request.method == "ping" { return .reply(result: #"{"version":"new","pid":1,"protocol":3,"accountSetupVersion":1,"warpAccountState":"missing"}"#) }
            return .reply(result: #"{"accountType":"plus","licenseApplied":true,"accountRegistered":true,"apiProtected":true}"#)
        }
        let status = try await client(d).applyWarpLicense("aB123456-abcdefgh-87654321", strategies: [strategy("warp-t-split")])
        XCTAssertTrue(status.accountType.isPlus)
        XCTAssertEqual(d.requests.map(\.method), ["ping", "setupWarpAccount"])
        let request = try XCTUnwrap(d.requests.last)
        XCTAssertEqual(request.params["operation"] as? String, "license")
        let candidates = try XCTUnwrap(request.params["strategies"] as? [[String: Any]])
        XCTAssertEqual(candidates.count, 1)
        XCTAssertEqual(candidates[0]["mode"] as? String, "split")
        XCTAssertEqual(candidates[0]["positions"] as? [String], ["1", "midsld"])
        XCTAssertNil(request.params["host"])
    }

    func testUncertainOrUnknownAccountStateNeverMeansMissing() async throws {
        for state in ["uncertain", "unavailable", "future-state"] {
            let d = try makeDaemon { _ in .reply(result: "{\"version\":\"new\",\"pid\":1,\"accountRegistered\":false,\"warpAccountState\":\"\(state)\"}") }
            do { _ = try await client(d).isAccountRegistered(); XCTFail("uncertain data granted registration permission") }
            catch { XCTAssertEqual((error as? WarpConnectionError)?.code, state == "uncertain" ? "account_uncertain" : "account_unavailable") }
            XCTAssertEqual(d.requests.map(\.method), ["ping"])
        }
    }

    func testApplicationPolicyRequiresCapabilityBeforeSendingAProfile() async throws {
        let profile = try ServerLinkImporter.parse("trojan://private-routing-fixture@server.example:443?security=tls")
        let source = try ConnectionSource(kind: .manual)
        let pair = try XCTUnwrap(ServerPairs.build(strategies: StrategyCatalog.builtIn, profiles: [profile], sourceID: source.id).first)
        var policy = ServerRoutingPolicy(); policy.applicationMode = .include; policy.applicationPaths = ["/Applications/Browser.app"]
        for supported in [false, true] {
            let daemon = try makeDaemon { request in
                if request.method == "ping" {
                    let feature = supported ? ",\"serverRoutingVersion\":1" : ""
                    return .reply(result: "{\"version\":\"test\",\"pid\":42,\"protocol\":3\(feature),\"runtimeCapabilities\":{\"schemaVersion\":1,\"modes\":[\"server\"],\"serverProtocols\":[\"trojan\"],\"outerTransports\":[\"tcp\",\"udp\"]}}")
                }
                return .reply(result: request.method == "close" ? #"{"closed":true}"# : Golden.openFullTunnel)
            }
            do {
                let handle = try await client(daemon).open(strategy: pair, endpoint: nil, timeoutMs: 1000, persistent: true,
                                                  routing: TunnelRouting(routeAll: true, overrideDNS: true, serverPolicy: policy))
                XCTAssertTrue(supported)
                let params = try XCTUnwrap(daemon.requests.last?.params["routingPolicy"] as? [String: Any])
                XCTAssertEqual(params["applicationMode"] as? String, "include")
                XCTAssertEqual(params["applicationPaths"] as? [String], policy.applicationPaths)
                await handle.close()
            } catch { XCTAssertFalse(supported); XCTAssertEqual((error as? WarpConnectionError)?.code, "unsupported") }
            XCTAssertEqual(daemon.requests.map(\.method), supported ? ["ping", "openServer", "close"] : ["ping"])
        }
    }

    func testServerCredentialsNeverGoToAWarpOnlyDaemon() async throws {
        let profile = try ServerLinkImporter.parse("trojan://private-ipc-fixture@server.example:443?security=tls")
        let source = try ConnectionSource(kind: .manual)
        let pair = try XCTUnwrap(ServerPairs.build(strategies: StrategyCatalog.builtIn, profiles: [profile], sourceID: source.id).first)
        let daemon = try makeDaemon { _ in .reply(result: Golden.ping) }
        do {
            _ = try await client(daemon).open(strategy: pair, endpoint: nil, timeoutMs: 1000, persistent: true, routing: .testRouteOnly)
            XCTFail("WARP-only daemon received a server profile")
        } catch { XCTAssertEqual((error as? WarpConnectionError)?.code, "unsupported") }
        XCTAssertEqual(daemon.requests.map(\.method), ["ping"])
    }

    func testServerOpenAndAdoptionPreserveModeAndSourceWithoutWarpEnrollment() async throws {
        let profile = try ServerLinkImporter.parse("trojan://private-ipc-fixture@server.example:443?security=tls")
        let source = try ConnectionSource(kind: .manual)
        let pair = try XCTUnwrap(ServerPairs.build(strategies: StrategyCatalog.builtIn, profiles: [profile], sourceID: source.id).first)
        let daemon = try makeDaemon { request in
            switch request.method {
            case "ping": return .reply(result: #"{"version":"test","pid":42,"protocol":3,"accountRegistered":false,"runtimeCapabilities":{"schemaVersion":1,"modes":["warp","server"],"serverProtocols":["trojan"],"outerTransports":["tcp","udp"]}}"#)
            case "openServer": return .reply(result: Golden.openFullTunnel)
            case "status": return .reply(result: "{\"daemonRunning\":true,\"connected\":true,\"activeMode\":\"server\",\"connectionId\":\"7\",\"strategyId\":\"\(pair.id)\",\"serverId\":\"\(profile.id)\",\"sourceId\":\"\(source.id)\",\"routeAll\":true}")
            default: return .reply(result: #"{"closed":true}"#)
            }
        }
        let provider = client(daemon)
        let opened = try await provider.open(strategy: pair, endpoint: nil, timeoutMs: 1000, persistent: true, routing: .testRouteOnly)
        XCTAssertEqual(opened.mode, .server)
        let live = try await provider.connectionSnapshot().live
        XCTAssertEqual(live?.handle.mode, .server)
        XCTAssertEqual(live?.sourceID, source.id)
        XCTAssertEqual(live?.serverID, profile.id)
        let params = try XCTUnwrap(daemon.requests.first { $0.method == "openServer" }?.params)
        XCTAssertEqual(params["sourceId"] as? String, source.id)
        XCTAssertEqual((params["profile"] as? [String: Any])?["host"] as? String, profile.host)
        XCTAssertEqual(params["allowPlain"] as? Bool, false)
        XCTAssertNil(params["endpoint"])
        await opened.close()
        XCTAssertEqual(daemon.requests.map(\.method), ["ping", "openServer", "status", "close"])
    }

    func testWarpPlusDoesNotSendLicenseToAnOlderDaemon() async throws {
        let daemon = try makeDaemon { _ in .reply(result: Golden.ping) }
        do { _ = try await client(daemon).applyWarpLicense("aB123456-abcdefgh-87654321"); XCTFail("old daemon received a license") }
        catch { XCTAssertEqual((error as? WarpConnectionError)?.code, "unsupported") }
        XCTAssertEqual(daemon.requests.map(\.method), ["ping"])
    }

    func testWarpPlusUsesTypedAccountMethodsWithNoConnectionRequest() async throws {
        let daemon = try makeDaemon { request in
            if request.method == "ping" { return .reply(result: #"{"version":"test","pid":42,"protocol":3,"warpPlusSupported":true}"#) }
            return .reply(result: #"{"accountType":"unlimited","licenseApplied":true}"#)
        }
        let result = try await client(daemon).applyWarpLicense("aB123456-abcdefgh-87654321")
        XCTAssertEqual(result.accountType, .unlimited)
        XCTAssertTrue(result.licenseApplied)
        XCTAssertEqual(daemon.requests.map(\.method), ["ping", "warpLicense"])
        XCTAssertEqual(daemon.requests.last?.params.keys.sorted(), ["license"])
    }

    func testCustomEndpointHasDedicatedPolicyAndRequiresUpdatedDaemon() async throws {
        let d = try makeDaemon { request in
            request.method == "ping"
                ? .reply(result: #"{"version":"parity","pid":42,"protocol":3,"accountRegistered":true}"#)
                : .reply(result: Golden.openFullTunnel)
        }
        let handle = try await client(d).open(strategy: strategy("warp-q-google6"),
                                              endpoint: "custom:[2606:4700::1]:8443", timeoutMs: 1000,
                                              persistent: false, routing: .testRouteOnly)
        let params = try XCTUnwrap(d.requests.first { $0.method == "open" }?.params)
        XCTAssertEqual(params["endpoint"] as? String, "[2606:4700::1]:8443")
        XCTAssertEqual(params["endpointPolicy"] as? String, "customWarp")
        await handle.close()

        let old = try makeDaemon { _ in .reply(result: Golden.ping) }
        do {
            _ = try await client(old).open(strategy: strategy("warp-q-google6"), endpoint: "custom:162.159.198.1:443",
                                           timeoutMs: 1000, persistent: false, routing: .testRouteOnly)
            XCTFail("a stale daemon must not silently ignore the custom endpoint contract")
        } catch {
            XCTAssertEqual((error as? WarpConnectionError)?.code, "unsupported")
        }
        XCTAssertFalse(old.requests.contains { $0.method == "open" })
    }

    func testPingDecodesTheDaemonsAnswer() async throws {
        let d = try makeDaemon { _ in .reply(result: Golden.ping) }
        let ping = try await client(d).ping()
        XCTAssertEqual(ping.version, "0.1.0")
        XCTAssertEqual(ping.pid, 4242)
        XCTAssertEqual(ping.effectiveProtocol, 2)
        XCTAssertEqual(ping.accountRegistered, true)
        XCTAssertNil(ping.runtimeCapabilities)
        XCTAssertEqual(d.requests.first?.method, "ping")
    }

    func testCapabilitiesDecodeTheSameWireShapeAsGo() async throws {
        let reply = #"{"version":"parity","pid":4242,"protocol":3,"accountRegistered":false,"runtimeCapabilities":{"schemaVersion":1,"modes":["warp"],"serverProtocols":[],"outerTransports":["tcp","udp"]}}"#
        let d = try makeDaemon { _ in .reply(result: reply) }
        let ping = try await client(d).ping()
        XCTAssertEqual(ping.runtimeCapabilities, .currentWarpOnly)
        XCTAssertEqual(ping.effectiveProtocol, 3)
        XCTAssertThrowsError(try ping.runtimeCapabilities?.require(mode: .server))
    }

    func testMalformedCapabilitiesFailWithoutSecretDiagnosticValues() async throws {
        let d = try makeDaemon { _ in
            .reply(result: #"{"version":"parity","pid":1,"protocol":3,"runtimeCapabilities":{"schemaVersion":1,"modes":["warp"],"serverProtocols":["private-secret-value"],"outerTransports":["tcp"]}}"#)
        }
        do {
            _ = try await client(d).ping()
            XCTFail("unknown capability was silently accepted")
        } catch {
            XCTAssertFalse(String(describing: error).contains("private-secret-value"))
        }
    }

    func testProviderRejectsMalformedServerIdentityAndUnknownModes() async throws {
        for mode in ["server", "future-private-mode"] {
            let d = try makeDaemon { _ in
                .reply(result: "{\"daemonRunning\":true,\"connected\":true,\"activeMode\":\"\(mode)\",\"connectionId\":\"7\",\"routeAll\":true}")
            }
            do {
                _ = try await client(d).connectionSnapshot()
                XCTFail("another active mode was adopted as WARP")
            } catch {
                XCTAssertEqual((error as? WarpConnectionError)?.code, mode == "server" ? "bad_response" : "unsupported")
                XCTAssertFalse(String(describing: error).contains("future-private-mode"))
            }
            XCTAssertEqual(d.requests.map(\.method), ["status"])
        }
    }

    func testADaemonFromBeforeVersioningIsRecognisedAsProtocolOne() async throws {
        let d = try makeDaemon { _ in .reply(result: #"{"version":"0.1.0","pid":7}"#) }
        let ping = try await client(d).ping()
        XCTAssertNil(ping.protocolVersion)
        XCTAssertEqual(ping.effectiveProtocol, 1)
        do {
            _ = try await client(d).isAccountRegistered()
            XCTFail("unknown account state must not grant permission to create another account")
        } catch {
            XCTAssertEqual((error as? WarpConnectionError)?.code, "unsupported")
        }
    }

    func testAccountRegisteredComesFromPing() async throws {
        for (json, expected) in [(#"{"version":"x","pid":1,"protocol":2,"accountRegistered":true}"#, true),
                                 (#"{"version":"x","pid":1,"protocol":2,"accountRegistered":false}"#, false)] {
            let d = try makeDaemon { _ in .reply(result: json) }
            let registered = try await client(d).isAccountRegistered()
            XCTAssertEqual(registered, expected)
        }
    }

    func testIdleStatusIsAnEmptySnapshot() async throws {
        let d = try makeDaemon { _ in .reply(result: Golden.statusIdle) }
        let snapshot = try await client(d).connectionSnapshot()
        XCTAssertNil(snapshot.live)
        XCTAssertNil(snapshot.lastLoss)
    }

    func testBusyScanOrCleanupHasNoAdoptableConnection() async throws {
        let d = try makeDaemon { _ in .reply(result: Golden.statusScanOrCleanup) }
        let snapshot = try await client(d).connectionSnapshot()
        XCTAssertNil(snapshot.live)
        XCTAssertNil(snapshot.lastLoss)
    }

    func testLegacyIdleReplyStillDecodesForGUIReconciliation() async throws {
        // GUI adoption is backward compatible. This reply cannot establish
        // idle network ownership for a privileged manual-test guard.
        let reply = #"{"daemonRunning":true,"accountRegistered":true,"connected":false,"routeAll":false}"#
        let d = try makeDaemon { _ in .reply(result: reply) }
        let snapshot = try await client(d).connectionSnapshot()
        XCTAssertNil(snapshot.live)
    }

    func testConnectedStatusBecomesALiveConnection() async throws {
        let d = try makeDaemon { _ in .reply(result: Golden.statusFullTunnel) }
        let live = try await client(d).connectionSnapshot().live
        XCTAssertEqual(live?.handle.id, "7")
        XCTAssertEqual(live?.handle.connectMs, 203)
        XCTAssertEqual(live?.handle.endpoint, "162.159.198.2:500")
        XCTAssertEqual(live?.strategyId, "warp-q-google6")
        XCTAssertEqual(live?.routeAll, true)
    }

    func testATestRouteOnlyTunnelIsNotMistakenForAFullTunnel() async throws {
        // Go sends "routeAll":false explicitly (it used to be omitempty, which made "test route
        // only" look like "field absent" and the app showed a plain Connected for a tunnel that
        // carries nothing but 1.1.1.1).
        let d = try makeDaemon { _ in .reply(result: Golden.statusTestRouteOnly) }
        let live = try await client(d).connectionSnapshot().live
        XCTAssertEqual(live?.handle.id, "2")
        XCTAssertEqual(live?.routeAll, false)
    }

    func testAnOldDaemonThatNeverSentRouteAllMeansTheTestRoute() async throws {
        let json = #"{"daemonRunning":true,"connected":true,"connectionId":"2","strategyId":"direct","connectMs":50}"#
        let d = try makeDaemon { _ in .reply(result: json) }
        let live = try await client(d).connectionSnapshot().live
        XCTAssertEqual(live?.routeAll, false, "every persistent connection of a daemon from before the field carried only the test route")
    }

    func testALostTunnelIsReportedWithItsReason() async throws {
        let d = try makeDaemon { _ in .reply(result: Golden.statusAfterLoss) }
        let snapshot = try await client(d).connectionSnapshot()
        XCTAssertNil(snapshot.live)
        XCTAssertEqual(snapshot.lastLoss, ConnectionLoss(connectionId: "3", reason: "no recent network activity"))
    }

    func testLogsDecodeIncludingAnEmptyRing() async throws {
        let d = try makeDaemon { _ in .reply(result: Golden.logs) }
        let logs = try await client(d).logs(since: 4)
        XCTAssertEqual(logs.lines?.map(\.text), ["closed #1"])
        XCTAssertEqual(logs.lines?.first?.timeMs, 1791284063527)
        XCTAssertEqual(logs.next, 5)
        XCTAssertEqual(logs.dropped, 2)
        XCTAssertEqual(d.requests.first?.params["since"] as? Int, 4)

        // Go encodes a nil slice as null, and omits `dropped` when zero.
        let empty = try makeDaemon { _ in .reply(result: Golden.logsEmpty) }
        let none = try await client(empty).logs(since: 0)
        XCTAssertNil(none.lines)
        XCTAssertEqual(none.next, 0)
    }

    func testRestartAndRegister() async throws {
        let d = try makeDaemon { req in
            req.method == "restart" ? .reply(result: #"{"acknowledged":true}"#) : .reply(result: #"{"accountRegistered":true}"#)
        }
        let restart = try await client(d).restart()
        XCTAssertTrue(restart.acknowledged)
        try await client(d).registerAccount()
        XCTAssertEqual(d.requests.map(\.method), ["restart", "register"])
    }

    // MARK: - What open sends

    func testNamedWarpRequiresCapabilityAndSendsNameAlongsideTheStrategy() async throws {
        for supported in [false, true] {
            let d = try makeDaemon { request in
                if request.method == "ping" {
                    let feature = supported ? ",\"warpTLSNameVersion\":1" : ""
                    return .reply(result: "{\"version\":\"test\",\"pid\":1,\"protocol\":3\(feature)}")
                }
                return .reply(result: Golden.openTestConnection)
            }
            do {
                _ = try await client(d).open(strategy: strategy("warp-q-vk-name"), endpoint: nil,
                                             timeoutMs: 1000, persistent: false, routing: .testRouteOnly)
                XCTAssertTrue(supported, "old daemon could silently ignore the strategy name")
            } catch let error as WarpConnectionError {
                XCTAssertFalse(supported)
                XCTAssertEqual(error.code, "unsupported")
            }
            if supported {
                XCTAssertEqual(d.requests.map(\.method), ["ping", "open"])
                let params = try XCTUnwrap(d.requests.last?.params)
                XCTAssertEqual(params["warpTLSName"] as? String, "vk.com")
                let fakes = try XCTUnwrap(params["fakeSteps"] as? [[String: Any]])
                XCTAssertEqual(fakes.first?["blob"] as? String, "quic_vk")
                XCTAssertEqual(fakes.first?["repeats"] as? Int, 6)
            } else {
                XCTAssertEqual(d.requests.map(\.method), ["ping"])
            }
        }
    }

    func testOpenSendsTheStrategyAsTheDaemonExpectsIt() async throws {
        let d = try makeDaemon { _ in .reply(result: Golden.openTestConnection) }
        let handle = try await client(d).open(
            strategy: strategy("warp-q-google-ttl"), endpoint: "isolated-3", timeoutMs: 15000, persistent: false, routing: .testRouteOnly)
        XCTAssertEqual(handle.id, "1")
        XCTAssertEqual(handle.connectMs, 10)

        let p = try XCTUnwrap(d.requests.first?.params)
        XCTAssertEqual(d.requests.first?.method, "open")
        XCTAssertEqual(p["transport"] as? String, "masqueH3")
        XCTAssertEqual(p["strategyId"] as? String, "warp-q-google-ttl")
        XCTAssertEqual(p["endpoint"] as? String, "isolated-3")
        XCTAssertEqual(p["timeoutMs"] as? Int, 15000)
        XCTAssertEqual(p["persistent"] as? Bool, false)
        let steps = try XCTUnwrap(p["fakeSteps"] as? [[String: Any]])
        XCTAssertEqual(steps.count, 1)
        XCTAssertEqual(steps[0]["blob"] as? String, "quic_google")
        XCTAssertEqual(steps[0]["repeats"] as? Int, 6)
        XCTAssertEqual(steps[0]["ipTTL"] as? Int, 4)
        XCTAssertEqual(steps[0]["ip6TTL"] as? Int, 4)
    }

    func testOpenSendsATCPSplitForHTTP2() async throws {
        let d = try makeDaemon { _ in .reply(result: #"{"connectionId":"1","connectMs":10}"#) }
        _ = try await client(d).open(strategy: strategy("warp-t-disorder"), endpoint: nil, timeoutMs: 1000, persistent: false, routing: .testRouteOnly)
        let p = try XCTUnwrap(d.requests.first?.params)
        XCTAssertEqual(p["transport"] as? String, "masqueH2")
        let split = try XCTUnwrap(p["tcpDesync"] as? [String: Any])
        XCTAssertEqual(split["mode"] as? String, "disorder")
        XCTAssertEqual(split["positions"] as? [String], ["1", "midsld"])
        XCTAssertEqual(p["endpoint"] as? String, "", "no endpoint means the account's own")
    }

    func testOpenMapsPersistenceAndRoutingAndTheirGuards() async throws {
        let d = try makeDaemon { _ in .reply(result: #"{"connectionId":"1","connectMs":10,"routeAll":true}"#) }
        let c = client(d)
        let full = TunnelRouting(routeAll: true, overrideDNS: true)
        _ = try await c.open(strategy: strategy("warp-q-google6"), endpoint: nil, timeoutMs: 1000, persistent: true, routing: full)
        _ = try await c.open(strategy: strategy("warp-q-google6"), endpoint: nil, timeoutMs: 1000, persistent: false, routing: full)
        let persistent = d.requests[0].params, test = d.requests[1].params
        XCTAssertEqual(persistent["routeAll"] as? Bool, true)
        XCTAssertEqual(persistent["overrideDNS"] as? Bool, true)
        // A scan's test connection must never ask for the whole machine's traffic.
        XCTAssertEqual(test["routeAll"] as? Bool, false)
        XCTAssertEqual(test["overrideDNS"] as? Bool, false)
    }

    func testWarningsFromTheDaemonReachTheHandle() async throws {
        let d = try makeDaemon { _ in .reply(result: Golden.openFullTunnel) }
        let handle = try await client(d).open(strategy: strategy("warp-q-google6"), endpoint: nil, timeoutMs: 1000, persistent: true, routing: .testRouteOnly)
        XCTAssertEqual(handle.warnings, ["DNS was not overridden: boom"])
        XCTAssertEqual(handle.endpoint, "162.159.198.1:443")
        XCTAssertEqual(handle.id, "9")
    }

    func testAnUnsupportedStrategyIsNeverSentBecauseItWouldRunAsADirectConnection() async throws {
        let d = try makeDaemon { _ in .reply(result: #"{"connectionId":"1","connectMs":10}"#) }
        for id in ["warp-t-seqovl", "warp-q-google-bad", "warp-wg-stun"] {
            do {
                _ = try await client(d).open(strategy: strategy(id), endpoint: nil, timeoutMs: 1000, persistent: false, routing: .testRouteOnly)
                XCTFail("\(id) must be refused")
            } catch let error as WarpConnectionError {
                XCTAssertEqual(error.code, "unsupported")
            }
        }
        XCTAssertEqual(d.connectionCount, 0, "not even a connection may be made for it")
    }

    func testPlainWarpRequestsAreRefusedBeforeOpeningIPC() async throws {
        let daemon = try makeDaemon { _ in .reply(result: Golden.openFullTunnel) }
        for transport in [Transport.masqueH3, .masqueH2] {
            for args in ["", "--payload=" + (transport == .masqueH3 ? "quic_initial" : "tls_client_hello")] {
                let plain = Strategy(id: "old-direct", name: "Old direct", transport: transport, args: args)
                do {
                    _ = try await client(daemon).open(strategy: plain, endpoint: nil, timeoutMs: 1000,
                                                      persistent: true, routing: .testRouteOnly)
                    XCTFail("plain WARP must not reach the daemon")
                } catch let error as WarpConnectionError {
                    XCTAssertEqual(error.code, "unsupported")
                }
            }
        }
        XCTAssertEqual(daemon.connectionCount, 0)
    }

    // MARK: - Errors

    func testConnectionFailureMetadataSurvivesWireDecoding() async throws {
        for (method, code, phase) in [("open", "peer_key_mismatch", "tls"), ("measure", "connection_lost", "traffic")] {
            let d = try makeDaemon { request in
                if request.method != method {
                    return .reply(result: #"{"connectionId":"9","connectMs":1,"endpoint":"162.159.198.2:443"}"#)
                }
                return .raw("{\"id\":\(request.id),\"error\":{\"message\":\"original transport reason\",\"timedOut\":false,\"code\":\"\(code)\",\"connection\":{\"endpoint\":\"162.159.198.2:443\",\"transport\":\"masqueH2\",\"phase\":\"\(phase)\",\"strategyId\":\"warp-t-split\",\"connectionId\":\"9\"}}}\n")
            }
            var opened: (any WarpConnectionHandle)?
            do {
                if method == "open" {
                    _ = try await client(d).open(strategy: strategy("warp-t-split"), endpoint: "isolated-14", timeoutMs: 1000, persistent: false, routing: .testRouteOnly)
                } else {
                    let handle = try await client(d).open(strategy: strategy("warp-t-split"), endpoint: nil, timeoutMs: 1000, persistent: false, routing: .testRouteOnly)
                    opened = handle
                    _ = try await client(d).measure(connection: handle, samples: 1)
                }
                XCTFail("expected the original failure")
            } catch let error as WarpConnectionError {
                XCTAssertEqual(error.code, code)
                XCTAssertEqual(error.message, "original transport reason")
                XCTAssertEqual(error.connection?.phase, phase)
                XCTAssertEqual(error.connection?.endpoint, "162.159.198.2:443")
                XCTAssertEqual(error.connection?.strategyId, "warp-t-split")
                XCTAssertEqual(error.connection?.connectionId, "9")
            }
            await opened?.close()
        }
    }

    func testErrorsKeepMessageTimeoutFlagAndCode() async throws {
        let d = try makeDaemon { _ in .error(message: "no WARP account yet", timedOut: false, code: "no_account") }
        do {
            _ = try await client(d).open(strategy: strategy("warp-q-google6"), endpoint: nil, timeoutMs: 1000, persistent: false, routing: .testRouteOnly)
            XCTFail("expected an error")
        } catch let error as WarpConnectionError {
            XCTAssertEqual(error.message, "no WARP account yet")
            XCTAssertEqual(error.code, "no_account")
            XCTAssertFalse(error.timedOut)
        }
        d.setBehavior { _ in .error(message: "timeout after 15s", timedOut: true) }
        do {
            _ = try await client(d).open(strategy: strategy("warp-q-google6"), endpoint: nil, timeoutMs: 1000, persistent: false, routing: .testRouteOnly)
            XCTFail("expected an error")
        } catch let error as WarpConnectionError {
            XCTAssertTrue(error.timedOut)
            XCTAssertNil(error.code)
        }
    }

    func testADaemonThatIsNotRunning() async {
        let c = ZarpdClient(socketPath: "/tmp/zfd-does-not-exist.sock")
        do {
            _ = try await c.ping()
            XCTFail("expected an error")
        } catch let error as WarpConnectionError {
            XCTAssertEqual(error.code, "daemon_unreachable")
            XCTAssertEqual(error.accountSetupMessage?.key, "connection.prepareFailed")
            XCTAssertFalse(error.message.contains("/tmp/"))
            XCTAssertFalse(error.message.contains("connect("))
        } catch {
            XCTFail("\(error)")
        }
    }

    func testAnOverlongSocketPathIsAnErrorNotACrash() async {
        let c = ZarpdClient(socketPath: "/tmp/" + String(repeating: "a", count: 200))
        do {
            _ = try await c.ping()
            XCTFail("expected an error")
        } catch {
            XCTAssertTrue(String(describing: error).contains("too long"))
        }
    }

    func testAnAnswerThatNeverComesIsATimeoutNotAHang() async throws {
        let d = try makeDaemon { _ in .hang }
        let start = Date()
        do {
            _ = try await client(d, scale: 0.04).ping() // 5 s * 0.04 = 200 ms
            XCTFail("expected a timeout")
        } catch let error as WarpConnectionError {
            XCTAssertTrue(error.timedOut)
            XCTAssertEqual(error.code, "daemon_timeout")
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 3)
    }

    func testMalformedAnswersAreErrors() async throws {
        let d = try makeDaemon { _ in .raw("this is not json\n") }
        do {
            _ = try await client(d).ping()
            XCTFail("expected an error")
        } catch {}
        let empty = try makeDaemon { req in .raw("{\"id\":\(req.id)}\n") }
        do {
            _ = try await client(empty).ping()
            XCTFail("an answer with neither result nor error must be an error")
        } catch let error as WarpConnectionError {
            XCTAssertTrue(error.message.contains("neither"))
        }
    }

    func testAHugeAnswerIsRefusedInsteadOfBufferedForever() async throws {
        let d = try makeDaemon { _ in .flood(bytes: 6 * 1024 * 1024) }
        do {
            _ = try await client(d).ping()
            XCTFail("expected an error")
        } catch let error as WarpConnectionError {
            XCTAssertTrue(error.message.contains("large"), error.message)
        }
    }

    // MARK: - Failure modes that used to kill the app or hang it

    func testAPeerThatHasGoneAwayDoesNotKillTheProcessWithSIGPIPE() async throws {
        // Without SO_NOSIGPIPE, writing to a socket whose peer has closed raises SIGPIPE and the whole
        // process (the app, in production) is terminated. Test runners commonly ignore SIGPIPE
        // themselves, which would hide the bug: put the default disposition back for the test.
        let previous = signal(SIGPIPE, SIG_DFL)
        defer { signal(SIGPIPE, previous) }
        let d = try makeDaemon { _ in .closeImmediately }
        let c = client(d)
        // Give the fake daemon time to close its end *before* the client writes — otherwise the
        // client wins the race and never touches a closed socket.
        c.afterConnectForTesting = { Thread.sleep(forTimeInterval: 0.15) }
        for _ in 0..<3 {
            do {
                _ = try await c.ping()
                XCTFail("expected an error")
            } catch let error as WarpConnectionError {
                XCTAssertTrue(error.message.contains("write()") || error.message.contains("closed"), error.message)
            }
        }
    }

    func testARefusalIsReadEvenThoughTheDaemonClosedBeforeReadingTheRequest() async throws {
        let d = try makeDaemon { _ in .refuse(code: "forbidden", message: "this process is not allowed to control zarpd") }
        let c = client(d)
        // The daemon has already written its refusal and closed by the time the client writes: the
        // write fails with EPIPE, but the reason is waiting to be read.
        c.afterConnectForTesting = { Thread.sleep(forTimeInterval: 0.15) }
        do {
            _ = try await c.ping()
            XCTFail("expected an error")
        } catch let error as WarpConnectionError {
            XCTAssertEqual(error.code, "forbidden", "the reason must reach the user, not 'broken pipe': \(error.message)")
        }
    }

    func testCancellingACallAbandonsItImmediatelyAndTheDaemonSeesTheClientLeave() async throws {
        let d = try makeDaemon { _ in .hang }
        let c = client(d)
        let task = Task { () -> String in
            do {
                _ = try await c.ping()
                return "answered"
            } catch let error as WarpConnectionError {
                return error.code ?? error.message
            } catch {
                return "\(error)"
            }
        }
        XCTAssertTrue(eventually { d.requests.count == 1 }, "the request should have reached the daemon")
        let cancelledAt = Date()
        task.cancel()
        let outcome = await task.value
        XCTAssertEqual(outcome, "cancelled")
        XCTAssertLessThan(Date().timeIntervalSince(cancelledAt), 2, "a cancelled call used to sit in read() until its full timeout")
        // The daemon notices the vanished client — that is what makes it abandon an open that is
        // still dialing.
        XCTAssertTrue(eventually { d.disconnectCount == 1 })
    }

    func testACallMadeFromAnAlreadyCancelledTaskNeverReachesTheDaemon() async throws {
        let d = try makeDaemon { _ in .reply(result: "{}") }
        let c = client(d)
        let task = Task { () -> Bool in
            // Wait until cancelled, then call.
            while !Task.isCancelled { try? await Task.sleep(nanoseconds: 1_000_000) }
            do { _ = try await c.ping(); return true } catch { return false }
        }
        task.cancel()
        let answered = await task.value
        XCTAssertFalse(answered)
        XCTAssertEqual(d.requests.count, 0)
    }

    func testClosingStillHappensWhenTheTaskThatClosesIsCancelled() async throws {
        // The engine's cancel path calls handle.close() from a task that has just been cancelled.
        // If the cancellation aborted *that* call too, every cancelled scan would leave its tunnel
        // open in the daemon.
        let d = try makeDaemon { req in
            req.method == "status"
                ? .reply(result: #"{"daemonRunning":true,"connected":true,"connectionId":"11","strategyId":"direct","connectMs":5,"routeAll":true}"#)
                : .reply(result: "{}")
        }
        let live = try await client(d).connectionSnapshot().live
        let handle = try XCTUnwrap(live?.handle)

        let task = Task {
            while !Task.isCancelled { try? await Task.sleep(nanoseconds: 1_000_000) }
            await handle.close() // runs with its own task already cancelled
        }
        task.cancel()
        await task.value

        let close = d.requests.first { $0.method == "close" }
        XCTAssertNotNil(close, "close must not be cancelled along with its caller")
        XCTAssertEqual(close?.params["connectionId"] as? String, "11")
    }

    func testClosingAGoneDaemonIsHarmless() async throws {
        let d = try makeDaemon { _ in .reply(result: #"{"daemonRunning":true,"connected":true,"connectionId":"1","strategyId":"direct","connectMs":5}"#) }
        let snapshot = try await client(d).connectionSnapshot()
        let handle = try XCTUnwrap(snapshot.live?.handle)
        d.stop()
        await handle.close() // must return, not throw or hang
    }

    func testManyConcurrentCallsAllSucceed() async throws {
        let d = try makeDaemon { _ in .reply(result: #"{"version":"x","pid":1,"protocol":2,"accountRegistered":true}"#) }
        let c = client(d)
        try await withThrowingTaskGroup(of: Int.self) { group in
            for _ in 0..<40 { group.addTask { try await c.ping().pid } }
            var n = 0
            for try await _ in group { n += 1 }
            XCTAssertEqual(n, 40)
        }
        XCTAssertEqual(d.requests.count, 40)
    }

    // MARK: - measure

    func testMeasureSendsTheConnectionAndMapsEveryResultKind() async throws {
        let d = try makeDaemon { req in
            switch req.method {
            case "status": return .reply(result: #"{"daemonRunning":true,"connected":true,"connectionId":"21","strategyId":"direct","connectMs":5}"#)
            default: return .reply(result: #"{"kind":"ok","pingMs":31,"warp":"on"}"#)
            }
        }
        let c = client(d)
        let snapshot = try await c.connectionSnapshot()
        let handle = try XCTUnwrap(snapshot.live?.handle)

        guard case .ok(let ping, let warp) = try await c.measure(connection: handle, samples: 3) else { return XCTFail("expected .ok") }
        XCTAssertEqual(ping, 31)
        XCTAssertEqual(warp, "on")
        let measure = try XCTUnwrap(d.requests.last)
        XCTAssertEqual(measure.method, "measure")
        XCTAssertEqual(measure.params["connectionId"] as? String, "21")
        XCTAssertEqual(measure.params["samples"] as? Int, 3)

        d.setBehavior { _ in .reply(result: #"{"kind":"notWarp","detail":"off"}"#) }
        guard case .notWarp(let detail) = try await c.measure(connection: handle, samples: 1) else { return XCTFail("expected .notWarp") }
        XCTAssertEqual(detail, "off", "the raw value, without a label")

        d.setBehavior { _ in .reply(result: #"{"kind":"noTraffic","lastError":"i/o timeout"}"#) }
        guard case .noTraffic(let err) = try await c.measure(connection: handle, samples: 1) else { return XCTFail("expected .noTraffic") }
        XCTAssertEqual(err, "i/o timeout")
    }

    func testMeasureRefusesAHandleThatIsNotFromTheDaemon() async throws {
        struct Foreign: WarpConnectionHandle {
            let id = "x"; let connectMs = 0; let endpoint: String? = nil
            func close() async {}
        }
        let d = try makeDaemon { _ in .reply(result: "{}") }
        do {
            _ = try await client(d).measure(connection: Foreign(), samples: 1)
            XCTFail("expected an error")
        } catch is WarpConnectionError {}
        XCTAssertEqual(d.connectionCount, 0)
    }

    // MARK: - Environment override

    func testTheDefaultSocketPathIsTheInstalledDaemons() {
        // (A debug build honors ZARP_SOCKET; this process doesn't set it.)
        XCTAssertEqual(ProcessInfo.processInfo.environment["ZARP_SOCKET"] ?? "", "")
        XCTAssertEqual(ZarpdClient.defaultSocketPath, "/var/run/zarpd.sock")
    }
}


/// The exact answers zarpd sends — copied from `TestWireFormat` in zarpd/ipc/protocol_test.go, which
/// pins the Go side to these very strings. Keep the two in step.
enum Golden {
    static let ping = #"{"version":"0.1.0","pid":4242,"protocol":2,"accountRegistered":true}"#
    static let statusIdle = #"{"daemonRunning":true,"accountRegistered":true,"connected":false,"networkBusy":false,"routeAll":false}"#
    static let statusFullTunnel = #"{"daemonRunning":true,"accountRegistered":true,"connected":true,"networkBusy":true,"connectionId":"7","strategyId":"warp-q-google6","endpoint":"162.159.198.2:500","transport":"masqueH3","connectMs":203,"connectStartedAt":"2026-10-06T10:00:00Z","utunName":"utun8","routeAll":true}"#
    static let statusTestRouteOnly = #"{"daemonRunning":true,"accountRegistered":false,"connected":true,"networkBusy":true,"connectionId":"2","routeAll":false}"#
    static let statusAfterLoss = #"{"daemonRunning":true,"accountRegistered":true,"connected":false,"networkBusy":false,"routeAll":false,"lastLoss":{"connectionId":"3","reason":"no recent network activity","at":"2026-10-06T10:01:00Z"}}"#
    static let statusScanOrCleanup = #"{"daemonRunning":true,"accountRegistered":false,"connected":false,"networkBusy":true,"routeAll":false}"#
    static let openFullTunnel = #"{"connectionId":"9","connectMs":120,"endpoint":"162.159.198.1:443","utunName":"utun8","routeAll":true,"warnings":["DNS was not overridden: boom"]}"#
    static let openTestConnection = #"{"connectionId":"1","connectMs":10,"routeAll":false}"#
    static let logs = #"{"lines":[{"seq":5,"timeMs":1791284063527,"text":"closed #1"}],"next":5,"dropped":2}"#
    static let logsEmpty = #"{"lines":null,"next":0}"#
}
