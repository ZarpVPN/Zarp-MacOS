import XCTest
@testable import ZarpCore

final class StrategyCatalogTests: XCTestCase {
    func testBuiltInIdsAreUnique() {
        let ids = StrategyCatalog.builtIn.map(\.id)
        XCTAssertEqual(ids.count, Set(ids).count, "duplicate strategy id in the built-in catalog")
    }

    func testBuiltInIsNotEmptyAndOrderIsStable() {
        // Order matters: the scan walks the list top to bottom, most-likely-first, same as
        // Windows Zarp. This just pins the first and last entries so a reorder is caught.
        XCTAssertEqual(StrategyCatalog.builtIn.first?.id, "warp-q-google6")
        XCTAssertEqual(StrategyCatalog.builtIn.last?.id, "warp-t-split-endhost")
    }

    func testPlainStrategiesAreAbsentAndCannotBecomeReady() {
        for id in ["direct", "direct-h2"] {
            XCTAssertFalse((StrategyCatalog.builtIn + StrategyCatalog.unavailable).contains { $0.id == id })
        }
        for transport in [Transport.masqueH3, .masqueH2] {
            for args in ["", "  ", "--payload=" + (transport == .masqueH3 ? "quic_initial" : "tls_client_hello")] {
                let strategy = Strategy(id: "old-plain", name: "Old plain", transport: transport, args: args)
                XCTAssertEqual(strategy.unsupportedReason?.key, "strategy.required")
            }
        }
        XCTAssertTrue(StrategyCatalog.builtIn.allSatisfy { $0.requiresDesync && !$0.plan.isDirect })
    }

    func testEveryBuiltInStrategyParsesWithoutError() {
        // Parsing must never crash regardless of what the technique needs — a `parseIssue` is a
        // valid, expected outcome for several of these (badsum, seqovl, md5, hostfakesplit).
        for s in StrategyCatalog.builtIn {
            _ = s.plan // must not trap
        }
    }

    func testKnownCleanStrategiesHaveNoParseIssue() {
        // These use nothing beyond a plain fake-packet send or a plain TCP split, so the parser
        // should describe them cleanly (readiness is a separate question — see StrategyReadiness).
        let cleanIds = ["warp-q-google6", "warp-q-google3", "warp-q-vk6", "warp-q-google-vk",
                         "warp-q-google10", "warp-q-google-ttl", "warp-q-vk-ttl",
                         "warp-wg-google6", "warp-wg-stun", "warp-wg-vk10", "warp-wg-google-ttl",
                         "warp-t-split", "warp-t-disorder"]
        for id in cleanIds {
            let s = (StrategyCatalog.builtIn + StrategyCatalog.unavailable).first { $0.id == id }
            XCTAssertNotNil(s, id)
            XCTAssertNil(s!.plan.parseIssue, "\(id) should parse cleanly, got \(String(describing: s!.plan.parseIssue))")
        }
    }

    func testKnownRawStrategiesAreFlagged() {
        // These need more than macOS's plain socket send/split can do (checksum tampering,
        // sequence-number games, TCP options) — the parser must say so, not silently accept them.
        let rawIds = ["warp-q-google-bad", "warp-t-google-md5", "warp-t-seqovl", "warp-t-vk-seq", "warp-t-hostfake"]
        for id in rawIds {
            let s = (StrategyCatalog.builtIn + StrategyCatalog.unavailable).first { $0.id == id }
            XCTAssertNotNil(s, id)
            XCTAssertNotNil(s!.plan.parseIssue, "\(id) should be flagged as needing more than a basic send")
        }
    }

    func testLoadAppendsCustomStrategiesAfterBuiltIn() {
        let custom = "My QUIC | h3 | --payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=8\n"
        let all = StrategyCatalog.load(customText: custom)
        XCTAssertEqual(all.count, StrategyCatalog.builtIn.count + 1)
        XCTAssertEqual(all.last?.legacyId, "custom-my-quic")
        XCTAssertTrue(all.last?.isCustom ?? false)
    }

    func testReadinessSaysWhichStrategiesTheDaemonCanActuallyRun() {
        // Product strategies execute fake-packet sends or TCP splits. Other
        // requests must be marked unsupported with a reason,
        // because an unsupported strategy sent to the daemon anyway would run as a plain direct
        // connection and be scored as if it had worked.
        let supported = Set(StrategyCatalog.builtIn.filter { $0.readiness == .available }.map(\.id))
        XCTAssertEqual(supported, [
            "warp-q-google6", "warp-q-google3", "warp-q-vk6", "warp-q-google-vk", "warp-q-google10",
            "warp-q-google-ttl", "warp-q-vk-ttl", "warp-t-split", "warp-t-disorder",
            "warp-q-google11", "warp-q-google12", "warp-t-split-host", "warp-t-split-sld", "warp-t-split-endhost",
            "warp-q-vk-name", "warp-q-google-name", "warp-t-vk-name", "warp-t-google-name",
            "warp-t-host-vk-name", "warp-t-host-google-name", "warp-t-sld-vk-name", "warp-t-sld-google-name",
            "warp-t-endhost-vk-name", "warp-t-endhost-google-name",
        ])
        let unsupported = Set(StrategyCatalog.unavailable.filter { $0.unsupportedReason != nil }.map(\.id))
        XCTAssertEqual(unsupported, [
            "warp-q-google-bad", "warp-t-google-md5", "warp-t-seqovl", "warp-t-vk-seq", "warp-t-hostfake",
            "warp-wg-google6", "warp-wg-stun", "warp-wg-vk10", "warp-wg-google-ttl",
        ])
        for s in StrategyCatalog.builtIn where s.unsupportedReason != nil {
            XCTAssertNotEqual(s.unsupportedReason?.key, "", s.id)
        }
        XCTAssertEqual(StrategyCatalog.unavailable.first { $0.id == "warp-wg-stun" }?.unsupportedReason?.key, "strategy.wgUnsupported")
        XCTAssertEqual(StrategyCatalog.unavailable.first { $0.id == "warp-q-google-bad" }?.unsupportedReason?.key, "strategy.badsum")
    }

    func testTLSNameVariantsRequireDesyncAndKeepSeparateConfigurationIdentity() throws {
        let original = try XCTUnwrap(StrategyCatalog.builtIn.first { $0.id == "warp-q-google6" })
        let named = try XCTUnwrap(StrategyCatalog.builtIn.first { $0.id == "warp-q-google-name" })
        XCTAssertEqual(named.args, original.args)
        XCTAssertNotEqual(named.configurationFingerprint, original.configurationFingerprint)
        XCTAssertEqual(named.warpTLSName, .google)
        let variants = StrategyCatalog.builtIn.filter { $0.warpTLSName != nil }
        XCTAssertEqual(variants.count, 10)
        XCTAssertTrue(variants.allSatisfy { $0.unsupportedReason == nil && !$0.plan.isDirect })
        let empty = Strategy(id: "empty", name: "Empty", transport: .masqueH3, args: "", warpTLSName: .vk)
        XCTAssertEqual(empty.unsupportedReason?.key, "strategy.required")
    }

    func testAnUnsupportedStrategyHasAnEmptyPlanSoItMustNeverBeSentToTheDaemon() {
        // This is *why* readiness matters: the wire format only carries fake steps and a TCP split.
        for id in ["warp-q-google-bad", "warp-t-google-md5", "warp-t-seqovl", "warp-t-vk-seq", "warp-t-hostfake"] {
            let plan = (StrategyCatalog.builtIn + StrategyCatalog.unavailable).first { $0.id == id }!.plan
            XCTAssertTrue(plan.fakeSteps.isEmpty && plan.tcpDesync == nil, "\(id) would be sent as a direct connection")
        }
    }

    func testNewQUICBudgetInvalidatesItsCacheAndKeepsWorkingH2Identity() throws {
        let quic = try XCTUnwrap(StrategyCatalog.builtIn.first { $0.id == "warp-q-google6" })
        let previous = Strategy.fingerprint(["warp-config-v2", quic.transport.rawValue, quic.args])
        XCTAssertNotEqual(quic.configurationFingerprint, previous)
        let h2 = try XCTUnwrap(StrategyCatalog.builtIn.first { $0.id == "warp-t-vk-name" })
        let working = Strategy.fingerprint(["warp-config-h2-v3", h2.transport.rawValue, h2.args, "tls-name-v1", "vk.com"])
        XCTAssertEqual(h2.configurationFingerprint, working)
        for marker in ["host", "sld", "endhost"] {
            let variants = StrategyCatalog.builtIn.filter {
                $0.transport == .masqueH2 && $0.plan.tcpDesync?.positions == ["1", marker] && $0.warpTLSName != nil
            }
            XCTAssertEqual(Set(variants.compactMap(\.warpTLSName)), Set(WarpTLSName.allCases))
        }
    }
}
