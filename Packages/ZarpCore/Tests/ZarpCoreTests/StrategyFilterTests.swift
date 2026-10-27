import XCTest
@testable import ZarpCore

final class StrategyFilterTests: XCTestCase {
    func testCountryUnionExcludesControlsAndRetainsRussianFakes() {
        let list = StrategyCatalog.builtIn
        let cn = list.filter { StrategyFilter.matches($0, value: "cn") }
        XCTAssertFalse(cn.contains { !$0.requiresDesync || $0.args.contains("vk") })
        let union = list.filter { StrategyFilter.matches($0, value: "ru,cn") }
        XCTAssertTrue(union.contains { $0.id == "warp-q-vk6" })
        XCTAssertTrue(union.contains { $0.id == "warp-t-split-host" })
        XCTAssertFalse(union.contains { $0.id == "direct" })
        XCTAssertEqual(StrategyFilter.normalize(" CN,ru,xx,cn "), "ru,cn")
    }

    func testFourthColumnDoesNotAlterArgumentsOrIdentity() {
        let line = "Name | h2 | --payload=tls_client_hello --lua-desync=multisplit:pos=1,host"
        let legacy = CustomStrategyFile.parse(line)[0]
        let tagged = CustomStrategyFile.parse(line + " | ru,cn")[0]
        XCTAssertEqual(tagged.args, legacy.args)
        XCTAssertEqual(tagged.id, legacy.id)
        XCTAssertEqual(tagged.configurationFingerprint, legacy.configurationFingerprint)
        XCTAssertEqual(tagged.countries, [.ru, .cn])
        XCTAssertEqual(tagged.readiness, .available)
        XCTAssertFalse(StrategyFilter.matches(legacy, value: "ru"))
        XCTAssertTrue(StrategyFilter.matches(legacy, value: "all"))
        XCTAssertTrue(CustomStrategyFile.parse(line + " | ru | extra").isEmpty)
    }

    func testArgumentEditsAndTransportChangeInvalidateIdentity() {
        let first = CustomStrategyFile.parse("Same | h3 | --payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=3")[0]
        let changed = CustomStrategyFile.parse("Same | h3 | --payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=6")[0]
        XCTAssertNotEqual(first.id, changed.id)
        XCTAssertNotEqual(first.configurationFingerprint, changed.configurationFingerprint)
        XCTAssertEqual(first.legacyId, changed.legacyId)
    }
}
