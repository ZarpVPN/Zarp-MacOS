import Foundation
import CoreFoundation

extension ServerProfile {
    var hasTransportOptions: Bool {
        xhttpMode != nil || xhttpExtra != nil || xhttpPadding != nil || echConfig != nil ||
        !certificatePins.isEmpty || !certificateNames.isEmpty || spiderX != nil || mldsaVerify != nil
    }

    var transportOptionIdentity: [String] {
        var fields = ["server-transport-options-v1", xhttpMode ?? "", xhttpExtra ?? "", xhttpPadding ?? "", echConfig ?? "", String(certificatePins.count)]
        fields += certificatePins
        fields += [String(certificateNames.count)]
        fields += certificateNames
        fields += [spiderX ?? "", mldsaVerify ?? ""]
        return fields
    }

    func validateTransportOptions() throws {
        if transport != .xhttp {
            guard xhttpMode == nil, xhttpExtra == nil, xhttpPadding == nil else { throw ConnectionContractError(.modeOptions) }
            guard certificatePins.isEmpty, certificateNames.isEmpty, spiderX == nil, mldsaVerify == nil else {
                throw ConnectionContractError(.parameters)
            }
        } else {
            guard serverProtocol == .vless || serverProtocol == .trojan, security != .none else { throw ConnectionContractError(.transport) }
            if let xhttpMode, !Self.xhttpModes.contains(xhttpMode) { throw ConnectionContractError(.modeOptions) }
            if let xhttpPadding, Self.optionRange(xhttpPadding, max: 65_535) == nil { throw ConnectionContractError(.padding) }
            guard xhttpExtra == nil || xhttpPadding == nil else { throw ConnectionContractError(.padding) }
            if let xhttpExtra {
                guard let data = xhttpExtra.data(using: .utf8), data.count <= 8192 else { throw ConnectionContractError(.extra) }
                do {
                    try StrictContractJSON.validate(data)
                    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], validExtra(object, download: true) else {
                        throw ConnectionContractError(.extra)
                    }
                } catch { throw ConnectionContractError(.extra) }
            }
        }
        if let echConfig {
            guard security == .tls, echConfig.utf8.count <= 4096, let bytes = Data(base64Encoded: echConfig), bytes.count >= 6,
                  Int(bytes[0]) * 256 + Int(bytes[1]) == bytes.count - 2 else { throw ConnectionContractError(.ech) }
        }
        guard certificatePins.count <= 8, certificatePins.allSatisfy({ $0.utf8.count == 64 && $0.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) }),
              certificatePins.isEmpty || security == .tls else { throw ConnectionContractError(.certificatePin) }
        guard certificateNames.count <= 8, certificateNames.allSatisfy({ Self.hostIsValid($0.hasPrefix("*.") ? String($0.dropFirst(2)) : $0) }),
              certificateNames.isEmpty || security == .tls else { throw ConnectionContractError(.certificateName) }
        if let spiderX {
            guard security == .reality, spiderX.hasPrefix("/"), Self.optionText(spiderX, max: 256) else { throw ConnectionContractError(.parameters) }
        }
        if let mldsaVerify {
            guard security == .reality, mldsaVerify.utf8.count == 2603,
                  mldsaVerify.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 }),
                  Data(base64Encoded: mldsaVerify.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + "=")?.count == 1952 else {
                throw ConnectionContractError(.publicKey)
            }
        }
    }

    private static let xhttpModes = ["auto", "packet-up", "stream-up", "stream-one"]
    private static func optionText(_ s: String, max: Int) -> Bool {
        s.utf8.count <= max && s.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) && $0.properties.generalCategory != .format }
    }
    private static func optionInteger(_ value: Any, max: Int) -> Int? {
        guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), n.doubleValue >= 0,
              n.doubleValue <= Double(max), n.doubleValue.rounded() == n.doubleValue else { return nil }
        return n.intValue
    }
    private static func optionRange(_ value: Any, max: Int) -> Int? {
        if let s = value as? String {
            let pieces = s.split(separator: "-", omittingEmptySubsequences: false)
            guard (1...2).contains(pieces.count), pieces.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy({ (48...57).contains($0) }) }),
                  let first = Int(pieces[0]), let last = Int(pieces.last!), first <= last, last <= max else { return nil }
            return last
        }
        return optionInteger(value, max: max)
    }

    /// Only fields supported by the pinned Xray release are accepted. A second
    /// download leg must target the same server and use the same outer transport.
    private func validExtra(_ object: [String: Any], download: Bool) -> Bool {
        let ranges = ["xPaddingBytes": 65_535, "uplinkChunkSize": 1_048_576, "scMaxEachPostBytes": 16_777_216,
                      "scMinPostsIntervalMs": 60_000, "scStreamUpServerSecs": 3600]
        let strings = Set(["xPaddingKey", "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod", "uplinkHTTPMethod",
                           "sessionIDPlacement", "sessionIDKey", "sessionIDTable", "seqPlacement", "seqKey", "uplinkDataPlacement", "uplinkDataKey"])
        let bools = Set(["xPaddingObfsMode", "noGRPCHeader", "noSSEHeader"])
        for (key, value) in object {
            if let max = ranges[key] { if Self.optionRange(value, max: max) == nil { return false }; continue }
            if key == "sessionIDLength" { if Self.optionRange(value, max: 256) == nil { return false }; continue }
            if strings.contains(key) { guard let s = value as? String, Self.optionText(s, max: 256) else { return false }; continue }
            if bools.contains(key) { guard let n = value as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { return false }; continue }
            switch key {
            case "headers":
                guard let headers = value as? [String: String], headers.count <= 32, headers.allSatisfy({ key, value in
                    !key.isEmpty && key.utf8.count <= 64 && key.lowercased() != "host" &&
                    key.utf8.allSatisfy({ (33...126).contains($0) && !Array("()<>@,;:\\\"/[]?={} ".utf8).contains($0) }) && Self.optionText(value, max: 1024)
                }) else { return false }
            case "scMaxBufferedPosts": if Self.optionInteger(value, max: 64) == nil { return false }
            case "serverMaxHeaderBytes": if Self.optionInteger(value, max: 1_048_576) == nil { return false }
            case "xmux":
                guard let mux = value as? [String: Any], mux.allSatisfy({ key, value in
                    let limits = ["maxConcurrency": 128, "maxConnections": 32, "cMaxReuseTimes": 10_000, "hMaxRequestTimes": 10_000,
                                  "hMaxReusableSecs": 86_400, "hKeepAlivePeriod": 3600]
                    guard let max = limits[key] else { return false }
                    return key == "hKeepAlivePeriod" ? Self.optionInteger(value, max: max) != nil : Self.optionRange(value, max: max) != nil
                }), !(mux["maxConcurrency"] != nil && mux["maxConnections"] != nil) else { return false }
            case "downloadSettings":
                guard download, let settings = value as? [String: Any], validDownload(settings) else { return false }
            default: return false
            }
        }
        let postSize = object["scMaxEachPostBytes"].flatMap { Self.optionRange($0, max: 16_777_216) } ?? 1_048_576
        let posts = object["scMaxBufferedPosts"].flatMap { Self.optionInteger($0, max: 64) } ?? 30
        return postSize * posts <= 67_108_864
    }

    private func validDownload(_ settings: [String: Any]) -> Bool {
        guard Set(settings.keys).isSubset(of: ["address", "port", "network", "security", "tlsSettings", "realitySettings", "xhttpSettings"]) else { return false }
        if let value = settings["address"] { guard (value as? String)?.lowercased() == host.lowercased() else { return false } }
        if let value = settings["port"] { guard Self.optionInteger(value, max: 65535) == port else { return false } }
        if let value = settings["network"] { guard value as? String == "xhttp" else { return false } }
        if let value = settings["security"] { guard value as? String == security.rawValue else { return false } }
        for key in ["tlsSettings", "realitySettings"] {
            if let value = settings[key] {
                guard key == (security == .tls ? "tlsSettings" : "realitySettings"), let tls = value as? [String: Any],
                      Set(tls.keys).isSubset(of: ["serverName", "alpn"]) else { return false }
                if let name = tls["serverName"] { guard name as? String == (serverName ?? host) else { return false } }
                if let protocols = tls["alpn"] { guard protocols as? [String] == alpn else { return false } }
            }
        }
        if let value = settings["xhttpSettings"] {
            guard var xhttp = value as? [String: Any] else { return false }
            if let value = xhttp.removeValue(forKey: "mode") { guard let mode = value as? String, Self.xhttpModes.contains(mode) else { return false } }
            if let value = xhttp.removeValue(forKey: "path") { guard let s = value as? String, s.hasPrefix("/"), Self.optionText(s, max: 2048) else { return false } }
            if let value = xhttp.removeValue(forKey: "host") { guard let s = value as? String, Self.hostIsValid(s) else { return false } }
            if let value = xhttp.removeValue(forKey: "extra") {
                guard xhttp.isEmpty, let extra = value as? [String: Any], validExtra(extra, download: false) else { return false }
            } else if !validExtra(xhttp, download: false) { return false }
        }
        return true
    }
}
