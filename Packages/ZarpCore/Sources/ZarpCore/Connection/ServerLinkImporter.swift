import Foundation

/// Pure import. It never resolves a name, starts a runtime or accepts WARP terms.
/// Options whose contracts are pending fail explicitly instead of being discarded.
public enum ServerLinkImporter {
    public static let maxLinkBytes = 8192

    public static func parse(_ input: String) throws -> ServerProfile {
        guard input.utf8.count <= maxLinkBytes else { throw ConnectionContractError(.profile) }
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let separator = text.range(of: "://") else { throw ConnectionContractError(.scheme) }
        let serverProtocol: ServerProtocol
        switch text[..<separator.lowerBound].lowercased() {
        case "vless": serverProtocol = .vless
        case "trojan": serverProtocol = .trojan
        case "hy2", "hysteria2": serverProtocol = .hysteria2
        default: throw ConnectionContractError(.scheme)
        }
        var body = String(text[separator.upperBound...])
        var label = ""
        if let hash = body.firstIndex(of: "#") {
            label = cleanLabel(String(body[body.index(after: hash)...]))
            body = String(body[..<hash])
        }
        var query = ""
        if let question = body.firstIndex(of: "?") {
            query = String(body[body.index(after: question)...])
            body = String(body[..<question])
        }
        if let slash = body.firstIndex(of: "/") {
            guard body[slash...] == "/" else { throw ConnectionContractError(.path) }
            body = String(body[..<slash])
        }
        guard let at = body.lastIndex(of: "@") else { throw ConnectionContractError(.credential) }
        let credential = try decode(String(body[..<at]), field: .credential)
        let authority = String(body[body.index(after: at)...])
        let (host, port) = try address(authority, serverProtocol: serverProtocol)
        let parameters = try parameters(query)

        let security: ServerSecurity
        switch parameters["security"] ?? (serverProtocol == .vless ? "none" : "tls") {
        case "none": security = .none
        case "tls": security = .tls
        case "reality": security = .reality
        default: throw ConnectionContractError(.security)
        }
        if let encryption = parameters["encryption"] {
            guard serverProtocol == .vless, ["", "none"].contains(encryption) else {
                throw ConnectionContractError(.encryption)
            }
        }
        for name in ["insecure", "allowInsecure"] {
            if let flag = parameters[name], !["0", "false"].contains(flag) {
                throw ConnectionContractError(.insecure)
            }
        }
        let transport: ServerTransport
        if serverProtocol == .hysteria2 {
            guard parameters["type"] == nil || parameters["type"] == "tcp" else {
                throw ConnectionContractError(.transport)
            }
            transport = .quic
        } else {
            switch parameters["type"] ?? "tcp" {
            case "tcp": transport = .tcp
            case "ws": transport = .ws
            case "grpc": transport = .grpc
            case "httpupgrade": transport = .httpUpgrade
            case "xhttp": transport = .xhttp
            default: throw ConnectionContractError(.transport)
            }
        }
        let flow: ServerFlow
        switch parameters["flow"] ?? "" {
        case "": flow = .none
        case "xtls-rprx-vision": flow = .vision
        default: throw ConnectionContractError(.flow)
        }
        guard parameters["sni"] == nil || parameters["peer"] == nil else {
            throw ConnectionContractError(.serverName)
        }
        let explicitName = parameters["sni"] ?? parameters["peer"]
        if security == .none && (explicitName != nil || parameters["alpn"] != nil) {
            throw ConnectionContractError(.security)
        }
        let alpn = (parameters["alpn"] ?? "").isEmpty ? [] :
            parameters["alpn"]!.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        let path: String?
        if [.ws, .httpUpgrade, .xhttp].contains(transport) {
            path = parameters["path"] ?? "/"
        } else {
            guard parameters["path"] == nil else { throw ConnectionContractError(.path) }
            path = nil
        }
        if parameters["host"] != nil && ![.ws, .httpUpgrade, .xhttp].contains(transport) {
            throw ConnectionContractError(.hostHeader)
        }
        if parameters["serviceName"] != nil && transport != .grpc {
            throw ConnectionContractError(.serviceName)
        }
        let serviceName = parameters["serviceName"].flatMap { $0.isEmpty ? nil : $0 }
        let fingerprint: TLSFingerprint?
        if let value = parameters["fp"] {
            guard let parsed = TLSFingerprint(rawValue: value) else { throw ConnectionContractError(.fingerprint) }
            fingerprint = parsed
        } else { fingerprint = security == .reality ? .chrome : nil }
        let obfs: ServerObfuscation?
        if let value = parameters["obfs"] {
            guard let parsed = ServerObfuscation(rawValue: value) else { throw ConnectionContractError(.obfs) }
            obfs = parsed
        } else { obfs = nil }
        let pins = try certificateList(parameters["pcs"], field: .certificatePin).map {
            $0.replacingOccurrences(of: ":", with: "").lowercased()
        }
        let names = try certificateList(parameters["vcn"], field: .certificateName)
        return try ServerProfile(label: label, host: host, port: port, serverProtocol: serverProtocol,
                                 credential: .init(kind: serverProtocol == .vless ? .uuid : .password, value: credential),
                                 transport: transport, security: security,
                                 serverName: security != .none ? explicitName ?? host : nil, alpn: alpn, flow: flow,
                                 path: path, hostHeader: parameters["host"], serviceName: serviceName,
                                 fingerprint: fingerprint, publicKey: parameters["pbk"], shortId: parameters["sid"],
                                 obfs: obfs, obfsPassword: parameters["obfs-password"],
                                 xhttpMode: parameters["mode"], xhttpExtra: parameters["extra"], xhttpPadding: parameters["x_padding_bytes"],
                                 echConfig: parameters["ech"],
                                 certificatePins: pins, certificateNames: names,
                                 spiderX: parameters["spx"], mldsaVerify: parameters["pqv"])
    }

    private static func certificateList(_ value: String?, field: ConnectionContractError.Field) throws -> [String] {
        guard let value else { return [] }
        let parts = value.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard parts.count <= 8, parts.allSatisfy({ !$0.isEmpty }) else { throw ConnectionContractError(field) }
        return parts
    }

    private static func address(_ authority: String, serverProtocol: ServerProtocol) throws -> (String, Int) {
        let host: String
        let portText: String?
        if authority.hasPrefix("[") {
            guard let close = authority.firstIndex(of: "]") else { throw ConnectionContractError(.host) }
            host = String(authority[authority.index(after: authority.startIndex)..<close])
            guard IPAddress(host)?.version == 6 else { throw ConnectionContractError(.host) }
            let suffix = String(authority[authority.index(after: close)...])
            guard suffix.isEmpty || suffix.hasPrefix(":") else { throw ConnectionContractError(.port) }
            portText = suffix.isEmpty ? nil : String(suffix.dropFirst())
        } else {
            let pieces = authority.split(separator: ":", omittingEmptySubsequences: false)
            guard pieces.count <= 2 else { throw ConnectionContractError(.host) }
            host = String(pieces.first ?? "")
            portText = pieces.count == 2 ? String(pieces[1]) : nil
        }
        guard let portText else {
            guard serverProtocol == .hysteria2 else { throw ConnectionContractError(.port) }
            return (host, 443)
        }
        guard !portText.isEmpty, portText.utf8.count <= 5,
              portText.utf8.allSatisfy({ (48...57).contains($0) }), let port = Int(portText),
              (1...65535).contains(port) else { throw ConnectionContractError(.port) }
        return (host, port)
    }

    private static func parameters(_ query: String) throws -> [String: String] {
        let supported: Set<String> = ["security", "sni", "peer", "alpn", "flow", "encryption", "type", "path",
                                      "host", "serviceName", "insecure", "allowInsecure", "fp", "pbk", "sid", "obfs", "obfs-password", "ech", "mode", "extra", "spx", "pqv", "pcs", "vcn", "x_padding_bytes"]
        let pending: [String: ConnectionContractError.Field] = ["support-x25519mlkem768": .parameters]
        var result: [String: String] = [:]
        for part in query.split(separator: "&") {
            let pair = part.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let key = try decode(String(pair[0]), field: .query)
            guard result[key] == nil else { throw ConnectionContractError(.query) }
            if let field = pending[key] { throw ConnectionContractError(field) }
            guard supported.contains(key) else { throw ConnectionContractError(.parameters) }
            result[key] = try decode(pair.count == 2 ? String(pair[1]) : "", field: .query)
        }
        return result
    }

    private static func decode(_ value: String, field: ConnectionContractError.Field) throws -> String {
        guard let decoded = value.removingPercentEncoding,
              decoded.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw ConnectionContractError(field)
        }
        return decoded
    }

    private static func cleanLabel(_ fragment: String) -> String {
        guard let decoded = fragment.removingPercentEncoding else { return "" }
        let scalars = decoded.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }
        var label = String(String.UnicodeScalarView(scalars)).split(whereSeparator: \.isWhitespace).joined(separator: " ")
        while label.utf8.count > 128 { label.removeLast() }
        return label
    }
}
