import Foundation

/// Checks the small contract grammar before Codable can collapse duplicate keys.
/// Contract numbers are integers. Ordinary application settings remain lenient.
enum StrictContractJSON {
    static func validate(_ data: Data) throws {
        guard String(data: data, encoding: .utf8) != nil else { throw Invalid() }
        var scanner = Scanner(bytes: Array(data))
        try scanner.value(depth: 0)
        scanner.whitespace()
        guard scanner.index == scanner.bytes.count else { throw Invalid() }
    }

    private struct Invalid: Error {}

    private struct Scanner {
        let bytes: [UInt8]
        var index = 0

        mutating func whitespace() {
            while index < bytes.count && [9, 10, 13, 32].contains(bytes[index]) { index += 1 }
        }

        mutating func take(_ byte: UInt8) -> Bool {
            whitespace()
            guard index < bytes.count, bytes[index] == byte else { return false }
            index += 1
            return true
        }

        mutating func value(depth: Int) throws {
            whitespace()
            guard depth <= 32, index < bytes.count else { throw Invalid() }
            switch bytes[index] {
            case 123:
                index += 1
                var keys = Set<String>()
                if take(125) { return }
                repeat {
                    let key = try string()
                    guard keys.insert(key).inserted, take(58) else { throw Invalid() }
                    try value(depth: depth + 1)
                    if take(125) { return }
                    guard take(44) else { throw Invalid() }
                } while true
            case 91:
                index += 1
                if take(93) { return }
                repeat {
                    try value(depth: depth + 1)
                    if take(93) { return }
                    guard take(44) else { throw Invalid() }
                } while true
            case 34: _ = try string()
            case 116: try literal("true")
            case 102: try literal("false")
            case 110: try literal("null")
            case 45, 48...57: try integer()
            default: throw Invalid()
            }
        }

        mutating func string() throws -> String {
            whitespace()
            let start = index
            guard take(34) else { throw Invalid() }
            while index < bytes.count {
                switch bytes[index] {
                case 34:
                    index += 1
                    // Foundation validates escapes and paired Unicode surrogates.
                    return try JSONDecoder().decode(String.self, from: Data(bytes[start..<index]))
                case 92: index += 2
                case 0...31: throw Invalid()
                default: index += 1
                }
            }
            throw Invalid()
        }

        mutating func literal(_ text: String) throws {
            let expected = Array(text.utf8)
            guard index + expected.count <= bytes.count,
                  Array(bytes[index..<(index + expected.count)]) == expected else { throw Invalid() }
            index += expected.count
        }

        mutating func integer() throws {
            if bytes[index] == 45 { index += 1 }
            guard index < bytes.count else { throw Invalid() }
            if bytes[index] == 48 { index += 1; return }
            guard (49...57).contains(bytes[index]) else { throw Invalid() }
            while index < bytes.count && (48...57).contains(bytes[index]) { index += 1 }
        }
    }
}
