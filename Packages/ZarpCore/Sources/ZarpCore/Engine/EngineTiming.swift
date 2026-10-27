import Foundation

/// Injectable time keeps stability, backoff and network-change checks testable
/// without waiting or opening a real tunnel.
public struct EngineTiming: Sendable {
    public let now: @Sendable () -> Date
    public let sleep: @Sendable (TimeInterval) async throws -> Void

    public init(now: @escaping @Sendable () -> Date = { Date() },
                sleep: @escaping @Sendable (TimeInterval) async throws -> Void = { seconds in
                    try Task.checkCancellation()
                    if seconds > 0 { try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000)) }
                }) {
        self.now = now
        self.sleep = sleep
    }
}
