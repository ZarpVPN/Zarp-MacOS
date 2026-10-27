import Foundation
@testable import ZarpCore

extension EngineTiming {
    static var immediate: Self { Self(sleep: { _ in try Task.checkCancellation() }) }
}
