import Foundation
import Security
import ZarpCore

/// Ordinary unprivileged HTTPS through the current system connection. No proxy
/// dictionary, interface binding, system setting or persistent storage is used.
/// Constructing it makes no request. Only an explicit downloader call starts one.
public struct FoundationSubscriptionTransport: SubscriptionHTTPTransport {
    private let configuration: @Sendable () -> URLSessionConfiguration
    private var testAnchor: LoopbackTestAnchor?

    public init() { configuration = { Self.privateConfiguration() } }
    init(configuration: @escaping @Sendable () -> URLSessionConfiguration) { self.configuration = configuration }
    init(loopbackTestCertificate: Data, port: Int) {
        configuration = { Self.privateConfiguration() }
        testAnchor = LoopbackTestAnchor(certificate: loopbackTestCertificate, port: port)
    }

    static func privateConfiguration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.waitsForConnectivity = false
        return configuration
    }

    public func get(url: URL, userAgent: String, deadline: ContinuousClock.Instant) async throws -> SubscriptionHTTPResponse {
        let attempt = Attempt(configuration: configuration(), testAnchor: testAnchor)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                attempt.start(url: url, userAgent: userAgent, deadline: deadline, continuation: continuation)
            }
        } onCancel: {
            attempt.finish(.failure(SubscriptionError.cancelled))
        }
    }
}

private struct LoopbackTestAnchor: Sendable {
    let certificate: Data
    let port: Int
}

private final class Attempt: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let configuration: URLSessionConfiguration
    private let testAnchor: LoopbackTestAnchor?
    private let lock = NSLock()
    private var continuation: CheckedContinuation<SubscriptionHTTPResponse, Error>?
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var response: HTTPURLResponse?
    private var body = Data()
    private var completed = false

    init(configuration: URLSessionConfiguration, testAnchor: LoopbackTestAnchor?) {
        self.configuration = configuration; self.testAnchor = testAnchor
    }

    func start(url: URL, userAgent: String, deadline: ContinuousClock.Instant, continuation: CheckedContinuation<SubscriptionHTTPResponse, Error>) {
        guard (try? ConnectionSource(kind: .subscription, subscriptionURL: url.absoluteString)) != nil else {
            continuation.resume(throwing: SubscriptionError.source)
            return
        }
        let components = ContinuousClock.now.duration(to: deadline).components
        let remaining = Double(components.seconds) + Double(components.attoseconds) / 1e18
        guard remaining > 0 else { continuation.resume(throwing: SubscriptionError.timeout); return }
        lock.lock()
        if completed {
            lock.unlock()
            continuation.resume(throwing: SubscriptionError.cancelled)
            return
        }
        self.continuation = continuation
        configuration.timeoutIntervalForRequest = min(remaining, 25)
        configuration.timeoutIntervalForResource = min(remaining, 25)
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: min(remaining, 25))
        request.httpMethod = "GET"
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue("gzip", forHTTPHeaderField: "Accept-Encoding")
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        let task = session.dataTask(with: request)
        self.session = session; self.task = task
        lock.unlock()
        task.resume()
    }

    func finish(_ result: Result<SubscriptionHTTPResponse, Error>) {
        lock.lock()
        if completed { lock.unlock(); return }
        completed = true
        let continuation = self.continuation, session = self.session
        self.continuation = nil; self.session = nil; task = nil; body = Data()
        lock.unlock()
        session?.invalidateAndCancel()
        continuation?.resume(with: result)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil) // The pure coordinator validates every redirect.
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let response = response as? HTTPURLResponse else {
            completionHandler(.cancel); finish(.failure(SubscriptionError.network)); return
        }
        if response.statusCode != 200 {
            completionHandler(.cancel)
            finish(.success(SubscriptionHTTPResponse(status: response.statusCode, location: response.value(forHTTPHeaderField: "Location"))))
            return
        }
        if response.expectedContentLength > SubscriptionParser.maxBytes {
            completionHandler(.cancel); finish(.failure(SubscriptionError.size)); return
        }
        lock.lock()
        self.response = response
        let active = !completed
        lock.unlock()
        completionHandler(active ? .allow : .cancel)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        if completed { lock.unlock(); return }
        if data.count > SubscriptionParser.maxBytes - body.count {
            lock.unlock(); finish(.failure(SubscriptionError.size)); return
        }
        // URLSession delivers decoded HTTP entity data here. This bound applies
        // incrementally to delivered bytes, including decompressed gzip bodies.
        body.append(data)
        lock.unlock()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error {
            finish(.failure(Self.sanitized(error)))
            return
        }
        lock.lock()
        let response = self.response, data = body
        lock.unlock()
        guard let response else { finish(.failure(SubscriptionError.network)); return }
        finish(.success(SubscriptionHTTPResponse(status: response.statusCode, body: data)))
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            if let anchor = testAnchor {
                // Internal fixture construction only. Default production trust
                // cannot select an anchor. It is restricted to the exact private
                // numeric loopback origin and still evaluates chain/time/IP SAN.
                guard challenge.protectionSpace.host == "127.0.0.1", challenge.protectionSpace.port == anchor.port,
                      challenge.protectionSpace.protocol == "https", anchor.certificate.count <= 16_384,
                      let certificate = SecCertificateCreateWithData(nil, anchor.certificate as CFData),
                      let trust = challenge.protectionSpace.serverTrust,
                      SecTrustSetAnchorCertificates(trust, [certificate] as CFArray) == errSecSuccess,
                      SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
                      SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
                      SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, "127.0.0.1" as CFString)) == errSecSuccess,
                      SecTrustEvaluateWithError(trust, nil) else {
                    completionHandler(.cancelAuthenticationChallenge, nil)
                    finish(.failure(SubscriptionError.tls))
                    return
                }
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            }
            completionHandler(.performDefaultHandling, nil)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, willCacheResponse proposedResponse: CachedURLResponse,
                    completionHandler: @escaping (CachedURLResponse?) -> Void) { completionHandler(nil) }

    private static func sanitized(_ error: Error) -> SubscriptionError {
        guard let error = error as? URLError else { return .network }
        switch error.code {
        case .timedOut: return .timeout
        case .cancelled: return .cancelled
        case .secureConnectionFailed, .serverCertificateHasBadDate, .serverCertificateUntrusted,
             .serverCertificateHasUnknownRoot, .serverCertificateNotYetValid, .clientCertificateRejected,
             .clientCertificateRequired: return .tls
        default: return .network
        }
    }
}
