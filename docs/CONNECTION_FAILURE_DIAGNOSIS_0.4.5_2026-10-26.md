# WARP failures in the 0.4.5 session: 2026-10-26

The latest user session fails on the WARP outer transport path. It does not
show an application or daemon crash, and it does not exercise imported server
protocols. The logs establish the failure mechanisms below, but cannot establish
the issuer of the QUIC resets or the exact HTTP2 timeout stage. Native WARP
loopback checks pass. A separate pinned product-backend matrix recorded one
XHTTP auto UDP timeout, described below. No claim of repaired carrier
connectivity is made.

## Evidence and scope

All times use Europe/Moscow. Read existing files only:

- `~/Library/Logs/Zarp/zarp.log`, lines 1496-1577: app 0.4.5.
- `/Library/Logs/Zarp/zarpd.log`, lines 277-321: daemon 0.4.5.
- Only the isolation, timeout and custom-endpoint count from the saved app
  settings. The WARP account file was not read.
- Sanitized summary with source and session hashes:
  `build/connection-failure-diagnosis-0.4.5-2026-10-26.json`.

At 11:16:31, initial automatic preparation reports
`SMAppServiceErrorDomain (1)`. It recovers at 11:16:45, before scanning starts.
The service then handles all 14 strategies through 11:18:41. This startup error
does not explain the transport failures after preparation succeeds. The app
observes a network change at 11:16:43, before the scan; no further change is
logged during it.

| Transport and outcome | Count | Evidence |
| --- | --- | --- |
| HTTP3/QUIC connection loss | 7 | CONNECT-IP opens in 282-516 ms. Handles #1-#7 then terminate with `received a stateless reset`, less than three seconds after opening at the log's one-second resolution. |
| HTTP3/QUIC handshake timeout | 2 | Both TTL=4 variants send their fakes and fail with `phase=quic_handshake`. Elapsed log times are about five seconds, although the configured upper limit is 15 seconds. |
| HTTP2/TLS connection timeout | 5 | Every attempt targets the dedicated `162.159.198.2:443` endpoint and expires after about 15 seconds. The old diagnostic reports `phase=connect_ip`; that label alone does not prove TLS completed. |

All seven opened handles are scan connections with `persistent=false` and
`routeAll=false`. No persistent 0.4.5 connection is established in this session.
The previous `no open connection` reporting defect is corrected: the table now
retains the underlying QUIC reset. HTTP2 no longer rotates through the HTTP3 IP
pool, and no new peer-key mismatch appears. These earlier fixes are active, but
neither is evidence of successful transport on the current network.

The native fake sender records nine attempted QUIC strategies, with packet and
byte counts and numeric destinations. This establishes that the sender ran. It
does not establish that the network's DPI accepted the strategy. There is no
evidence here that disabling delayed stability checks, increasing retries or
silently using plain transport would repair these connections.

Only `masqueH3` and `masqueH2` WARP attempts appear. There is no XHTTP, VLESS,
Trojan or other imported-server attempt in this session, so these logs cannot
support an all-server-protocol regression claim.

Read-only installed-bundle metadata confirms 0.4.5 (11), both pinned backend
directories and the backend guardian are present. The shared source/IPC path
uses `openServer` for imported profiles, retaining their source/server identity;
server opens skip WARP account registration. XHTTP uses its dedicated Xray
compiler and mandatory outer relay. These paths were preserved. File presence
and static inspection do not pass signed runtime or system-TUN acceptance.

The pinned quic-go reset detector checks a received packet against a known
16-byte reset token before terminating the connection. This is more specific
than a generic packet drop. The
[QUIC reset specification](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3.1)
defines token-based detection, but the retained log has no packet/path evidence
to determine the actual issuer or why its state was lost. No QUIC library
downgrade or speculative change to connection IDs, MTU or key verification was
made on that evidence.

## Confirmed diagnostic defect and correction

The HTTP2 request has a session context, cancelled by a separate dial timeout.
The HTTP transport can return that cancellation before its custom dial callback
returns the underlying TCP or TLS error. The previous fallback labelled the
whole operation `connect_ip` and wrapped a cancellation without retaining a
typed `context.DeadlineExceeded` for its own timer.

Reproduced with an actual numeric loopback peer that accepts TCP but never
completes TLS. Before correction it reports `connect_ip`, although there is no
completed TLS handshake or HTTP request. A separate authenticated TLS fixture
with no HTTP2 response and a fixture that receives CONNECT but never replies
also reproduce the lost deadline type. Evidence:
`/tmp/zarp-connection-investigation-phase-reproduction.log`.

The working source now retains a concurrent-safe last observed stage:

- `tcp`: creating the selected physical TCP connection.
- `tls`: the custom TLS handshake has begun.
- `http2`: TLS completed, before the request-header callback.
- `connect_ip`: the HTTP transport wrote the CONNECT headers.

The stage is diagnostic progress, not proof of a peer response. HTTP2 can write
CONNECT headers before receiving peer SETTINGS; a private fixture verifies this
distinction. Existing typed TCP/TLS and key-pin errors still take precedence.
The dial timer now also retains `context.DeadlineExceeded`, and caller
cancellation retains the underlying error chain. No credentials, certificates
or HTTP header values are logged by this change. The installed app and daemon
have not been replaced, so their existing logs cannot acquire this extra detail
retroactively.

The [Go HTTP trace documentation](https://pkg.go.dev/net/http/httptrace) confirms
that callbacks can run concurrently and that `WroteHeaders` describes a local
header write. Context7 documentation for
[usque](https://github.com/Diniboy1123/usque/blob/main/api/masque.go), checked
against the locally pinned module, matches the current CONNECT URI, protocol
headers, HTTP2 ALPN, HTTP3 datagram settings and 20-byte QUIC connection IDs.
No dependency upgrade, TLS-pin bypass or account reset is indicated by this
comparison.

## Local validation and remaining limits

Added real numeric IPv4 and IPv6 loopback fixtures for both product dialers.
They use ephemeral client authentication, the product's endpoint-key pin,
HTTP2 ClientHello splitting, and private same-socket fake sends before HTTP3.
Both directions carry actual IP payloads after the short dial context ends and
again 2.1 seconds later, beyond the local reproduction's two-second dial limit.
Cleanup closes the owned sessions and fixture servers. This checks transport
and lifetime behavior without an OS tunnel, production credentials or routes.

The first HTTP2 fixture dereferenced absent request TLS metadata in the local
Go HTTP2 adapter. Its corrected version relies on required TLS client
authentication instead. That fixture error is not a product failure or a pass.
The earlier incorrect expectation that HTTP2 waits for peer SETTINGS before
writing headers was also corrected; the retained test explicitly documents
what the observed phase does and does not establish.

Final suite results are recorded in
[IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md#latest-045-session-and-http2-timeout-diagnostics-2026-10-26).
No production app, daemon installation, production IPC, real TUN, physical-path
probe or network-setting mutation was performed. The user's VPN is untouched.

The external reset issuer, a working strategy on this access network, actual
product TUN integration, real ECH/Reality-XHTTP combinations and signed-release
acceptance remain separate unverified items. Existing pending user tests are
not counted as passes, and no unchanged manual test is requested again.

## Separate product-backend runtime investigation

The full ordinary Go suite passes, but the real pinned backend cases are
explicitly skipped without their engine environment variables. To check the
new functionality directly, both existing engine files were independently
checksum-verified and the existing `TestPinnedProductServerRuntime` was run
with both pins. No engine was downloaded or replaced. The long-soak option and
production socket override were cleared.

This fixture executes the product profile compiler, private guardian and outer
strategy relay with local TLS/UDP destinations. It uses ephemeral credentials
and no TUN or production account. The first matrix has 12 cases:

- VLESS, Trojan and Hysteria2 pass both HTTPS and UDP.
- XHTTP packet-up, stream-up, stream-one, H3, bounded extra and a separate
  download leg pass both HTTPS and UDP.
- XHTTP auto passes HTTPS but its first single UDP echo times out after three
  seconds. Five immediate focused repetitions pass HTTPS and UDP.
- Both incorrect-credential cases reject HTTPS after the outer strategy runs.

The first matrix is a failure, not a passed all-protocol run. Its log is
`/tmp/zarp-connection-investigation-product-runtime.log`; the five focused
passes are in `/tmp/zarp-connection-investigation-xhttp-auto-repeat.log`.
The timeout is independent of the user's WARP log and is not established as a
cause of its QUIC resets. There is insufficient evidence to attribute it to XHTTP auto, the
SOCKS UDP ingress, the first-packet path or the private fixture.

Added atomic receive/reply counts and backend/outer-flow status to this private
test's failure output, with joined echo-worker cleanup. These diagnostics
contain no credentials or packet contents. They identify whether a later
failed echo reached and left the local target. No retry, larger timeout,
protocol substitution or production behavior change was used to hide the
failure. All ten instrumented auto repetitions pass. The final full matrix
also passes all 12 cases, including auto:
`/tmp/zarp-connection-investigation-product-runtime-instrumented.log`.
The first timeout remains an unresolved observation despite 16 later
successful auto attempts. These passes establish private backend traffic and
outer-strategy execution, not carrier bypass or actual product-TUN acceptance.
