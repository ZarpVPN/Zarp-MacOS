# Strategy failures in the 0.4.4 session: 2026-10-26

The original investigation is preserved below. Corrections for the confirmed
endpoint-selection and failure-reporting defects are implemented in 0.4.5;
validation and remaining carrier-network limits are recorded in
[IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md).

Read-only analysis of the existing app log, daemon log and saved strategy
results. Times below use Europe/Moscow. No production app, IPC, tunnel or
external transport probe was started. No service, account or network state was
changed. Product code is unchanged by this investigation.

Evidence:

- `~/Library/Logs/Zarp/zarp.log`, latest launch beginning at line 1392.
- `/Library/Logs/Zarp/zarpd.log`, daemon 0.4.4 beginning at line 211.
- `~/Library/Application Support/Zarp/zarp.json`: only isolation settings and
  strategy result fields were inspected. Account file contents were inaccessible
  and were not read. No license, token, private key or subscription URL was copied.
- Sanitized, source-hashed summary:
  `build/strategy-failure-diagnosis-2026-10-26.json`.

## Observed sequence

- 00:06:57: the first automatic preparation attempt reports
  `SMAppServiceErrorDomain (1)`.
- 00:07:05-00:07:06: the daemon starts and preparation succeeds. A persistent
  HTTP3 connection opens. It is explicitly closed by the app at 00:07:16.
- 00:07:20-00:07:38: three QUIC strategies pass their fresh checks. Another
  persistent connection opens at 00:07:39, passes verification at 00:07:43 and
  is explicitly closed by the app at 00:07:47. These closes do not establish a
  spontaneous transport failure; the exact UI action is not logged.
- 00:07:55: the app observes an access-network change. The subsequent scan
  starts at 00:07:59 and exhausts all 14 eligible strategies at 00:09:40.
  No additional network-change message occurs during that scan. The next
  observations are at 00:09:53 and 00:10:01.

The 14 scan failures have distinct causes:

| Group | Count | Actual evidence |
| --- | --- | --- |
| QUIC connection loss | 7 | Daemon connections #9-#15 terminate with stateless resets 1-3 seconds after opening. The app later reports `no open connection`. |
| QUIC connection timeout | 2 | Both TTL=4 variants exceed the 15-second connection timeout. |
| TLS public-key mismatch | 3 | split midsld, host and endhost fail peer public-key verification. |
| TLS connection timeout | 2 | disorder midsld and split sld exceed the 15-second connection timeout. |

## Confirmed HTTP2 endpoint-selection defect

`daemon/endpoints.go` resolves isolation tokens through the shared HTTP3 IP pool
`162.159.198.1`, `162.159.198.2`. The HTTP2 branch only changes the port to 443.
It bypasses the account's dedicated `EndpointH2V4` value for isolation requests.
The saved settings have isolation enabled and no custom WARP endpoints.

Saved result tokens let the existing resolver determine the failed HTTP2
destinations without opening another network connection:

| Strategy | Saved token | Resolved TCP endpoint | Result |
| --- | --- | --- | --- |
| split 1,midsld | isolated-14 | 162.159.198.1:443 | Public-key mismatch |
| disorder 1,midsld | isolated-15 | 162.159.198.2:443 | Timeout |
| split 1,host | isolated-18 | 162.159.198.1:443 | Public-key mismatch |
| split 1,sld | isolated-19 | 162.159.198.2:443 | Timeout |
| split 1,endhost | isolated-20 | 162.159.198.1:443 | Public-key mismatch |

These addresses are derived from saved tokens and the resolver, rather than
from new packet captures. Failed handshakes do not currently log their resolved
endpoint. The exact correspondence is confirmed by the stored tokens.

`warp.TLSConfigFromAccount` supplies the same enrolled endpoint public key to
both transports. `DialH2` clones that config and changes ALPN to h2. The pinned
usque verifier returns the exact logged message when the peer's ECDSA public
key differs. This is a peer-key mismatch, rather than a generic missing CA or
certificate-expiry error. Repeating a TLS split cannot change the expected key.

The [upstream HTTP2 documentation](https://github.com/Diniboy1123/usque/wiki/HTTP-2-support)
uses a dedicated HTTP2 endpoint with default 162.159.198.2 and explicitly notes
that TCP/TLS endpoints can present a different public key from QUIC. That
supports separating protocol-specific endpoints and trust metadata. It does
not establish that .1 can never offer HTTP2, or that the two .2 timeouts would
disappear after correcting selection. Both remain separate concerns.

Do not remove pin verification to make a candidate pass. Use an authenticated
HTTP2 endpoint and its appropriate trusted key, and report a trust mismatch
as such. This analysis does not propose automatic account re-registration.

## QUIC root cause and reporting defect

For #9-#15, `open` succeeds before the packet pump reports
`connect-ip read: received a stateless reset`. The daemon closes and removes the
connection. A later traffic-measurement request reaches `Manager.measure`, which
finds no active entry and returns `no open connection #N`. That message is a
consequence of the prior loss; it hides the useful reset reason in the table.

The trace establishes short-lived QUIC transport failure on the changed path.
It does not identify the issuer or underlying cause of the resets. A stateless
reset alone cannot attribute the event to carrier DPI. The
[QUIC termination specification](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3)
describes it as termination when a peer cannot associate packets with active
connection state. No packet capture or outer-path telemetry is available here
to distinguish endpoint behavior, path/NAT behavior or network interference.

The earlier Wi-Fi success is consistent with the user's external zapret setup.
It does not establish that the native fake-packet techniques bypass the hotspot's
network. The new stability checks detect these failures; increasing retries or
the timeout does not itself repair either reset or peer-key mismatch.

`H3_NO_ERROR (local)` and closed-stream messages accompanying `closed by the app`
are cleanup noise in this trace. The occasional inner Hop Limit 1 drop is not
the demonstrated cause of the seven outer QUIC stateless resets. The daemon
continues serving requests through the failing scan; no daemon crash is shown.

## Corrections supported by this evidence

1. Separate HTTP2 endpoint selection from the HTTP3 rotation pool. Honor the
   dedicated account/validated HTTP2 destination during isolated tests. Keep
   fresh connection checks without inventing endpoint independence.
2. Make HTTP2 trust compatibility explicit. Keep key verification and distinguish
   a peer-key mismatch from a failed desync strategy or ordinary timeout.
3. Preserve the terminal reason of a closed handle for a bounded time and return
   it to a later measurement request. Show the QUIC reset in the result instead
   of only `no open connection`.
4. Record failed connection phase, resolved endpoint and strategy identity in
   sanitized logs. No account key, license or subscription secret is needed.
5. Investigate native QUIC outer-strategy effectiveness separately from recovery
   behavior. The exact hotspot reset cause remains unverified. Existing evidence
   does not justify changing the user's VPN, routes or DNS for autonomous tests.

No fix, new release or live test is claimed by this analysis.
