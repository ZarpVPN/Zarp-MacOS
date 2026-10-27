# Phone hotspot connection loss: 2026-10-25

The investigation below is preserved. Its corrections are now implemented in
0.4.4; validation and remaining live-network limits are recorded in
[IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md).

This is a read-only investigation of the user's 0.4.3 session. No service, route,
DNS, interface, system proxy, account or VPN state was changed. No live connection
or production IPC query was initiated. Product code is unchanged by this review.

## Observed sequence

Sources: `~/Library/Logs/Zarp/zarp.log` and `/Library/Logs/Zarp/zarpd.log`.
Sanitized connection summary: `build/hotspot-diagnosis-2026-10-25.json`.

- 23:11:11: automatic preparation succeeds; daemon 0.4.3 is listening. The
  previous service-startup failure is not present in this session.
- 23:11:29-23:13:22: persistent connection #8 remains open for about 113 seconds.
  It closes with `closed by the app`, immediately before another quick scan.
  This log entry is app-requested cleanup, rather than evidence of a spontaneous
  transport failure. The precise UI action that requested it is not logged.
- 23:13:24-23:13:26: Google x6 and Google x3 pass short scan/recheck requests.
- 23:13:29: test connection #14 fails with `sendmsg: network is unreachable`.
  This agrees with the user's reported network transition. The logs do not
  identify the exact physical interface or precise moment the hotspot became
  the active path.
- 23:13:36: #15 fails with `received a stateless reset`. Another QUIC candidate
  subsequently passes short traffic checks. The quick scan reaches three
  confirmed candidates and chooses Google x6 by its score.
- 23:13:54-23:14:08: persistent connections #18-#21 repeatedly use Google x6 and
  `162.159.198.2:4500`. Each closes within the same or following logged second
  with a QUIC stateless reset, shortly after passing connection traffic checks.
- 23:13:56, 23:14:00 and 23:14:04: the GUI starts a new recovery cycle, each
  displaying attempt `1/3`. At 23:14:09 the three-cycle limit is reached.
- 23:14:12-23:14:25: another connect workflow tries Google x6, Google x3 and
  Google x10, including ports 4500, 4443 and 500. Resets recur. The final wrapper
  reports a closed network connection after a preceding stateless-reset message.
- Every logged tunnel attempt in this session uses `masqueH3`. There is no
  logged MASQUE/HTTP2 attempt.

## Confirmed application behavior

1. `ZarpEngine.apply` accepts a persistent connection after one measured traffic
   sample plus the daemon's warm-up request. These are real WARP traffic checks,
   but there is no stability interval. A tunnel that dies immediately afterwards
   is briefly displayed as connected.
2. `scheduleReconnect` reuses the selected strategy and its pinned endpoint. A
   brief successful `apply` ends the current retry loop. The next loss starts a
   new cycle with attempt 1, so the 10/30-second backoff is not reached in this
   trace. Three such cycles in ten minutes exhaust the anti-loop limit.
3. Recovery does not advance to another transport or perform a new bounded
   strategy search after repeated brief successes. Quick search can stop after
   three short-lived QUIC confirmations before testing TLS/HTTP2 candidates.
4. Scan results bind to source, strategy and endpoint configuration, but have no
   network-path generation. Successful checks before an observed path failure
   remain eligible alongside later results. The trace alone cannot establish
   which earlier successful check used which access network.

Relevant code:

- `Packages/ZarpCore/Sources/ZarpCore/Engine/ZarpEngine.swift`:
  `searchAndApply`, `apply`, `scheduleReconnect`, `persistentEndpoint`.
- `zarpd/daemon/measure.go`: warm-up and sample requests reuse the HTTP transport;
  samples are not separated by a stability interval.
- `zarpd/daemon/opener.go`: the current physical interface is selected for each
  new outer connection. The investigation does not establish a stale-interface
  bug across independent connection attempts.

## Interpretation and limits

The observed failure is repeated loss of the selected QUIC tunnel after a path
transition, combined with recovery that keeps using the same short-lived
combination until its limit. Port rotation alone already failed in this trace.

A stateless reset terminates a QUIC connection. It is not a log-level proof of
carrier DPI. The origin and reason for the resets are not captured here. The
[QUIC specification, section 10.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3)
describes resets when an endpoint cannot associate packets with active connection
state. The user's upstream zapret on Wi-Fi is additional external protection,
so Wi-Fi success cannot establish native strategy effectiveness on the hotspot.

The Hop Limit 1 drop and closed-stream messages during deliberate scan cleanup
are not the primary cause demonstrated by this sequence.

## Corrections identified, not implemented in this investigation

- Verify persistent traffic over a bounded stability interval before publishing
  connected state. A failed interval must join cleanup before another candidate.
- Treat rapid repeated losses as one recovery episode, retaining retry/backoff
  progress instead of granting a new episode for a momentary success.
- After bounded repeated losses, invalidate only the current network's unstable
  pair evidence and try other compatible endpoints/transports, including supported
  TLS/HTTP2 strategies. Keep explicit plain mode off and preserve foreign-VPN guards.
- Observe network changes without modifying system state, cancel stale scan work
  and separate/revalidate evidence after a path-generation change.

These findings do not justify asserting that TLS/HTTP2 works on this hotspot or
that a specific carrier is blocking the connection. That remains unverified.
