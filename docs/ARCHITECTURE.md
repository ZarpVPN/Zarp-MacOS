# Architecture

How Zarp for macOS is put together, and why. This describes the code as it is today; how it got
here (the rejected designs, the phase-by-phase log of what was verified on a real Mac) is kept in
[history/](history/).

Target: macOS 14+ on Apple Silicon (arm64 only). Swift (SwiftUI + AppKit) for the app, Go for the
networking daemon.

- [1. Overview](#1-overview)
- [2. Code layout](#2-code-layout)
- [3. Connecting through DPI](#3-connecting-through-dpi)
- [4. The engine: scanning, scoring, self-healing](#4-the-engine-scanning-scoring-self-healing)
- [5. The IPC protocol](#5-the-ipc-protocol)
- [6. Routing, DNS and fail-safety](#6-routing-dns-and-fail-safety)
- [7. The privileged daemon: install and update](#7-the-privileged-daemon-install-and-update)
- [8. User interface](#8-user-interface)
- [9. Data, logs and privacy](#9-data-logs-and-privacy)
- [10. Security model](#10-security-model)
- [11. Licensing and provenance](#11-licensing-and-provenance)
- [12. Testing](#12-testing)
- [13. Known limitations](#13-known-limitations)

## 1. Overview

Zarp makes [Cloudflare WARP](https://one.one.one.one/) usable on networks whose DPI (deep packet
inspection) blocks the WARP handshake. It does **not** drive or wrap the official WARP client. Zarp is
itself a WARP client: it registers a WARP account, opens a MASQUE tunnel (CONNECT-IP over HTTP/3 or
HTTP/2) and moves the Mac's packets through it. Because Zarp makes the connection itself, it can apply
the "strategy" (a few decoy packets sent first, or a split of the TLS ClientHello) in exactly the place
the DPI looks at: the first packets of that connection.

```
┌──────────────── Zarp.app (your user, unprivileged, SwiftUI/AppKit) ────────────────┐
│ UI ── ZarpEngine (scan, score, self-heal; ZarpCore, no networking of its own)       │
│        └── ZarpdClient (ZarpdIPC) ──── newline-delimited JSON over a Unix socket ──┼──┐
└──────────────────────────────────────────────────────────────────────────────────────┘  │
                                                                                          ▼
┌──────────────────── zarpd (root; LaunchDaemon registered with SMAppService) ─────────────────┐
│ • WARP account registration (only after the user accepted Cloudflare's terms)                │
│ • DPI strategy executor: opens the UDP/TCP socket itself, sends the decoys on it, then hands │
│   that same socket to the real MASQUE/QUIC dial                                              │
│ • MASQUE session (HTTP/3 or HTTP/2), CONNECT-IP: pumps packets between a utun and the session│
│ • routes, DNS override, crash recovery; the cdn-cgi/trace measurement used to score strategies│
└───────────────────────────────┬──────────────────────────────────────────────────────────────┘
                                │ physical interface only (never routed back into the utun)
                                ▼
                    Cloudflare WARP MASQUE endpoint (162.159.x.x)
```

Why two processes. Creating a utun device and changing routes and DNS needs root; a SwiftUI app should
not run as root. So a small root daemon (`zarpd`) does everything privileged and everything that has to
happen on the connection's own socket, and the app does everything else. The app never runs a shell
command with elevated rights; it asks the daemon, over a socket, to do a small, fixed set of things
(§5), and the daemon validates every field (§10).

Why scanning lives in Swift, not in the daemon. Which strategy to try next, how to score it, when to
re-check it and when to heal are product decisions that need no privileges and are easiest to test as
pure logic. The daemon only ever executes one thing at a time: "open a connection with this strategy",
"measure through it", "close it".

## 2. Code layout

```
App/Sources/Zarp/            SwiftUI app: AppViewModel (wiring, monitor loop), ZarpApp (scenes, menu
                              bar, app delegate), Screens/ (main window, strategies, settings, log,
                              close confirmation), Components/ (power button, toggles, steppers),
                              ZarpdInstaller (SMAppService), SystemNetworkInspector (foreign-VPN check)
Packages/ZarpCore/           SwiftPM package, Foundation only, tests run without Xcode
  Sources/ZarpCore/            Strategy/ (model, catalog, args parser, readiness, custom strategies),
                              Results/ (scoring), Settings/, Localization/, Logging/,
                              Engine/ (ZarpEngine actor; EngineProtocols = the network seam), Support/
  Sources/ZarpdIPC/            ZarpdClient: the Swift side of the daemon protocol
  Sources/ZarpSubscriptions/   unprivileged bounded HTTPS transport, currently separate from app activation
  Tests/ZarpCoreTests, Tests/ZarpdIPCTests, Tests/ZarpSubscriptionsTests
zarpd/                       the Go daemon (its own module)
  cmd/zarpd/                   entry point: flags, rotating log file + in-memory ring, signals
  cmd/zarpctl/                 command-line client for the protocol (development, integration test)
  daemon/                      Manager (the connection registry), request handlers, the real Opener
                              (dial + utun + routes), endpoint pool, trace measurement, log ring
  ipc/                         protocol types, request validation, socket server (peer check, limits)
  route/                       routes, utun addressing, full tunnel, endpoint exclusion + journal, DNS
  tunnel/                      the utun <-> MASQUE packet pump
  warp/                        account registration, MASQUE dial (H3 and H2), strategy executor
Resources/Lang/              UI strings, one `key = value` file per language
Resources/blobs/             fake-packet captures (QUIC Initial, TLS ClientHello, STUN) from zapret2
Resources/Licenses/          third-party notices bundled into the app
scripts/                     package.sh (DMG), test-integration.sh (real network), gen-notices.sh, ...
project.yml                  XcodeGen spec; Zarp.xcodeproj is generated from it and not committed
```

`ZarpCore` contains all strategy, scan, settings and localization logic and has no AppKit, SwiftUI or
network dependency. `Engine/EngineProtocols.swift` is the entire seam where networking plugs in
(`WarpConnectionProvider`, `WarpProbe`, `NetworkInspector`); the app wires `ZarpdClient` into it and the
tests wire scripted fakes into it.

## 3. Connecting through DPI

Native WARP strategies cover retried handshakes: TCP splitting follows both
ClientHello records, and QUIC decoys precede every new Initial destination CID
on the same bound socket. Retransmits are deduplicated and there is a four-flight
limit. Count-only callbacks report completed sends; real traffic verification
and independent confirmation remain required.

Alternate-name WARP profiles combine outer TLS names with mandatory
fake or split steps. The enrolled Cloudflare public key still authenticates the
peer. Names are not resolved and CONNECT authority stays fixed. These profiles
require the additive warpTLSNameVersion=1 capability, have separate configuration
identities and are excluded from imported-server pairs and registration. Their
local transport tests do not establish a carrier-network pass.

Native H3 reserves framing space by clamping TCP MSS in both SYN directions to
a 1200-byte inner packet budget. Interface MTU stays 1280. The H2 path does not
apply this adjustment. Bounded socket metadata distinguishes packet-size
problems from transport closure without retaining packet contents or secrets.
The actual 0.4.8 user log establishes H2 success with alternate names; remaining
QUIC resets and the separate local MTU regression are documented in
[the mobile diagnosis](WARP_MOBILE_DIAGNOSIS_0.4.8_2026-10-27.md).

**A strategy** is a transport plus a [zapret2](https://github.com/bol-van/zapret2)-style argument
string, for example `--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=6`.
`StrategyArgsParser` turns it into a `DesyncPlan` (which fake blobs, how many times, with what TTL; or
where to split a ClientHello). The plan is what crosses to the daemon, flattened and validated; the daemon
never sees the original string. The primary catalog contains 16 portable profiles. Nine unsupported
historical profiles remain in a separate diagnostic catalog. Custom files accept
`name | h3/h2/wg | args | optional countries`. Country tags do not change identity.

**The same-socket trick (HTTP/3).** DPI that blocks WARP recognises the QUIC Initial packet sent to a WARP
address. A decoy Initial that the DPI believes is the real one (a captured QUIC Initial for a harmless
site such as google.com) is sent first, from the *same* 5-tuple, and the server ignores it. The sequence,
all in one Go function in `zarpd/warp`:

1. open the UDP socket and bind it to the physical interface (`IP_BOUND_IF`), so it can never loop back
   into the tunnel it is about to carry;
2. for each fake step, optionally set a short TTL (`ip_ttl`, `ip6_ttl`) so the decoy dies before the server,
   send the blob *N* times, restore the TTL;
3. hand that same `net.UDPConn` to quic-go, so the real Initial leaves through the identical 5-tuple.

**Split and disorder (HTTP/2).** For the HTTP/2 transport the ClientHello is split across several TCP
segments (`split`), optionally with the first segment sent at TTL 1 so it dies on the first hop and is
retransmitted later (`disorder`). This wraps the dial's `net.Conn`: the first write, recognised by the TLS
record byte `0x16`, is cut at configured offsets (literal, or relative to the SNI such as `midsld`).

**What macOS cannot do.** Tricks that need raw sockets or packet injection have no equivalent in an
unprivileged-socket model and are shown as "not available on macOS" with the reason as a tooltip; they are
never attempted (the daemon is only sent what a `DesyncPlan` describes, and an unsupported strategy has no
plan). The primary catalog adds Google x11/x12 and TLS splits at host/sld/endhost to the existing
portable profiles. WireGuard and raw techniques remain unavailable. TCP disorder still uses a low
TTL and kernel retransmission, rather than exact reverse segment transmission.

**The packet pump.** `zarpd/tunnel` copies packets between a real utun (wireguard-go's darwin `tun`
package) and the MASQUE session's CONNECT-IP stream directly, in both directions. There is no userspace
network stack and no local SOCKS proxy in between (the Android app needs both because Android's VPN API
gives it a different primitive).

**Endpoints.** Default HTTP3 scans rotate a finite IPv4 pool using `isolated-N` tokens.
HTTP2 isolation honors the account's dedicated HTTP2 address, with the pinned
upstream HTTP2 default only when that address is absent. It does not rotate
through the HTTP3 IP pool. Rechecks still open fresh TCP connections, and a
repeated remote address is reported as reused, rather than independent.
Custom lists accept
up to 64 public numeric IPv4/IPv6 address-port pairs without DNS lookup. Scans rotate that list and
avoid the first actual endpoint for rechecking when another address exists. Persistent connections
pin the endpoint that passed confirmation. Custom requests use protocol 3's `endpointPolicy=customWarp`;
ordinary overrides retain the WARP-range restriction. Both policies retain the enrolled WARP TLS pin.
IPv6 control sockets use udp6/tcp6, IPv6 interface binding and hop limits, the IPv6 default gateway
including its zone, and IPv6 host exclusions. Live route/tunnel checks remain awaiting user results.

**Failure context.** Optional IPC error metadata preserves transport, actual
endpoint, strategy identity and failed connection phase. Peer-key mismatch is
classified separately while keeping the enrolled pin enabled. Completed handle
reasons are available for two minutes, capped at 128 records. Measurements check
the same handle before and after their traffic phase, so a reset or replacement
cannot report success through a newer tunnel. Cleanup uncertainty retains its
existing refusal. Ordinary close, spontaneous loss and unknown handles remain
distinct; scan losses do not populate persistent lastLoss status.

## 4. The engine: scanning, scoring, self-healing

`ZarpEngine` is a Swift actor: one operation at a time (connect, quick or full scan, test selected, use,
disconnect, cancel), written only against the protocols in `EngineProtocols.swift`.

- **Scoring.** A test passes if the tunnel comes up and `cdn-cgi/trace` through it reports `warp=on`
  (or `plus`). Score = connect time + 4 x ping, lower is better.
- **Confirmation.** Each successful initial attempt is rechecked inline on a fresh connection.
  Quick Scan counts confirmations and continues after failed rechecks until N or list exhaustion.
  `independent` records different actual endpoints; `endpointReused` records the same endpoint.
  Missing endpoint evidence never proves independence. Cancellation preserves the previous result.
- **Identity.** Custom IDs hash length-delimited name, transport and arguments. Results also bind to
  a separate executable fingerprint and endpoint-list fingerprint. Country changes preserve results.
  Legacy custom selections migrate only with a unique name match; results without configuration
  evidence require retesting. Latencies are bounded before score arithmetic.
- **Filtering.** Country multi-selection is a union and applies to every action
  and fallback without deleting hidden history. Product WARP connections require
  an executable outer strategy through the catalog, custom profiles and IPC. Selected
  tests apply only their own candidates. Foreign VPN conflicts refuse scans and connections.
- **Connect.** Use the saved strategy; if that fails, the other confirmed strategies by score; if none is
  left, run a quick scan (which stops after *N* confirmed strategies, 3 by default) and use the best.
- **Self-healing.** If the saved strategy stops working the engine tries the other verified ones before it
  searches again.
- **Unsupported strategies** (§3) are never sent to the daemon and never counted as failures.
- **Stable confirmation.** Persistent connections pass three traffic-measurement
  phases separated by two-second pauses before Connected is published. Each scan
  connection receives a delayed follow-up before its fresh recheck.
- **Losing the connection.** One episode retains retry/backoff progress through
  brief successes. Two rapid losses advance to alternatives, preferring another
  transport. Each alternative gets fresh strategy/traffic confirmation and
  persistent verification. Recovery admits at most three original retries and
  eight alternative candidates, checks a 180-second admission window and retains
  the three-mature-episodes-per-ten-minutes limit. A session must last at least
  30 seconds before a later loss starts a fresh episode. Plain WARP connections
  are unavailable, including discovery and fallback.
- **Access-network changes.** A read-only SystemConfiguration adapter produces an
  opaque physical-path hash. Results and endpoint pins require the same hash.
  Busy operations check their path during traffic verification; a changed scan
  restarts its requested scope once. Continuing changes stop it. The heartbeat
  observes idle changes and reconnects only its owned affected tunnel. Missing
  observations cannot distinguish access networks; they do not bypass traffic or
  foreign-VPN checks.
- **Cancellation** is honoured at every await point, including mid-dial (the request's socket is shut down
  and the daemon aborts the dial). An epoch counter discards the result of anything that finished after a
  newer operation had already started.

`AppViewModel` runs a monitor loop every four seconds: ping the daemon, reconcile with its status, pull its
log lines into the app's log. Reconciling means the GUI can start (or restart after a crash) while a tunnel
is already up and adopt it instead of fighting it. An outdated daemon is replaced automatically
only when explicit status confirms it is idle. Before a connection the app warns about another VPN
(a dialog; you can continue, but the daemon refuses a full tunnel while another VPN owns the default route)
and, the first time, asks for consent to create a WARP account.

## 5. The IPC protocol

Protocol version **3**, defined in `zarpd/ipc/protocol.go` (Go) and `ZarpdClient.swift` (Swift) and pinned
by golden wire-format fixtures that both test suites share.

- **Transport.** Newline-delimited JSON over a Unix domain socket, `/var/run/zarpd.sock`: one request per
  line, one response per line, correlated by `id`. No code generation on either side.
- **Methods.** `ping` (version, pid, protocol, whether an account exists), `status` (the one persistent
  connection, if any, and the last unrequested loss), `register` (create the WARP account; idempotent),
  `open` (dial with a flattened strategy; test connection or persistent; optional full tunnel and DNS),
  `close`, `measure` (trace through a connection), `logs` (lines since a cursor), `restart`.
- **Idle ownership.** `status.networkBusy` is always emitted by the current daemon.
  It includes queued/dialing opens, scan connections, teardown, shutdown and known
  incomplete cleanup. `connected` continues to describe only a GUI-adoptable
  persistent connection. A safety guard requires both values explicitly false;
  a legacy missing field or failed status call cannot establish idle. Closing
  entries remain registered until their single teardown completes; competing
  close/loss/lease/replacement requests join it before another tunnel starts.
  Shutdown closes admission, cancels and joins its in-flight dial, and cleans up
  a connection that arrives after cancellation. Reported cleanup or startup
  recovery failures keep network ownership uncertain and refuse subsequent opens.
  This additive metadata preserves protocol 3 and GUI decoding of older replies.
- **Account setup capability.** `ping.accountSetupVersion == 1` enables
  `setupWarpAccount` with version 1, operation `register`, `status` or `license`,
  and at most 32 typed TLS split/disorder candidates. The fixed API origin and
  socket policy stay inside the daemon. `warpAccountState` distinguishes ready,
  missing, pending, uncertain and unavailable data. Unknown state never grants
  permission to create an account. The account request shares tunnel admission;
  shutdown cancels and joins it. Existing persistent tunnels are preserved and
  prohibit physical-interface fallback. The total setup deadline is 180 seconds,
  each HTTP request is bounded to 15 seconds, and the IPC client waits 190 seconds.
  API success never modifies tunnel strategy results.
- **Errors** carry a machine-readable `code`: `bad_request`, `forbidden`, `busy`, `no_account`,
  `foreign_vpn`, `unsupported`, `cancelled`, `internal`, plus `timedOut` for the scan loop's timeout-versus-
  failure distinction.
- **Lifetime.** A client keeps its connection open until it has read the response. The server treats the
  client going away as "abandon what is in flight for it", which is how pressing Cancel aborts an `open`
  that is still dialing.
- **Versioning.** The app compares `ping.protocol` with the version it was built for, so a stale daemon
  left running after an update is noticed instead of failing in confusing ways.

The external-engine foundation retains its restricted loopback plans. The separate
product constructor accepts validated `ServerPlan` profiles through `openServer`,
checks pinned engine identities and supervises an owned child with authenticated
listener readiness, renewable leases and private cleanup. The daemon additionally
requires real HTTPS and actual outer-strategy application before starting its
native userspace bridge/utun. A separate post-TUN probe verifies the owned route.
GUI/source selection and app-bundle engine packaging are implemented. Actual product
TUN and signed-installation acceptance remain unverified. No raw configuration or
client binary/argv paths are accepted. Adoption/readiness alone does not certify
traffic; status never renews a lease. See the current
[product implementation and evidence](WINDOWS_RELEASE_REVIEW.md).
See [BACKEND_PARITY_POC.md](BACKEND_PARITY_POC.md) for actual traffic evidence and limits.

The separate signed-inventory constructor verifies a final digest and Developer ID
team/identifier on the private executable before any engine probe. Its release
policy is trusted construction data, not an imported manifest or IPC option.
The standalone loopback guardian watches exclusive inherited anonymous pipes;
daemon control loss cancels only its owned engine. Bounded native pipe I/O, strict
frames and cooperative termination are verified with private crash/traffic tests.
The development typed launcher holds its isolated guardian unreaped and verifies
ordinary private group/session cleanup, including guardian-only SIGKILL. Native
ownership checks also refuse adoption/renewal after actual child exit. Detached
sessions, signed release acceptance, production launch and system-resource ownership
remain pending. An armed childless recovery member now retains the private session
in a separate group. Daemon/guardian control loss stops only the original group,
checks remaining members and the held root directory identity, then removes private
files. Fake ready/startup and simultaneous-owner crashes, plus actual pinned IPv4/IPv6
engine owner crashes, pass. Changed groups retain a failed status and files; detached
sessions, pre-arming simultaneous loss and recovery-helper death are outside this proof.

Ping/status now include additive `runtimeCapabilities` metadata. Persistent WARP status
sets `activeMode=warp`; legacy replies can omit both. The current inventory advertises
WARP only, with no server protocols. The WARP client refuses to adopt another explicit
active mode. These additions do not change the protocol 3 open contract.

Swift/Go connection contracts share [synthetic vectors](../testdata/connection-contracts.json).
They reject duplicate JSON keys and decoder normalization that could change executable
configuration. `ServerLinkImporter` is a pure, bounded parser; pending options fail by
field name. `ServerProfileStore` keeps its versioned collection in a separate private
directory with atomic 0600 files. This preserves existing WARP settings/account/history.
The source library feeds server-mode UI, compatible pairs and the typed open handler.

`ConnectionSourceLibrary` stores up to 32 sources in a separate schema 1 document,
bounded to 512 KiB. WARP stays available. The exact source ID persists across renames;
removed selections stay unavailable, and URL changes create distinct sources.
`ConnectionSourceStore` and the profile store share restricted atomic file operations.
Missing source storage migrates to WARP without writing existing preferences, account
or server documents. Source persistence does not fetch, refresh or activate a connection.

Reality/Vision and Salamander have bounded shared profile fields. Optional advanced
fields add a tagged fingerprint suffix, preserving older server IDs when absent.
The private `PlanFromLoopbackProfile` compiler rejects unproven fingerprint/ALPN
values instead of discarding them. It accepts Chrome and the documented PoC ALPN
sets only. Actual IPv4/IPv6 traffic, failure and teardown checks are recorded in
[BACKEND_PARITY_POC.md](BACKEND_PARITY_POC.md).

`ConnectionSource` distinguishes WARP, manual servers and HTTPS subscriptions. Its
identity binds to the exact original subscription URL, including query tokens,
while excluding the label. Swift and Go share URL/error/identity vectors. This pure
metadata contract performs no fetch, refresh, WARP registration or mode activation.

Subscription list/cache/downloader models are independent work explicitly allowed
before TUN readiness. The pure core parses plain/base64 lists, deduplicates shared
profile identities, preserves unavailable selections and stores a restricted cache
bound to the original source hash. Refresh ownership prevents late publication
after cancellation/deletion and retains valid offline data after fetch failure.
The separate ZarpSubscriptions target supplies streaming URLSession HTTPS through
the current connection, with one 25-second deadline, five validated HTTPS redirects,
a format-only second user agent, a delivered 2 MiB limit and default system TLS.
It uses no persistent cookie/credential/cache storage. Actual private-CA loopback
tests verify gzip expansion and rejection by the unchanged default trust path.
Settings > Servers and subscriptions now uses a separate `ServerLibraryViewModel`
and the unprivileged `ConnectionLibrary` actor. It imports manual links, persists
subscription metadata, refreshes/cancels/deletes subscriptions, and saves a server
selection within each source. Opening the screen and saving a URL make no request.
Explicit Refresh downloads immediately. The connection lifecycle also refreshes a
subscription older than twelve hours and keeps its offline cache after a failed
fetch, with a warning. Damaged caches
are preserved and reported per source without blocking other lists. The manager
has no connection provider or IPC reference, so configuration edits cannot replace
a live connection. The engine shares this actor and snapshots configuration before
starting a connection; active pairs retain their immutable execution inputs.

Its documents live under the user data directory's private `Connections` folder:
`connection-sources.json`, `server-profiles.json`, and one cache document per source
under `subscriptions/`. They use the existing owner-only directory/file checks and
atomic writes. URLs are masked on input and never used as list titles or error text.

## 6. Routing, DNS and fail-safety

A scan's test connection routes one host (`1.1.1.1`, the measurement target) through the utun, which is all
a measurement needs. A persistent connection (`routeAll`, the normal "Connect") routes everything.

**Routes.** The full tunnel uses the shape `wg-quick` uses on macOS: `0.0.0.0/1` and `128.0.0.0/1` (and
`::/1`, `8000::/1` when WARP assigned an IPv6 address) added *through the utun interface*. They are more
specific than the default route, so they win, and the real default route is never touched. Because they are
bound to the interface, the kernel deletes them when the interface disappears, **even if `zarpd` is killed
with `kill -9`**: a crash fails open (traffic simply goes out the normal way) instead of leaving a default
route into a tunnel that no longer exists. If an IPv4 route cannot be added (typically another VPN already
owns it) everything done so far is rolled back and the connect fails with a clear message; IPv6 and DNS are
best-effort and reported as warnings. The full tunnel is refused when the default route is itself on a
`utun` (another VPN or proxy): two tunnels fighting for the same routes is not a supported configuration.

**The endpoint exclusion route.** The tunnel's own control connection (QUIC or TCP to the WARP endpoint) must
keep using the physical network. Binding its socket to the physical interface is not enough: on the primary
network service there is no interface-scoped default route, so a bound socket falls back to the ordinary
table, meets the more specific `0.0.0.0/1` through the utun, and fails with `ENETUNREACH` (this was found by
the first real-network run). So `route add -host <endpoint> <gateway>` (or `-interface <if>` when the default
route has no gateway) goes in first and comes out last. Unlike the `/1` routes this one is not tied to the
utun and would survive a `kill -9`, so it is written to `/var/db/zarpd/exclusions.json` *before* it is added
and removed from the journal after it is deleted; whatever the journal still lists at the next daemon start is
deleted then. A route for the endpoint that already exists through the same interface is used and left alone;
one through another interface (another VPN pulling the endpoint into its tunnel) fails the connect.

**DNS.** While a full tunnel is up, DNS is pointed at Cloudflare's resolvers with `networksetup
-setdnsservers` on the physical interface's network service. The resolvers are fixed in the daemon and never
taken from a client (a client-chosen DNS server in a root daemon would be a hijack primitive). The original
setting is written to `/var/db/zarpd/dns-backup.json` *before* anything changes, and restored on disconnect,
on SIGTERM and, after a crash, at the next daemon start before any request is served.

**One tunnel at a time.** A new `open` closes whatever is still open (the previous persistent connection, or
a test connection whose client crashed). A test connection carries a lease (2 minutes by default) and is
reaped if its client never closes it. A tunnel whose data plane dies by itself is torn down, with routes and
DNS restored, and reported as lost.

| If the daemon... | what remains | what restores it |
|---|---|---|
| is stopped (SIGTERM, restart, quit) | recovery data if a cleanup step fails | it attempts owned route/DNS cleanup before exiting; failures are reported and retained for recovery |
| is killed with `kill -9` or crashes | the endpoint host route, the DNS override | the `/1` routes vanish with the utun; the next start removes the host route (journal) and restores DNS (backup) |
| is not restarted at all | the endpoint host route (harmless: it only matters for that one address) and the DNS override | `sudo networksetup -setdnsservers <service> Empty` (see [TROUBLESHOOTING](TROUBLESHOOTING.md)) |

Recovery errors are not idle state. Failed exclusion deletions remain in the
journal; successfully cleaned or externally replaced entries are removed only
after ownership checks. Unreadable journals and DNS backups are retained without
guessing their original state. The current manager reports networkBusy and
refuses new tunnels after a reported recovery/cleanup failure. Real restoration
still needs the user-run system checks; fake tables and a nil method result
alone do not establish that this Mac's network was restored.

Everything in this section is exercised against the real network by `scripts/test-integration.sh` (§12),
including the `kill -9` and SIGTERM cases.

## 7. The privileged daemon: install and update

`zarpd` is built from source by a script phase in `project.yml` and embedded in the app bundle
(`Contents/MacOS/zarpd` and `Contents/Library/LaunchDaemons/io.github.zarp.mac.zarpd.plist`). It is
registered automatically with `SMAppService.daemon` by `ZarpdInstaller.swift`.
macOS can require administrator authentication and approval under
*System Settings > General > Login Items & Extensions*. The app and daemon must
be signed by the same Team ID, which is what lets registration work
with a free Apple Development identity. The embedded property list sets `KeepAlive` on unsuccessful exit
only, so `restart` (which exits with status 1 on purpose) brings the daemon back and a normal stop does not.

The release launch manifest uses explicit `Program` and one `ProgramArguments`
entry for `/Applications/Zarp.app/Contents/MacOS/zarpd`, avoiding a failed relative
container lookup observed in the background-item database. Release preparation
requires that exact bundle location. Debug builds stamp their own absolute
executable path into the manifest. `DaemonLaunchConfiguration` checks the label,
absolute canonical program, current bundle ownership and exact arguments before
mutation. The app refuses temporary, translocated or mismatched copies.

`AutomaticDaemonCoordinator` serializes startup, connection/scan and account
preparation. It probes IPC independently of registration metadata. A missing
service is registered; an unreachable registration or explicitly idle outdated
service is unregistered asynchronously before the current bundle is registered.
A short observation window avoids replacing a service already starting. Active
tunnels, network work and a responding service with unknown idle metadata are
preserved. The app's own busy state is checked again before replacement.

Automatic replacement is limited to one attempt per app launch. Readiness polls
are bounded; monitoring cannot create a prompt/re-registration loop. A normal
user action can retry preparation. The macOS approval pane opens once
automatically if required, with a localized connection message. There is no
service-maintenance window or separate install, restore, restart or remove button.
Native authorization and completion are not simulated by production IPC restart.

Preparation emits typed journal events for registration, replacement, readiness,
permission and failure. The app logs its version at startup and forwards these
events to the same in-memory/file LogBus used by the main log panel. Native
diagnostics include bounded domain/code only, excluding error UserInfo. The view
model publishes the authoritative bounded snapshot so concurrent delivery and
entry-cap rotation cannot produce an inconsistent display.

## 8. User interface

A main window (380 pt wide, fixed size) with the power button, status line, language and settings
buttons and an expandable log; an independent settings window (strategy table,
scan buttons, options and custom-strategy editor); separate connection, server,
application routing and WARP+ windows; and a menu bar item
(Open, Connect/Disconnect/Cancel, Settings, Quit). Closing the
main window asks whether to hide to the menu bar or quit, with "remember my choice", reachable from the
titlebar button, Cmd-Q and the menu bar Quit alike.

The UI follows [Zarp for Windows](https://github.com/feg55/Zarp) so the apps feel the same: a dark theme
with one accent colour.

| Token | RGB | Use |
|---|---|---|
| back | 18, 20, 25 | window background, table header |
| panel | 27, 30, 37 | rows, buttons, log |
| panelHover | 37, 41, 50 | hover, selected row |
| border | 46, 50, 60 | lines, disabled button border |
| text / textDim | 196, 200, 208 / 128, 134, 146 | body text / headers and hints |
| accent | 244, 129, 32 | connected, primary button, toggles |
| busy / ok / bad | 80, 150, 255 / 64, 196, 120 / 232, 84, 84 | searching and "works (1 check)" / "works ✔✔" / errors |

Nine languages ship (English, Russian, Spanish, Portuguese, Chinese, Hindi, French, German, Persian). Text is
resolved when it is displayed, so a language change updates status, log and error messages already on screen.

## 9. Data, logs and privacy

| File | Written by | What |
|---|---|---|
| `~/Library/Application Support/Zarp/zarp.json` | app | settings and strategy results |
| `~/Library/Application Support/Zarp/strategies.txt` | you | custom strategies |
| `~/Library/Logs/Zarp/zarp.log` | app | app log (2 MB, rotated to `.1`); daemon lines appear with a `zarpd:` prefix |
| `/Library/Application Support/Zarp/zarp-warp-config.json` | daemon | the WARP account: device id, token and private key. Mode 0600, root only |
| `/Library/Application Support/Zarp/zarp-warp-config.json.registration-pending` | daemon | versioned registration checkpoint with generated keys and any created device identity. Mode 0600; removed after atomic final account commit. An uncertain creation is never replayed automatically. |
| `/Library/Logs/Zarp/zarpd.log` | daemon | daemon log (2 MB, rotated to `.1`) |
| `/var/db/zarpd/dns-backup.json`, `exclusions.json` | daemon | crash-recovery state (§6); present only while a full tunnel is up |
| `/var/run/zarpd.sock` | daemon | the IPC socket |

There is no telemetry and no analytics. The only network requests are:

- **Cloudflare WARP registration** (through the `usque` library), once, after you accept Cloudflare's
  terms in the app. It creates an anonymous device account for this Mac and sends no personal information.
- **The MASQUE tunnel** to the WARP endpoint (Cloudflare address ranges), which is the point of the app.
- **`https://1.1.1.1/cdn-cgi/trace`** through the tunnel, while testing and connecting, to check that
  traffic really goes through WARP and to measure latency.

WARP itself is a Cloudflare service under Cloudflare's own terms and privacy policy.

## 10. Security model

`zarpd` is a root process that accepts requests from user-level code, so its job is to be useless to anyone
who is not the Zarp app, and of limited use even to them.

- **Who can talk to it.** The socket is `0660`, group `staff`. On top of that the server reads the
  connecting process's credentials from the kernel (`LOCAL_PEERCRED`, not anything the peer claims) and
  admits only root and the user currently at the console. Another logged-in user, an SSH session or a
  service account is refused with `forbidden`.
- **What it will do.** Only the eight methods in §5. No request carries a path, a command or a DNS server.
  Strategies arrive flattened and every field is bounded (at most 8 fake steps, 50 repeats each, TTL 1 to
  255, 16 split positions, timeouts up to two minutes); the decoy blobs come from a fixed list; an endpoint
  override uses WARP ranges or the explicit bounded public numeric custom policy with WARP pinning;
  the resolvers are constants. Commands the daemon runs
  (`route`, `ifconfig`, `networksetup`) take arguments from its own state or from validated values (IP
  addresses, interface and service names read from the system), never from request text.
- **Resource limits.** At most 32 connections, 8 requests in flight per connection, 256 KiB per request;
  a panic in a handler is recovered and answered with `internal`.
- **Where it can live.** A release build registers the daemon only from `/Applications` (§7).
- **At rest.** The WARP account file is root-owned, mode 0600.
- **What this does not stop.** A process running as you (the console user) can do what the Zarp app can do:
  open and close tunnels to WARP endpoints. That is by design (the app is that process) and it gives no
  more than connecting your own Mac to Cloudflare WARP.

Please report weaknesses privately; see [SECURITY.md](../SECURITY.md).

## 11. Licensing and provenance

Zarp for macOS is [MIT](../LICENSE). It descends from three projects by the same author and one upstream:

- **Zarp for Windows (MIT).** The strategy list, the scan and scoring algorithms, the UI texts and the first
  translations come from it and are reused under its (identical) licence.
- **zapret2 (MIT, bol-van).** The fake-packet blobs in `Resources/blobs` are captured by it and included
  unmodified; the strategy argument syntax is its `winws2` syntax.
- **Zarp for Android (GPL-3.0).** Its Go core (`zarpcore`) is the design reference for the same-socket
  trick, the MASQUE dial sequence and the TLS split algorithm. Its third-party dependencies (`usque`,
  `connect-ip-go`, `quic-go`, `wireguard-go`) are permissively licensed and are used directly. `zarpd`'s Go
  code is written fresh against those libraries, studied from but not copied from `zarpcore`, so the
  macOS networking core stays MIT instead of becoming GPL-3.0.
- **The Go dependencies of `zarpd`** are statically linked; their licence texts ship in
  `Resources/Licenses/THIRD_PARTY_NOTICES.md` (regenerated by `scripts/gen-notices.sh`, checked in CI).

Cloudflare and WARP are trademarks of Cloudflare, Inc. Zarp is an independent project, not affiliated with
or endorsed by Cloudflare, and ships no Cloudflare software.

## 12. Testing

- **Go** (`cd zarpd && go test -race ./...`): unit tests per package. Routes and DNS run against a fake
  command runner that models a routing table, so tests assert on state, order and rollback. The dial and the
  desync executor are tested on loopback sockets, including TTL on the wire and socket-leak checks. The IPC
  server is tested for peer policy, limits, cancellation and the golden wire fixtures.
- **Swift** (`cd Packages/ZarpCore && swift test`): the engine against scripted fakes (cancellation,
  re-entrancy, reconnect policy), settings and logging robustness, localization parity (every language has
  exactly the English keys and placeholders, and every key is used), and `ZarpdClient` against a fake
  Unix-socket daemon.
- **Real network** (`scripts/test-integration.sh`, VPN off, asks for `sudo`): builds the daemon, runs its
  own copy on a private socket, and drives it with `zarpctl` through the same calls the app makes: real
  tunnel, full tunnel with IPv4 and IPv6, DNS override and exact restore, `kill -9` and SIGTERM recovery. It
  verifies that the machine is back to normal at the end, whatever happens.
- **CI** (`.github/workflows/ci.yml`): gofmt, vet, race tests, Swift tests, the notices check and an
  unsigned app build on Apple Silicon.

## 13. Known limitations

- Apple Silicon and macOS 14 or later only.
- The release is not notarized (there is no paid Apple Developer membership behind the project): the first
  launch needs *Open Anyway*, see [TROUBLESHOOTING](TROUBLESHOOTING.md).
- WireGuard transport and the raw-socket strategies (§3) are not implemented.
- IPv6 control connections are implemented and tested over loopback. Live IPv6 WARP and route exclusions
  remain unverified until the user runs the separate manual scenarios.
- Private-network ranges that are not directly attached are sent into the tunnel with everything else (there
  are no split-tunnel exclusions yet).
- After sleep or a network change, traffic can stall for up to about 30 seconds (QUIC's idle timeout) while
  the routes still point into a session that has silently died; then the tunnel is noticed as dead, torn down
  (traffic goes direct again) and reconnected.
- DNS and routes follow the physical interface's network service; if the Mac moves to another interface while
  connected, the tunnel is lost and re-established there.
- Daemon log history older than its 1000-line in-memory ring, or from before the app started, is not replayed
  into the app's log.
- Another VPN must be off while Zarp connects.


### Signed guardian construction and private UDP limits

The backend library now has separate development and signed guardian constructors.
The signed path checks the final helper digest and fixed Developer ID/team
requirement on a private executable snapshot before execution. The release helper
uses a fixed embedded backend catalog, never environment, control-message or
unsigned-manifest policy, and refuses an empty catalog. This remains a bounded
loopback construction; positive signed release acceptance, packaging and system
frontend integration are pending. See [the PoC](BACKEND_PARITY_POC.md#signed-guardian-release-construction).

The loopback UDP relay can temporarily set a bounded TTL/IPv6 hop limit on its
own connected socket for the initial fake only. Its single writer restores the
original policy before forwarding real traffic and closes the association on any
uncertain operation. Darwin's IPv6 inherited-default sentinel is preserved.
Shared socket-option helpers serve WARP and the outer relay without interface,
routing, DNS or global policy changes. Kernel header evidence is a separate
user-run gate from stream traffic and socket-option readback.


### Owned private HTTPS probe

The private backend owner can perform two fresh authenticated SOCKS/HTTPS
confirmations for its exact ready run generation, with one shared bounded
deadline, a dedicated certificate/name and exact response marker. Results contain
only identity fingerprints and first-response timings. Strict authentication,
TLS validation, response bounds and no direct/redirect fallback apply. Stop and
Close join admitted probes before reporting cleanup; measurement never renews a
lease or starts reconnect. This method remains a loopback prerequisite with no
production IPC/UI or post-TUN health activation. See [the evidence](BACKEND_PARITY_POC.md#owned-bounded-https-verification).
