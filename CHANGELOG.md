# Changelog

All notable changes to Zarp for macOS are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- HTTPS subscription test fixtures resolve Go from the caller's PATH, including
  actions/setup-go, instead of a local Homebrew path. They reuse the configured
  compiler cache and allow a bounded first build on a fresh CI image.
- Subscription downloader tests no longer assume that two delayed requests fit
  into a 100 ms deadline on a busy CI runner. Shared deadlines, timeout cleanup
  and cancellation are checked separately, with safe request extraction and an
  explicit request-start expectation. Production timeout policy is unchanged.

## [1.0.0] - 2026-10-27

### Added

- Twenty-four portable WARP profiles, including alternate TLS names with mandatory outer strategies, All/RU/IR/CN country selection, and optional custom strategy country tags.
- Public numeric IPv4/IPv6 WARP endpoint lists, scan rotation, confirmed endpoint pinning, and protocol 3 validation.
- A supervised user-run parity test with private credentials and sanitized machine-readable results.
- Restricted backend configuration and pinned-engine supervision, verified with real local traffic. Server selection reaches the app connection lifecycle; actual product TUN acceptance remains unverified.
- Server-link imports, shared Swift/Go validation, a private atomic profile library and a Settings server-management screen. Main-window source selection now feeds compatible server + zapret pairs and typed server IPC.
- WARP and server runtime capabilities and active-mode IPC metadata, with compatibility checks for older replies.
- Strict Reality, Vision, TLS fingerprint and Salamander profile options, verified in private IPv4/IPv6 backend tests.
- Shared WARP/manual/subscription source identity with bounded HTTPS URL validation and redacted diagnostics.
- An isolated user-run IPv4 TUN/process test with private TCP/UDP/DNS fixtures, guarded startup and owned cleanup. Live results remain pending.
- Private backend lease renewal and daemon-owned adoption with generation-checked stop/renew, verified after client detachment in loopback tests.
- Restricted atomic source-list persistence with WARP migration and unavailable removed selections.
- Bounded HTTPS subscriptions with Save, Refresh, Cancel, Delete and per-source server selection. Connection-time twelve-hour refresh preserves the last successful offline list; damaged caches are reported separately. Results and remembered pairs are isolated by source.
- WARP+ secure license input, own-account API and account-type confirmation. The key is not persisted or logged, and account operations preserve an active connection.
- Bundled checksum-pinned sing-box/Xray, typed product compiler, outer TLS/UDP strategy relay, renewable guardian/recovery ownership and daemon-owned userspace IP frontend. Private HTTPS/UDP checks pass; actual product TUN and signed-installation acceptance remain unverified.
- XHTTP import and all four modes, exact-h3 UDP selection, bounded extra, mandatory-relay download legs and typed ECH/certificate/Reality options. Real ECH and Reality-XHTTP combinations remain unverified.
- Native reserved-child/group ownership and a typed development guardian launcher, including guardian-only crash cleanup and acknowledged bounded leases.
- A restricted signed-backend inventory loader and isolated inherited-pipe guardian, with private signature-rejection, crash and traffic checks. Positive signed-release acceptance remains unverified.
- A user-run passive loopback packet check for outer TLS splitting and same-tuple UDP fake ordering, with private fixtures and sanitized reports. User IPv4 and IPv6 kernel packet evidence passes with exact split boundaries, zero drops and verified cleanup. Production and ISP checks remain pending.
- Private session recovery after an armed daemon/guardian crash, verified with fake descendants and pinned IPv4/IPv6 engine traffic. System integration remains unverified; detached sessions are outside the ownership proof.
- Signed guardian construction with fixed embedded release policy and private signature/ad-hoc rejection checks. Positive signed-release acceptance remains pending.
- Bounded outer UDP fake TTL/IPv6 hop limits with original socket policy restoration, pinned traffic checks and user-verified IPv4/IPv6 kernel headers.

- Owned bounded HTTPS confirmation through the exact private backend run, with strict SOCKS/TLS checks, fresh connections and joined cancellation. System acceptance remains unverified.
- A read-only installation inspector with bounded tools, redacted metadata and optional restricted adapter-report review. It never bypasses live-test guards or changes a service/network.

### Changed

- Automatic bundled-service preparation at startup and before account or connection actions. macOS handles required authorization; service maintenance controls are removed from the user flow.
- Plain WARP catalog entries, legacy selections and empty custom profiles are removed. The daemon requires an executable outer strategy before starting WARP.
- Quick Scan counts confirmations and continues after failed rechecks. Actual endpoint independence is shown separately.
- Custom identity and saved results bind to configuration fingerprints. Ambiguous legacy names do not migrate.
- Selected tests cannot apply unrelated saved candidates. Cancellation preserves previous completed results.
- Foreign VPN conflicts refuse scans and connections. Exclusion cleanup preserves externally replaced routes.
- Stage 1 live network verification is pending user-run tests; compilation and loopback checks do not establish ISP effectiveness.

### Fixed

- Native WARP strategies cover retry ClientHello and new QUIC Initial flights. H3 TCP MSS adjustment prevents the locally reproduced HTTPS packet-size stall, and bounded diagnostics record remaining transport failures.
- The WARP packet pump bounds repeated empty reads, rejects malformed packet metadata, and stops forwarding after the other direction fails.
- WARP account presence checks reject FIFO/symlink, oversized and group/other writable files with bounded reads and redacted errors. Verified through private ping/status IPC, without changing the installed daemon.
- Network status includes opening, scan and teardown work; concurrent replacement waits for the same cleanup. Shutdown cancels and joins late dials, and known cleanup/recovery failures refuse another tunnel. Manual-test guards require explicit idle activity metadata.
- Failed route/DNS rollbacks propagate uncertainty and retain DNS recovery data, including corrupt backups. These paths are checked with fake system state; live acceptance remains pending.

### Known limitations

- The user's 0.4.8 logs verify alternate-name HTTP2 traffic. Recovery from the recorded mobile QUIC stateless resets is still unverified; the packet-size fix addresses a separate reproduced defect.
- Actual product TUN, positive signed-release backend acceptance, real ECH and Reality-XHTTP combinations, and complete XHTTP extra-field compatibility remain unverified.
- Apple Silicon and macOS 14 or later are required. The release is signed with Apple Development and is not notarized.

## [0.4.9] - 2026-10-27

### Fixed

- Prevent native H3 HTTPS stalls on a 1280-byte UDP path by reserving framing space through bidirectional TCP MSS adjustment. Interface MTU and HTTP2 sizing are preserved.
- Invalidate old H3 confirmations after the packet-size correction while preserving the working H2 configuration identity.

### Added

- Six H2 profiles combine host/sld/endhost splitting with the alternate names that passed the user's 0.4.8 checks. Independent confirmation and the enrolled Cloudflare key pin remain mandatory.
- Bounded QUIC packet-size, MSS, Packet Too Big and typed-closure diagnostics, excluding packet contents, keys, reset tokens and raw error strings.

### Verification

- Private pinned HTTPS request/response transfer now passes over the limited UDP path for IPv4 and IPv6. The recorded mobile QUIC reset cause and recovery remain unverified.

## [0.4.8] - 2026-10-26

### Fixed

- Native TCP strategies now split the second ClientHello after HelloRetryRequest, including writes preceded by a TLS compatibility CCS record.
- Native QUIC strategies now send decoys before each new Initial flight on their original socket. Retransmissions reuse the existing burst, and new-flight sends have a strict bound.

### Added

- Four WARP strategies combine vk.com or www.google.com outer TLS names with required fake packets or TCP splitting. They retain the enrolled Cloudflare key pin, independent confirmation and fallback; imported servers and registration origins keep their own TLS names.
- Additive daemon capability checking prevents older services from silently ignoring a strategy TLS name. Changed WARP execution fingerprints require fresh verification.

### Verification

- Local pinned TLS/HTTP2 and QUIC/HTTP3 traffic, a real HelloRetryRequest, packet ordering and trust-rejection regressions are covered. These checks do not establish recovery on the user's carrier network or identify its reset issuer.

## [0.4.7] - 2026-10-26

### Removed

- Plain WARP connections over HTTP3 and HTTP2. Their saved selections and cached
  successes are removed on load. Empty and payload-only custom profiles are
  refused, and the daemon requires an executable outer strategy for WARP opens.

### Changed

- An exhausted scan reports failed traffic verification and points to configured
  servers or compatible strategies. It no longer suggests that increasing the
  timeout will repair an unverified path.
- The user's 0.4.6 hotspot log confirms seven QUIC resets, two QUIC handshake
  timeouts, four HTTP2 timeouts after local CONNECT header writes and one TLS
  handshake timeout. Removing plain controls does not repair these failures.

### Fixed

- QUIC handshake idle timeout honors the configured connection budget. The
  library's default five-second idle limit previously ended longer attempts
  early. The total dial still obeys the caller's deadline and cancellation.

## [0.4.6] - 2026-10-26

### Fixed

- HTTP2 dial timeouts retain the observed TCP/TLS/HTTP2/header-write phase when
  request cancellation masks the pending dial error. The dial timer preserves
  the deadline error type, and caller cancellation retains the underlying error.

### Validation

- Local pinned TLS/IP exchanges pass over HTTP2 and HTTP3 on IPv4 and IPv6.
  The final private product-backend matrix passes all 12 cases. An initial
  XHTTP auto UDP timeout remains unresolved despite 16 later successful checks.
- This build provides corrected diagnostics for the next user-run connection
  test. The external WARP reset cause and carrier connectivity remain unverified.

## [0.4.5] - 2026-10-26

### Fixed

- Isolated HTTP2 tests use the account's dedicated TCP endpoint, with the pinned
  upstream default when absent. They no longer alternate through the HTTP3 IP pool.
  Old HTTP2 confirmations and endpoint pins require fresh verification.
- Closed scan handles retain their terminal transport reason for two minutes,
  capped at 128 records. Measurements report the original reset instead of
  `no open connection`; loss during a measurement cannot certify success.
- Peer-key rejection has a dedicated code, localized explanation and actual
  endpoint. Certificate pinning remains enforced on every connection.
- Failure diagnostics carry transport, endpoint and connection phase through
  IPC. Native QUIC logs record sent outer fake-packet counts without credentials.

## [0.4.4] - 2026-10-25

### Fixed

- Persistent connections require three traffic checks separated by two-second
  pauses before showing Connected. Scan attempts also perform a delayed follow-up.
- Brief successful reconnects retain the same recovery episode and backoff.
  Repeated rapid losses advance to verified alternatives, preferring a different
  transport, including supported TLS/HTTP2 strategies after QUIC failures.
- Recovery has bounded primary retries, alternative candidates and admission
  time. Cancellation joins owned cleanup. Automatic fallback excludes plain
  control strategies and retains foreign-VPN and source/routing guards.
- Quick search continues with untested candidates when its confirmed choices
  fail persistent verification.
- Cached confirmations and endpoint pins bind to an opaque access-network
  identity. Path changes invalidate stale evidence and restart an interrupted
  scan once; continuing network changes stop the scan. No network settings change
  is needed to observe the path.

## [0.4.3] - 2026-10-25

### Fixed

- Release service configuration uses an explicit executable at
  `/Applications/Zarp.app/Contents/MacOS/zarpd`. This avoids the relative
  container lookup that failed with EX_CONFIG on the affected machine.
  Startup validates that the installed copy owns the configured executable;
  Debug builds target their own build directory.
- The journal records application startup, automatic preparation stages and
  native error domain/code or readiness timeout. Private error metadata is
  excluded. A failed preparation no longer leaves an empty journal.
- Log display reads the authoritative bounded log snapshot, scrolls to the
  latest entry on opening and keeps scrolling when the entry limit is reached.

## [0.4.2] - 2026-10-25

### Changed

- Connection preparation automatically registers or restores Zarp's bundled
  service at startup and before connection, scan and WARP+ actions. An outdated
  responding service is replaced only when explicit status confirms it is idle.
- Removed the service-management window and Install, Restore, Restart and
  Uninstall controls from the app. Only macOS authorization remains interactive
  when required. Preparation status uses ordinary connection wording.
- Automatic recovery and system approval presentation have a per-launch bound.
  Concurrent requests share one operation. A normal connection or account action
  can retry after a failure, without a separate maintenance workflow.

## [0.4.1] - 2026-10-25

### Fixed

- A registered daemon with no IPC socket can be restored through ServiceManagement.
  Recovery waits for asynchronous unregistration before registering the current
  app. An unavailable daemon no longer relies on an IPC-only restart.
- The power button opens service settings while the daemon is unavailable.
  Connection and scan actions are held until the service responds, with a clear
  localized status instead of raw socket errors.
- WARP+ distinguishes an unavailable service from an account API failure and
  provides a direct path to service recovery. Cached account type is not presented
  as current while the daemon is unavailable.

## [0.4.0] - 2026-10-25

### Added

- Context-aware, cancellable native WARP registration with a private checkpoint
  for resumed MASQUE enrollment. An uncertain account creation is not replayed.
- Fixed-origin HTTPS account setup with portable TLS split/disorder recovery,
  candidate ordering and protection through enrollment, WARP+ and confirmation.
  Existing accounts and active tunnels are preserved; API success does not
  confirm a tunnel strategy. No official Cloudflare installation is required.
- Complete Persian translation, RTL windows and LTR technical fields/tables.

### Fixed

- Window titles follow language changes, including reopened windows.
- VPN advice checks actual selected destinations and both route families, with
  conservative handling of incomplete observations. Daemon guards stay intact.
- Unknown account data, request quotas, certificate failures and uncertain
  license responses receive distinct messages without exposing credentials.

## [0.3.2] - 2026-10-20

### Changed

- Main-window height fits its contents, removing the empty space above the log.
  Opening and collapsing the log adjusts the height to match.
- Removed the duplicate server-library button from the connection form and
  shortened its help. Advanced saved-list management is available in the source
  menus; direct server/subscription input stays in one field.

## [0.3.1] - 2026-10-20

### Fixed

- Main-window status, detail and connection hint stay together. Extra window space
  is placed after the hint while the log control stays at the bottom.
- Language and settings symbols are 20 points inside the existing 40-point
  buttons, restoring their visual weight after the button-size change.

## [0.3.0] - 2026-10-20

### Added

- Own-server application routing: include or exclude selected application bundles
  and executables, with a searchable installed-app list and persistent rules.
  TCP/UDP owner lookup and separate server/direct forwarding are integrated into
  the native bridge. System-TUN acceptance remains unverified.
- Direct server-link or HTTPS subscription input in Server and endpoints, with
  an explicit own-server switch, IPv6 setting and custom numeric DNS resolver.
- Versioned routing capability checks and owned scoped-route recovery. Required
  IPv6/DNS setup failures refuse partial server routing and roll back changes.

### Changed

- Server, application and account settings use separate windows. Server-mode
  connection help no longer describes connecting WARP.
- All eight languages include the new server and application controls.

## [0.2.0] - 2026-10-08

### Changed

- The disk image now opens as a drag-to-Applications window (Zarp, an arrow and the Applications folder, with
  Zarp's icon on the volume) instead of a plain folder. The old `READ ME FIRST.txt` is gone: the README
  explains the first launch.
- The app and the background service are otherwise the same as in 0.1.0.

### Documentation

- The README is shorter and follows the style of the Windows and Android READMEs, with download links for all
  three platforms and a step-by-step "Why won't Zarp open?" guide with screenshots.

## [0.1.0] - 2026-10-08

The first public release.

### Added

- A native SwiftUI app for Apple Silicon (macOS 14 or later): one power button, a strategy list with results,
  quick and full scan, custom strategies (`strategies.txt`), a menu bar item, a log view, and eight languages
  (English, Русский, Español, Português, 中文, हिन्दी, Français, Deutsch).
- **Zarp is its own Cloudflare WARP client.** It registers an anonymous WARP account after the user accepts
  Cloudflare's terms and speaks MASQUE (CONNECT-IP) over HTTP/3 or HTTP/2, with no dependency on the official
  WARP app.
- **DPI strategies**: decoy QUIC packets sent from the connection's own socket (with TTL and repeat options),
  and TLS ClientHello split and disorder for the HTTP/2 transport. Eleven of the 20 catalog strategies run;
  those that need raw sockets or WireGuard are listed as unavailable, with the reason.
- **`zarpd`, a privileged helper** (a Go daemon registered with `SMAppService`) that owns the tunnel: the
  utun device, the packet pump, routes, DNS, and the measurement used to score strategies.
- **A whole-Mac tunnel** for IPv4 and IPv6 with an optional DNS override. It uses `0/1` + `128/1` routes (and
  `::/1` + `8000::/1`) through the utun, so the real default route is never changed and a crashed daemon fails
  open. The control connection to Cloudflare is kept off the tunnel with a journaled host route; DNS and that
  route are restored on disconnect, on SIGTERM, and at the next start after a crash.
- **Scanning that checks itself**: each test uses a fresh endpoint, a strategy needs a second independent pass
  for the double check mark, a failing saved strategy falls back to the other verified ones, and a lost
  connection is re-established quietly with the same strategy.
- A **real-network integration test** (`scripts/test-integration.sh`) covering the full tunnel, DNS restore,
  `kill -9` and SIGTERM recovery, and a check that the machine ends up as it began.
- A packaging script that produces a signed disk image (`scripts/package.sh`), third-party notices bundled in
  the app, and CI (Go, Swift, build, notices, documentation links).

### Known limitations

- The release is **not notarized** (no paid Apple Developer membership): the first launch needs *Open Anyway*.
- WireGuard and the raw-socket strategies (`badsum`, `tcp_md5`, `seqovl`, `hostfakesplit`) are not available.
- Developed and tested on macOS 15 on a Wi-Fi network; macOS 14 and other network types are not yet tested.
- After sleep or a network change traffic can stall for up to about 30 seconds before the tunnel is
  re-established. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#13-known-limitations) for the full list.
- Translations other than English and Russian have not been reviewed by native speakers.

[Unreleased]: https://github.com/ZarpVPN/Zarp-MacOS/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ZarpVPN/Zarp-MacOS/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/ZarpVPN/Zarp-MacOS/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ZarpVPN/Zarp-MacOS/releases/tag/v0.1.0
