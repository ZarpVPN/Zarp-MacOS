# macOS parity implementation progress

Working date: 2026-10-27 (Europe/Moscow). Earlier results retain their execution dates.

## Constraints and baseline

- Preserve the current VPN. Autonomous checks use fakes, loopback, and temporary IPC only.
- No installation, production GUI launch, real tunnel, route/DNS changes, commit, or publication.
- Keep the historical analysis and snapshot unchanged. Existing user changes: `.gitignore` and the three analysis/instruction files.
- Working checkout: `f942a4bf4b9550bbdf63d5ee9e45791c1ee08216`.
- Clean local Windows reference: `07406eb5af0a2ad1812fde3692965313cc2798fc`.
- Clean local Android reference: `9399fd496bb1fb791f83f4cb80a2f450186be31d`.
- Clean saved macOS reference: `dca673a4df1e6d18999675f2f88b1f74922c305a`.
- Historical references match the snapshot and were preserved. A separate Windows
  1.6 prerelease reference was added, as recorded below. `_reference/` is ignored.

## Release 1.0.0 preparation: 2026-10-27

- Set app and embedded-daemon marketing version to 1.0.0 and build to 16.
  Promoted the unreleased feature record to 1.0.0, kept the earlier local-build
  history, added public release notes and updated the issue version examples.
- Fetched current upstream metadata without changing the working branch. Eleven
  local commits have patch-equivalent upstream counterparts; four later upstream
  commits update README links, downloads and community information. The release
  README merges those updates with the existing local functionality and uses
  the confirmed canonical repository, ZarpVPN/Zarp-MacOS. No remote write,
  commit, tag or push has been performed by the agent.
- Corrected README profile count, server-selection behavior and automatic
  service wording. Release instructions use automatic macOS-owned preparation
  and preserve separate evidence for local checks and unverified system tests.
- Formatting-only correction in the existing daemon account-setup initializer
  makes the repository-wide gofmt gate clean. Runtime behavior is unchanged.
  An extra EOF blank line in the historical feature analysis was removed to
  pass the staged whitespace check; its analysis content is retained.
- Full validation and clean signed packaging PASS: `/tmp/zarp-100-package.log`.
  Repository-wide gofmt is clean; Go vet and full race tests pass, including
  proxy 171.173 s, tunnel 6.190 s and WARP 30.656 s. All 351 Swift tests,
  notices, clean arm64 Release build, matching app/daemon metadata, bundle and
  read-only mounted-image signature checks and image verification pass.
- Rehearsed commit, fetch, rebase, annotated v1.0.0 tag and atomic main/tag push
  using temporary local repositories only. The final rebase preserves every
  prepared file and produces a descendant of fetched upstream 42be52a.
  Initial rehearsal exposed two unnecessary README formatting conflicts;
  preserving the exact upstream additions removes both. No production history
  was rewritten. Evidence: `build/release-1.0.0-git-rehearsal.json`.
- Verified 336 build source/config/resource fingerprints, original engine pins,
  signed guardian digest, nine language resources and asset exclusions.
  Evidence: `build/source-snapshot-1.0.0.json` and
  `build/release-1.0.0-verification.json`. Build/cache/reference files and private
  signing configuration are excluded from the 367-file publication inventory.
- Artifact: `build/Zarp-1.0.0-arm64.dmg`, 51,869,816 bytes, with adjacent checksum.
  SHA256: `00e85f5e7b6709104dad049af8b3c9780682288840cbfedc7e6756019bc03803`.
  Release notes: [releases/1.0.0.md](releases/1.0.0.md). Publishing commands
  include rebase onto origin/main and one atomic push of main and v1.0.0.
- QUIC carrier reset attribution/recovery,
  product TUN, signed backend acceptance, real ECH/Reality-XHTTP and complete
  extra compatibility retain their existing unverified status. No production
  app/service/TUN, VPN, route, DNS, account or license action was performed.

## Mobile WARP follow-up and packet-size correction: 2026-10-27

- User clarified that the remaining request concerns WARP QUIC and the other
  WARP strategies. Existing 0.4.8 logs now establish two confirmed alternate-name
  H2 strategies and a verified persistent H2 session, followed by an app-owned
  close. Nine QUIC resets, two TTL timeouts, four standard-name H2 CONNECT
  timeouts and one disorder TLS timeout remain. Full diagnosis:
  [WARP_MOBILE_DIAGNOSIS_0.4.8_2026-10-27.md](WARP_MOBILE_DIAGNOSIS_0.4.8_2026-10-27.md).
  Source-hashed evidence: `build/hotspot-0.4.8-analysis-2026-10-27.json`.
- The controlled HTTP2 comparison supports an outer-name/fingerprint inference.
  It does not identify an enforcing network device. All QUIC attempts emit
  three fake bursts, confirming that the previous retry fix is active.
  Reset issuer and the precise external cause remain unverified.
- Reproduced a different product defect using the real native H3 dialer and
  packet pump, private pinned TLS, userspace IP stacks and a loopback UDP path
  capped at 1280 bytes. The interface's full-size inner TCP segments cannot fit
  with QUIC/HTTP DATAGRAM overhead, and a repeated 1280-byte ICMP hint does not
  correct that budget. Both IPv4 and IPv6 HTTPS transfers time out before the
  fix: `/tmp/zarp-049-path-mtu-reproduction-final.log`.
- Native H3 now clamps SYN and SYN-ACK MSS to a 1200-byte inner TCP packet
  budget while retaining interface MTU 1280. HTTP2 remains unchanged. The
  incremental checksum update preserves invalid residuals and handles odd
  option alignment. Fragments, malformed headers/options and IPsec are not
  rewritten. Real request/response payloads pass after the fix. This proves a
  local packet-size correction, not resolution of the recorded carrier resets.
- Added six named H2 split profiles for host/sld/endhost. Existing working H2
  identities are preserved; H3 fingerprints move from v2 to v3 for fresh checks.
  Server pairs and registration exclude WARP-only names. Disorder and plain-mode
  policy are unchanged. No supported backend or imported-server feature is removed.
- Added bounded QUIC socket-size, MSS and PTB statistics with fixed closure
  classes, preserving OOB/ECN/batch I/O. At most 256 sends and 256 receives are
  sampled; no payloads, connection IDs, reset tokens, keys or raw error strings
  enter statistics. Separate tests prove bounds and exclusion of decoy TX.
- Focused race checks PASS: `/tmp/zarp-049-focused-final.log` (tunnel 6.732 s,
  WARP 30.770 s, daemon 3.453 s). All 351 Swift tests PASS:
  `/tmp/zarp-049-swift-final.log`. Named H2 transport tests cover both names and
  every new split position with a real retry and IP echo. The path regression
  confirms bidirectional MSS adjustment and no Packet Too Big response.
- App/daemon version is 0.4.9 (15). Final full Go vet/race, all 351 Swift tests,
  notices and clean signed Release/DMG packaging PASS:
  `/tmp/zarp-049-package-final.log`. Final WARP, tunnel and proxy suites take
  30.853 s, 6.978 s and 173.073 s respectively.
  The first full Go run stopped at an unrelated private-child
  recovery assertion (`/tmp/zarp-049-package.log`). Three isolated race repeats
  passed (`/tmp/zarp-049-recovery-reproduction.log`). Failure-only diagnostics
  now record the reservation, cleanup result and read-only member count. The
  recovery and signaling implementation is unchanged; the first assertion's
  cause remains unresolved; the subsequent full run passes without changing
  recovery or signal authority.
  The agent did not launch production GUI/IPC/TUN or alter the
  service, current VPN, routes, DNS, account or license. QUIC hotspot recovery,
  the six new profiles on the carrier and large UDP behavior remain unverified.
- Final app/daemon versions, release manifest, all nine language resources,
  original backend pins, signed guardian digest, code markers, asset exclusions
  and source fingerprints PASS. Bundle and mounted-image signatures and image
  checksums PASS. Evidence: `build/release-0.4.9-verification.json` and
  `build/source-snapshot-0.4.9.json`. The auxiliary verifier initially assumed
  unspaced localization assignments; it now parses the existing format. Its
  codesign trust query requires the same host trust-store access as packaging.
  These verifier issues do not change the built product.
- Artifact: `build/Zarp-0.4.9-arm64.dmg`, 51,869,492 bytes.
  SHA256: `3e31b48865b9dc428fe4ff751f0df4e58329fa695a09f80446f815b8452d69e7`.

## Retry coverage and alternate WARP TLS names: 2026-10-26

- Read the user's subsequent 0.4.7 session, 13:01:24-13:03:55, from existing
  application and daemon logs. All seven post-open QUIC resets remain. The
  two configured 15-second budgets are now respected; one TTL variant reaches
  CONNECT-IP. Four HTTP2 attempts stall after local CONNECT writes and one
  stalls during TLS. The 13:07:14 network-change event is after this scan.
  Reset origin remains unverified. No production connection or capture was
  started by the agent. Sanitized source-hashed evidence:
  `build/hotspot-0.4.7-2026-10-26.json`.
- Reproduced a native TCP strategy defect with a real pinned TLS 1.3 server
  requesting P-256 after an X25519 first share: two ClientHello messages were
  sent, but the strategy applied only once. Reproduction:
  `/tmp/zarp-048-hrr-reproduction.log`. The record-aware writer now splits
  both, preserves a preceding compatibility CCS, serializes writes and keeps
  application data unchanged. Completed segment counts are logged without
  packet contents, keys or hostnames. Fixed regression:
  `/tmp/zarp-048-hrr-fixed.log`.
- Reproduced the same coverage gap in native QUIC using a real HTTP3 server
  and a receiver-side UDP observer. The retry Initial used a new destination
  CID and arrived with zero preceding decoys. Reproduction:
  `/tmp/zarp-048-quic-retry-reproduction.log`. The product dial now injects
  the requested decoys before each new Initial CID, reuses the original bound
  socket, preserves quic-go's OOB/ECN/MTU capabilities, deduplicates retransmits
  and rejects more than four new Initial flights. Fixed local wire evidence:
  `/tmp/zarp-048-quic-retry-fixed.log`. Every observed new Initial has three
  private decoys before it; all packets share one source tuple and actual IP
  exchange passes. This proves local application, not carrier DPI bypass.
- Added four explicit WARP strategies combining alternate vk.com or
  www.google.com outer TLS names with existing fake or split techniques.
  The enrolled Cloudflare public-key pin, client authentication, numeric
  endpoint and CONNECT authority are preserved. Names are a closed enum in
  Swift and an allowlist in the daemon. A name alone cannot authorize plain
  WARP. No plaintext fallback was added.
- Alternate names carry independent configuration identities and an additive
  warpTLSNameVersion=1 capability gate. An older daemon is rejected before
  open. WARP execution fingerprints are now H3 v2 and H2 v3, invalidating
  stale confirmation after the retry correction. Imported-server pairs and
  account registration exclude these WARP-only variants, preserving their
  original origins and verification policy.
- Name-based profile rationale is an inference from the existing fixed-SNI
  scan and the upstream [warpscout implementation](https://github.com/vernette/warpscout/blob/master/masque.go).
  It is not evidence that these names work with this account or carrier.
  Current Context7 crypto/tls and quic-go documentation was consulted and
  checked against the pinned Go 1.27.1/quic-go 0.60.0 sources.
- Local transport checks cover both alternate names, actual pinned HTTP2/H3
  packet exchange after the dial context ends, and rejection of unrelated
  TLS peer keys. The first expanded HTTP2 test fixture accessed a nil request
  TLS state; it now observes the actual ClientHello in GetConfigForClient.
  This was a fixture error, not a product handshake failure.
- Focused WARP/IPC/daemon race checks PASS:
  `/tmp/zarp-048-go-focused-final.log` (WARP 30.593 seconds). The first Swift
  suite PASS: 350 tests, zero failures, `/tmp/zarp-048-swift.log`. A missing
  import in the subsequent budget test was corrected before final packaging.
  Retry-budget and TTL-restore tests PASS:
  `/tmp/zarp-048-initial-budget.log`.
- App/daemon 0.4.8 (14), full Go vet/race, all 350 Swift tests, notices and
  clean signed Release/DMG packaging PASS: `/tmp/zarp-048-package.log`.
  The final WARP suite takes 30.699 seconds; the full proxy package takes
  171.939 seconds. No production GUI, service, IPC, TUN, routes, DNS or account
  file was changed by the agent. Subsequent user logs establish H2 success as
  recorded above; QUIC recovery and reset attribution remain unverified.
- Final metadata, release manifest, nine language resources, mandatory WARP
  strategy refusal, TLS-name capability, bounded retry code, original engine
  pins, signed guardian digest, asset exclusions and bundle/mounted-image
  signature and image-checksum checks PASS. Evidence:
  `build/release-0.4.8-verification.json` and
  `build/source-snapshot-0.4.8.json`.
- Artifact: `build/Zarp-0.4.8-arm64.dmg`, 51,877,701 bytes.
  SHA256: `58a599adfd7f3430b12dcc66ad00dc9b6bff9dd7e5789f5785d2009d3e644431`.

## Plain WARP removal and user hotspot result: 2026-10-26

- The user reports that 0.4.6 still fails through phone tethering and explicitly
  requests removal of plain WARP connections. Existing app log lines 1578-1659
  and daemon lines 323-367 establish the new session. Sanitized, source-hashed
  evidence: `build/hotspot-0.4.6-2026-10-26.json`.
- Actual transport evidence: seven QUIC stateless resets and two QUIC handshake
  timeouts remain. Corrected diagnostics now distinguish four HTTP2 timeouts
  after local CONNECT header writes from one disorder TLS handshake timeout.
  The four header-write events establish completed TLS and local request writes,
  not a peer CONNECT response. The reset issuer and exact external cause remain
  unverified. No plain strategy was attempted in this failing scan.
- Removed direct/direct-h2 from the catalog and all nine localization tables.
  Load clears those legacy selections and cached results across network IDs
  while preserving other sources and server pairs. Empty and payload-only
  custom entries are skipped; manually constructed plain strategies are not
  ready and the Swift IPC provider refuses them before connecting.
- Root IPC rejects WARP opens without fake steps or TCP desync with an additive
  strategy_required code, before account work, an opener or active-tunnel
  replacement. Server mode retains its existing typed outer-strategy policy.
  Updated positive test fixtures to include actual requested strategy steps.
- Full Swift suite PASS: 347 tests, zero failures, `/tmp/zarp-047-swift.log`.
  Regressions cover absent controls, empty/payload-only custom refusal, persisted
  legacy-selection cleanup, preservation of unrelated pairs, zero plain IPC
  connections and refusal without disturbing an existing fake tunnel. A first
  targeted Go run correctly rejected an old endpoint-only positive fixture;
  corrected that fixture to request its normal QUIC fake strategy.
- Bumped app/daemon to 0.4.7 (13); signed local DMG packaging PASS. This
  implements the requested removal; hotspot transport success remains unverified.
  No current VPN, production GUI/service/IPC, routes, DNS or account file was
  changed by the agent. No unchanged hotspot test is requested again.
- Found a separate functional timeout defect matching the two five-second
  QUIC handshake failures: the application set a longer total context deadline
  but retained quic-go's five-second HandshakeIdleTimeout default. The pinned
  0.60.0 config/source confirms that independent timer. Context7 documentation
  was consulted; its current HandshakeTimeout naming is not used for this pin.
- A real pinned loopback TLS/HTTP3 fixture delays its handshake response for
  5.5 seconds with an eight-second configured budget. The old product dialer
  fails with no recent network activity:
  `/tmp/zarp-047-quic-timeout-reproduction.log`. Set HandshakeIdleTimeout to
  the normalized attempt budget; the existing overall context still bounds
  handshake and CONNECT-IP and retains earlier caller cancellation.
- This correction cannot establish why already-opened connections receive
  stateless resets or why the HTTP2 peer does not reply. Do not count the
  local delayed-handshake result as a carrier-network pass.
- Final affected WARP race suite PASS, including the real delayed handshake
  and packet exchange: `/tmp/zarp-047-warp-final.log` (20.126 seconds). Final
  full vet PASS: `/tmp/zarp-047-vet-final.log`. Full pre-timeout-change Go race,
  347 Swift tests, notices and first clean packaging PASS are retained in
  `/tmp/zarp-047-package.log`. Repeated clean packaging after the one-field
  timeout correction PASS using --skip-tests with those checks and the final
  affected WARP regression already completed; final log
  `/tmp/zarp-047-package-final.log`.
- Matching app/daemon metadata, all nine packaged language files, root plain
  refusal, original backend pins, embedded signed guardian digest, clean asset
  checks, bundle and read-only mounted-image signatures and disk-image checksum
  PASS. Evidence: `build/release-0.4.7-verification.json` and
  `build/source-snapshot-0.4.7.json`.
- Artifact: `build/Zarp-0.4.7-arm64.dmg`, 51,834,123 bytes.
  SHA256: `e6ef78ec1ccacff19ea7277737bbdf9b8439bb32bd8f92fad7d8416ae1913a15`.

## Local 0.4.6 diagnostic build: 2026-10-26

- User requested an installable build for their own check. Bumped app and
  embedded daemon metadata to 0.4.6 (12), allowing the app to identify the older
  installed service. This build includes the HTTP2 diagnostic correction below
  and preserves the existing server, subscription, strategy and recovery paths.
- Signed clean Release/DMG packaging PASS through the reviewed
  `scripts/package.sh` workflow: `/tmp/zarp-046-package.log`. Full Go vet/race,
  344 Swift tests and notice consistency pass. The daemon `-version` branch
  returns before logs, DNS/route recovery or IPC are initialized. No production
  GUI, service registration or real connection is run as part of packaging.
- Bundle and read-only mounted-image signature checks, disk-image checksum,
  matching app/daemon 0.4.6 (12) metadata, explicit release launch manifest,
  all nine language files, unchanged engine pins and exclusion of preview/test
  assets pass. The final signed guardian digest is present in the daemon.
  Evidence: `build/release-0.4.6-verification.json` and
  `build/source-snapshot-0.4.6.json`. The initial auxiliary verifier assumed
  trimmed Go build metadata retained linker flags; checking the embedded digest
  directly corrected that verifier assumption without changing the artifact.
- Artifact: `build/Zarp-0.4.6-arm64.dmg`, 51,832,264 bytes.
  SHA256: `29b5cfa5c72927e01ef98c49f96d326a8e280d0bfe3a8a1cd4ee5702f23b7662`.
- The user's subsequent hotspot check failed, as recorded above. Local checks
  and packaging did not establish that the external WARP resets were repaired.

## Latest 0.4.5 session and HTTP2 timeout diagnostics: 2026-10-26

- Read the latest existing app/daemon 0.4.5 session, 11:16:45-11:18:41
  Europe/Moscow, and allowlisted isolation/timeout/endpoint-count settings only.
  The account file was not read. The recovered preparation error precedes the
  scan; no daemon crash or logged network change occurs during it.
- Actual external evidence: seven HTTP3 handles open and then receive a QUIC
  stateless reset, two TTL=4 variants time out during QUIC handshake, and all
  five HTTP2 strategies time out on the dedicated 162.159.198.2:443 endpoint.
  Nine native fake-send logs record packet/byte counts. The earlier endpoint and
  retained-loss fixes are active. No new peer-key mismatch appears. These are
  WARP-only attempts; there is no imported-server/XHTTP failure in this session.
- Confirmed a further diagnostic defect with a real loopback stalled TLS peer:
  request cancellation can mask the dial callback's typed error, so the old
  connect_ip fallback does not establish TLS completion. The own timer also
  lost context.DeadlineExceeded. Added concurrent-safe TCP/TLS/HTTP2/header-write
  phase retention and preserved deadline/cancellation error chains. The
  installed app/service and saved account remain unchanged.
- Added actual pinned IPv4/IPv6 HTTP2 and HTTP3 loopback IP exchanges, requiring
  an ephemeral client certificate, TCP splitting and private same-tuple UDP
  fake sends as appropriate. Traffic survives dial-context cancellation and a
  2.1-second delay beyond the two-second dial limit. Separate stalled TLS,
  authenticated peer without HTTP2 response and unanswered CONNECT fixtures
  cover timeout phases and type retention. Local header writes do not prove a
  peer SETTINGS/CONNECT response. No actual OS tunnel is used.
- Detailed diagnosis: `docs/CONNECTION_FAILURE_DIAGNOSIS_0.4.5_2026-10-26.md`.
  Sanitized, source/session-hashed log summary:
  `build/connection-failure-diagnosis-0.4.5-2026-10-26.json`.
- Validation PASS: full Go race suite in
  `/tmp/zarp-connection-investigation-go-race.log`, full `go vet ./...` in
  `/tmp/zarp-connection-investigation-go-vet.log`, and 344 Swift tests with zero
  failures in `/tmp/zarp-connection-investigation-swift-verified.log`. Native
  WARP loopback payload and phase/deadline regressions are included in the Go
  race result. The normal suite's opt-in pinned backend cases are separate.
- Read-only installed-bundle metadata confirms 0.4.5 (11), both backend engine
  directories and the guardian are present. Reviewed source selection, server
  IPC and account separation. No shared all-protocol defect is established by
  the existing WARP session. File presence is not signed-runtime acceptance.
- Independently verified both existing engine checksums and explicitly ran the
  private product compiler/guardian/outer-relay matrix. Initial result FAIL:
  11 of 12 cases pass, while XHTTP auto HTTPS passes and its single UDP echo
  times out. VLESS/Trojan/Hysteria2 and all other XHTTP modes carry HTTPS/UDP;
  negative credential cases reject traffic. Evidence:
  `/tmp/zarp-connection-investigation-product-runtime.log`. This is independent
  of the user's WARP resets; no cause or production repair is claimed.
- Five focused XHTTP auto repetitions PASS in
  `/tmp/zarp-connection-investigation-xhttp-auto-repeat.log`. Added private
  target receive/reply counters, backend/outer-flow status on failure, and joined
  echo-worker cleanup. Ten instrumented repetitions PASS in
  `/tmp/zarp-connection-investigation-xhttp-auto-instrumented.log`. Final full
  product matrix PASS, all 12 cases, in
  `/tmp/zarp-connection-investigation-product-runtime-instrumented.log`.
  The initial UDP timeout is preserved as an unresolved observation, not
  certified fixed by the 16 later successful auto attempts. No production UDP
  retry, larger timeout, disabled mode or strategy bypass was introduced.
- Affected relay vet PASS after the test-only diagnostics change:
  `/tmp/zarp-connection-investigation-relay-vet.log`. Local documentation links
  and anchors, prohibited punctuation in new text and `git diff --check` pass.
  Sandbox-only attempts could not bind loopback or write the Swift compiler
  cache and are not product failures or passes. The reviewed checks used
  temporary IPC, fake routes, private keys and loopback only, with bounded owned
  fixture/engine processes. No engine downloads or production socket probes.
- No new functionality was removed, no dependency or protocol downgraded, and
  no plain fallback, pin bypass or automatic account re-registration introduced.
  The external reset issuer and exact installed-session HTTP2 timeout stage
  remain unverified. Local traffic cannot establish carrier DPI bypass or pass
  pending product-TUN, real ECH/Reality-XHTTP and signed-release gates. No
  production app/service/IPC or network settings were touched; no unchanged
  manual test is requested again.

## HTTP2 selection and terminal failure corrections: 2026-10-26

Implemented for 0.4.5 (11), following the diagnosis below:

- Isolated HTTP2 opens honor the dedicated account EndpointH2V4, falling back to
  the pinned upstream HTTP2 default only when that field is empty. They do not
  select an address from the HTTP3 pool. Explicit custom endpoints retain their
  existing validation and key pin. Invalid configured addresses remain errors.
- HTTP2 executable fingerprints are versioned separately. Existing HTTP2 cache
  entries, including metadata-free legacy entries, cannot certify or pin an
  endpoint selected under the old policy. Other strategy evidence is preserved.
- Closed handle reasons remain available for two minutes, with a 128-record cap
  and deterministic eviction. Spontaneous loss, requested close, active cleanup,
  unknown/expired handles and sticky cleanup failures remain distinct. Scan losses
  do not become persistent status loss, and stale handles cannot measure a newer
  tunnel. Measurements recheck their exact handle after the traffic phase.
- Native connection failures retain TCP/TLS/QUIC/CONNECT-IP or setup phase and
  actual numeric destination. IPC carries optional connection context to the
  engine and table. Trust mismatch receives peer_key_mismatch and a translated
  message in all nine languages; endpoint public-key verification remains enabled.
- Native QUIC fake sends log bounded strategy identity, endpoint, packet count
  and byte count. This records strategy execution, not proof of carrier DPI bypass.
- New regressions cover the user's saved isolation tokens, delayed scan reset,
  loss during measurement, cleanup in progress, retention expiry/eviction, old
  HTTP2 evidence refusal and structured Go/Swift private IPC failures. Actual
  loopback TLS still rejects a mismatched key and retains the TLS error phase.

Validation:

- Swift PASS: 344 tests, zero failures, in `/tmp/zarp-045-swift.log`.
- Full Go race suite PASS in `/tmp/zarp-045-go-race.log`. Final affected
  daemon/warp/IPC race regressions PASS in `/tmp/zarp-045-go-final-targeted.log`,
  including nested native TLS error conversion. Final `go vet ./...` PASS in
  `/tmp/zarp-045-go-vet.log`. The existing duplicate `-lproc` warning remains.
- Third-party notice consistency PASS in `/tmp/zarp-045-notices.log`.
- Clean signed Release and DMG packaging PASS in `/tmp/zarp-045-package.log`.
  Bundle and read-only mounted-image signature checks pass. App and embedded
  daemon metadata match 0.4.5 (11); the explicit launch manifest is valid, all
  nine packaged language files match source and preview/test assets are excluded.
  Artifact: `build/Zarp-0.4.5-arm64.dmg`, 51,859,486 bytes.
  SHA256: `0048c69b8546e9ca39420a604b1f4dff7a90d7bc39b6e8bda89b6f70921597cd`.
  Machine-readable evidence: `build/release-0.4.5-verification.json`.

No production app/service/account, real TUN or network configuration has been
changed. The hotspot's QUIC reset issuer and successful carrier traversal remain
unverified; no repeated manual test has been requested. No insecure pin bypass,
automatic account reset or silent plain-transport fallback was introduced.

## All-strategy failure investigation: 2026-10-26

- Analyzed existing 0.4.4 app/daemon logs and saved isolation/result fields only.
  No production IPC, account contents, external transport probe, service or
  network mutation was used. No additional user-run test was requested.
- The post-change scan at 00:07:59-00:09:40 exhausts 14 strategies: seven QUIC
  stateless resets, two QUIC timeouts, three TLS peer-key mismatches and two TLS
  timeouts. Earlier persistent connections are explicitly closed by the app;
  the daemon is running successfully during the failing scan.
- Saved isolation tokens plus the real resolver establish that all three TLS
  key mismatches target 162.159.198.1:443; the two TLS timeouts target .2:443.
  The isolation branch bypasses EndpointH2V4 and shares the HTTP3 IP pool.
  HTTP2 uses the same enrolled peer key as QUIC, although the upstream documents
  a possible transport-specific key difference. Disabling verification is not
  a proposed correction. Selecting .2 alone is not proven to fix its timeouts.
- The QUIC table error `no open connection` is secondary: the daemon removed a
  handle after a logged stateless reset before the next measurement request.
  The reset issuer/cause and actual hotspot DPI effectiveness remain unverified.
- Detailed evidence and required corrections:
  `docs/STRATEGY_FAILURE_DIAGNOSIS_2026-10-26.md` and
  `build/strategy-failure-diagnosis-2026-10-26.json`.
- Product code and artifacts are unchanged by this investigation. Existing
  tests were not rerun for this documentation-only analysis.

## Stable verification and adaptive recovery for hotspot changes: 2026-10-25

Implemented for 0.4.4 (10), following the existing-log diagnosis below:

- Persistent apply performs three real traffic-measurement phases with two
  two-second pauses. The UI remains Connecting/Checking stability until all
  phases pass. Each scan connection receives one delayed follow-up, in addition
  to its initial measurement. Two fresh connections still establish confirmation.
  A failed/cancelled phase closes and joins its owned handle before the next one.
- Added an injected EngineTiming dependency. Production waits remain enabled;
  unit tests use deterministic fake time and fake providers without a TUN.
- One recovery episode retains attempt/backoff progress through brief successes.
  Two rapid losses of its original pair advance to alternatives. A connection
  that lasts at least 30 seconds can begin a fresh episode when subsequently lost.
- Alternative discovery prefers a different transport from the failed original
  pair, then confirmed scores and catalog order. Each alternative gets two fresh
  stable tests and persistent stable verification through the existing compiler,
  outer relay and traffic provider. Only the selected source is eligible. No
  plain control strategy is an automatic discovery/fallback candidate.
- Admission is bounded to three original-pair retries and eight alternative
  candidates per episode. The 180-second admission window is checked before and
  after backoff; an already-started operation retains its existing bounded
  provider timeout and joined cleanup. Three mature episodes in ten minutes
  retain the anti-loop limit. A normal explicit user operation resets recovery.
- Failed persistent confirmation in quick discovery advances to the remaining
  requested candidates instead of stopping with short-lived QUIC results.
- Added read-only physical path identity from SystemConfiguration service state:
  interface, service, router and assigned addresses. VPN/tunnel services are
  excluded even when macOS lists them as the global primary interface, so an
  owned tunnel starting cannot itself look like another access-network change.
  Only its opaque hash is stored in results. No SSID permission, external network request, DNS/proxy,
  route, interface or service mutation is used for observation. Nil observations
  cannot identify separate access networks; traffic verification still applies.
- Results and pinned endpoints require a matching network identity. Older
  unbound evidence does not certify a newly identified network. Evidence for a
  different network remains in storage until replaced by a newer result for that
  strategy. Changed paths during a scan discard incomplete evidence and restart
  the original requested scope once. Continuing changes stop with a clear notice.
- The heartbeat observes path changes while idle and reconnects an affected owned
  tunnel. Busy scans check their own path at every traffic phase. Current foreign
  VPN checks run before each recovery candidate and remain enforced by the daemon.
- Added six localized status/log/result messages in all nine languages. The
  existing compact windows, journal and automatic service preparation remain.

Validation:

- Swift regression PASS: 340 tests, zero failures, in `/tmp/zarp-044-swift.log`.
  New cases cover separated
  traffic phases, delayed loss, cancellation/cleanup, quick-scan continuation,
  retained backoff, preferred verified TLS alternatives, bounded flapping,
  mature-session reset, recovery deadline admission, foreign-VPN refusal,
  heartbeat path changes, one-shot scan restart, continuing path flaps, cache/pin
  isolation and cross-network confirmation refusal. Existing engine, server,
  account, subscription, localization and private IPC cases also pass.
- Release compile PASS in `/tmp/zarp-044-release-build.log`; the existing duplicate
  `-lproc` linker warning remains. No Go behavior or dependency pins changed.
- Context7 tools are unavailable. The read-only adapter was checked against the
  installed SystemConfiguration SDK headers. Apple API reference:
  [SCDynamicStoreCopyMultiple](https://developer.apple.com/documentation/systemconfiguration/scdynamicstorecopymultiple(_:_:_:)).
- Read-only native adapter PASS: an access-network fingerprint is available and
  stable across repeated observations. The temporary CLI compiles the actual
  SystemNetworkInspector and outputs only booleans, without raw addresses or
  production IPC. Evidence: `/tmp/zarp-044-path-observation.log`.
- Inert native appearance fixture PASS: independent settings windows, compact
  main frames, journal expansion/scrolling at the cap, startup failure logging,
  Farsi RTL/language switching and absence of maintenance controls.
  Evidence: `build/appearance-preview/report.json` and
  `/tmp/zarp-044-appearance.log`. Fake providers only; no production service starts.
- Third-party notice consistency PASS in `/tmp/zarp-044-notices.log`.
- Clean signed Release and DMG packaging PASS in `/tmp/zarp-044-package.log`.
  The app and embedded daemon both report 0.4.4 (10), the explicit release
  launch manifest is valid, all nine packaged languages match source and
  preview/test assets are excluded. Bundle and mounted-image signature checks
  pass. Packaging did not install or start the app/service.
  Artifact: `build/Zarp-0.4.4-arm64.dmg`, 51,821,383 bytes.
  SHA256: `1d2436a35dd584b56011c2f852318a19adc9909268840cd674e2ba92535308ea`.
  Machine-readable evidence: `build/release-0.4.4-verification.json`.
- The phone hotspot's actual ISP behavior is not verified by fake time/traffic
  tests. No production app, daemon, route/DNS state or foreign VPN was changed or
  started for autonomous checks. No repeat manual test was requested.

## Phone hotspot log investigation: 2026-10-25

- Read the user's existing app/daemon logs without production IPC or any service,
  network or VPN change. The user-run 0.4.3 session confirms successful automatic
  registration/start at 23:11:11 and an initially persistent tunnel. This is new
  user-session startup evidence, separate from earlier autonomous fake checks.
- At 23:13:29 the scan records a temporarily unreachable UDP path. Subsequent
  persistent HTTP3 connections repeatedly terminate with stateless resets within
  roughly one second of opening. Recovery uses the same Google x6 strategy and
  `162.159.198.2:4500` for three cycles, then hits its limit. Later endpoint/port
  changes also reset. No HTTP2 attempt appears in this session.
- Code review explains the connected/reconnecting display: persistent apply has
  a short traffic check without a stability interval; a brief success ends each
  retry loop, and the next loss begins another cycle at 1/3. Recovery does not
  switch transport. Scan evidence has no access-network generation binding.
- Carrier DPI is not proven by a stateless-reset message. The exact reset origin
  and timing of access-network changes are not recorded. No speculative transport
  parameter or network change was applied while diagnosing.
- Detailed findings and required corrections:
  `docs/HOTSPOT_DIAGNOSIS_2026-10-25.md`. Sanitized summary:
  `build/hotspot-diagnosis-2026-10-25.json`. Product code was not changed during
  this investigation; no new system test was requested or run.

## Startup path failure and empty journal: 2026-10-25

Read-only evidence from the user's failed 0.4.2 launch:

- Saved system events show repeated launchd error 128: the specified relative
  executable `Contents/MacOS/zarpd` could not be resolved as a bundle. BTM also
  reports `fullPath is nil`, `container=(null)` and a missing container item for
  the same historical daemon record. Re-registering reused that record. This
  explains the prior EX_CONFIG and absence of a daemon IPC socket. It does not
  establish why the system database lost the parent association.
- Events at 22:50-22:51 are saved privately in
  `/tmp/zarp-043-launch-events.json`. Only Zarp-related launchd/smd/BTM records
  were queried. No full-disk diagnostic or other app's state was collected.
  The bounded query contains 138 matching path-resolution failures and 278
  missing-container events. Sanitized summary:
  `build/startup-path-diagnosis-2026-10-25.json`.
- At this investigation, `/Applications/Zarp.app`, the Zarp job and its socket
  are absent. No production app/service/process was launched, installed,
  registered, removed, signaled or repaired to reproduce the problem.
- The journal was empty because preparation and native errors were swallowed
  without writing any log event, while the backend never started. Separate
  issues were found in initial log scrolling and updates at the entry cap.

Implemented for 0.4.3 (9):

- Replaced relative BundleProgram with an explicit Program and argv[0] for the
  fixed release installation `/Applications/Zarp.app`. Debug configuration
  stamps its own build path so it cannot launch another installed copy.
- Added preflight manifest validation and packaging checks for label, canonical
  absolute executable, exact arguments and ownership by the current app bundle.
  The startup path correction does not reset global BTM state or alter any other
  service. Actual acceptance by the affected system remains unverified.
- Added application-start and preparation-phase journal events, including
  registration/replacement, waiting, readiness, authorization and terminal error.
  Native diagnostics include only bounded domain/code, excluding private
  UserInfo, descriptions, account paths, profiles and licenses.
- Log display refreshes from the authoritative bounded LogBus snapshot. Opening
  the panel scrolls to its newest entry. Subsequent scrolling observes the last
  entry identity, including appends that leave the capped entry count unchanged.
- Main-window service maintenance controls remain removed. Preparation and
  active-work guards retain their automatic workflow and bounded retry policy.

Source verification:

- Context7 tools are not available in this session. The installed SDK
  SMAppService.h permits standard launchd keys in addition to BundleProgram.
  The installed launchd.plist(5) manual explicitly defines Program as the absolute
  executable path. The installed LaunchServices header and the
  [Apple DTS service setup guide](https://developer.apple.com/forums/thread/802443)
  were checked. Explicit Program is a path-resolution workaround based on the
  local error; this is not a claim that the documented BundleProgram feature is
  generally invalid. No speculative global reset was performed.

Verification:

- Swift: 322 tests PASS, no failures, `/tmp/zarp-043-swift.log`. New regression
  checks use the actual source launch manifest, refuse relative/mismatched paths
  and extra arguments, preserve debug build ownership, verify ordered native
  failure events with private metadata excluded and record a readiness timeout.
- Release compilation PASS: `/tmp/zarp-043-release-build.log`. The existing
  duplicate `-lproc` linker warning remains. No Go runtime or dependencies changed.
- Inert appearance fixture PASS: `/tmp/zarp-043-appearance.log` and
  `build/appearance-preview/report.json`. It uses the same view-model coordinator
  factory and preparation method as the app, with a failing fake service. Native
  errors reach the real LogBus and view. Screenshots confirm initial scrolling,
  updated last entry at a fixed 20-entry cap, readable wrapped errors and compact
  collapse in the same failure state. Farsi/RTL and independent windows still pass.
- Private PlistBuddy stamping with a build path containing spaces PASS. Packaging
  shell syntax and `git diff --check` PASS. Notice consistency PASS in
  `/tmp/zarp-043-notices.log`. No real service operations are part of these checks.
- Signed clean Release and DMG packaging PASS: `/tmp/zarp-043-package.log`.
  Final compilation includes the shared production/fixture coordinator factory.
  App and daemon report 0.4.3 (9), and the packaged launch manifest has the explicit
  release Program and exact argv[0]. All nine packaged languages match source.
  Signature preservation, DMG integrity, drag-to-Applications layout and fixture
  exclusion pass. Artifact: `build/Zarp-0.4.3-arm64.dmg`, 51,768,505 bytes,
  SHA-256 `17b06f4c7c007d5f371619d0b11631bce8aeaa5cffc58fb2660c8e32982d0a3e`.
  Verification metadata: `build/release-0.4.3-verification.json`. Older release
  artifacts are preserved. No installed app was replaced during packaging.
- Actual system startup with the path correction remains unverified. No production
  daemon or TUN was started, and no routes, DNS, proxy settings or foreign VPN were
  changed. Unit/appearance/build results do not establish actual system acceptance.

## Automatic connection preparation replaces manual maintenance: 2026-10-25

Implemented in 0.4.2 (8), superseding the manual 0.4.1 service-recovery UI below:

- Deleted the service-management view, scene and settings/main/WARP+ entry
  points. Users no longer install, restore, restart or remove a service in the
  app. Technical socket errors are mapped to ordinary connection wording.
- Added a shared automatic coordinator for launch, power button, scan, strategy
  selection and WARP+ actions. It probes the actual daemon and automatically
  registers a missing service or replaces broken/outdated registration using
  the current bundled daemon. Native asynchronous removal completes before
  registration. The install location is validated before either mutation.
- Responsive current services and active work are preserved. An outdated
  responding service needs explicit `networkBusy: false` and disconnected status
  before replacement. Missing/failed activity metadata is treated conservatively.
  Local engine ownership is checked again immediately before replacement.
- One automatic replacement attempt per launch and one automatic approval-pane
  presentation prevent monitoring loops. Concurrent requests join the same
  operation. Readiness probes are bounded; a normal user connection/account
  action can retry a failed preparation. Quit cancels and joins native removal
  before skipping registration. There is no global background-item reset.
- macOS authorization cannot be granted by the app. When required, the app opens
  the OS approval pane and shows a localized connection notice. Removed unused
  maintenance text from all nine languages and added four connection messages.
- WARP+ automatically prepares access before reading an account or submitting a
  key. Its ordinary actions remain available after a preparation failure. A
  cancelled request cannot submit a key after preparation completes.
- Main-window content sizing, independent settings and Farsi/RTL are preserved.
  Automatic preparation shows its status without another maintenance window or
  duplicate hint. README and troubleshooting describe the automatic workflow.

Verification:

- Swift policy and fake IPC checks PASS: 316 tests, no failures, in
  `/tmp/zarp-042-swift.log`. New checks cover first registration, broken/outdated
  registration, transient launch delay, active-work deferral, bounded failures,
  explicit retry, approval presentation, location refusal, concurrent joining,
  quit cancellation and conservative decoding of idle metadata.
- Release compilation PASS: `/tmp/zarp-042-release-build.log`. The existing
  duplicate `-lproc` linker warning remains; no new compiler errors or warnings.
- Final inert appearance check PASS: `/tmp/zarp-042-appearance.log` and
  `build/appearance-preview/report.json`. The fixture compiles out service
  registration and uses fake providers. No maintenance window opens. Main frames
  remain 380x471 and 380x513 with a server source. Preparation no longer repeats
  its hint, and returning to idle restores the original content-sized frame.
- Final wording-only cleanup removes residual advice to check/update the daemon
  from connection-loss and WARP+ messages in every language. All 18 localization
  checks PASS in `/tmp/zarp-042-final-localization.log`. Notice consistency PASS
  in `/tmp/zarp-042-notices.log`; `git diff --check` PASS.
- Signed clean Release and DMG packaging PASS: `/tmp/zarp-042-package.log`.
  App and embedded daemon report 0.4.2 (8); all nine bundled languages match final
  source, and preview/test fixtures are excluded. Signature preservation, image
  integrity and drag-to-Applications checks pass. Artifact:
  `build/Zarp-0.4.2-arm64.dmg`, 51,758,161 bytes, SHA-256
  `26dd6d19ad9c3ee1f97e0fe2174ba6ee18e5b25ec07b7ecea91dee8383443eed`.
  Verification: `build/release-0.4.2-verification.json`. Previous releases remain
  available; no installed bundle or production service was replaced.
- No Go behavior or dependencies changed in this revision. Prior Go race/vet and
  packet/transport evidence remains separate from this UI/lifecycle change.
- No production service, installed app, account API, routes, DNS, live TUN or
  foreign VPN was changed or started. Actual macOS registration/recovery and
  existing system/ISP acceptance remain unverified by autonomous checks.

## Missing daemon after app replacement: 2026-10-25

Historical 0.4.1 behavior, superseded by automatic preparation above.

Evidence collected without service or network changes:

- The installed app reports 0.4.0, build 6. `/var/run/zarpd.sock` is absent.
- The fixed launchd job exists, is repeatedly scheduled, and reports exit status
  `78: EX_CONFIG`. Its recorded parent bundle version is still 1. This is evidence
  of stale registration metadata and a launch failure, not an account API failure.
- The installed app and daemon pass read-only signature verification outside the
  sandbox. The installed daemon hash matches the delivered 0.4.0 binary. Sandbox
  signature-query failures were not treated as proof of a damaged app.
- No registration, unregister, restart, installation, production GUI launch,
  account read/creation or route/DNS operation was performed. The existing job and
  the user's VPN remain untouched by this investigation.

Implemented:

- Added explicit Restore service using SMAppService. The app validates its install
  location first, awaits asynchronous unregister completion, then registers the
  current bundle. Authorization failures stop recovery. A confirmed missing job
  is handled without ignoring unrelated errors. Requires-approval state opens
  the system approval pane. No global background-item reset is used.
- The recovery path is independent of daemon IPC. An unreachable service no longer
  attempts to repair itself by sending a restart request through its missing socket.
  Mutating service operations are serialized; polling pauses during recovery and
  startup checks use bounded one-second pings. There is no automatic recovery loop.
- Missing service state directs the power button, scans and selection actions to
  service settings, avoiding repeated connection attempts. Main and WARP+ windows
  show localized service diagnostics. WARP+ holds key submission while the service
  is unavailable and provides a service-settings action; cached account type is
  shown as unknown until service access is restored.
- Added seven service-recovery strings across all nine languages. Existing window
  sizing, independent windows, language switching and RTL are preserved.
- The platform API was checked against the installed Apple SDK SMAppService.h and
  [Apple's asynchronous unregister documentation](https://developer.apple.com/documentation/servicemanagement/smappservice/unregister(completionhandler:)).
  The SDK explicitly guarantees re-registration after the completion callback.
  Context7 tools were unavailable in this session, so primary Apple sources were used.

Verification:

- Swift: 303 tests PASS in `/tmp/zarp-041-swift.log`. New fake-service tests prove
  that registration waits for completion, failed authorization cannot trigger
  registration, and cancellation waits for removal before skipping registration.
  The missing-socket IPC test verifies a typed, redacted, localizable error.
- Release compilation PASS in `/tmp/zarp-041-release-build.log`.
- Inert appearance fixture PASS in `/tmp/zarp-041-appearance.log`, including the
  missing-daemon main screen, power-button routing to service settings, readable
  Restore service UI and the WARP+ unavailable state. Native registration is
  compiled out of the fixture. Screenshots are in `build/appearance-preview/`.
- Signed clean Release and DMG packaging PASS: `/tmp/zarp-041-package.log`.
  App and daemon report 0.4.1 (7); all nine packaged language files match source.
  Signature preservation, image integrity, drag-to-Applications layout and fixture
  exclusion pass. Artifact: `build/Zarp-0.4.1-arm64.dmg`, 51,785,285 bytes,
  SHA-256 `e7ee2198d6ffa68b5d535e4d013c98f522aabd446e5014c1543a7fd8b003206a`.
  Verification metadata: `build/release-0.4.1-verification.json`. Notice consistency
  PASS: `/tmp/zarp-041-notices.log`. Previous DMGs were preserved.
- Actual system recovery remains user-triggered and unverified: replace the app
  in Applications, open it, choose Restore service, and approve macOS if requested.
  Prior TUN, actual account registration and ISP DPI acceptance remain unverified.

## Native port of Windows 1.6/1.7 updates: 2026-10-25

- Implemented native account setup in `zarpd/warp/registration.go` and its fixed
  HTTPS transport. Ordinary access is tried first; retryable pre-request network
  failures can advance to supported TLS split/disorder candidates. Normal system
  trust, the fixed API Host/SNI, certificate checks, bounded responses and redirect
  refusal remain active. DNS failures can use published Cloudflare API addresses;
  consumer API compatibility on those backup addresses is not live-verified.
- Replaced contextless usque registration HTTP calls with owned request contexts.
  Setup has a 180-second overall deadline and 15-second HTTP deadlines. Cancellation
  returns after owned request work has stopped; there is no abandoned writer.
  Each attempt owns a terminal HTTP transport that cancels and joins detached
  dialing before releasing setup ownership. Read-only route inspection inherits
  the dial context and joins its command. Possible POST transmission is tracked
  from TLS connection acquisition, before HTTP writes can race cancellation.
- Generated keys and request identity are checkpointed privately before creation.
  A successful POST saves the device ID/token before MASQUE enrollment. A failed
  PATCH resumes with that same device and key. Final account commit is atomic,
  exclusive and mode 0600; damaged existing data is never replaced. The pending
  checkpoint is removed after commit. A lost POST response after possible send
  produces `account_uncertain` and blocks automatic recreation. Quota responses
  stop the strategy loop. Terms consent is retained across a resumable failure.
- One typed `setupWarpAccount` IPC request owns registration, enrollment, optional
  license PUT and account GET. Capability version 1 prevents silently sending new
  setup semantics or a key to older daemons. Ping distinguishes missing, pending,
  ready, uncertain and unavailable account data. Existing premium credentials are
  preserved. An acknowledged license is not reapplied while retrying status; a
  possibly sent license is checked through GET instead of automatically resent.
- Only supported TLS WARP candidates are used for API protection, ordered by
  selected strategy, matching confirmed result, then catalog order. Country
  filtering and the 32-candidate bound apply. API success does not update tunnel
  results, selected strategy, endpoint confirmation or server-pair evidence.
- Setup shares daemon admission and shutdown joining. It preserves an existing
  persistent tunnel. Physical socket fallback is forbidden with an active owned
  tunnel or foreign tunnel routes. Route/interface inspection is read-only; no
  TUN, route, DNS, system proxy, firewall, service or VPN change is needed.
- Added all 288 current keys in Persian, including 138 macOS-specific translations
  and eight new account setup strings. Reviewed common Windows key semantics and
  replaced official-client/Windows-specific wording. Nine languages have matching
  keys and placeholders. Persian mirrors natural-language UI without restart;
  technical inputs, keys, paths, logs and tables stay LTR. Reopened window titles
  now follow language changes.
- Refined UI warnings using both default families and selected WARP/API/server
  destinations. Failed or truncated observations keep conservative interface
  warnings, including IPv6 candidates. The daemon keeps its stricter conflict
  refusal. No foreign VPN is stopped or bypassed to make a setup check succeed.

Validation:

- Swift: 300 tests PASS, including protected IPC capability gating, combined
  setup/consent, selected/confirmed candidate ordering, unchanged tunnel results,
  preserved active connections, unknown state refusal, route evidence and Farsi.
  Log: `/tmp/zarp-040-swift-third.log`.
- Go: full `go test -race ./...` PASS and `go vet ./...` PASS. After final response
  validation and uncertain-license cases, `go test -race ./warp ./daemon` PASS.
  Logs: `/tmp/zarp-040-all-go-race.log`, `/tmp/zarp-040-go-vet.log`,
  `/tmp/zarp-040-final-account-race.log`, `/tmp/zarp-040-owned-setup-race.log`.
  Final changed-package checks include `./route` and a barrier proving that a
  cancelled HTTP request cannot release a still-running detached dial. Tests use
  temporary files, fake HTTP/IPC
  and owned loopback TLS, including actual native split/disorder handshakes with
  normal certificate verification, enrollment recovery, rate limits, lost POST,
  cancellation joining and license confirmation without repeated PUT.
- Third-party notice consistency PASS. No dependency versions were changed.
- Inert appearance fixture PASS: live Farsi/RTL and return to Russian, localized
  reopened titles, independent settings and compact main/log layout. Captured
  main, settings, server editor, WARP+ and application routing windows in
  `build/appearance-preview/`. Main frames remain 380x471 and 380x513 in server mode.
  The fixture excludes production services and uses fake network/account providers.
- Signed clean Release and DMG packaging PASS: `/tmp/zarp-040-package-final.log`.
  App and daemon metadata match 0.4.0 (6); all nine languages are bundled and
  packaged Farsi matches source. Signature preservation, image integrity,
  drag-to-Applications layout and fixture exclusion checks pass. Artifact:
  `build/Zarp-0.4.0-arm64.dmg`, 51,757,254 bytes, SHA-256
  `694f76d2b58b98f3770875925a6acbd63723a71c70800f6cef3ce0c79b738a72`. Previous DMGs were preserved.
  Verification metadata: `build/release-0.4.0-verification.json`.
- No production Cloudflare registration, real license activation, installed app,
  live TUN or ISP DPI acceptance was run. Earlier system-adapter failures remain
  unpassed. These changes do not turn prior local evidence into system acceptance.

## Fresh Windows release analysis: 2026-10-25

- Read the current GitHub REST release descriptions for v1.6.0 and v1.7.0,
  both published on October 23, and pinned their exact Git commits. The public
  web reader had returned a cached October 20 release index; it was not accepted
  as current. Latest main and v1.7.0 both resolve to
  `d6695efb64030f37cbe1a52f74c742e1fc61f3da`.
- Saved a clean current Windows checkout in `_reference/Zarp-Win-2026-10-25`.
  It and `_reference/release-metadata/` are ignored. Earlier source references
  and the historical parity snapshot were preserved. The delta from the prior
  prerelease contains two commits, 30 files, +1,284/-53 lines.
- Wrote [the detailed review](WINDOWS_UPDATES_2026-10-25.md) and
  [a reproducible snapshot](windows-update-snapshot-2026-10-25.json). It covers
  Persian/RTL, safer registration, route-aware warnings, API TLS strategy search
  and WARP+ completion under temporary protection. It distinguishes already
  implemented native WARP+ from missing protected native registration.
- Identified the download boundary: the new protection applies to registration
  API HTTPS. WarpInstaller remains unchanged and its ordinary MSI download does
  not gain this protection. Native macOS uses its bundled WARP implementation.
- Identified native prerequisites for porting: context-aware owned HTTP work,
  safe partial-enrollment recovery, typed missing/unknown account states and a
  coordinated overall/IPC deadline. Persian needs 138 additional current macOS
  key translations plus semantic review of the 142 matching key names.
- Source and existing test review only. No Windows tests/binaries, Cloudflare
  registration, license activation, product GUI, service or system-network
  operation was run. Application sources and release artifacts are unchanged.
- Verification PASS: current reference HEAD/tag consistency and clean worktree,
  parent ignore rules, unchanged hashes of the reviewed macOS sources, snapshot
  JSON consistency, local document links, new-text punctuation and
  `git diff --check`. Earlier Windows reference heads remain `07406eb5` and
  `3e78f4d`. These checks are documentation/source evidence only.

## Compact main window and simpler server form: 2026-10-20

- Removed the main window's fixed 520-point height and vertical expanding space.
  Its width stays 380 points; height now follows the labels, optional source
  selector and expanded log. The log control follows the hint with a fixed gap.
  Collapsing the log removes its space again. Separate settings remains an
  independent window.
- Removed the extra Servers and subscriptions button from the server form.
  One editor accepts server links or a subscription URL. The existing saved-list
  menu retains selection, adding a new source and access to advanced management;
  the main source menu also provides that access. Existing refresh/delete and
  individual-server selection functionality is retained.
- Shortened the save explanation in all eight languages. It describes updating
  a subscription or replacing the imported list, without another library block.
- Version metadata: 0.3.2, build 5. These changes affect layout and navigation.
  No connection, backend, policy, process or system-network behavior changed.
- Isolated appearance check PASS: `/tmp/zarp-032-compact-appearance.log`.
  The captured Russian main window measures 380 by 471 points including the
  title bar, down from 380 by 548. Server mode measures 380 by 513. Log expansion
  adds its panel and collapse returns to the prior size. Separate/single-instance
  settings, independent close and minimum settings size still pass. Captures
  under `build/appearance-preview/` use synthetic data and inert providers.
- Localization usage checks PASS, three tests:
  `/tmp/zarp-032-compact-localization.log`. No padding/constant unit tests added.
  Existing Core/Go results remain applicable; no production GUI, service, actual
  tunnel, VPN, route, DNS or proxy mutation was performed.
- Signed Release and DMG checks PASS: `/tmp/zarp-032-compact-package.log`.
  App and daemon metadata match 0.3.2 (5). Production fixture exclusion, packaged
  signatures and image integrity pass. Artifact: `build/Zarp-0.3.2-arm64.dmg`,
  51,676,689 bytes, Apple Silicon. Previous images remain available.
  SHA-256: `16e6f428545f87a4fc88ee8bac4c4d827f72b66f5f17d64b84a6eacb3086f434`.
  New text punctuation and `git diff --check` pass.

## Main-window spacing and symbols: 2026-10-20

- Corrected the reported main-window spacing regression. The expanding Spacer
  follows the connection hint again, keeping status/detail/hint spacing fixed
  while the log control stays at the bottom. The main content remains 380 by
  520 points; server selection and separate settings windows retain their sizes.
- Increased language/settings SF Symbols from 14 to 20 points within their
  existing 40-point buttons. The earlier button enlargement had left their
  symbols at the old size, reducing their relative visual weight.
- Isolated appearance check PASS: `/tmp/zarp-031-main-appearance.log`.
  Reviewed Russian captures of the supplied foreign-VPN warning state and server
  mode, plus the English warning capture. The fixture's warning is synthetic;
  its providers are inert. The existing window checks remain PASS in
  `build/appearance-preview/report.json`. No production app/service was launched.
- This is a UI-only fix plus version metadata: 0.3.1, build 4. Core/network
  implementations and their earlier test results are unchanged. No additional
  unit tests were introduced for fixed padding or icon-size constants.
- Signed Release and DMG checks PASS: `/tmp/zarp-031-main-package.log`.
  App and daemon metadata both match 0.3.1 (4), the appearance fixture is excluded
  from the production executable, and packaged signatures/image integrity pass.
  Artifact: `build/Zarp-0.3.1-arm64.dmg`, 51,675,586 bytes, Apple Silicon.
  SHA-256: `afcfebf6af2e6044a4b38541a1e190f8921b45ef54a16b52897dd790e4ef7572`.
  The previous 0.3.0 image remains available. `git diff --check` passes.
- No VPN, system route, resolver, proxy or tunnel changes were made. Earlier
  system-runtime verification limits still apply.

## Application routing and direct server setup: 2026-10-20

The previous 0.2.0 appearance build did not implement per-application routing.
Its source menu listed only saved sources, so a fresh installation showed WARP
and required a separate library window to add servers. This continuation adds
the missing server editor and the application routing path, rather than another
placeholder control. Version and daemon capability move to 0.3.0, build 3.

- Server and endpoints now has an explicit own-server switch. Paste VLESS,
  Trojan or Hysteria2 links, or an HTTPS subscription URL, directly into this
  window. Save validates the full inline list or refreshes the subscription
  before selecting it. Failed downloads preserve the previously selected source
  and cached profiles. Saving never connects or disconnects a tunnel. The
  existing library remains available for managing several saved subscriptions.
- The server editor exposes IPv6 and a numeric DNS server. WARP endpoints and
  WARP+ remain in the WARP branch. Main-window help follows the selected mode.
- Settings opens a separate Applications window. Select installed application
  bundles or executable files, search by name/path, and choose either only the
  selected applications or all except the selected applications. Bundle rules
  include executable descendants inside that bundle. Helpers installed outside
  it require their own entry. Lists and modes persist in typed settings.
- This policy applies to own-server mode. Proxied flows still use the selected
  backend and outer zapret strategy. WARP remains a separate source, matching the
  supplied Windows distinction. Per-app mode requires full traffic interception;
  the saved policy is applied on the next connection.
- The native userspace bridge preserves each TCP/UDP flow's original tuple.
  The daemon resolves the socket's actual executable with Darwin libproc before
  choosing the server or a physically bound direct socket. Unknown/ambiguous
  owners are refused. The exact daemon HTTPS measurement is separately allowed.
  This is path-based routing, not a process security boundary.
- Direct app flows use interface-scoped physical /1 routes and IP_BOUND_IF.
  They do not add global destination exclusions that would bypass the tunnel
  for other apps sharing an address. Journaled ownership, the PROTO1 marker and
  exact route identity protect cleanup and recovery. Existing/replaced routes
  are preserved; collisions and uncertain cleanup refuse another connection.
  Apple's [XNU lookup implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/route.c#L3084)
  supports this design: an unbound lookup follows its global result's interface;
  an explicitly bound lookup searches its requested scope. This source review
  is not live evidence for the installed kernel.
- With DNS override enabled, ordinary shared system DNS goes through the server
  to the chosen resolver, including DNS initiated by unselected applications.
  The window explains this system-resolver limitation. Turning IPv6 off blocks
  proxied IPv6 while retaining direct IPv6 where a physical route is available.
  Mandatory interception/DNS setup failures roll back the whole server setup.
- Swift and Go strictly validate the same versioned routing contract. Corrupt
  saved policies fail closed. The client checks daemon routing capability before
  sending an advanced policy; an old daemon cannot silently ignore it.

Verification:

- Full Swift suite: 291 tests PASS, zero failures in 5.882 seconds,
  `/tmp/zarp-application-routing-final-swift.log`. Covers strict settings and IPC,
  manual/subscription activation and cancellation, engine propagation and busy
  guards. Localization namespaces include the new application/server labels.
- Full Go suite with races PASS, including existing proxy, relay, native bridge,
  daemon, IPC and route coverage: `/tmp/zarp-application-routing-all-go.log`.
  `go vet ./...` PASS: `/tmp/zarp-application-routing-vet.log`.
- In-memory IPv4/IPv6 IP-stack tests carry actual TCP and UDP payloads through
  different outputs for selected and other apps. Native PID/executable lookup
  passes on owned connected TCP/UDP loopback sockets and wildcard UDP sockets
  for both families. The latter and required IPv6/DNS rollback/collision/cleanup
  fault cases pass with races in `/tmp/zarp-application-routing-rollback-go.log`.
  No test creates a system interface or changes a real route or resolver.
- The isolated appearance fixture now checks the server editor and application
  selector, alongside separate/single-instance settings and main-size checks.
  It compiles the real views with inert providers and synthetic application and
  connection data. Captures/report are under `build/appearance-preview/`.
- Upstream notices check PASS: `/tmp/zarp-routing-notices.log`.
- Final localization checks PASS, three tests:
  `/tmp/zarp-routing-final-localization.log`. Appearance checks PASS:
  `/tmp/zarp-routing-final-appearance.log`. New text punctuation, local document
  file links and `git diff --check` PASS.
- Signed Release and DMG packaging PASS:
  `/tmp/zarp-030-routing-package-final.log`. App and embedded daemon both report
  0.3.0, build 3. The generated app plist now takes CFBundleVersion from
  CURRENT_PROJECT_VERSION. Image integrity, packaged signatures and installer
  layout passed; the production executable excludes the appearance fixture.
  Artifact: `build/Zarp-0.3.0-arm64.dmg`, 51,675,513 bytes, Apple Silicon.
  SHA-256: `68a5685c8b93d916f87582808b9ec2ba292007fe989aadb9c5ff70cb635c76b9`.
  The earlier `build/Zarp-0.2.0-arm64.dmg` remains available. Signing policy is
  unchanged; no installation or production GUI launch was performed.

Actual product TUN and kernel routing under these new app rules remain unverified.
The old external sing-box adapter FAIL is not reclassified as a pass. No current
VPN, production daemon/service, system route, DNS or proxy was modified, and the
production GUI was not launched. Geo/domain presets, WireGuard and remaining
raw-packet techniques are separate incomplete parity items.

## Windows appearance and separate windows: 2026-10-20

- Aligned the interface with the supplied Windows screenshots: compact main
  window, dense dark strategy table with vertical separators, a country dropdown
  at the top right, dark menu controls and two columns of options. The default
  settings size shows all current macOS options. Smaller sizes retain scrolling.
- Main content stays 380 by 520 points. Settings is a separate, resizable,
  single-instance window, also opened by Command-comma and the menu bar. Opening,
  resizing or closing it does not resize or close the main window. Log expansion
  remains an explicit action in the main window.
- Moved endpoints into their own window. Server/subscription management, WARP+
  and daemon controls also use independent windows. Existing connection and
  account actions are retained. No placeholder routing or per-app controls added.
- Country filtering retains multi-country unions. The native strategy table
  retains multiple selection, keyboard navigation, double-click Use and full
  error tooltips. Stale selections are pruned when the strategy list changes.
  New labels and country names are present in all eight languages.
- Isolated appearance check PASS: `python3 scripts/preview-appearance.py`.
  It compiles the actual views without the production entry point, uses in-memory
  settings, private temporary connection storage and inert network/account
  providers, and excludes service/autostart actions. The fixture has a 20-second
  runtime limit. Its inputs stay outside Documents to avoid macOS privacy prompts.
  `build/appearance-preview/report.json` confirms separate, single-instance
  settings, unchanged main size, independent close and minimum-size handling.
  Russian and English captures are under `build/appearance-preview/`; displayed
  connection results are synthetic. Earlier fixture startup attempts without a
  completed report are not counted as passes.
- Localization checks PASS, three tests: `/tmp/zarp-ui-localization.log`.
  Signed Release build and packaging PASS: `/tmp/zarp-ui-package-final.log`.
  App/image signatures, image checksum and installer layout passed verification.
  The production binary excludes the appearance fixture.
- Updated artifact: `build/Zarp-0.2.0-arm64.dmg`, 51,469,641 bytes, Apple Silicon.
  SHA-256: `9993bfeb83960a70445aa86bb4616f416a1e889fcfe477535eae9b2bb353813d`.
  The original user-delivered image and checksum are preserved under
  `build/previous-dmgs/20261020T094748-ui`. The signing policy is unchanged.
- No production GUI launch, installation, daemon/service mutation, real TUN,
  VPN, route or DNS changes. Earlier system-runtime acceptance limits remain.

## Current implementation: Windows 1.6 review, WARP+ and server runtime

The Windows release list includes `1.6.0_Pre-release_2`, commit
`3e78f4dff74d03d06c4115bf43865de016f04340`. It was saved separately under
`_reference/Zarp-Win-1.6.0_Pre-release_2`. See
[the release review](WINDOWS_RELEASE_REVIEW.md) for the release links, comparison
and exact implementation limits. The historical parity analysis and snapshot
were not rewritten.

Implemented in this continuation:

- WARP+ secure key/account UI, typed capability-checked IPC and fixed account API
  on Zarp's own account. Key acceptance and account-type confirmation are separate.
  The key is not persisted or logged. Account changes do not stop an active tunnel.
- Shared source selection in the main window, compatible strategy/server pairs,
  per-source result/selection storage and connection-time subscription refresh.
  Removed or unavailable selections fail closed. There is no implicit WARP or
  plain fallback and no WARP enrollment for a server connection.
- Typed `openServer`, checksum-pinned engines in the app bundle, production
  guardian and physical-interface-bound outer relay. Backend HTTPS and actual
  strategy application must succeed before the native frontend starts.
- Daemon-owned Go utun plus gVisor IP-to-SOCKS bridge, IPv4/IPv6 TCP/UDP/DNS,
  foreign-VPN guards and owned route/DNS lifecycle. Native connection code checks
  its measurement route before and after post-TUN HTTPS. The actual system path
  remains untested under the user's VPN restriction.
- XHTTP import/contracts/compiler for all four modes, exact-h3 UDP selection,
  bounded extra and a mandatory-relay download leg. Typed ECH, certificate
  names/pins and Reality options are included. Real ECH and Reality-XHTTP traffic
  evidence remains pending. Unknown/unsafe extra fields are refused.
- Product leases now renew both the engine and independent recovery watchdog.
  Inspection found and removed the inherited two-minute recovery cap from the
  product path. Finite PoC paths retain their caps. Temporary product engine
  configuration is removed after authenticated readiness.
- Upstream engine licenses, full GPL text and source/release links accompany the
  bundled executables. No upstream runtime implementation was copied into the app.

Verification:

- 283 Swift tests PASS: `/tmp/zarp-final-swift.log`. New coverage includes
  source isolation, persisted choices, removed-server refusal, server mode without
  WARP enrollment, XHTTP validation and shared Swift/Go option fingerprints. The
  actual Swift IPC client refuses to send profiles to WARP-only daemons and
  preserves mode/source identity on open and adoption.
- Product runtime: twelve pinned-engine cases PASS with races in 18.637 seconds,
  plus the no-SNI/numeric-split guard: `/tmp/zarp-product-complete-runtime.log`.
  HTTPS and UDP passed for VLESS/Trojan/Hysteria2, XHTTP auto/packet-up/stream-up/
  stream-one, HTTP/3, extra and a separate download leg. Wrong credentials failed.
- The renewable VLESS path carried fresh HTTPS after 130 seconds, beyond the
  original PoC cap: `/tmp/zarp-product-final-runtime.log`. That first aggregate
  run failed only its custom-padding fixture because the server still required
  default padding. Context7 confirmed server-side range validation. Matching the
  private fixture's range to its advertised profile fixed that case; the final
  twelve-case run passed. The failed aggregate is not claimed as a pass.
- All Go packages PASS with races: `/tmp/zarp-product-final-go.log`, including
  proxy ownership/recovery in 169.663 seconds after the watchdog extension.
  Changed daemon/route/bridge/contracts/IPC/SOCKS checks also passed separately:
  `/tmp/zarp-server-checks-go.log`. `go vet ./...` PASS:
  `/tmp/zarp-server-vet.log`.
- One earlier real HTTPS-subscription fixture missed its metadata startup deadline
  under concurrent builds. It passed unchanged on an isolated retry, then the
  complete Swift runs passed, ending with 283 tests. No manual test was requested or changed.
- WARP+ account API and lifecycle fakes passed. No paid key or external account API
  was used during verification. No GUI, installed daemon, real TUN, active VPN,
  routes, DNS, proxy, firewall or network services were changed autonomously.
- Release app build PASS: `/tmp/zarp-product-final-build.log`. Artifact:
  `build/ParityDerivedData/Build/Products/Release/Zarp.app`. Exact upstream engine
  hashes, the daemon's embedded guardian identity, bundled notices, notice
  regeneration check and `git diff --check` PASS. The app was not installed or launched.

The old external-engine system-adapter FAIL remains unpassed. It is separate from
the new daemon-owned native frontend. Full parity is not marked complete: native
acceptance, release signing acceptance, routing/Geo/per-app policies, broader raw
packet strategies and WireGuard remain outstanding. No repeat manual run is
requested here, and independent implementation was not held behind the old test.

## DMG packaging: 2026-10-20

- Built the user-requested local installer with `scripts/package.sh --skip-tests`.
  The current source already passed 283 Swift tests, the complete Go race suite
  and vet. Rechecked notices before a clean signed Release build. No application
  code, version, account data or service configuration changed for packaging.
- Artifact: `build/Zarp-0.2.0-arm64.dmg`, 51,391,034 bytes, Apple Silicon.
  SHA-256: `f0ad04959ad58a78bf618d96d3251079cbe9efe7013c1ea34353389856c31f38`.
  Companion file: `build/Zarp-0.2.0-arm64.dmg.sha256`.
- Image checksum, read-only mounted app signature and installer layout checks
  passed. App, daemon and guardian share the configured Apple Development team.
  Verified both bundled engine pins, the daemon's embedded signed guardian hash
  and bundled license texts. The existing unnotarized signing policy is unchanged.
- Preserved the previous image and checksum under
  `build/previous-dmgs/20261020T060034Z`. Packaging logs:
  `/tmp/zarp-dmg-package.log`, `build/xcodebuild.log`, `build/dmgbuild.log`.
- No app launch, installation, daemon/service operation, real TUN, VPN, routes or
  DNS changes were performed. System runtime acceptance remains unverified.

## User clarification: 2026-10-20

The primary product is a WARP/server tunnel wrapped with an additional zapret
strategy. Happ is the user's reference for subscription management and server
selection. Subscription import and selection must feed strategy/server pairs;
the next priority is integrating those pairs and the outer relay into the app's
connection lifecycle. A saved server list alone does not complete this workflow.
These requirements and the VPN/test constraints are persisted in [AGENTS.md](../AGENTS.md).

The user states that XHTTP works. Existing pinned Xray stream-one H2/H3 loopback
evidence is retained. The continuation above adds shared imports, typed options
and the app/daemon server lifecycle. It does not turn the failed system-adapter
result into a pass.

## Stage status

Latest user system-adapter run `zarp-parity-adapter-covd51sy`: FAIL, cleanup PASS,
1.63 seconds, `startup`, reason "private TUN engine exited during startup".
The supplied version 1 RESULT reports live_test_started=true, matching network
baseline afterward, zero traffic checks and no default-route/system-DNS
configuration. Its root-owned matching report has not been independently read.
This run entered live startup but does not establish a working interface, route
or traffic. Engine stderr and guardian errors were discarded, so the exact cause
cannot be recovered from this RESULT. Stale socket removal is no longer a
requested prerequisite. This remains an unpassed TUN/process gate.
Added bounded nonblocking stderr capture, fixed diagnostic markers, guardian
phase/exit facts and a second allowlist at the RESULT boundary. No raw messages
or private paths are reported. Fourteen safe tests pass, including startup
failure reporting and unchanged cleanup. The corrected direct-route matcher
remains intact. Native startup, route ownership and all six selected/excluded
traffic cases remain unverified. No further manual run is requested in this
continuation. System acceptance remains pending while the separate product
implementation proceeds. No service, socket, VPN or system-network modification
was performed.

Continuation: connected the existing server and subscription models to a real
Settings screen. Import, Save, Refresh, Cancel, Delete and per-source server
selection now use restricted persistent storage through `ConnectionLibrary`.
Opening the screen or saving a URL makes no HTTP request. An explicit Refresh uses
the current system connection and retains the previous cache after a failed fetch.
The latest continuation also connects this library to source selection and the
server runtime; the screen now explains the source/pair workflow.

| Stage | Tasks | Status | Gate / next action |
|---|---|---|---|
| 0 | Baseline | verified | Reviewed test entrypoints; safe baseline passed |
| 1 | T01-T03 | awaiting_user_test | Implementation and safe checks complete; live WARP/TUN gates pending |
| 2 | T04-T05 | in_progress | Product compiler/guardian/relay/IPC/frontend implemented; native and signed-release acceptance pending |
| 3 | T06 | implemented_local_checks | Pair construction, source identity, real traffic/strategy checks and UI connection path implemented |
| 4 | T07-T08 | in_progress | T07 integrated with connection lifecycle; XHTTP modes/extra implemented; advanced/native evidence pending |
| 5 | T09-T10 | planned | Requires verified policy backend |
| 6 | T11-T13 | planned | Requires process PoC, policies, WARP L4 adapter |
| 7 | Finish T14-T15 | planned | UI/tests evolve in each stage; manual checks remain separate |
| 8 | T16 | planned | Separate packet and WireGuard research |

## Task status

| Task | Status | Changes / next safe operation |
|---|---|---|
| T01 | implemented | Portable catalog, country union, fourth column, all-action filtering, and eight-language UI; safe checks passed |
| T02 | awaiting_user_test | Confirmation, identity, migration, cancellation and endpoint reuse checked with scripted providers; live checks pending |
| T03 | awaiting_user_test | Numeric list, rotation/pinning, protocol 3, IPv6 control and owned exclusions implemented; live checks pending |
| T04 | in_progress | Product backend/outer relay and renewable ownership implemented; real private traffic checked; signed-release and system acceptance pending |
| T05 | in_progress | Typed server-open IPC, source UI, bundled engines and native frontend implemented; actual product TUN acceptance pending |
| T06 | implemented_local_checks | Strategy-major compatible pairs, source-scoped state, two attempts and actual traffic/application checks |
| T07 | implemented_local_checks | Private source/cache UI, main source selection, twelve-hour connection-time refresh and offline retention |
| T08 | in_progress | Shared imports, all XHTTP modes, extra/download and typed ECH/verification options implemented; advanced/native evidence pending |
| Windows 1.6 WARP+ | implemented_local_checks | Secure key input, own-account API, public status and connection-preserving lifecycle; paid license not used |
| T09 | planned | Rule priority and DNS path |
| T10 | planned | Geo conversion and bounded atomic downloads |
| T11 | planned | Executable/helper matching and per-app policy |
| T12 | planned | MASQUE L4 adapter and policy frontend |
| T13 | planned | DNS/IPv6 policy and resilience |
| T14 | in_progress | Country/endpoints and server/subscription screens in eight languages compiled; visual UI QA pending |
| T15 | in_progress | Baseline and Stage 1 safe suites, loopback pin failures, unsigned app and private manual binary built; later engine/package checks pending |
| T16 | planned | Controlled packet and independent WG PoCs |

## Continuation after the failed system-adapter run

- Reviewed the current GUI, typed contracts, private stores, subscription downloader/repository, backend plan/supervisor and system-adapter startup path. The supplied failure contains no engine cause; reading its root-owned report would require a password. No additional user action was requested.
- Added `ConnectionLibrary` to coordinate manual imports, source metadata, cached subscription lists and per-source server selection. Configuration operations have no daemon or connection-provider reference.
- Added Settings > Servers and subscriptions with Import, Save, Refresh, Cancel, Delete, saved-selection markers, missing-selection warnings and last-update dates. Forty new messages are translated into all eight languages. Subscription URLs are masked and excluded from source titles and errors.
- Opening the screen and saving URLs do not fetch. Only Refresh requests HTTPS through the current system connection. Failed updates keep the previous list; a damaged cache is preserved and reported without blocking other sources. Removing a selected server keeps an unavailable selection rather than choosing another server.
- Production server activation remains incomplete. The screen states this, and the main connection button still uses WARP. This continuation does not pass the TUN/process gate or claim complete feature parity.
- Swift package: PASS, 268 tests, zero failures, including five new storage/refresh integration cases. Log: `/tmp/zarp-parity-continued-swift.log`. Fakes, temporary storage and existing loopback fixtures only.
- Unsigned Release app build: PASS. Log: `/tmp/zarp-parity-continued-app-build.log`. Artifact: `build/ParityDerivedData/Build/Products/Release/Zarp.app`. Not launched or installed. No new Go behavior was introduced in this continuation.
- Documentation links and whitespace checks pass. No new live/manual runner was added or requested. References, the historical parity snapshot, production settings, services, VPN, routes and DNS were not changed.
- Next implementation scope: connect typed server requests, owned backend sessions and strategy/server pair selection to production IPC and the engine. Keep native TUN verification as a separate release/activation check; continue independent implementation without repeatedly requesting the same manual run.

## Stage 0 checks

- Read implementation prompt, parity analysis, snapshot, README, architecture, development guide, changelog, and relevant Swift/Go sources/tests.
- Reviewed `Makefile`, `Package.swift`, test sources and `scripts/test-integration.sh`. Ordinary suites have no environment-enabled live cases. The integration script is live even with `--no-tunnel` and is excluded from autonomous execution.
- Swift: `env -u ZARP_SOCKET -u SWIFTPM_BUILD_DIR CLANG_MODULE_CACHE_PATH=/tmp/zarp-parity-clang-cache swift test --package-path Packages/ZarpCore`: PASS, 175 tests, 0 failures. Log: `/tmp/zarp-parity-baseline-swift.log`.
- Go (from `zarpd`): `env GOTOOLCHAIN=local GOCACHE=/tmp/zarp-parity-go-cache go vet ./...` and `env GOTOOLCHAIN=local GOCACHE=/tmp/zarp-parity-go-cache go test -race -count=1 ./...`: PASS, six tested packages. Log: `/tmp/zarp-parity-baseline-go.log`.
- `python3 scripts/check-docs.py`: PASS, 15 Markdown files at baseline.
- Initial sandbox runs denied Swift manifest sandbox/cache access and local socket binding. Reviewed suites passed outside that sandbox. These were environment restrictions, not baseline regressions.
- Context7 consulted for SwiftPM test invocation and Go test/cache semantics. No production app or daemon was started.
- No manual network checks have been run or passed during this implementation.

## Decisions

- Preserve SwiftUI, ZarpCore, ZarpdIPC, and zarpd boundaries and MIT implementation provenance.
- Country tags describe catalog applicability, not proof of ISP effectiveness.
- Two successful connections and two different actual endpoints are separate properties. Isolation tokens alone never prove independence.
- Legacy custom selection can migrate only to a unique match. Legacy custom results without configuration evidence cannot certify current arguments.

## Stage 1 changes

- T01: 16 portable primary profiles, including `warp-q-google11`, `warp-q-google12`, and TLS `split-host`, `split-sld`, `split-endhost`. Nine historical unsupported profiles moved out of the primary catalog and retained in `StrategyCatalog.unavailable`. Unsupported custom profiles still fail explicitly before opening a socket.
- Country union: Google/TLS tags cover RU/IR/CN; VK profiles cover RU only. All includes untagged and direct controls. Selecting countries excludes those controls. Filters affect the table, saved Connect, auto-connect through Connect, selected tests/Use, scans, confirmations, fallback and reconnect eligibility. Hidden country history is retained.
- Custom files: three or four columns, BOM/CRLF support, unchanged executable arguments. SHA-256 IDs bind length-delimited name/transport/arguments; countries do not affect identity. Unique legacy selection migrates. Legacy custom results without argument evidence are discarded for retesting; ambiguous names do not migrate.
- T02: inline double checks continue Quick Scan until N confirmations or exhaustion. Selected tests only apply their tested subset. Cancel during a recheck preserves the prior completed result. Missing or repeated actual endpoint evidence never earns independent status. Scores reject invalid latencies before arithmetic.
- T03: up to 64 public numeric IPv4/IPv6 address-port pairs, comments, canonical deduplication, Save/Reset, a single-endpoint indicator, rotation and confirmed endpoint pinning. Empty restores the default pool. Changed lists invalidate prior results. Invalid stored lists refuse an operation instead of silently using defaults. Saved custom successes must belong to their bound list.
- IPC protocol 3 adds `endpointPolicy=customWarp`. Legacy requests retain WARP-range and transport-port restrictions. Custom requests reject local/private/scoped/multicast destinations, hostnames and invalid ports. Custom opens require a protocol 3 daemon. All opens retain the enrolled WARP TLS pin.
- IPv6: explicit udp6/tcp6, IPV6_BOUND_IF, independent IPv6 fake hop limits and restoration, family-specific default lookup, scoped IPv6 gateway preservation and IPv6 host exclusions. TUN traffic IPv6 support alone is not counted as proof of this control path.
- Foreign VPN guards strengthened: no missing/accepting GUI hook bypass, no daemon scan permission through a tunnel default route. Exclusion cleanup checks exact destination, host flag, interface and gateway before deleting. Borrowed/replaced routes are preserved.
- UI: country multi-selection, endpoint list Save/Reset and validation, single-endpoint limitation, separate confirmation/independence tooltip. New and revised product strings translated into all eight supported languages. GUI not launched because startup could read production settings and auto-connect.

Affected source groups:

- `Packages/ZarpCore/Sources/ZarpCore/{Strategy,Engine,Results,Settings,Support}` and matching tests.
- `Packages/ZarpCore/Sources/ZarpdIPC/ZarpdClient.swift` and fake IPC tests.
- `App/Sources/Zarp/AppViewModel.swift`, `Screens/StrategiesView.swift`, `Screens/SettingsView.swift`, `Resources/Lang/*.txt`.
- `zarpd/{ipc,daemon,warp,route}` and fake/loopback tests.
- `scripts/test-parity-manual.sh`, `scripts/parity_manual.py`, README, architecture, development guide and changelog.

### Decisions and versions

- Keep existing Go dependency pins unchanged: Go 1.27.1, usque `v1.5.1-0.20260720063354-6aa03fc97d12`, quic-go `v0.60.0`, x/net `v0.56.0`, x/sys `v0.48.0`. A compatibility engine has been pinned for the Stage 2 loopback PoC below; no external proxy engine is bundled.
- Use system CryptoKit SHA-256 without a new third-party dependency. Package tests target macOS, including the existing Darwin-only IPC tests; the prior Foundation-only Linux description no longer applies.
- Custom endpoints use public numeric addresses and ports 1-65535 through a distinct pinned-WARP contract, not a general server or shell-execution mode.
- List order is part of the endpoint-list fingerprint. Country tags are not part of either fingerprint.
- Existing built-in legacy results migrate only because their retained arguments are unchanged. Historical unsupported results are removed. Custom name-only evidence is insufficient for confirmation.
- Current pinned usque sets `DefaultEndpointH2V6` to empty. IPv6 H2 sockets and key-pin rejection passed loopback tests. Live H2-over-IPv6 requires an actual H2-capable public endpoint; no guessed default is claimed to work.
- Separate confirmed, independent and endpoint-reused metadata. Finite pools and one custom address are normal cases, not automatic failures or evidence of independence.

### Checks actually passed

- Final Swift suite: `env -u ZARP_SOCKET -u SWIFTPM_BUILD_DIR CLANG_MODULE_CACHE_PATH=/tmp/zarp-parity-clang-cache swift test --package-path Packages/ZarpCore`: PASS, 194 tests, 0 failures. Log: `/tmp/zarp-parity-stage1-swift.log`.
- Go: `env GOTOOLCHAIN=local GOCACHE=/tmp/zarp-parity-go-cache go vet ./...` and `env GOTOOLCHAIN=local GOCACHE=/tmp/zarp-parity-go-cache go test -race -count=1 ./...` from `zarpd`: PASS, six tested packages. Log: `/tmp/zarp-parity-stage1-go.log`. After the last family-selection change, route race tests and Go vet passed again: `/tmp/zarp-parity-route.log`.
- Actual IPv4/IPv6 loopback TLS with unrelated peer keys: enrolled WARP pin rejects both and closes sockets. IPv6 UDP fakes use the requested hop limit and restore the socket setting. Log: `/tmp/zarp-parity-loopback.log`.
- Scripted Swift cases: failed Quick Scan rechecks followed by later successes; country-filtered saved selection/fallback; selected-subset isolation; finite/repeated H2 addresses despite unique tokens; single custom address; IPv4/IPv6 list rotation/pinning; restart cache validation; argument/tag identity; ambiguous legacy selection; interrupted recheck preservation; malformed latencies and stored endpoints.
- Fake route cases: IPv6 gateway zones/family flags, exact exclusion ownership, external interface/gateway replacement preservation, journal recovery and existing rollback suite.
- `xcodegen generate`, then `env GOCACHE=/tmp/zarp-parity-go-cache CLANG_MODULE_CACHE_PATH=/tmp/zarp-parity-clang-cache xcodebuild -project Zarp.xcodeproj -scheme Zarp -configuration Release -destination 'platform=macOS,arch=arm64' -derivedDataPath build/ParityDerivedData CODE_SIGN_IDENTITY=- CODE_SIGNING_ALLOWED=NO build`: PASS. Log: `/tmp/zarp-parity-build.log`. Artifact: `build/ParityDerivedData/Build/Products/Release/Zarp.app`. Not launched or installed.
- Private manual binary built with `env GOTOOLCHAIN=local GOCACHE=/tmp/zarp-parity-go-cache go build -trimpath -ldflags '-X main.version=parity-manual-v1' -o ../build/parity-manual/zarpd ./cmd/zarpd` from `zarpd`: PASS. SHA-256: `472c34c1fb8c99c69cc0f10e83c9f1843d52d8fe4a1b1fbda34273131eb37fb0`.
- Manual runner: `bash -n scripts/test-parity-manual.sh`, Python AST syntax check, `scripts/test-parity-manual.sh --help`, and `scripts/test-parity-manual.sh --self-test`: PASS. Self-test uses pure guards plus a temporary fake IPC peer. Live branches were not invoked.
- `python3 scripts/check-docs.py`: PASS, 16 Markdown files. `git diff --check`: PASS. Added/changed lines and new implementation files checked for U+2013/U+2014: none. Historical documents remain unchanged.
- Reviewed suites requiring local socket permission ran outside the tool sandbox. No real VPN, routes, DNS, daemon registration, GUI startup, or installation was used for autonomous verification.

### Pending user checks and exact commands

Runner: [test-parity-manual.sh](../scripts/test-parity-manual.sh). Supervisor: [parity_manual.py](../scripts/parity_manual.py).

Each live scenario needs sudo and a real system utun. It creates a separate temporary daemon binary,
new test WARP account, private socket/logs/journal/report, and a measurement host route. `--full-tunnel`
also temporarily creates IPv4/IPv6 /1 routes where available and an endpoint exclusion. DNS is never
overridden. Conflicts with foreign VPNs or active/uncertain production Zarp refuse the run. It never
disconnects a VPN. The supervisor watches external changes, verifies child ownership before stopping,
handles signals, and reserves cleanup time within a 600-second worker budget. Build has a separate
180-second limit; sudo authorization time is outside those limits. Only its owned route journal can be
recovered after its own child is killed. Original system configuration is not restored over external changes.

Run from `/Users/andrumoskow/Documents/Zarp-MacOS`, when the user chooses:

```sh
scripts/test-parity-manual.sh --scenario warp-h3 --full-tunnel --accept-warp-terms
scripts/test-parity-manual.sh --scenario warp-h2 --full-tunnel --accept-warp-terms
scripts/test-parity-manual.sh --scenario warp-account-ipv6 --full-tunnel --accept-warp-terms
```

The third scenario uses the new isolated test account's IPv6 endpoint, not production credentials.
Optional live IPv6 H2: `scripts/test-parity-manual.sh --scenario warp-custom --transport h2 --endpoint '[PUBLIC_H2_IPV6]:443' --full-tunnel --accept-warp-terms`, after a real public H2-capable IPv6 endpoint is available. The placeholder is not an execution-ready address and is not asserted to work.

Report schema: version 1, IPC protocol 3, unique run ID, source SHA, source digest, binary checksum,
scenario, control family, PASS/FAIL/SKIP, duration and cleanup. No credential UUIDs/keys/tokens or secret
URIs are printed. The test account material is deleted at cleanup. Private raw logs/baselines are retained
for local diagnosis; only the sanitized RESULT/report should be shared.

Prepared supervisor/source digest: `a7628e7986b6369e8b2fe605566e2e9d5c8a5a77ffe0e46df4ae40f75352bdf8`.
The user supplied three preflight SKIP results, recorded below. None of these live checks is passed. Real ISP effectiveness, live IPv6
control, actual route cleanup, and UI visual QA remain unverified. A failed strategy on an ISP is not
by itself proof of an implementation regression; inspect scenario coverage and cleanup first.

## User preflight results and diagnostic repair

- Received schema version 1 results for `warp-h3`, `warp-h2`, and `warp-account-ipv6`: each `run_id=not-started`, `status=SKIP`, `cleanup=PASS`, duration 0.02-0.03 seconds. They exited before build, sudo, account registration, daemon startup or TUN. This is not a pass of any live scenario.
- The user reports that the VPN was closed during those runs. The old generic error text did not distinguish an actual tunnel conflict from an observation failure, so the past blocker cannot be determined from these reports.
- A separate current read-only observation shows default interface `utun4` and one connected VPN service. This only describes the later observation, not the user's earlier execution state. No network state was changed.
- Fixed `scripts/parity_manual.py`: typed, sanitized preflight reason codes distinguish tunnel routes, connected VPN services, uncertain/active production Zarp, missing production socket, missing default route, unavailable/failed/timed-out observation commands and unexpected internal errors.
- Added `--preflight`: read-only diagnostic mode, no scenario or terms needed, no build/sudo/daemon/TUN. It prints `phase=preflight` and `live_test_started=false`; a preflight PASS is never a live test PASS. Conflict details contain only interface/flag/category/count metadata, not IP addresses, UUIDs, keys, tokens, command responses or service names.
- Foreign VPN guard behavior is preserved, including conservative refusal of scoped/default and residual non-link-local tunnel routes. No bypass/force flag was added. Additional classification needs the user's diagnostic evidence rather than assuming the earlier VPN state.
- Verification: shell and Python syntax, `--help`, and expanded `--self-test` PASS. Added mocked diagnostic CLI cases assert no subprocess startup, build or elevation. Active/scoped/multicast tunnel and connected-service cases still refuse. Command-failure redaction retains tool/exit code while excluding raw private output. Temporary fake IPC still passes. No Swift/Go source changed in this repair, so those suites were not repeated.
- Ran `--preflight` autonomously only in its read-only mode: SKIP with exact `foreign_tunnel_routes` metadata, expected for the later observed active session. No live scenario was executed. Initial sandbox observations denied route socket access and DNS observation; separate read-only observation outside that sandbox succeeded. These restrictions are distinct from the user's console results.
- Updated supervisor/source digest: `5cbea8f39ea0893e3185f0743c2ce19169d4600516363f00e32eb8bb4412f9ec`. The Go daemon binary is unchanged by this repair.

Next user command, from the repository, in the state the user chooses for testing:

```sh
scripts/test-parity-manual.sh --preflight
```

Paste its sanitized RESULT. This command only reads system state and never modifies or disconnects a VPN.

## Continuation

Wait for the user's diagnostic RESULT before changing any guard interpretation or retrying live checks.
The three supplied SKIPs leave Stage 1 live gates pending. Independent T05 contracts and T04 loopback work can continue under the documented dependency graph. Do not request an in-chat active session;
the user runs terminal commands and sends console results. No autonomous live test or dependent stage
is authorized by a preflight PASS. Resume from the concrete blocker reported by the new diagnostic mode.

## Stage 2 independent implementation

- The user's `continue` resumes safe work. T04 explicitly permits designing T05 formats alongside its PoC. This does not pass the Stage 1 live gates or enable production server mode.
- Added typed draft `ConnectionMode`, `ServerProfile`, credentials, transport/security/flow, `ConnectionOptions`, `RuntimeCapabilities`, `ProbeKind`, and bounded versioned `ConnectionRequest`. Profile identity excludes labels and binds credentials and transport configuration. Unknown JSON keys, mismatched modes/probes, invalid literals and unsupported combinations fail with field-only diagnostics. Current runtime capabilities still advertise WARP only. Production IPC remains v3 and its separate WARP validation is unchanged. Imports, migration and server IPC wiring are pending.
- Swift verification: 206 tests PASS, including 12 new contract tests. Logs: `/tmp/zarp-parity-contract-tests.log`, `/tmp/zarp-parity-contract-build.log`. Unsigned app build PASS: `/tmp/zarp-parity-contract-app-build.log`. No GUI launched.
- PoC pin: sing-box 1.13.14, revision `25a600db24f7680ad9806ce5427bd0ab8afe1114`, matching reference configurations. GitHub reports 1.14.3 as latest stable on this working date; 1.13.14 is a compatibility PoC choice, not claimed current latest. Archive SHA-256 `73e8967b0fc08e17bce4263ca56ebc394822401a16497a1c4e02316c888202ab`; Darwin arm64 binary SHA-256 `813d8effd02a19572a8d75aef29fc073101404ca535b2496be86f21827c7684d`. Kept under ignored `build/parity-backends`; not bundled or distributed.
- Licensing: upstream sing-box is GPL3 or later with an additional derivative naming/association clause. No GPL implementation was copied into the MIT core. Separate processes do not alone establish absence of distribution obligations. Source/notices, signing and packaging remain required before distribution. Official Xray stable endpoint reports 26.3.27, while reference candidates 26.7.28 and 26.9.30 are marked prerelease; no Xray production selection is claimed yet.
- Added a bounded loopback-only authenticated SOCKS5 TCP transport relay, fixed numeric target, bounded ClientHello parsing across reads/records, mapped outer SNI offset, ALPN inspection and three stream writes. No root handler, TUN, routes, system DNS or physical-interface binding exists in this package.
- Actual checksum-pinned external VLESS and Trojan each carried two fresh HTTPS transfers through the outer detour. Dedicated TLS trust verified the server; inner HTTPS trust remained enabled. Split observations matched outer SNI `outer.example.test` and ALPN `http/1.1`. These are stream-write counters, not proof of exact kernel packet boundaries or ISP effectiveness.
- Pure/loopback Go race tests passed: real TLS ClientHello fragmented across records/one-byte reads, unchanged original wire bytes/SNI mapping, malformed records, wrong relay authentication, fixed-target rejection and cancellation before handshake. Explicit external PoC log: `/tmp/zarp-parity-backend-loopback.log`. Ordinary suites skip external execution unless its checksum-pinned binary is supplied explicitly.
- Remaining Stage 2 gates: Xray detour/XHTTP H3, external backend IPv6, packet capture/production techniques, production supervisor and typed IPC, user-run TUN/DNS/routes/process matching. Server runtime/UI is not enabled.

### Stage 2 transport verification follow-up

- VLESS, Trojan and Hysteria2 now carry actual HTTPS and UDP echo payloads through the external detour. Each backend accepts its generated public-key pin and rejects an incorrect pin and incorrect protocol credential before a real HTTPS response. The first negative-pin attempt combined certificate trust and pins, which the pinned engine correctly rejected at configuration check; corrected tests use mutually exclusive TLS options and now verify actual peer-pin rejection. Final explicit external race suite PASS, including 13 backend cases.
- Session credentials are generated per case. The server route permits only the private HTTPS/UDP marker ports on loopback and rejects other destinations. Private engine configs/certificates/keys have restricted permissions. No arbitrary server request can become a general test outbound.
- Added authenticated loopback SOCKS5 UDP associations with session-fixed numeric destinations, bounded lifetime/concurrency and owned cancellation. An independent IPv4/IPv6 UDP receiver proved fake-first ordering and identical outer source tuple, no repeated fake in one association, reverse payloads, malformed/wrong-target rejection and teardown. The fake is invalid PoC data, not a completed production desync strategy.
- Hysteria2 fresh-session cases complete TLS-protected QUIC with h3 and real traffic; application requests can reuse the QUIC session and are not counted as separate outer handshakes. TCP observers still inspect actual outer SNI/ALPN per new outer flow.
- Reproducible runner: [test-parity-backend-loopback.py](../scripts/test-parity-backend-loopback.py), with optional verified official HTTPS download, pinned executable checksum, cleared Go environment flags, restricted temporary storage, isolated child group, signal/watchdog cleanup and sanitized RESULT. It uses no sudo, TUN or system configuration. Actual runner RESULT: PASS, cleanup PASS, 3.42 seconds, system_network_changed=false. Log: `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-a1b20wq0.log`. Separate owned process-group termination check PASS.
- Architecture, reproduction, source/license links, evidence and outstanding gates: [BACKEND_PARITY_POC.md](BACKEND_PARITY_POC.md).
- Stage 1 preflight diagnostic remains requested from the user; no new RESULT has been supplied and no live WARP gate has passed. Continue from that result before interpreting or changing guards. Independent next Stage 2 work is Xray/IPv6 and production transport/supervisor contracts.

### Final safe checks for this unit

- Go vet and ordinary race suite PASS across seven tested packages, with external backend opt-in cleared. Log: `/tmp/zarp-parity-stage2-go.log`.
- Explicit pinned-engine relay race suite and bounded runner PASS. No autonomous live integration entrypoint was used.
- Python runner syntax/help and isolated owned-child termination PASS. Documentation links PASS across 17 Markdown files; `git diff --check` PASS; changed/new implementation text has no U+2013/U+2014.

## Received expanded user preflight result

- User supplied read-only preflight SKIP, cleanup PASS, live_test_started=false, duration 0.03 seconds. IPv4 default interface is `en0`; connected VPN services count is zero. Sixteen routes were classified as conflicts. The report showed only the first eight, all scoped defaults with `UGcIg` on `utun0/1/2/3/7/8/10/11`. The remaining eight routes and effective IPv6 path were not included, so this is not sufficient evidence to declare an active global VPN or a safe live-test state.
- Apple's XNU [route flag definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/route.h) distinguish interface scope from global routing. No interface owner or prior network state is inferred from these flags. Foreign-VPN guards are preserved; no route or interface was removed, ignored or changed.
- Expanded the existing `--preflight` report to include up to 32 route entries, truncation status, category totals, address family and gateway category without raw addresses. It additionally performs two read-only numeric RTM_GET route lookups to show effective IPv4/IPv6 interfaces. No traffic, DNS resolution, sudo, build, daemon startup or network mutation is involved. Lookup failures are explicitly unknown, not assumed to mean IPv6 is safely disabled. Live preflight/monitor guards remain unchanged.
- Safe verification PASS: Python AST syntax, shell syntax, `--self-test` including a 16-entry scoped-default/multicast fixture, preserved blocking, complete category reporting, redaction, exact numeric read-only lookup commands, failed IPv6 lookup behavior, effective scoped tunnel metadata, mocked CLI no-build/no-sudo assertions and temporary fake IPC. No live scenario or autonomous system observation was run in this unit.
- Next command remains `scripts/test-parity-manual.sh --preflight`, now with the additional metadata. User runs it in their chosen state and pastes RESULT. Stage 1 live checks remain pending; do not alter route classification without this evidence.

## Second detailed preflight result and stderr repair

- User result: preflight SKIP, cleanup PASS, live_test_started=false, 16 entries with no truncation. All are IPv6: eight interface-scoped defaults and eight interface-scoped multicast entries, each with a link-local gateway. No foreign unicast/split routes were reported. Connected VPN services count is zero; effective IPv4 route uses `en0`. IPv6 was reported as `route_interface_unknown`. These entries do not identify an active global VPN, but tunnel ownership remains unverified and no live scenario passed.
- Found a specific observer bug by a separate read-only reproduction: Darwin's numeric IPv6 route GET returned status zero, empty stdout and `not in table` on stderr. This observation describes the reproduction, not proof of the user's earlier IPv6 state. The command helper discarded successful-command stderr. Fixed route GET handling to report `route_not_found` or an unknown sanitized route diagnostic, using a stable C locale. No route to one destination is not treated as proof that every IPv6/per-app tunnel is disabled.
- Expanded pure regression cases cover status-zero missing-route stderr, unknown stderr redaction, correct no_route/unknown distinctions and locale stability. Manual runner `--self-test`, shell/Python syntax and punctuation checks PASS. Live guard behavior remains unchanged under the user's no-weakening constraint; no route/interface is ignored or removed to obtain PASS. Repeating preflight alone is not required to confirm the existing scoped-route blocker.
- Continued independent Stage 2 verification: external pinned VLESS, Trojan and Hysteria2 now run against both IPv4 and IPv6 loopback outer servers, with real HTTPS and UDP payloads, correct-pin acceptance, incorrect-pin/credential rejection, observed outer technique and cleanup. The bounded runner passed all 25 external backend cases plus parser/relay cases: RESULT PASS, cleanup PASS, duration 5.89 seconds, system_network_changed=false. Log: `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-_yls1j5m.log`. No production app, daemon, VPN, TUN, DNS or active routes were changed.
- Stage 1 live gates remain pending. Stage 2 external-engine loopback IPv6 gate is now verified; real TUN/process matching, production supervisor, Xray and imports remain pending.

## Latest paired preflight reports and proposed criterion

- Read the user's attached report: default/effective IPv4 `utun4`, one connected VPN service, 39 conflicting routes with unicast entries, explicit IPv6 route_not_found. This is an active-VPN preflight SKIP, cleanup PASS, live_test_started=false. The interrupted turn made no code or system changes after reading the attachment.
- Latest terminal report after the user says they stopped the VPN client: default/effective IPv4 `en0`, zero connected services, IPv6 route_not_found, 16 scoped IPv6 default/multicast entries, preflight SKIP, cleanup PASS, live_test_started=false, 0.04 seconds. This confirms that the original guard still blocks this scoped-only state. It does not establish individual interface owners.
- Prepared read-only interface observations and a narrow self-gateway/link-local-only candidate classifier. It requires independent effective-route evidence and rejects addressed interfaces, mismatching gateways, global/unique-local addresses, unfamiliar route flags and unknown observations. No candidate bypasses the current live guard. Reports expose only candidate counts and sanitized interface/address-category metadata. Raw address data remains private.
- Source review found that Apple creates scoped multicast interface routes, while scoped defaults can participate in policy decisions. This is insufficient to certify every scoped-default owner inactive. Under the user's express no-weakening instruction, the proposed acceptance change remains unapplied pending explicit approval. Concrete criteria and limits: [PREFLIGHT_GUARD_PROPOSAL.md](PREFLIGHT_GUARD_PROPOSAL.md).
- Verification: manual runner self-test PASS with candidate-only assertions and active/unknown tunnel refusal regressions plus fake Unix IPC. The first tool approval timed out before executing the test; the permitted single retry succeeded. No approval rejection remains unresolved. No autonomous live scenario, route mutation, VPN termination or installation was run.
- Continuation: get a decision on the concrete test-guard proposal before changing the acceptance criterion. Stage 1 live gates remain pending. No new preflight rerun is requested merely to reproduce the already known blocker.

## Approved narrow manual preflight classification

- The user approved the proposed change, conditional on the assistant not disconnecting their VPN. This authorizes only the concrete narrow manual-runner criterion from [PREFLIGHT_GUARD_PROPOSAL.md](PREFLIGHT_GUARD_PROPOSAL.md). It does not authorize an autonomous live TUN scenario or changes to production VPN/route/DNS state.
- Applied the exact self-gateway/link-local-only route classification in `guard_network`, with fresh interface/effective-route observations on each snapshot. The original route table remains intact for baseline/cleanup comparisons; nothing is removed from the system. Unknown or nonmatching observations keep blocking. Connected VPN services and production Zarp checks remain unchanged. The application and daemon guards are unchanged.
- Live-command preflight now includes sanitized interface profiles and candidate counts so a remaining SKIP can be diagnosed without discarding the new evidence. A successful preflight is still not a live-test PASS. No assumption is made that the user's actual gateways match their own interface addresses.
- Verification PASS: pure guard fixtures, mocked CLI no-startup/no-sudo cases, exact metadata acceptance, active services/tunnels and global/unique-local/malformed address refusal, missing profiles/unknown IPv6 refusal, unicast/split-route refusal, own-interface full-tunnel handling, and active/uncertain/missing-socket production Zarp refusal. Temporary fake IPC, shell/Python syntax and documentation checks pass. Swift/Go sources were unchanged, so their already passed suites were not repeated.
- Prepared runner/source digest: `7c3098212d885528bfe62af3adbb24ea0364ffcc5ca5cc7ef3bd1de8cdc16718`. No current system observation or live test was run in this unit.
- Next user command: `scripts/test-parity-manual.sh --scenario warp-h3 --full-tunnel --accept-warp-terms`. The user chooses the network state and runs it in their own terminal. It rechecks all guards before sudo/startup and monitors external changes. Temporary owned TUN/account/socket/log/journal, measurement and /1 routes, endpoint exclusion; DNS unchanged. Worker budget 600 seconds, build 180 seconds, sudo authorization excluded. Wait for the sanitized RESULT before counting this gate passed or diagnosing the next failure.

## Scoped default gateway representation repair

- Received user-run `warp-h3 --full-tunnel` result: preflight SKIP, cleanup PASS, live_test_started=false, 0.05 seconds. Eight self-address multicast routes matched the narrow classification; eight scoped IPv6 defaults still conflicted. All eight observed interface profiles were link-local-only; physical default/effective IPv4 was `en0`, no connected services, IPv6 route_not_found. Nothing was started and no live gate passed.
- Separate read-only inspection identified the mismatch without exposing addresses: each remaining scoped default uses the exact bare `fe80::%utunN` form rather than an address assigned to the interface. This is a representation the initial implementation omitted. Interface address data stayed private.
- Corrected the approved narrow classifier to accept that exact marker only with a matching self-address scoped multicast route on the same link-local-only interface and all existing independent egress checks. Other link-local peers/prefixes, absent/mismatched multicast pairs, assigned IPv4/global/unique-local addresses, unknown observations, connected services and foreign effective routes still refuse. No fixed interface-name whitelist or generic scoped-route exception was added.
- Pure regressions PASS, including a full eight-interface/16-route fixture and a separate active `utun4` state. Marker cases require the paired route; incomplete/foreign/active/unknown variants refuse. Original routes remain unchanged in baseline comparisons. Temporary fake IPC and Python/shell syntax PASS. No Swift/Go source changed.
- A current read-only preflight after the repair correctly refused an active session: default/effective IPv4 `utun4`, one connected VPN service, 41 conflict entries, candidate count zero, cleanup PASS, live_test_started=false. This later observation does not reinterpret the user's earlier physical-network report. No daemon, TUN, VPN changes, route/DNS changes or live test were run autonomously.
- Runner/source digest: `25da63fb2dcfed0cc55f68edea0fc24ec4b0366f19ae85bc85835a1f5c9520ee`. Docs describe the exact marker condition. Stage 1 live gates still await user-run results.
- Next user command remains `scripts/test-parity-manual.sh --scenario warp-h3 --full-tunnel --accept-warp-terms`. The user chooses a suitable network state and runs it themselves. Worker 600 seconds, build 180 seconds excluding sudo authorization, isolated owned resources and routes, DNS unchanged. Wait for RESULT.

## Production status blocker after route classification

- User-run `warp-h3 --full-tunnel` now recognizes all 16 scoped entries as metadata under the approved narrow checks. Preflight still returns SKIP, cleanup PASS, live_test_started=false, 3.07 seconds, reason `production_status_unknown`. Effective IPv4 is `en0`, zero connected services and IPv6 route_not_found. No build, elevation, private account/daemon or TUN started. No live gate passed.
- Read-only local observation: `/var/run/zarpd.sock` is a regular root-owned Unix socket with mode 0660, not a symlink. Separate production `ping` and `status` queries each reached their three-second deadline without a response. No open/close/restart/register RPC was sent; no installed process or VPN was changed. This observation identifies nonresponse, not proof that production Zarp is idle.
- Improved IPC diagnostics: typed deadline/cancellation/peer-close/size-limit reasons and safe exception type/errno metadata for production status failures. Missing or nonboolean connected status can no longer be treated as idle. The uncertain-production guard remains fail-closed.
- Added `--production-status`, an isolated read-only diagnostic that sends only bounded ping/status queries, exposes only socket type/mode/root-owner, caller privilege, protocol number, connected boolean and sanitized error metadata. It never observes/modifies network configuration, builds, elevates itself, or starts/stops a daemon. A diagnostic PASS means replies received, not a live tunnel PASS. It may be run by the user with sudo to check the root-vs-normal caller distinction.
- Safe checks PASS: mocked diagnostic replies/timeouts/redaction, no spawn/build/elevation assertions, missing/malformed status refusal, CLI parsing/help, Python/shell syntax, existing guard fixtures and temporary fake IPC. A real temporary stalled Unix peer verifies the ipc_timeout code and bounded cleanup. Swift/Go source was unchanged, so broad suites were not repeated.
- Runner/source digest: `05d83a4db4d51bd046159ae269cdf2b239a2845b9642569872ac2afd8e461150`. No autonomous live scenario or sudo was run.
- Next user command: `sudo scripts/test-parity-manual.sh --production-status`. Six-second query budget, excluding sudo authentication. No temporary network resources or changes; the VPN may remain connected. Wait for sanitized RESULT before diagnosing root authorization versus an unresponsive installed service. Do not restart or bypass the production daemon guard.

## Root production diagnostic result and independent Xray work

- Received user-run `sudo --production-status` diagnostic: privileged_caller=true, ping/status both ipc_timeout, duration 6.01 seconds, root-owned regular socket mode 0660, SKIP, cleanup PASS, live_test_started=false. This rules out a simple normal-user permissions explanation. It does not establish that installed Zarp is idle. No production service restart or guard bypass is authorized. Stage 1 live checks remain blocked and pending.
- Continued safe independent T04 work. Official release metadata identifies Xray 26.9.30 as a prerelease dated 2026-09-30. Darwin arm64 archive SHA-256 `4b363bd924df5bf09f87bd445755ff8e5742b9a8a0480cda261061416c3c7dce`; binary SHA-256 `118d6c6c8c2fb913c4b2aeb056a58936016b36813c38d9b75653311787c0f93c`. Binary version reports revision `b26a91d`, Go 1.27.1, darwin/arm64. Stored in ignored build/parity-backends, never installed/bundled. Upstream license MPL2; distribution notices/source requirements remain to be handled. No upstream implementation was copied into the MIT core.
- Context7 Xray/core and official docs consulted; moving docs were checked against pinned 26.9.30 source. Verified outer sockopt.dialerProxy behavior, the pinned certificate DER hash field, SOCKS authentication and exact XHTTP H3 selection.
- Implemented external-engine tests for VLESS raw TLS, XHTTP H2 and XHTTP H3, each with IPv4/IPv6 loopback outer server, real HTTPS and UDP echo payloads, valid pin, incorrect pin and incorrect credential. All 18 cases PASS. Negative cases must reach the outer relay before rejection. Raw TCP new flows, including the flow carrying UDP, receive outer TLS split writes. XHTTP pooled requests are not counted as fresh outer connections. H3 uses the authenticated UDP association and fake-first socket path.
- The first valid transfers stalled because the pinned Xray freedom outbound blocks private destinations by default for VLESS inbounds. Fixed isolated test configs with exact IP/port allow rules for their two loopback markers, followed by Block; server routing also denies other destinations. Config syntax is checked by the pinned engine. Dedicated leaf certificate pins remain verified; no allowInsecure flag was used.
- Actual XHTTP H2 offer is [h2,http/1.1] even when settings request [h2]. Server permits only h2 and carries real traffic, so negotiation is h2; tests assert actual offered ALPN rather than claim literal h2-only forwarding. Raw offers http/1.1; H3 configuration is exactly [h3] and actual UDP transfer succeeds. Full XHTTP parameter combinations/ECH and same-server downloadSettings remain T08 work.
- Added bounded private engine diagnostics: at most 32 KiB in memory, shared writer protected for concurrency; user-visible output contains only fixed event category counts, never raw configuration/errors/credentials. Redaction/concurrency/size-limit race test PASS.
- Reproducible bounded runner now supports `--engine sing-box|xray`, each with independent binary/archive pins and cleared external-test environment. Xray runner RESULT PASS, cleanup PASS, 8.29 seconds, system_network_changed=false; log `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-22tosd0w.log`. Existing sing-box runner regression PASS, cleanup PASS, 6.10 seconds; log `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-ml9xo2vi.log`.
- Go vet and ordinary race suites PASS across seven tested packages with both external-engine opt-ins cleared: `/tmp/zarp-parity-stage2-xray-go.log`. Swift models unchanged; their 206-test result still applies. Production capabilities remain WARP-only. No production GUI/daemon, TUN, VPN, active routes or DNS were changed.

### Xray unit final validation and continuation

- Added three pure archive regression tests covering both ZIP and TAR, fixed-member-only extraction, restricted binary permissions, symlink refusal and old binary retention after archive/binary checksum failure. These use mocked HTTPS responses and never execute an engine or access the network. PASS: `python3 scripts/test_parity_backend_runner.py`.
- Backend reproduction and pinned source/licensing details updated in [BACKEND_PARITY_POC.md](BACKEND_PARITY_POC.md). The new archive tests and existing private-diagnostic concurrency/redaction test are meaningful integrity checks; no success stubs or TLS bypass were introduced.
- Next safe Stage 2 work: typed runtime/config compiler and bounded production supervisor, profile imports/migration and negative teardown/ECH vectors. Production capability activation still depends on real manual gates. The privileged installed-daemon diagnostic remains unknown; keep Stage 1 pending and do not request repeated preflight merely to reproduce that timeout. No installed daemon/VPN restart is authorized.

## Repeated privileged timeout and packet-pump progress fix

- Received the same user-run privileged diagnostic again: both ping and status timed out after 6.01 seconds, SKIP, cleanup PASS, no live test started. The installed daemon's connected state remains unknown. This does not pass the Stage 1 gate.
- Read-only diagnosis found launchd's installed service running as root with PID 96212. Darwin LOCAL_PEERPID on an independent diagnostic socket identifies that same PID as the peer. The process was runnable and observed at 198.3 percent CPU. Normal newline framing and a diagnostic connection with its own write half closed still received no response within the bounded deadline. These observations establish an unresponsive running service, not its cause or connected state. No debugger, process signal, restart, installation, or network change was used against it.
- Found a source hazard in `zarpd/tunnel/tunnel.go`: repeated device reads returning zero packets without an error had no progress bound or delay. The pinned Darwin device can return zero packets on a short read. Added a cancellable one-millisecond yield and a limit of 100 consecutive empty reads, returning wrapped io.ErrNoProgress. Transient empty reads recover normally. Invalid batch counts/sizes and empty session packets fail before forwarding. Each direction checks the other direction's stop signal after a read returns. The caller still owns closing the device/session to unblock a blocking read. This fixes a demonstrated source failure mode; it has not been attributed to the installed service or deployed there.
- Added meaningful fake-device tests for bounded empty reads, transient recovery with real packet bytes, malformed metadata, peer failure cancellation, empty session packets, and packets released only after peer failure. Existing zero-allocation writer checks still pass. Full Go vet and race suites PASS across seven tested packages with external-engine opt-ins cleared: `/tmp/zarp-parity-pump-go.log`.
- Extended manual-runner timeout diagnostics with bounded peer PID, response byte count and phase only. Kernel peer metadata is read-only. Regression checks reject arbitrary strings, raw responses, booleans and out-of-range metadata. The temporary stalled Unix peer checks the actual deadline and sanitized metadata. No guard is weakened and unknown production state still stops the live test before build/elevation.
- Rebuilt only the private test daemon: `build/parity-manual/zarpd`, SHA-256 `178cc6fbc0439dc2c6d0ac8ecdf59dd719509aa5da2cfe4a483dceca2dd6dc08`. A separately launched unprivileged instance with private temporary socket, account path, log and nonexistent recovery journals answered ping/status: protocol 3, connected=false, PASS, cleanup PASS, 0.6 seconds. It registered no account and created no tunnel. Only that owned child was stopped and its private directory removed. This proves fresh-source IPC works, not that the installed service is fixed.
- Unsigned arm64 Release app build PASS: `/tmp/zarp-parity-pump-app-build.log`. The app was not installed or launched. No Swift sources changed in this block; the previous 206-test Swift result remains applicable.
- Final checks PASS: `scripts/test-parity-manual.sh --self-test` using only temporary fake IPC and mocked system state; Python/shell syntax; documentation links across 18 Markdown files; changed-text punctuation; `git diff --check`. No autonomous live scenario or sudo was run.
- Continuation: installed-service recovery requires a separate user-directed action that preserves the VPN. Do not repeat the same diagnostic, assume idle, bypass the guard, or start a real tunnel. Stage 1 remains awaiting_user_test. Independent Stage 2 compiler/supervisor work can continue safely; production activation remains gated.

## Confirmed peer timeout and Stage 2 supervisor foundation

- Received the enhanced privileged user-run diagnostic: both requests connected to peer_pid=96212, ipc_phase=await_response, response_bytes=0, ipc_timeout, 6.01 seconds, SKIP, cleanup PASS. This confirms the same installed peer accepts connections but does not return a response. Connected state is still unknown. No further identical diagnostic or autonomous production operation was run. Stage 1 remains awaiting_user_test.
- Implemented `zarpd/proxy/plan.go`: a restricted typed loopback configuration compiler for sing-box VLESS/Trojan/Hysteria2 TLS and Xray VLESS raw TLS/XHTTP stream-one H2/H3. All target/listener/relay addresses must be numeric loopback endpoints; the listener and authenticated relay use 127.0.0.1, with distinct endpoints. Each plan requires a dedicated engine-specific SHA-256 pin, bounded credentials and a validated SNI name. Unsupported combinations, malformed UUIDs, invalid UTF-8/control characters and noncanonical public-key pins fail with static redacted errors. No raw config, TUN, DNS, binary/config path, shell or argv is represented.
- Implemented `zarpd/proxy/supervisor.go`: a trusted in-process inventory root plus fixed version/digest catalog, regular-file/symlink/FIFO/writable-file refusal, a size-bounded private verified executable snapshot, version check and engine config validation before startup. The snapshot prevents replacing the source after its checksum check from changing the executed bytes. The root is daemon construction data and must never come from IPC or profiles. No production caller is registered yet.
- Private directory/config/executable permissions are 0700/0600/0500. Child environment is a fixed allowlist, clearing inherited engine config, preload/proxy settings and secrets. Version output is retained privately up to 32 KiB; validation/runtime output is discarded, with only bounded byte counts/capped status exposed. No raw child diagnostic text is returned.
- Startup has one shared bounded deadline. Readiness requires a complete authenticated SOCKS greeting, not a listening TCP port alone; its state is explicitly listener_ready, not connected or verified traffic. Runtime has a bounded lease, parent cancellation and idempotent Close. Stop uses only the exact process handle created by Start, SIGTERM followed by SIGKILL after grace if necessary; WaitDelay bounds inherited output pipe waits. Configuration cleanup follows verified child exit; a failed cleanup is reported rather than marked successful. This primitive does not yet own whole relay/frontend chains or handle daemon-death child reaping, process trees, GUI adoption or persistent lease renewal. Those production gates remain pending.
- Added nine meaningful fake-only test groups for authenticated readiness and privacy, restrictive permissions/environment, TERM-ignoring cancellation, lease expiry/early exit, configuration failure/hang and authentication/listener failure, integrity/version/resource refusal, strict plan combinations, concurrent diagnostics, snapshot replacement independence and pre-cancelled/invalid-bound startup. Cancellation during authentication is tested separately and is not reported as a child startup failure; internal timer cleanup after early child exit is not reported as caller cancellation. Initial fixture failures came from /var versus /private/var canonical paths and race-helper exit delays; fixed the fixtures and required failures to occur at the intended stage. No production guard was relaxed.
- Updated existing real-engine loopback tests to use the typed compiler and supervisor for every Xray client and sing-box positive/negative pin and credential cases. Existing sing-box dedicated-CA cases remain separate. The tests still require actual HTTPS and UDP transfer, outer relay observations and wrong-pin/credential failure. All 18 Xray and 25 sing-box cases PASS, including loopback IPv4/IPv6. New supervisor is exercised by 36 of those cases.
- Xray runner RESULT: PASS, cleanup PASS, 16.73 seconds, system_network_changed=false; `/tmp/zarp-parity-supervisor-xray-result.log`, detailed private log `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-u0gc51l4.log`. Sing-box runner RESULT: PASS, cleanup PASS, 15.73 seconds, system_network_changed=false; `/tmp/zarp-parity-supervisor-singbox-result.log`, detailed private log `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-ul7kx_u9.log`. Existing binary pins and licenses are unchanged; nothing was bundled or installed.
- Go vet and ordinary race suites PASS across eight tested packages with both external-engine opt-ins removed, GOENV=off and GOFLAGS cleared: `/tmp/zarp-parity-supervisor-go.log`. No Swift or production main/IPC source changed in this block. Previous Swift/app build evidence still applies. The generated Python bytecode file from the previous syntax check was removed; user files were preserved.
- Context7 consulted for Go os/exec and pinned sing-box configuration; moving Xray docs were cross-checked against official 26.9.30 CLI source. Supervisor behavior was verified with the actual pinned executables, not inferred from JSON parsing. Documentation describes the remaining signing, child ownership and runtime gates explicitly.
- Final affected-package race checks PASS after cancellation classification and helper-command guard changes: `/tmp/zarp-parity-supervisor-final.log`, 26.678 seconds. Documentation links PASS across 18 Markdown files; new/changed text punctuation and `git diff --check` PASS. No installation, production GUI/daemon operation, sudo, real tunnel, active route/DNS change, commit or publication was performed.
- Next safe Stage 2 unit: Go-side shared contract validation, import vectors and migration, then complete managed relay/frontend chain supervision and daemon status/lease adoption. Prepare isolated user-run system adapter tests before production activation. Keep WARP-only capabilities and current IPC version 3 until that integration is ready. Installed Zarp/VPN recovery and real TUN/DNS/process checks remain pending user-directed work.

## Manual-test handoff preference

- The user confirmed that required manual checks should be handed over with an exact terminal command, then reviewed from their pasted console RESULT. Include prerequisites, temporary changes and timeout; wait for the result before passing the gate. Do not use an active chat test session or repeat an unchanged diagnostic.
- No additional manual run requested in this coordination turn. The existing Stage 1 live command would still stop on unknown production state; a loopback rerun would add no necessary evidence. No recovery, restart or installation is authorized by this test-handoff preference. Continue independent source work while preserving the current VPN.

## Continued Stage 2 implementation, 2026-10-14

- The user clarified that a pending live check is not a reason to stop independent source work. Continued implementation without requesting another status retry, restarting an installed service, or passing a manual gate.
- Added `ServerLinkImporter.swift`: bounded pure parsing for vless/trojan/hysteria2/hy2 links, percent-decoded credentials/query values, bracketed IPv6, explicit/default ports, protocol/security/transport/flow validation, TLS names/ALPN, WS/HTTPUpgrade paths/host headers and gRPC service names. Labels are presentation only. Imports never resolve DNS, connect, register WARP or accept terms. Renaming, query order and hy2 aliases preserve the configuration identity; changed credentials or transport change it.
- Unsupported options fail with a fixed field name instead of being discarded. This includes TLS verification bypass, Reality, fingerprints, ECH, Salamander and XHTTP options whose full shared contracts/runtime combinations are pending. Unknown arbitrary keys report parameters rather than echo a secret-bearing key. Imports reject duplicate decoded query keys, conflicting sni/peer aliases, malformed percent/UTF-8 encoding, control characters, inapplicable fields, scoped/raw IPv6, malformed/leading-zero numeric IPv4 and invalid ports/UUIDs. Explicit false insecure flags retain verification. These deliberate strictness differences are documented; full reference import parity is not claimed yet.
- Added `StrictContractJSON.swift` and Go `connection/json.go`: duplicate object keys (including escaped aliases), invalid UTF-8/unpaired Unicode surrogates, non-integer numbers, trailing values and excessive nesting fail before the platform decoder can normalize them. Foundation keeps first duplicate values while Go can replace/merge later ones, so relying only on ordinary decoders would cross the boundary differently. Existing lenient WARP settings decoding is unchanged.
- Added pure Go `connection/contracts.go` mirroring draft profile, credential, options, mode/probe, capabilities and versioned request validation. Exact field names, bounds, separate mode/account requirements and length-delimited SHA-256 server identity match Swift. Nested errors are static and preserve the failing field. No server-open handler or shell/binary/config paths are accepted, and the existing WARP validator remains separate.
- Added shared synthetic `testdata/connection-contracts.json`: 49 URI imports, 36 profile JSON cases and 19 request cases. Both languages verify the same accepted profile/request shapes and server fingerprints. Vectors are based on inspected Windows 07406eb parser semantics, not a claim of executing the reference apps; no Android implementation was copied. Go boundary fuzzing PASS: 115,327 executions, 10-second requested budget, no panic/raw error leak. Known-field diagnostic assertions also run in seed/race tests.
- Added `ServerProfileLibrary.swift` and `ServerProfileStore.swift`: versioned, bounded 200-profile/2 MiB collection, identity-based label upserts and explicit selection that remains unavailable after deletion. Missing collection is the migration from WARP-only builds; existing WARP preferences/history/account remain authoritative and are not copied or rewritten. Tests preserve the old settings file byte-for-byte, including language, autoconnect, terms and confirmed history. The first migration fixture used a fractional timestamp that existing ISO8601 storage rounds to seconds; corrected the fixture, not the product behavior.
- Secret collection storage requires an owned private 0700 directory and regular 0600 file. Directory-relative descriptors, no-follow/nonblocking opens, exclusive temporary creation, fsync and atomic rename avoid following file symlinks or partially replacing data. Reads are bounded; FIFOs, symlinked directories/files and public permissions are refused. Damaged/unknown/duplicate data throws safe errors and remains intact. Tests use private temporary directories only; this store is not yet wired to production UI or mode activation.
- Added `proxy/chain.go`: startup transfers ownership of its approved outer relay, including failure paths. Child exit, cancellation and lease expiry close both engine and relay. TCP/UDP relays expose bounded owned cleanup; the chain reports failure if either cleanup is unverified. Tests cover early/configuration failure, concurrent Close, lease expiry, cancellation, exactly-once resource closure and cleanup failure without success status. Daemon-death child reaping, descendants, GUI adoption, frontend/system adapters and persistent leases remain production gates.
- Existing supervised external client tests now own the full engine/outer-relay chain. Xray: all 18 cases PASS, cleanup PASS, 20.01 seconds, `/tmp/zarp-parity-chain-xray-result.log`, private details `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-t1bzrm03.log`. Sing-box: all 25 cases PASS, cleanup PASS, 18.00 seconds, `/tmp/zarp-parity-chain-singbox-result.log`, private details `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-2re69mid.log`. HTTPS/UDP traffic and outer observations still determine success. Both reports say system_network_changed=false; pins/licenses are unchanged and no backend was bundled.
- Added backward-compatible `runtimeCapabilities` metadata to ping/status and actual activeMode=warp for persistent WARP sessions. Protocol 3/open shape stays unchanged. The daemon advertises only WARP and no server protocols; loopback proofs never enable production capabilities. Swift decodes strict capability fields, tolerates their absence in older daemons and refuses to adopt or close an explicitly different active mode through its WARP provider. Golden wire/fake IPC/manager tests cover these boundaries and safe malformed-capability errors.
- Safe suites PASS: 221 Swift tests, zero failures, `/tmp/zarp-parity-stage2-final-swift.log`; Go vet and race suites across nine tested packages with external opt-ins cleared, GOENV=off and GOFLAGS empty, `/tmp/zarp-parity-stage2-final-go.log`. Unsigned arm64 Release app build PASS, `/tmp/zarp-parity-stage2-import-app-build.log`. The app was not installed/launched.
- Rebuilt private test daemon SHA-256 `6379d95b2490f5501e71ec04b8527a75610db01dd8be31db67782ffe23da9ff1`. Fresh unprivileged daemon with private socket/account/log and nonexistent recovery journals answered real ping/status with protocol 3, schema 1, modes=[warp], serverProtocols=[], connected=false, accountRegistered=false. RESULT PASS, cleanup PASS, 0.37 seconds, production_changed=false, system_tunnel_started=false. Only that exact owned child was stopped. This does not fix or verify the installed daemon.
- Next Stage 2 work: remaining typed source/profile options, managed signed inventory, mode-aware open/config integration and the isolated system-adapter test. Critical TUN/DNS/process decisions and production server activation remain pending the user-run gate. The installed-daemon state is still unknown. Continue safe independent work without repeating that diagnostic or changing the VPN.

### Additional verified outer TLS transports

- Continued the independent transport PoC after the contract/storage/IPC block. Extended the restricted sing-box compiler for VLESS/Trojan WS, gRPC and HTTPUpgrade over TLS, with applicable path/host/service validation. Raw TCP still omits the transport block; unsupported/inapplicable options fail instead of being silently discarded. Xray and Hysteria2 do not receive these sing-box transport fields.
- Expanded the pinned sing-box matrix from 25 to 65 cases: all six protocol/transport combinations over IPv4/IPv6 loopback, positive pin, incorrect pin and incorrect credential, plus separate fresh gRPC sessions. Each positive case carries actual HTTPS and UDP through the outer TLS relay. Negative cases, including the original raw/Hysteria cases, now explicitly require an outer observation before rejection; a client-side configuration failure cannot masquerade as a successful negative protocol check.
- gRPC actually offers [h2]. Its HTTP/2 session can pool multiple inner flows, so two HTTPS requests and a UDP request are not described as three fresh outer handshakes. Separate fresh-session cases prove that new outer sessions receive the splitter. TCP stream-write counters still do not prove packet boundaries or ISP effectiveness.
- Pinned sing-box runner RESULT: PASS, cleanup PASS, 64.57 seconds, system_network_changed=false; `/tmp/zarp-parity-expanded-transports-result.log`, private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-1ql_p1o2.log`. All 65 case results were verified in the log. Version/digest/terms/licensing boundaries are unchanged, and the 120-second suite watchdog remains in place.
- Added fake-only compiler cases for invalid/inapplicable HTTP options and supported defaults. Production capabilities remain WARP-only; no installed binary, service, account, VPN, active route/DNS, GUI or TUN was changed.
- Final transport-unit checks PASS: Go vet and races across nine tested packages, `/tmp/zarp-parity-expanded-transports-go.log`; documentation links across 18 Markdown files; new/changed punctuation and `git diff --check`. Swift production metadata/storage code was unchanged during this last transport unit, so its 221-test and unsigned Release build results remain applicable. All private child/test sessions completed and generated Python bytecode was removed.

## Advanced profiles and source contracts, 2026-10-14

- Continued implementation on the user's repeated request, without restarting the installed daemon, repeating its unchanged diagnostic, or passing a live gate. Production IPC remains version 3 and advertises WARP only.
- Added shared Reality, public-key/short-ID/fingerprint and Salamander/password fields. VLESS Vision is allowed on raw TLS/Reality TCP only. Reality requires VLESS TCP, a DNS SNI, an admissible fingerprint and canonical unpadded 32-byte URL-safe key. Short IDs are at most eight bytes of even-length hex. Salamander/password applies only to Hysteria2. Incorrect, inapplicable, malformed and unknown fields fail with static field-only errors. ECH/full XHTTP options remain explicitly pending. No Android implementation was copied.
- Existing schema 1 profiles with absent advanced options retain every previous fingerprint and selection ID. Present options use a tagged suffix and bind keys/short IDs/fingerprints/obfuscation credentials. Labels remain excluded. Restricted storage and unavailable selection tests now include Reality and Salamander. Shared fixtures expanded to 72 URI imports, 58 profile JSON cases and 19 request cases; previous accepted IDs remain unchanged.
- Added `proxy/profile.go`: shared profile JSON decodes into a finite loopback plan before supervised client startup. A profile cannot redirect a test to a different address/port, supply executable/raw-config fields or silently lose an unproven fingerprint/ALPN. Chrome and the PoC's observed ALPN sets are the executable subset. Broader admissible source fields do not advertise production runtime support.
- Added real Vision TLS, Reality with/without Vision, Chrome TLS and Salamander IPv4/IPv6 traffic cases. Correct authentication carries real HTTPS and UDP. Incorrect pins/credentials/Vision flow/Reality keys/short IDs and missing/wrong obfuscation passwords fail only after outer observations. Reality camouflage stays on a separate loopback TLS server whose marker cannot pass authenticated probes. Its observed Chrome ALPN is [h2,http/1.1]; the initial stricter single-ALPN assertion failed and was corrected to the observed pinned-engine behavior. No failed run was counted as a pass.
- Full sing-box runner PASS, cleanup PASS, 123 external cases, 130.85 seconds, system_network_changed=false: `/tmp/zarp-parity-advanced-full-result.log`; private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-rdtvcj3j.log`. Advanced-only shared-profile run passed all 58 cases in 65.93 seconds. Xray regression PASS, cleanup PASS, 18 cases, 18.01 seconds, system_network_changed=false: `/tmp/zarp-parity-advanced-xray-result.log`; private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-o6y4ipm_.log`.
- Engine server fixtures now use the same finite environment boundary as supervised clients. The runner rejects no-test/skipped external selections and reports actual case counts. Its total watchdog is now 180 seconds with a 170-second Go limit, retaining 20-second per-case contexts. Five pure archive/evidence regression tests pass. TCP write counters and UDP ordering still do not establish kernel packet boundaries, production fake semantics or ISP effect.
- Added pure shared `ConnectionSource`: WARP/manual/subscription kinds, separate account modes, label-independent identity bound to the exact original HTTPS URL including tokens, no automatic fetch or redirect rebinding. Source diagnostics/debug output are redacted. Strict URL rules reject non-HTTPS, userinfo/fragments, malformed/control encoding, raw Unicode, invalid numeric/scoped/unbracketed addresses, invalid ports and inapplicable URLs. Swift/Go agree on 57 synthetic source vectors, including Go's optional legacy colon parser mode. Subscription persistence/downloader/UI remain later work.
- Swift full suite PASS, 226 tests, zero failures: `/tmp/zarp-parity-source-swift.log`; final source-vector check PASS: `/tmp/zarp-parity-source-final-swift.log`. Go vet and races passed nine tested packages after advanced compiler changes: `/tmp/zarp-parity-advanced-final-go.log`. Source package race checks PASS: `/tmp/zarp-parity-source-final-go.log`; legacy URL parser compatibility PASS: `/tmp/zarp-parity-source-compat-go.log`. Five-second profile/request/source boundary fuzzing passed 150,840 executions with static-error checks; targeted advanced/source seeds added afterward for subsequent checks. Unsigned Release app build passed after advanced profile changes: `/tmp/zarp-parity-advanced-app-build.log`; source-metadata rebuild remains to be checked.
- Added the isolated user-run system-adapter script and private probe helper. Live mode remains unexecuted. Completing its fake/config/loopback checks and watchdog/normal-user process proof before handoff. It creates only one owned utun and one reserved measurement host route; private loopback fixtures carry TCP/UDP/DNS. No default routes or system DNS configuration. It reuses the unchanged production/foreign-VPN guards before live startup. The installed daemon's state remains unknown, and the script must refuse that state.

### Isolated system-adapter handoff

- Completed `scripts/test-parity-system-adapter.{sh,py}` and `cmd/parity-adapter-probe`. Only --loopback-check was executed autonomously. It builds in a private cache, snapshots the checksum-pinned engine, validates the TUN JSON with check without calling Start, and transfers authenticated HTTPS/UDP/DNS over loopback. Final RESULT PASS, cleanup PASS, 1.24-second worker duration, live_test_started=false: `/tmp/zarp-parity-system-adapter-verified.log`; retained report `/private/tmp/zarp-parity-adapter-7y_odaqn/report.json`. Temporary secrets/configs/cache/binaries were removed. Earlier completed owned binary snapshots were also removed by exact verified paths, preserving reports.
- Live mode is user-run only. It uses one private IPv4 utun/address and one 198.18.0.2 host route, refusing existing route coverage. Default routes, DNS/proxy settings, production files and accounts stay untouched. Selected/excluded probe executables run under the original user's UID while the frontend runs as root. Root seals their files against replacement; a bounded inherited pipe supplies their nonce/trusted certificate without public argv/env credentials. All forwarded destinations are fixed authenticated loopback fixtures.
- Root worker and independent engine guardian both retain the foreign-VPN/production-state checks before startup. The guardian owns its exact engine process handle and stops it on cancellation, deadline or parent death. Route removal requires exact destination/HOST flag/gateway/interface ownership. Replacement routes and external changes are preserved, with no global restoration. Live PASS requires six actual selected/excluded protocol results, verified owned cleanup and matching route/DNS baseline. No live test was run or counted as passed.
- Four pure adapter tests PASS for missing/stale/symlink selection, changed/partial/non-host route metadata, production-status-unknown preventing any TUN child/route command, and parent death stopping only the guardian's owned child. Five archive/evidence tests PASS. Shell/Python syntax checks PASS. Context7/official pinned sources were checked for TUN schemas, constructor versus Start, Go URLs and TLS fixture lifecycle. The Python Context7 request had a transport error, so official Python 3.14 documentation was used as fallback.
- Final Go vet and race suites PASS across nine tested packages, with the new probe command compiled and both external-engine opt-ins cleared: `/tmp/zarp-parity-stage2-complete-safe-go.log`. One automatic approval review timed out before starting the routine race suite; its permitted single retry succeeded. No permission action remains rejected or pending. Seeded boundary fuzzing PASS, 59,138 executions with advanced/source seeds: `/tmp/zarp-parity-source-seeded-fuzz.log`. Unsigned arm64 Release rebuild with source metadata PASS: `/tmp/zarp-parity-source-final-app-build.log`.
- Next user command: `scripts/test-parity-system-adapter.sh --run`, from the repository in the network state the user chooses. Prerequisites macOS arm64/Go/pinned sing-box/sudo. Build budget 180 seconds, root worker budget 120 seconds, sudo authorization excluded. Send the sanitized RESULT afterward. Unknown installed-daemon state still produces SKIP; do not retry the unchanged production diagnostic, bypass its guard, restart/install a service or pass any pending gate. Production server-open, signed inventory and integrated frontend/backend activation remain pending.

### User-run system-adapter result and continued runtime work

- Received the user's system-adapter RESULT: SKIP, cleanup PASS, 3.59 seconds, live_test_started=false, checks empty, production_status_unknown. Report: `/private/tmp/zarp-parity-adapter-ef28mwl9/report.json`. Neither default routes nor system DNS was configured. This is not a passing TUN/process check. The installed daemon still has unknown state; the existing guard correctly prevented startup.
- Continue independent Stage 2 runtime ownership and lease work with fake engines/private loopback sockets. Do not repeat the unchanged diagnostic, bypass the production guard, restart the installed daemon or change the current VPN. System-adapter and Stage 1 live gates remain awaiting_user_test.

### Renewable leases, daemon ownership and private source storage

- Added trusted in-process lease renewal to the loopback engine/chain. Each renewal retains the original limit of at most one minute and respects the parent deadline. Readiness, renewal and expiry share the same state lock. Expired, cancelled, exited and stopping children cannot be renewed or adopted, even before the watcher updates terminal status. No automatic GUI heartbeat or production IPC renewal method was added.
- Added `proxy/owner.go`: a daemon-context owner of one private chain. Validated profile data derives server identity; executable strategy fingerprints and random run generations identify the actual run. Request cancellation tears down incomplete startup. After readiness, request/client disappearance does not cancel the daemon-owned chain. Adoption returns bounded identity/status only; it does not start/renew a run or claim traffic health. Stale stop/renew requests cannot affect a replacement. Concurrent admission/shutdown, failed startup and cleanup failures retain ownership; unverified cleanup blocks replacement. Arbitrary PID adoption and daemon-death recovery remain unsupported.
- Fake-engine lease/owner race checks PASS: original-deadline renewal, eventual expiry, parent deadline, concurrent close/renew, client disappearance/adoption of the same authenticated child, stale generations, request cancellation/retry, daemon cancellation during/after startup, simultaneous admission, redacted status and retained cleanup failure. Initial focused run: `/tmp/zarp-parity-owner-first-go.log`, 77.63 seconds. A sandbox-only compilation smoke check could not bind a loopback socket; the authorized private loopback run passed, so this was an environment restriction, not a project regression.
- Final Go vet and safe race suites PASS across nine tested packages, external-engine opt-ins cleared: `/tmp/zarp-parity-owner-vet.log`, `/tmp/zarp-parity-owner-safe-go.log`; proxy package 81.18 seconds. Real sing-box shared-profile cases now detach the request, adopt the owned run and renew its bounded lease before HTTPS/UDP probes. Full runner PASS, cleanup PASS, 123 cases, 136.02 seconds, system_network_changed=false: `/tmp/zarp-parity-owner-sing-result.log`; private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-e3t12tz7.log`. Xray lease regression PASS, cleanup PASS, 18 cases, 22.99 seconds, system_network_changed=false: `/tmp/zarp-parity-owner-xray-result.log`; private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-cej90kc8.log`.
- Added app-side `ConnectionSourceLibrary` and `ConnectionSourceStore`: schema 1, 32-source/512 KiB limits, permanent WARP availability, exact-original-URL identity, rename/upsert, explicit selection and unavailable removed selections. A URL/token change creates a different source; it cannot silently rebind the selected ID. Missing storage migrates to WARP without modifying settings, account or profile documents. Metadata persistence never fetches a subscription or changes a runtime.
- Profile/source stores now share the existing restricted file implementation: owned 0700 directory, no-follow bounded regular 0600 files, exclusive temporary file, fsync/atomic rename, static errors and cleanup on failure. Symlinks/FIFOs, public permissions, malformed/duplicate/unsupported/oversized data fail while preserving the original. Existing profile-store behavior and tests remain intact. Source URLs are redacted in both display/debug descriptions, including source selections.
- Swift safe full suite PASS, 233 tests, zero failures: `/tmp/zarp-parity-source-storage-swift.log`. Seven new source-store cases verify migration isolation, private offline selection, token persistence/redaction, identity changes, transactional limits, corrupted-file preservation and unsafe-filesystem refusal. No production source file, app, account, service, VPN, TUN, route or DNS was changed.
- Unsigned Release app build PASS: `/tmp/zarp-parity-owner-source-app-build.log`; app executable is Mach-O arm64. The app was built only, never installed, registered or launched. Rendered local links across 11 top-level Markdown documents, new/changed-text punctuation and `git diff --check` PASS. A first link-check attempt incorrectly included a fenced release-note template; excluding code examples resolved that checker false positive without modifying the historical document.
- Continuation: keep Stage 2 in_progress and the system-adapter/Stage 1 live checks awaiting_user_test. Next independent production prerequisite is a signed backend inventory and daemon-death/descendant ownership design. Server-open, GUI runtime activation and system routing/DNS/process features require their actual manual gates. The unchanged production-status timeout must not be treated as idle, retried as a new result or repaired by an autonomous service/VPN restart.

### Signed inventory and isolated guardian foundation

- Added `proxy/inventory.go`: a separate signed-bundle constructor with fixed Contents/MacOS members, pinned versions and fixed backend signing identifiers. Trusted release construction supplies the expected ten-character team and final signed-file SHA-256 digests; absent digests omit engines. No policy is read from IPC, profiles, an unsigned manifest or the binary under test. Signing changes executable bytes, so original upstream hashes are not a signed-release catalog.
- Snapshot hash verification precedes bounded native codesign verification. The private 0500 snapshot must satisfy strict/all-architecture validation, Apple generic anchor, Developer ID CA/application certificate OIDs, expected team and fixed identifier before version/configuration/engine execution. Native output is discarded. Ad-hoc, development, unrelated or mismatched identities cannot silently fall back to the development loader. Production capabilities and packaging remain unchanged.
- Six inventory tests PASS with races in 4.53 seconds: malformed/omitted policy, fixed catalog and immutability, checksum before signature, signature before version/secret config, source replacement independence, native requirement compilation and rejection of a valid matching-identifier ad-hoc fixture. Log: `/tmp/zarp-parity-inventory-first-go.log`. Only an owned temporary fake fixture was ad-hoc signed, with no identity/keychain access. Fake-verifier acceptance checks wiring only; no Developer ID signed-release acceptance result is claimed.
- Added `proxy/guardian.go` and the standalone private `cmd/parity-backend-guardian`. A guardian owns a single restricted loopback engine and exclusive inherited anonymous control/report pipes. Initial messages are bounded to 32 KiB; subsequent versioned renew/stop messages to 256 bytes. Duplicate, normalized/unknown, malformed, oversized and unsupported fields fail. No binary/config path, arbitrary argv, process name/PID, TUN or system policy is accepted in the control message. Strict shared JSON validation now also supports this internal boundary.
- Control EOF/malformed input cancels startup or the owned engine. Reports contain only bounded status/static codes. Nonblocking native pipe reads/writes avoid macOS inherited-FIFO polling limitations; cancellation/idle waits and two-second write bounds prevent spin/backpressure hangs. Descriptors are close-on-exec so the engine cannot retain its parent's control/report handles. The PoC has an independent two-minute guardian cap, the existing engine lease, bounded message count and cooperative SIGINT/SIGTERM cleanup.
- Five guardian race tests PASS in 17.36 seconds: actual SIGKILL of the exact temporary fake-daemon child, authenticated same-engine readiness, control-loss cleanup/report EOF/private file removal, preservation of an independent listener, renewal past the original deadline, explicit stop, malformed controls, rejected start shapes and bounded full-pipe writes. Log: `/tmp/zarp-parity-guardian-first-go.log`. No installed PID, service, VPN, TUN, route or DNS was touched.
- Added pinned-engine guardian cases carrying actual VLESS/Hysteria2 HTTPS/UDP over IPv4/IPv6, with outer observations and private EOF cleanup. Initial focused runner PASS, cleanup PASS, four cases, 7.32 seconds, system_network_changed=false: `/tmp/zarp-parity-guardian-pinned-result.log`; private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-34mjqvh9.log`. Added a separate cooperative SIGTERM case afterward. `--suite guardian` selects these safe sing-box-only checks. Formatting initially targeted the wrong directory and was corrected before final checks.
- Limits remain explicit: this guardian is not launched by production IPC, does not own system resources or descendant subprocesses, and does not survive its own SIGKILL. Its lease timer runs inside that guardian; it is not an engine-internal fallback after guardian death. Signed release acceptance, catalog generation/distribution, protected descendant ownership and production guardian/frontend integration remain pending. No live/system gate has advanced.
- Final Go vet and race suites PASS across nine tested packages, both external-engine opt-ins cleared. Guardian command compiled without execution by the ordinary suite. Logs: `/tmp/zarp-parity-inventory-guardian-vet.log`, `/tmp/zarp-parity-inventory-guardian-safe-go.log`; proxy races 100.01 seconds. Final full sing-box runner PASS, cleanup PASS, 128 cases, 140.36 seconds, system_network_changed=false: `/tmp/zarp-parity-inventory-guardian-sing-result.log`; private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-uz23z9mx.log`. Five guardian cases include real IPv4/IPv6 TCP/UDP traffic, EOF cleanup and SIGTERM cleanup. Xray regression PASS, cleanup PASS, 18 cases, 24.22 seconds, system_network_changed=false: `/tmp/zarp-parity-inventory-guardian-xray-result.log`; private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-dz29rupt.log`.
- Five archive/evidence runner tests PASS. Swift app/core code was unchanged in this unit, so its 233-test result remains applicable. The native/ad-hoc fixture and private loopback/crash checks neither claim signed-release acceptance nor advance the user's system-adapter SKIP. Production protocol 3 still advertises WARP only.
- Unsigned Release app rebuild PASS: `/tmp/zarp-parity-inventory-guardian-app-build.log`; executable is Mach-O arm64. Built only, never installed, registered or launched. Python syntax, rendered local links in 11 Markdown documents, changed-text punctuation and `git diff --check` PASS. All owned test sessions completed.
- Next concrete independent Stage 2 work: protect descendant subprocess ownership without signaling a reused PID/process group, then connect a typed guardian launcher to the daemon-owner foundation with fake/loopback checks. Keep signed-release catalog/acceptance and production/frontend activation pending. Do not repeat the unchanged installed-peer diagnostic, assume it idle, weaken any network guard or restart the user's service/VPN. The user's live system-adapter RESULT remains SKIP with cleanup PASS and live_test_started=false.

### Native descendant ownership and typed guardian launcher

- Added Darwin/cgo ownership helpers using waitid with WNOWAIT, proc_listpids and BSD process metadata. A freshly isolated session/group is created before exec. The direct child stays unreaped while native checks confirm its ordinary group and session members have stopped. A mutex serializes the final ownership check, signal and reap; saved objects refuse signals after reaping. Unsupported native builds fail before execution. Fixed-size queries fail closed on truncation or uncertain metadata.
- TERM-ignoring descendants are stopped even after their engine leader exits. Changed-group session members prevent a clean result and are never individually signaled. This does not prove cleanup for a descendant that creates a separate session. Unknown cleanup retains private files/ownership rather than permitting replacement. Installed processes and foreign groups are never selected by name or saved numeric PID.
- Added the trusted development GuardianLauncher and GuardedSession. The fixed parity-backend-guardian member is verified into a private 0500 snapshot. The parent holds its isolated leader unreaped; the guardian's version/check/runtime children remain in that private group. Guardian-only SIGKILL during startup or readiness therefore leaves a reserved owner able to clean ordinary engine descendants. Control contains no paths, argv, PIDs or system policy. The daemon-owner/chain interfaces now accept this launcher as well as the direct supervisor. Production IPC remains WARP-only.
- A lease renewal returns success only after the bounded guardian acknowledgement validates the actual lease. Cancellation, control loss, child exit, malformed reports and startup failure tear down the owned chain. Report descriptors are joined before close to prevent descriptor reuse races. Full CleanupOK comes from the parent's native group check plus removal of its private tree, never a guardian assertion alone.
- Native descendant checks PASS, three cases with races in 8.52 seconds: `/tmp/zarp-parity-descendants-go.log`. Launcher checks PASS, five cases with races in 15.47 seconds: `/tmp/zarp-parity-launcher-first-go.log`. They verify adoption after request disappearance, acknowledged renewal past the original deadline, concurrent stop/renew, exact guardian crash with a TERM-ignoring descendant, crash during startup, integrity/cancellation refusal, bounded report shapes and preservation of an independent engine.
- Pinned guardian subset PASS, cleanup PASS, nine actual cases in 13.80 seconds, system_network_changed=false: `/tmp/zarp-parity-launcher-pinned-result.log`; private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-btng69l4.log`. Four new typed-owner cases carry authenticated VLESS/Hysteria2 HTTPS/UDP over IPv4/IPv6 after request detachment, adoption and acknowledged renewal. Five previous standalone EOF/SIGTERM cases remain covered.
- Fixed the Python loopback watchdog's saved-group handling: normal completion never signals a reaped leader; interrupted runs send TERM/KILL before their sole wait. Unknown SIGCHLD policy refuses group signals. A lost Go owner cannot certify every private engine session, so watchdog interruption/timeout explicitly reports cleanup FAIL. Eight pure archive/evidence/ownership runner cases PASS: `/tmp/zarp-parity-launcher-runner-tests.log`.
- Go vet and complete safe race suites PASS across nine tested packages, both engine opt-ins cleared: `/tmp/zarp-parity-launcher-vet.log`, `/tmp/zarp-parity-launcher-safe-go.log`; proxy races 119.16 seconds. Full sing-box regression PASS, cleanup PASS, 132 cases in 137.92 seconds: `/tmp/zarp-parity-native-full-sing-result.log`; private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-tswr5kn5.log`. Xray regression PASS, cleanup PASS, 18 cases in 18.87 seconds: `/tmp/zarp-parity-native-xray-result.log`; private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-sviz6hsh.log`. Both report system_network_changed=false. Unsigned rebuild remains to be checked with the subsequent Swift models.
- Limits: this development launcher is not production IPC or a signed-release guardian loader. Guardian-only crash cleanup requires its parent owner to survive. Simultaneous owner/guardian death, typed launcher's owner-death descendant/file recovery, detached sessions and system-resource recovery remain unverified. The standalone EOF proof does not pass those additional cases. No user's pending live gate advanced.
- Continue independent subscription parser/offline-cache models under T07's explicit allowance before TUN integration, while dependent server/runtime/UI activation remains gated. The installed-peer timeout is unchanged and must not be retried or interpreted as idle.

### Independent subscription list and offline-cache models

- T07 explicitly permits downloader/cache models before TUN readiness. Added pure SubscriptionParser/SubscriptionResult: bounded 2 MiB UTF-8 input, plain and standard/URL-safe padded/unpadded base64 lists, BOM/CRLF/comments, shared strict URI parsing, first-label configuration deduplication, 200 distinct accepted profiles and separate unsupported/refused/excess counts. HTML/JSON receive static format errors; neither arbitrary client JSON nor secret refused values are retained in diagnostics.
- Added SubscriptionSnapshot/SubscriptionCache using the existing restricted file helper. Exact original source identity determines a fixed hash filename; redirect destinations cannot rebind it. A snapshot preserves the explicit selected server ID across refreshes, including when it becomes unavailable. Configuration removals return IDs for later pair invalidation without changing a runtime. Offline loading, strict schema/duplicate/integer validation, 12-hour freshness with clock-regression refusal, stale-update rejection and source-specific deletion are implemented. Failed/empty/older updates preserve the prior document. Paths are app construction data, never root IPC input.
- Snapshot credentials use documented owned 0700/0600 storage with no-follow bounded regular files, fsync and atomic rename. Cache/source tokens do not appear in debug descriptions; the cache contains a source hash, with its original URL remaining in the separate restricted source store. Symlinks/FIFOs and cross-source documents are refused. Deletion validates the exact owned regular file and preserves other sources.
- Focused Swift checks PASS, 11 tests: `/tmp/zarp-parity-subscription-corrected-swift.log`. An initial test exposed Swift's treatment of CRLF as one Character: splitting on a literal LF skipped a comment-prefixed body. Newline-aware splitting fixed the import; the test now avoids unchecked array access on failure. No initial failed result was counted as passed. The full Swift suite and HTTP downloader are being checked next.
- This is independent model implementation only. It does not activate subscriptions in the UI, fetch a production URL, replace an active pair, start a server/TUN or pass a pending stage gate. Windows source was inspected for the accepted list contract; no Android GPL implementation was copied. Foundation decoding/strict UTF-8 documentation was retrieved through Context7.

### Bounded subscription HTTPS and refresh ownership

- Added an injected SubscriptionDownloader in the pure core and a separate ZarpSubscriptions transport target. The app is not wired to it. An explicit call uses ordinary HTTPS through the current connection, with no physical binding, proxy override, system setting or persistent cookie/credential/cache store. Every redirect is validated before the next request; five are allowed. Both Zarp/1.0 and the format-only v2rayN/7.0 retry share one monotonic 25-second deadline. Network/TLS/status/size failures are not disguised as a format retry. A failed second format attempt preserves the first HTML/JSON diagnosis; cancellation remains cancellation.
- URLSession streams delivered data into a 2 MiB bound and cancels on overflow. The default TLS path uses system validation; errors expose static categories and an HTTP status only. Control/state cancellation resumes the request exactly once, invalidates its private session and drops retained data. Credentials and token-bearing URLs never appear in the transport's own diagnostics. An internal test-only construction restricts a dedicated CA to the exact numeric loopback origin, evaluates chain/time/IP SAN and disables certificate network fetching for that fixture. It never installs a trust anchor or weakens the production constructor.
- Eleven fake HTTP/coordinator cases PASS: `/tmp/zarp-parity-subscription-http-first-swift.log`. They cover streaming/header overflow, private session settings, status/redirect bodies, TLS/network error redaction, stalled-session cancellation, expired admission, valid/unsafe/sixth redirects, user-agent policy and the same deadline across attempts.
- Real loopback HTTPS/gzip fixture PASS in 1.59 seconds: `/tmp/zarp-parity-subscription-real-tls-corrected-swift.log`. Actual compressed lists, HTTPS redirects, user-agent retry and repeated cookie-free loads transfer valid profiles. A compressed body expanding beyond 2 MiB fails and preserves the prior cache; HTTP downgrade fails. The production default trust constructor rejects the private CA. The owned fixture stops on exclusive input EOF, is reaped, and independently has a 40-second limit. It creates no outbound connection, system tunnel, routes, DNS or keychain entries.
- An initial real-fixture run failed after its 40-second cap because a fixed-size pipe read waited for EOF before delivering the metadata. A bounded poll/newline handoff fixed the test harness; no failed run was certified. Go and Security documentation were queried through Context7. Where the query did not cover trust APIs, current Apple SDK headers and pinned local Go sources supplied the primary reference.
- Added SubscriptionRepository: one owned generation per source, four concurrent sources at most, explicit refresh, current-selection preservation after fetch, source-specific delete and joined shutdown. Cancel/delete/close prevent late cache publication; stale cached lists remain available offline with static network/TLS/size/timeout/format warnings. Cancellation never becomes an implicit connection. No runtime/account/source-metadata state is changed. Five focused cases PASS: `/tmp/zarp-parity-subscription-repository-swift.log`.
- Final complete Swift suite PASS, 261 tests, zero failures: `/tmp/zarp-parity-subscription-final-swift.log`. Unsigned arm64 app build with parser/cache/downloader core PASS: `/tmp/zarp-parity-native-subscription-app-build.log`. The transport is a separate library and tests compile it, with no app activation. Final core-repository app rebuild PASS: `/tmp/zarp-parity-subscription-repository-app-build.log`. No application or service was installed, registered or launched.
- Closed a native readiness race: renewal/adoption now checks the exact unreaped child's native exit state under the ownership lock, before the cleanup watcher publishes its terminal status. A real exited fixture with its done channel still open verifies refusal for direct and guarded sessions. Focused native/launcher race checks PASS in 24.16 seconds: `/tmp/zarp-parity-native-ready-first-go.log`. Go vet PASS: `/tmp/zarp-parity-native-ready-vet.log`; all affected proxy races PASS in 118.74 seconds: `/tmp/zarp-parity-native-ready-final-go.log`. Other packages retain the preceding full safe suite result because they were unchanged. Final pinned guardian regression PASS, nine actual cases, cleanup PASS, 12.75 seconds, system_network_changed=false: `/tmp/zarp-parity-native-ready-pinned-result.log`; private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-yktqkck0.log`.
- Stage 1 WARP and Stage 2 system-adapter tests remain awaiting_user_test. Their earlier SKIPs are not passes. Dependent production server/TUN/process/UI activation, signed-release acceptance and guardian owner-death recovery remain pending. Continue safe implementation and verify each new prerequisite; do not repeat an unchanged installed-peer diagnostic or infer inactivity.

### Passive outer-packet test prepared for the user

- Continued T04 with `cmd/parity-packet-probe`, `scripts/test-parity-outer-packets.sh` and its private Python runner. The childless worker uses the existing outer TCP/UDP relays, fixed numeric IPv4 loopback targets and in-memory certificates/authentication. Two fresh HTTPS flows verify SNI/ALPN and real responses. Two fresh UDP associations verify invalid-fake-first, same-tuple real markers and reverse echo. There is no production IPC, account/config access, physical binding, TUN, route/DNS/proxy/firewall/interface change or process-name signaling.
- User-only capture opens a read-only/nonblocking BPF descriptor on existing lo0. Reject-all precedes attachment; an exact loopback/protocol/two-reserved-port filter precedes traffic. SDK-native headers/alignment, full frames, bounds and zero capture drops are required. Reader completion precedes descriptor close; raw packets stay within 4 MiB/4096 packets in memory. TCP proof requires exact split payload boundaries, continuous sequence and original handshake bytes on each fresh outer tuple. Repeated UDP datagrams cannot be collapsed into a passing result.
- Context7 Apple kernel documentation and current Apple XNU loopback/BPF source were inspected. The source exposed an error in the draft input-only choice: lo0 provides an output tap. Corrected seesent on this private descriptor before handoff, preserving the same address/port filter and strict datagram count. No BPF device was opened autonomously.
- Runner SIGINT/SIGTERM and watchdog cleanup closes its exclusive worker input, then joins and validates the fixed helper's terminal report. It never signals a saved/reaped PID or another process. A wrapper exit without a helper report cannot certify cleanup. Unverified build/worker interruption retains private work and reports cleanup FAIL. Verified completion removes binary/cache/logs, retaining only an owned 0700 directory and sanitized 0600 report.json. Reports accept a fixed bounded schema and expose static capture error categories/errno and counts only; secret/unknown fields cannot be echoed as success.
- Five synthetic Go filter/decoder/boundary/order cases PASS with races, 1.357 seconds: `/tmp/zarp-parity-packet-final-go.log`. They include native libpcap filter execution without a device, IPv4 options, foreign/truncated/fragmented frames, coalescing/wrong TCP bytes/order/tuple, and repeated/reordered/wrong-tuple UDP. Go vet PASS: `/tmp/zarp-parity-packet-vet.log`. Eight runner cases PASS: `/tmp/zarp-parity-packet-runner-tests.log`, including a real private stdin-EOF child, signal handling, timeout/unknown cleanup retention, fixed command/environment, report permissions and refusal of stream-only/missing/drop/error evidence as a capture PASS. Mocked capture reports are schema tests, not kernel evidence.
- Final unprivileged fixture RESULT PASS, cleanup PASS, 6.19 seconds, two HTTPS flows and two UDP associations, capture_started=false and both packet-proof flags false: `/tmp/zarp-parity-packet-final-loopback-result.log`. Sanitized report: `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-packets-oykb4a96/report.json`. Helper SHA-256 `a211bc72a79e60d76e9e12688113a8a395894ba4ecebda52fe850e14633c263c`. A prior sandboxed fixture failure was not counted as passing; the approved loopback-only execution passed. No privileged capture or autonomous sudo was run.
- Python/shell syntax, script help, all local links/anchors in 18 Markdown documents, changed-text punctuation and `git diff --check` PASS. Production/app sources did not change in this packet block, so the preceding safe suites and unsigned build remain applicable. All owned test sessions completed.
- Required user check: `cd /Users/andrumoskow/Documents/Zarp-MacOS` then `scripts/test-parity-outer-packets.sh --run`. The current VPN may remain connected. Prerequisites: macOS arm64, Go, Xcode command-line tools, sudo for passive BPF access. Temporary resources: private loopback listeners/relays, one BPF descriptor, private helper/cache/logs; sanitized report retained. Build limit 180 seconds; worker limit 30 seconds, excluding sudo authorization. Send the RESULT block. Do not invoke this mode autonomously.
- Capture acceptance remains awaiting_user_test. If TCP coalesces or packet evidence is incomplete, adjust and retest the actual relay behavior rather than weaken the proof. This IPv4 invalid-fake check does not prove IPv6 kernel behavior, production fake hop limits, ISP effectiveness, selected-process/TUN policy, signed-release acceptance or owner-death recovery. The earlier system-adapter production-status SKIP is unchanged and no live gate has passed. Continue from the user's packet result; keep dependent production activation gated.

### User IPv4 kernel packet evidence accepted

- Reviewed the user's capture RESULT and its matching restricted report at `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-packets-suawtss2/report.json`. Version 1, run ID matching the private directory, phase capture, expected scenario and exact helper SHA-256 `a211bc72a79e60d76e9e12688113a8a395894ba4ecebda52fe850e14633c263c` match the prepared test. Report/directory modes are 0600/0700; only report.json remains after cleanup.
- User-run PASS, cleanup PASS, 6.56 seconds, capture_started=true, 54 captured packets, zero drops, system_network_changed=false. Each of two fresh authenticated HTTPS flows has exact TCP payload boundaries `[1, 116, 1420]` and complete original outer ClientHello bytes. Both fresh UDP associations prove invalid-fake-first order on the same tuple and real reverse echo. tcp_packet_split_verified and udp_fake_order_tuple_verified are true. This passes this IPv4 loopback kernel packet gate only.
- No relay change or repeated capture is needed for these bytes. IPv6 kernel capture, production fake/hop-limit behavior and ISP effect remain unverified. The separate system-adapter SKIP and unknown installed production status are unchanged; no TUN/process/DNS or signed-release gate has passed. The current VPN was not changed by the agent.
- Continue independent Stage 2 ownership/recovery prerequisites with private fakes and actual loopback engines. Do not stop after merely recording the result or activate dependent production features while their gates remain pending.

### Private session recovery implementation and checks

- Added `proxy/recovery.go` and a fixed `--recover-session` guardian bootstrap. The typed guardian arms a childless helper before any engine/probe starts. That helper has a different group inside the same freshly created session, exclusively inherited control/report/acknowledgement pipes and an owned directory capability. It derives its target SID from the kernel; no message can select a PID, group, binary, argv or filesystem path. The only metadata is a bounded fixed engine/version identity.
- On guardian control EOF, malformed extra input, SIGINT/SIGTERM or its independent cap, the helper verifies its still-held session, stops only the original session-leader group, checks remaining session members and the exact private root inode/owner/mode, then removes that root. Guardian renewal cannot extend the helper cap. It does not own production/system resources or adopt observed processes. Changed-group members refuse success/file removal; detached sessions and loss of the recovery helper remain outside this proof. Pre-arming simultaneous death is not claimed.
- Queried Context7 for Darwin session and Go exec semantics. Current Apple XNU PID allocation excludes existing session/group IDs; installed Go 1.27.1 sources confirm Setpgid/ExtraFiles and raw-file-descriptor lifetime. No upstream implementation was copied. The new helper preserves the original SID while its former leader can be reaped after daemon death, and never signals scanned PIDs or an unrelated group.
- Initial launcher checks exposed a source error: the ownership watcher signaled a zombie-only original group while the recovery member was still finishing. It now waits while retaining its reserved leader when the original group has no live members. The corrected five launcher race checks PASS in 18.43 seconds: `/tmp/zarp-parity-recovery-launcher-corrected-go.log`. The initial failure is not a pass.
- Initial owner-crash fixtures also exposed premature closure of os.File objects used only through native integer descriptors. Deferred ownership now retains both input/report handles, including the older fake guardian-parent fixture. The new ready fixture forces garbage collection before its proof. No raw child output or secret data is logged.
- Recovery race checks PASS in 31.865 seconds before the final added GC stress: `/tmp/zarp-parity-recovery-owner-final-go.log`. Three actual crash variants kill only the exact owned fake daemon, or that daemon and its exact owned guardian, after recovery arming. They cover ready and in-progress startup, TERM-ignoring engine descendants, private file removal and preservation of an independent authenticated engine. Other cases reject replaced/public root capabilities and malformed/secret/arbitrary recovery identity fields. A changed-group fixture ends under its own six-second cap; cleanup stays failed and files/anchor remain while it lives, with no observed PID/group signal. Its later exit does not revive the failed status.
- Pinned guardian traffic regression PASS, nine VLESS/Hysteria2 IPv4/IPv6 cases, cleanup PASS, 15.95 seconds, system_network_changed=false: `/tmp/zarp-parity-recovery-pinned-guardian-result.log`; private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-dxnnyd73.log`. These verify traffic/ordinary guarded cleanup with the new recovery member, not actual pinned-engine owner-crash acceptance yet. Full safe Go races and vet are being checked, with both engine opt-ins cleared.
- Continue actual pinned-engine owner-crash coverage and the remaining independent Stage 2 release/ownership prerequisites. Keep signed guardian acceptance, production/frontend activation and user TUN/process checks pending. Do not retry the unchanged installed-peer diagnostic, assume idle or change the user's VPN.

### Pinned-engine owner-crash evidence and final recovery validation

- Added a bounded `--owner-probe` development bootstrap using the same typed GuardianLauncher, private inherited pipes and restricted loopback plans. It has no arbitrary executable/argv/path/group inputs and does not own a frontend or system resource. Its ready result contains a generated private directory and session number for read-only fixture checks, never adoption or signal authority. Only the exact unreaped direct fixture parent receives SIGKILL, before its sole wait.
- Actual VLESS and Hysteria2 HTTPS/UDP traffic now precedes four IPv4/IPv6 owner-crash cases. The surviving guardian/recovery member removes private engine files, closes the authenticated listener and leaves no live matching private session/group members. Final pinned guardian runner PASS, 13 actual cases, cleanup PASS, 18.11 seconds, system_network_changed=false: `/tmp/zarp-parity-recovery-pinned-owner-final-result.log`; private detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-6x85p7kg.log`. Nine existing traffic/EOF/termination/typed-owner cases remain included.
- An initial new fixture failure correctly rejected different lexical `/var` and `/private/var` paths. Resolved-path comparison now requires the same owned fixture parent, with no broader directory exception. The original failed suite was not counted as passed. Its runner had misleadingly kept cleanup PASS; failed/incomplete runs now return cleanup/status FAIL and retain their 0700 private directory rather than deleting under an unverified child. Nine pure runner integrity/ownership/retention cases PASS: `/tmp/zarp-parity-recovery-runner-tests.log`. Successful verified suites still remove private work.
- Full safe Go race suite PASS across ten tested packages, including final GC-stressed recovery fixtures, proxy 151.928 seconds: `/tmp/zarp-parity-recovery-final-safe-go.log`. Go vet PASS: `/tmp/zarp-parity-recovery-final-vet.log`. Both pinned-engine opt-ins were cleared. The subsequent strict owner-probe stop check PASS with races in 9.714 seconds: `/tmp/zarp-parity-recovery-owner-api-go.log`; duplicate stop fields fail after verified cleanup, while valid stop succeeds. Production app/Swift sources were unchanged; their preceding 261-test and unsigned build results remain applicable.
- Updated architecture and backend evidence. The recovery results apply after arming to ordinary members of the original private session-leader group. Changed groups remain failed until their independently bounded fixture ends, and detached sessions, pre-arming simultaneous death, loss of the recovery helper, signed release acceptance and production/system-resource recovery remain pending. The separate user IPv4 packet proof remains accepted; IPv6 kernel packet verification is next. No production daemon, VPN, TUN, active routes or DNS was changed.


### IPv6 passive packet fixture ready for user verification

- Extended the same childless packet helper and runner with `--family ipv6`. It selects fixed numeric ::1 TCP/UDP targets, preserves private certificate validation/SNI/ALPN and requires the complete IPv6 SOCKS UDP reverse address/marker. The authenticated SOCKS frontend stays private IPv4 loopback. No DNS lookup, outbound interface binding, installed daemon query or system network operation is introduced. The default IPv4 command remains supported.
- Added a separate native 31-instruction IPv6 BPF filter for both full 128-bit ::1 addresses, TCP/UDP and the newly reserved fixture ports in either direction. The decoder validates Darwin DLT_NULL AF_INET6, version, payload/transport bounds and fixed headers; extensions, fragments and jumbograms fail. Capture additionally checks its selected family. IPv6 is explicit in the sanitized report; an unlabeled historical IPv4 report cannot certify an IPv6 request. Reject-all before attachment, output-tap choice, bounded RAM, drop refusal and joined descriptor cleanup are preserved. No privileged capture was run autonomously.
- Eight pure Go packet tests PASS with races in 1.491 seconds: `/tmp/zarp-parity-packet-ipv6-go.log`. Native libpcap filter execution opens no BPF device. New cases change every source/destination address byte, both reserved directions/protocols, family, lengths, extension/fragment type and truncation; decoded IPv6 traffic must meet the same exact TCP/UDP proofs. Go vet PASS: `/tmp/zarp-parity-packet-ipv6-vet.log`. Ten runner tests PASS: `/tmp/zarp-parity-packet-ipv6-runner-tests.log`, including fixed IPv6 arguments in both modes and cross-family report refusal. Capture reports in those tests are synthetic, not kernel evidence.
- Actual unprivileged IPv6 fixture PASS, cleanup PASS, 8.56 seconds, two real HTTPS flows and two UDP associations: `/tmp/zarp-parity-packet-ipv6-loopback-result.log`; restricted report `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-packets-zf3pmbfy/report.json`. IPv4 regression also PASS, cleanup PASS, 7.39 seconds: `/tmp/zarp-parity-packet-ipv4-regression-result.log`; report `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-packets-d3sqcujl/report.json`. Both used helper SHA-256 `048d181216fc6700b5c9b8d4c8c27b09b96374160e61c08cadc3c786b6d6f2da`, with capture_started=false and both packet-proof flags false. These results do not pass the IPv6 kernel gate.
- Required user test, awaiting_user_test: from `/Users/andrumoskow/Documents/Zarp-MacOS`, run `scripts/test-parity-outer-packets.sh --run --family ipv6` and paste the RESULT. The current VPN may stay connected. macOS arm64, Go, Xcode command-line tools and sudo for passive read-only BPF access are required. Temporary resources are private loopback TLS/UDP listeners/relays, one lo0 BPF descriptor and private helper/cache/logs; only a sanitized restricted report remains after verified cleanup. No TUN, routes, DNS, proxy, firewall, production application/service or VPN changes. Build limit 180 seconds; worker limit 30 seconds, excluding sudo authorization.
- Continue from that RESULT: review schema, selected family, helper pin, zero drops, exact split/order evidence and cleanup. An incomplete or coalesced capture remains failed. The accepted historical IPv4 kernel result remains valid for its helper snapshot. Production fake/hop-limit, signed-release and user TUN/process gates remain pending; the unchanged production-status SKIP is not retried or treated as inactivity. This packet-only change does not alter the preceding checked proxy/Swift/app sources.
- Final handoff checks PASS: shell/Python syntax, fixed script help, local links/anchors in 18 Markdown files, new/changed-text punctuation, restricted report identity/permissions and `git diff --check`. All owned test workers completed. IPv6 passive capture is prepared and remains user-run only; no automatic capture, sudo, VPN operation or system-network test was performed.


### User IPv6 kernel packet evidence accepted

- Reviewed the supplied RESULT and matching restricted report `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-packets-5sigjhtz/report.json`. Version/scenario/capture phase, explicit IPv6 family, run ID/path and prepared helper SHA-256 `048d181216fc6700b5c9b8d4c8c27b09b96374160e61c08cadc3c786b6d6f2da` match. Directory/report permissions are 0700/0600; only report.json remains.
- User-run PASS, cleanup PASS, 6.56 seconds, 54 packets, zero capture drops and system_network_changed=false. Each of two fresh HTTPS outer flows has exact TCP payload boundaries `[1, 116, 1420]` and original ClientHello bytes. Two fresh UDP associations prove invalid-fake-first order on their original tuple and reverse echo. Both proof flags are true. This passes the IPv6 loopback kernel packet gate; the prior IPv4 proof also remains accepted.
- Production fake/hop-limit and ISP behavior, signed release acceptance and the separate TUN/process/DNS checks remain unverified. The production-status timeout is unchanged and does not imply inactivity. Continue the independent Stage 2 signed guardian construction/verification boundary, using private fake/ad-hoc fixtures without starting a production application or changing the VPN.


### Signed guardian construction boundary

- Added `proxy/guardian_inventory.go`: a separate trusted signed-bundle guardian constructor, fixed helper filename/identifier and final signed-file digest. Hash verification precedes the Developer ID requirement on the private 0500 snapshot; signature rejection precedes control-pipe creation and helper execution. Pins are copied construction data, never profile, IPC, environment or unsigned-manifest input. Omitted engines remain unavailable.
- Added fixed `--release-session` bootstrap with engine team/digests embedded only by trusted build flags. The guardian checks its private session-leader state, derives the bundle from its launcher-selected working directory, and constructs the signed parent-session supervisor. Empty/malformed embedded policy fails without development fallback. Recovery, finite lease, typed plans, and anonymous control channels remain unchanged; all accepted plans are loopback-only.
- Context7 Apple Security primary sources confirm the Developer ID CA/Application OIDs and ad-hoc distinction. Four new signed-guardian checks plus affected inventory cases PASS with races in 9.134 seconds: `/tmp/zarp-parity-signed-guardian-first-go.log`. They cover malformed/mutable policy, hash-before-signature/signature-before-execution, fixed release-mode fake execution/source replacement and native matching-identifier ad-hoc refusal. Native requirement compilation and valid ad-hoc signature verification use only owned fake binaries; no signing identity/keychain access or signed-release acceptance is claimed. Vet PASS: `/tmp/zarp-parity-signed-guardian-first-vet.log`.
- Four childless release-bootstrap cases PASS with races, 5.590 seconds: `/tmp/zarp-parity-signed-guardian-bootstrap-go.log`. Empty build pins ignore plausible environment values; fixed test build pins construct the private policy, malformed pins fail, and a process outside a private session refuses. These are construction tests, not engine/signature acceptance. Actual development pinned guardian regression PASS, cleanup PASS, 13 VLESS/Hysteria2 IPv4/IPv6 traffic and owner-crash cases in 19.77 seconds: `/tmp/zarp-parity-signed-guardian-pinned-result.log`; detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-9_ub8frj.log`.
- Final release signing/catalog generation, positive Developer ID acceptance and production activation remain pending. No identities were queried, no production program was executed and no VPN/system network setting changed. Continue independent outer UDP TTL/hop-limit support and prepare packet verification for the user's terminal; the prior invalid-fake tuple proofs alone do not establish those header fields.


### Outer UDP TTL/hop-limit implementation and user check preparation

- Added optional `FakeHopLimit` to the loopback UDP relay, bounded to 0..255. The association's sole upstream writer temporarily changes only its own connected socket for the first fake, restores the exact original policy, then permits real writes. Read/set/write/short-write/restore failure ends the association and closes that socket. Restoration failure is retained alongside write failure. Zero preserves the preceding relay behavior. No interface or system network policy changes.
- Extracted the existing WARP socket-option operations to internal/socketopts and kept its original wrappers/API. Relay policy is separate from WARP accounts and runtime. Context7 x/sys documentation was retrieved and pinned v0.48.0 sources checked. No upstream implementation was copied.
- The initial pinned/fixture IPv6 runs exposed an incorrect original-value restriction: Darwin reports -1 for inherited IPv6 policy. The draft rejected it. Apple's current IPv6 socket-option source confirms the sentinel; corrected code allows it only for IPv6 and restores it verbatim. New tests cover inherited policy and explicit value 73. Initial failed logs `/tmp/zarp-parity-udp-hoplimit-pinned-result.log` and `/tmp/zarp-parity-udp-hoplimit-ipv6-loopback-result.log` are not passes. The failed pinned runner correctly retained its private directory and cleanup FAIL; no observed process was adopted or signaled.
- Corrected safe relay/packet/WARP race checks PASS: `/tmp/zarp-parity-udp-hoplimit-corrected-go.log`. Pure fault cases verify read/set/write/short-write/restore ordering, absence of false success and combined errors. IPv4/IPv6 private connected-socket tests verify exact original-value restoration and same-tuple fake/real delivery. Four actual pinned Hysteria2 IPv4/IPv6 HTTPS/UDP and incorrect-pin cases PASS, cleanup PASS, 7.42 seconds, system_network_changed=false: `/tmp/zarp-parity-udp-hoplimit-corrected-pinned-result.log`; detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-6bx6udc8.log`.
- Added fixed `--fake-hop-limit` to the existing packet runner/helper. It requests value 1, retains separate requested/verified flags and bounded captured header pairs, and requires two fresh associations with actual fake header 1 followed by a real header greater than 1 on the same tuple. Pure decoders/validators reject unchanged/reversed/zero/missing limits, wrong scenario and stream-only proof. No BPF descriptor was opened autonomously.
- Required user commands, awaiting_user_test: `scripts/test-parity-outer-packets.sh --run --fake-hop-limit` and `scripts/test-parity-outer-packets.sh --run --family ipv6 --fake-hop-limit`, from the repository. Current VPN may remain connected. macOS arm64, Go, Xcode tools and sudo for passive read-only lo0 capture required. Only private loopback fixtures/socket limits/BPF descriptor/helper/cache/logs are temporary; a restricted sanitized report remains. No TUN, routes, DNS, proxy, firewall, installed app/service or VPN changes. Build limit 180 seconds; worker limit 30 seconds, excluding authorization. Paste both RESULT blocks. Do not count this kernel header gate as passed before review.
- Prior IPv4/IPv6 user split/order packet results remain accepted for their recorded snapshots. The invalid-fake fixture does not prove production fake shape, expiration on a routed path, endpoint invisibility or ISP effect. Positive signed release acceptance and the unchanged live system-adapter/Stage 1 gates remain pending.

- Final safe Go race suite PASS across eleven tested packages, including the new release bootstrap, signed guardian cases and existing native recovery; proxy 166.328 seconds: `/tmp/zarp-parity-signed-hoplimit-final-safe-go.log`. Vet all PASS: `/tmp/zarp-parity-signed-hoplimit-final-vet.log`. Both pinned-engine opt-ins and production socket overrides were cleared. Twelve packet runner tests PASS: `/tmp/zarp-parity-udp-hoplimit-final-runner-tests.log`; nine backend runner cases PASS: `/tmp/zarp-parity-udp-hoplimit-backend-runner-tests.log`.
- Final unprivileged IPv4 temporary-TTL fixture PASS, cleanup PASS, 10.09 seconds: `/tmp/zarp-parity-udp-hoplimit-final-ipv4-loopback-result.log`; report `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-packets-atv6oygb/report.json`. IPv6 fixture PASS, cleanup PASS, 9.81 seconds: `/tmp/zarp-parity-udp-hoplimit-final-ipv6-loopback-result.log`; report `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-packets-49lujs6i/report.json`. Both are two-flow/two-association stream/socket checks with capture_started=false, no packet proof and system_network_changed=false. Helper SHA-256 `b509a36a49148a946ddae21958801ad69747d270487b07a7ddd4f27c51592dee`. Matching reports, modes 0700/0600 and removal of all private work were verified. No BPF capture or autonomous sudo was run.

- Unsigned arm64 Release app rebuild PASS: `/tmp/zarp-parity-signed-hoplimit-app-build.log`. Built only, never installed, registered or launched; the embedded build daemon was ad-hoc signed without a signing identity. Swift sources were unchanged, retaining their preceding 261-test result. Shell/Python syntax, fixed CLI help, all local links/anchors in 18 Markdown documents, new/changed-text punctuation and `git diff --check` PASS. All owned test/build sessions completed. The only next requested terminal checks are the two prepared passive packet captures above; their TTL/hop-limit gate remains awaiting_user_test.


### User IPv4/IPv6 UDP header-limit evidence accepted

- Reviewed both supplied RESULTs and their matching private reports: IPv4 `zarp-parity-packets-69i0bij4` (6.31 seconds) and IPv6 `zarp-parity-packets-_18pom9c` (6.33 seconds), under the reported restricted temporary directory. Version/scenario/capture phase, selected families, run IDs/paths and prepared helper SHA-256 `b509a36a49148a946ddae21958801ad69747d270487b07a7ddd4f27c51592dee` match. Directory/report modes are 0700/0600, with only report.json remaining in each directory.
- Both user-run PASS with cleanup PASS, 54 packets each, zero capture drops, two HTTPS flows, two UDP associations and system_network_changed=false. Both fresh HTTPS outer tuples preserve exact `[1, 116, 1420]` split payloads. Both UDP associations in each family show same-tuple fake-first/real order and captured header pairs `[1, 64]`. Requested/verified hop-limit flags and TCP/UDP proof flags are true. The loopback temporary TTL/IPv6 hop-limit kernel gate is passed.
- This evidence does not establish production fake shape, expiration along a routed path, endpoint invisibility or ISP effectiveness. Signed-release acceptance, production activation and the separate real TUN/process/DNS gates remain pending. The installed production-status uncertainty is unchanged; no daemon/VPN action or repeated diagnostic is authorized. Continue the remaining independent bounded backend traffic-probe prerequisite before the live system gate.


### Owned bounded HTTPS probe prerequisite

- Added `proxy/probe.go` and `RuntimeOwner.ProbeLoopbackHTTPS`. A trusted private fixture specifies only a numeric loopback target, dedicated certificate/name, exact bounded marker and one shared deadline of at most 15 seconds. The method admits only the exact owned ready run, keeps one probe per run and returns only run/server/strategy fingerprints plus two first-response timings. It does not renew the lease, mutate health state, configure a frontend or expose a production IPC method.
- Each confirmation opens a fresh connection to that run's authenticated SOCKS listener. The strict greeting offers only username/password; an unauthenticated selection, wrong auth, foreign/domain/malformed bind reply or proxy failure cannot fall back to a direct connection. TLS chain/name/time verification remains enabled with the dedicated trust root and exact leaf certificate. ALPN must be http/1.1. Synchronous HTTP parsing bounds the complete decrypted response to 16 KiB and body to 4 KiB, refuses redirects/encoding/status/marker errors, and credits timings only after both full real HTTPS responses pass. No environment proxy, cookies, DNS lookup, WARP trace or public URL is used.
- Stop/lease loss/Close cancel and join admitted probes before publishing cleanup. Admission and cancellation share the owner lock so a WaitGroup cannot miss a newly admitted probe. Terminal owner state clears its retained probe credentials. A cancelled request frees only its probe slot; stale run IDs cannot touch a replacement. Socket-deadline expiry is checked alongside context state so timer publication races cannot credit an over-budget result or mislabel its timeout.
- Context7 Go documentation was retrieved, then pinned Go 1.27.1 and x/net v0.56.0 source inspected. The general SOCKS helper also offers no-auth; this private probe therefore uses an explicit bounded authenticated handshake instead. No library implementation was copied. An initial compile-only failure from an unused test import was fixed before execution; no failed run was counted as passed.
- Eight focused test groups PASS with races in 1.515 seconds: `/tmp/zarp-parity-owned-https-final-focused-go.log`. Actual private TLS/SOCKS fixtures cover fresh requests and unchanged lease, IPv6 inner targets, auth downgrade/wrong auth, malformed/foreign bind replies, wrong name/certificate, redirect, wrong/oversized body/headers/encoding, failed second confirmation, stale generation, shared timeout, handshake/body cancellation, busy refusal and stop/close joining. Twelve simultaneous admission/stop iterations exercise the ownership barrier. Production bounds and result/error formatting exclude private inputs.
- Eight actual pinned VLESS/Hysteria2 IPv4/IPv6 guardian-owned probe cases PASS, cleanup PASS, 18.02 seconds, system_network_changed=false: `/tmp/zarp-parity-owned-https-pinned-result.log`; detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-3hq5098b.log`. They use the same typed profile/owner path, confirm actual HTTPS or reject the wrong inner name/marker, then verify ordinary HTTPS/UDP and teardown. Fresh inner confirmations do not claim different remote endpoints or fresh engine-pooled outer flows. Thirteen existing pinned guardian traffic/crash regressions also PASS, cleanup PASS, 20.45 seconds: `/tmp/zarp-parity-owned-https-guardian-regression-result.log`; detail `/var/folders/jp/0kssyvp56ds2ddf4kc9j961r0000gn/T/zarp-parity-backend-t1yctzow.log`.
- Rechecked the prepared system-adapter script's entrypoints, guards, fake tests and unprivileged path. Four pure adapter cases and nine backend runner cases PASS: `/tmp/zarp-parity-owned-https-adapter-tests.log`, `/tmp/zarp-parity-owned-https-backend-runner-tests.log`. Actual `--loopback-check` PASS, cleanup PASS, 1.28 seconds, three private HTTPS/UDP/DNS fixture transfers, live_test_started=false, no default routes/system DNS configured: `/tmp/zarp-parity-owned-https-system-adapter-loopback-result.log`; report `/private/tmp/zarp-parity-adapter-cje1iqg0/report.json`. That result does not pass TUN/process policy. The live mode was not run autonomously.
- The next dependent acceptance check remains user-only: `scripts/test-parity-system-adapter.sh --run` from this repository. It requires no foreign VPN and an observably idle or absent production Zarp daemon. The earlier production-status-unknown SKIP remains unresolved; the script must keep refusing that state, and unchanged ping/status diagnostics are not retried. The user must choose and establish the test state; the agent does not stop/restart/install their app, daemon or VPN. Temporary changes are one private utun and the owned 198.18.0.2 host route plus private engines/producers/fixtures. Default routes/system DNS stay unchanged. macOS arm64, Go, pinned sing-box 1.13.14 and sudo required; build limit 180 seconds and worker limit 120 seconds, excluding sudo authorization. Paste the RESULT after an actual run. Never bypass the guard or count SKIP as passed.

- Final full safe Go race suite PASS across eleven tested packages, including all new probe cases and existing native ownership/recovery, proxy 170.664 seconds: `/tmp/zarp-parity-owned-https-final-safe-go.log`. The subsequent small deadline-classification refinement passes all eight focused groups with races in 1.574 seconds: `/tmp/zarp-parity-owned-https-deadline-focused-go.log`. Vet all PASS: `/tmp/zarp-parity-owned-https-deadline-vet.log`. No broad suite was repeated without a new reason. Both live engine opt-ins and production socket override were cleared for the safe suite.
- Confirmed the production daemon's dependency graph excludes proxy/relay: `/tmp/zarp-parity-owned-https-production-dependencies.log`. Production Go/Swift/app inputs are unchanged in this unit; their prior 261-test Swift and unsigned arm64 build results remain applicable. Shell/Python syntax, script help, local links/anchors in all 18 Markdown documents, changed/new text punctuation and `git diff --check` PASS. The matching adapter loopback report has the expected identity and 0700/0600 modes. All owned sessions completed; no production status probe, service action, BPF capture, real tunnel or active network change was performed autonomously.
- Continuation after user system-adapter RESULT: inspect actual selected/excluded TCP/UDP/DNS outcomes and owned cleanup before deciding the policy frontend and wiring dependent server runtime/IPC. PASS must include a real live start and the required checks; loopback-only or SKIP is insufficient. If the unchanged production-status guard still refuses, retain the gate and require a user-established observable safe state. Do not bypass that guard, repeat unchanged diagnostics or stop/restart the user's daemon/VPN.


### Latest system-adapter refusal and bounded account presence checks

- Reviewed the user's latest pasted RESULT for `zarp-parity-adapter-g0nc0trg`: SKIP, cleanup PASS, 3.58 seconds, `production_status_unknown`, empty checks and live_test_started=false. Default routes and system DNS were not configured. The matching directory is root-owned 0700, so the unprivileged report read was denied. No independent verification of that report is claimed. The live gate remains unpassed and the guard is unchanged.
- Source review found both ping/status can reach the account loader. Replaced its unbounded file read with nonblocking/no-follow open, regular-file and group/other write-permission checks, a 64 KiB size/read limit and static redacted errors. Missing-file errno identity remains compatible. This addresses a reproducible FIFO/unbounded-input risk, not an established cause of the installed daemon's timeout. Regular storage I/O has no hard kernel deadline. No fix was installed or running daemon changed.
- Private tests cover a valid account, FIFO without a writer, directory, final symlinks, oversized/unsafe files, malformed or incomplete data and diagnostic redaction. A separate private fake manager/IPC socket proves concurrent ping/status remain responsive with a FIFO account and terminate cleanly. An initial errno-wrapping regression failed the missing-file test, was fixed, and is not counted as passed.
- A sandbox run denied loopback/Unix socket binds, including existing tests; it did not establish a source regression. Reviewed WARP and daemon race suites PASS outside that sandbox: warp 3.160 seconds, daemon 3.681 seconds, `/tmp/zarp-parity-account-bounds-unsandboxed-go.log`. Live-engine opt-ins and production socket override were cleared. Vet all PASS: `/tmp/zarp-parity-account-bounds-final-vet.log`. The preceding full safe suite remains applicable to unchanged proxy/relay packages; no broad repeat was needed.
- Unsigned arm64 Release rebuild PASS: `/tmp/zarp-parity-account-bounds-unsandboxed-app-build.log`. The first sandbox build failed on required SwiftPM/cache temporary-file access; the authorized build retry succeeded. Built only, never installed, registered or launched. Swift inputs are unchanged; their preceding 261-test result remains applicable.

### Read-only installation inspection prepared

- Added `scripts/test-parity-production-inspect.sh` and its isolated Python entrypoint. It never connects to production IPC, observes/configures networking, attaches a debugger, starts/stops/restarts a service or executes a discovered binary. Only fixed read-only launchctl/ps/codesign commands and native path/code metadata calls are available. Any timeout/interruption signals and reaps only the inspector's exact owned unreaped read-tool child. Observed daemon PIDs are never control/adoption authority.
- Reports allowlisted file/service/process metadata and bounded SHA-256/CDHash comparisons where available. Raw paths, environment/arguments, account/log contents and private inputs are omitted. launchctl output and process identity comparisons are advisory; PASS means diagnostic metadata only, never idle or live-test acceptance. The optional fixed-format adapter ID reads only its root-owned protected report, rejects special files/replacement/oversize and reduces fields before output. No temporary files are created. Each read tool has a three-second limit, with a cooperative overall 25-second observation budget and at most one additional second per owned tool for cleanup.
- Thirteen pure fixture/fake-tool groups PASS: `/tmp/zarp-parity-production-inspect-final-unit.log`. They cover command mutation/injection refusal, expired budget, timeout/output bounds, interruption/reaping/cleanup failure, nested secret redaction and ambiguous service parsing, file types and binary replacement, strict signature/process parsing, fixed read-only native operations, report ownership/mode/type/schema/redaction and explicit absence of production-state inference. No installed process is queried by these tests.
- Read-only unprivileged observations show a root-owned regular 0600 bounded account file, a root-owned 0660 socket and the same launchd-owned zarpd process PID 96212 using about two CPU cores. Thus the FIFO fixture is not evidence for the actual installed cause. SMAppService's launchctl output omits an executable program and reports a submitted-service marker instead of a plist path. Native code-hash metadata returned errno 85, retained as uncertainty rather than an inactivity claim. Partial sanitized observations: `/tmp/zarp-parity-production-inspect-final-unprivileged.log` and `/tmp/zarp-parity-production-inspect-path-unprivileged.log`. They are SKIP, not accepted gates; no production process control was attempted.
- The optional restricted report read correctly returns SKIP/file_metadata_permission when run unprivileged: `/tmp/zarp-parity-production-inspect-restricted-report.log`. Required next user command, awaiting_user_test: `sudo scripts/test-parity-production-inspect.sh --inspect --adapter-run zarp-parity-adapter-g0nc0trg` from this repository. Root access is for the restricted report and process metadata. The VPN can stay connected; no temporary network/service changes occur. Paste the sanitized RESULT. This gathers new privileged evidence rather than repeating stalled ping/status or the unchanged live TUN refusal.
- Python/shell syntax, fixed CLI help, Go formatting, all links/anchors in 18 Markdown documents, new/changed-text punctuation and `git diff --check` PASS. Current native APIs were checked against the local SDK and official Apple sources after Context7 lookup. All owned test/build sessions completed. No live tunnel, route/DNS change, production IPC retry, daemon/service action or VPN operation was performed.


### Privileged user evidence reviewed, 2026-10-19

- Reviewed the complete supplied version 1 production-inspect RESULT for `--adapter-run zarp-parity-adapter-g0nc0trg`. The privileged report reader confirms the matching adapter's SKIP/production_status_unknown, cleanup PASS, zero checks, no live start and no default-route/system-DNS configuration. The inspector itself is SKIP/kernel_metadata_unknown, errno 85, 0.02 seconds, cleanup PASS and system_network_changed=false. Production-state inference remains explicitly false.
- Root still sees PID 96212 as launchd-owned, state Rs and 196.4% CPU. Executable path is unavailable with errno 3; on-disk program metadata is unavailable. The protected regular 0600 account/socket metadata and local-build hash match the preceding observed values. No executing-image comparison succeeded and no installed fix or root cause is established. The shell parse error followed the complete JSON RESULT; likely output was subsequently interpreted as shell input. It does not convert either SKIP into PASS.
- Do not repeat the inspector, ping/status diagnostic or live test unchanged in this state. Never stop/restart/control the observed PID or installed service autonomously. Continue safe lifecycle prerequisites, then require a user-established absent or observable idle production service for the real TUN gate.

### Explicit network activity and joined teardown

- Added always-emitted additive `status.networkBusy` metadata while retaining protocol 3 and persistent-only GUI adoption. It covers admitted/queued dials, scan/test connections, teardown, terminal shutdown and known cleanup/recovery failures. The manual guard now requires connected=false and an explicit boolean networkBusy=false. A missing/invalid field from an older daemon is unknown. Active/uncertain state still refuses startup; no guard was relaxed.
- A closing registry entry stays until its single Close returns. Concurrent app/lease/loss/replacement requests join the same result. A new open cannot skip a teardown another request already started; a cancelled replacement cannot dial after joining cleanup. Scan connections and closing handles are never GUI-adoptable. Status reads immutable published interface metadata, and account-file observation no longer holds the tunnel registry mutex.
- Shutdown closes admission, cancels its exact in-flight dial and joins it through the open semaphore. A late returned connection is closed before shutdown completes. Queued/new requests cannot revive a stopped manager. Restart acknowledges only after joined successful cleanup; a reported failure refuses the exit hook rather than claiming a clean restart. None of these handlers was called against the installed daemon.
- Conn.Close now retains reported teardown errors. Registered or unpublished cleanup failure and startup DNS/exclusion recovery errors keep the manager busy and refuse further tunnel starts. Raw cleanup errors are replaced by a fixed IPC message. Actual route/DNS restoration remains independently required by the live test; nil return alone is not system proof. Underlying cancellation/Close cooperation remains required; no timeout falsely publishes idle.
- Eight new daemon test groups cover opening/scan/terminal state, competing closes, cancelled replacement, natural loss, late and queued shutdown dials, sticky cleanup failures, startup failure, account-lock separation, cached interface metadata, and concurrent device/route close failure. All use fake connections/runners. Test harness cleanup now joins its fake manager; the existing natural-loss assertion waits for network work to end rather than only connected=false. An initial duplicate test helper declaration was fixed before the passing run. No failed run is counted as a pass.

### Recovery failure preservation

- A failed IPv4 rollback, failed partial IPv6 rollback or uncertain DNS rollback is fatal with a typed cleanup marker. Other owned cleanup steps are still attempted. Uncertain DNS cannot become an ordinary warning on an otherwise ready tunnel. RealOpener propagates that marker to the manager's sticky busy state; device/route teardown errors likewise reach the manager.
- DNS apply no longer assumes a failed setter left state unchanged. A confirmed rollback removes its own backup; a failed rollback retains original recovery data. Failed backup removal is reported. Corrupt DNS recovery data is retained and cannot become commands or a fresh successful override.
- Exclusion undo retains its record if deletion fails. Recovery serializes against journal updates, clears verified successes/external replacements, and retains only failed entries. Journal write/removal errors propagate. Corrupt/null/invalid address records are preserved, rejected without route commands and cannot be silently overwritten by add/remove. Existing foreign-route ownership checks remain intact. Recovery files are not production-path inputs to any autonomous test.
- Five new fake recovery-fault groups and updated DNS/journal cases verify IPv4/IPv6 rollback failure, preservation of unrelated routes, a DNS setter that changes state before reporting failure, confirmed/uncertain restoration, owned deletion retry, partial journal recovery and invalid-record refusal. These are fake state transitions, not live restoration or VPN-effectiveness evidence. Later DNS/IPv6/foreign-change policy and real pump/process recovery acceptance remain gated by the staged system tests.

### Checks and next required manual state

- Full safe Go race suite PASS across eleven tested packages, including all production lifecycle/rollback changes then present and unchanged proxy recovery: `/tmp/zarp-parity-lifecycle-full-safe-go.log` (proxy 171.291 seconds). Live engine opt-ins and production socket override were cleared. The final exclusion-journal refinement and test-fixture joining pass affected route/daemon/IPC/daemon-main race checks: `/tmp/zarp-parity-lifecycle-recovery-final-go.log` (1.441/3.137/1.724/1.637 seconds). Vet all PASS: `/tmp/zarp-parity-lifecycle-recovery-final-vet.log`. No unaffected broad suite was repeated for that refinement.
- Swift PASS, 263 tests and zero failures: `/tmp/zarp-parity-lifecycle-swift.log`. Shared wire fixtures include the additive field. Busy scan/cleanup replies remain unadoptable; legacy idle replies still decode for GUI reconciliation without authorizing a privileged test.
- Manual runner fake/private-IPC self-test PASS: `/tmp/zarp-parity-lifecycle-manual-selftest.log`. Sandbox initially denied its owned Unix listener; the authorized safe retry passed. Four pure adapter and thirteen inspector cases PASS: `/tmp/zarp-parity-lifecycle-adapter-unit.log`, `/tmp/zarp-parity-lifecycle-inspect-unit.log`. The initial broad Go attempt also encountered that socket restriction and the duplicate test helper; neither is treated as passed. A wrong-directory formatting command was corrected before subsequent formatting/checks.
- Unsigned arm64 Release rebuild PASS after the final recovery changes: `/tmp/zarp-parity-lifecycle-recovery-final-app-build.log`. Built only with local ad-hoc signing; never installed, registered or launched. Shell/Python syntax, Go formatting, all 18 Markdown documents' local links/anchors, new/changed punctuation and `git diff --check` PASS. All owned test/build sessions completed. No production IPC request, daemon/service action, BPF capture, real TUN, active route/DNS change or VPN operation was performed autonomously.
- Critical T04 gate remains awaiting_user_test. The user must choose a safe test window with no foreign VPN conflict and production Zarp absent or explicitly observable idle. Closing its window does not unregister the background service. The installed app's Settings > zarpd daemon > Uninstall action is the user's removal path when appropriate for their connection; the agent does not open the app or invoke this action. Do not retry unchanged diagnostics to infer safety.
- Once that prerequisite is established, exact command from this repository: `scripts/test-parity-system-adapter.sh --run`. It requests sudo itself after private preparation. Prerequisites: macOS arm64, Go and pinned sing-box 1.13.14. Temporary resources: one private utun, owned 198.18.0.2/32 host route, private engine/producer/HTTPS/UDP/DNS fixtures and restricted reports. No default routes or system DNS configuration. Build limit 180 seconds; worker limit 120 seconds, excluding authorization. It never disconnects another VPN and removes only owned resources. Paste its RESULT here, not into the terminal as a command. PASS must include live start, all six selected/excluded TCP/UDP/DNS checks and verified cleanup before policy/runtime/frontend work can proceed. SKIP remains unpassed.


### Repeated user refusal and preserved blocker details

- Reviewed the user's version 1 live-phase RESULT for `zarp-parity-adapter-o_f8tzdy`, reported path `/private/tmp/zarp-parity-adapter-o_f8tzdy/report.json`. Status SKIP/production_status_unknown, cleanup PASS, duration 3.56 seconds, live_test_started=false, checks empty, no default routes/system DNS configured. The matching file has not been independently read. Nothing in this result passes TCP/UDP/DNS process policy or resolves the earlier production-state uncertainty.
- Requested the missing setup fact: whether the user only closed the window/client, Uninstall showed Not installed, or Uninstall failed. Do not infer that unregister completed from another skipped run. Do not repeat the same production probes, request another unchanged live attempt, remove a production socket, or control a PID/service to make the guard pass.
- Found that the adapter worker discarded the underlying sanitized IPC failure details already provided by its guard. Added production_blocker_details and additive RESULT details limited to known static error codes/phases plus bounded integer errno/peer_pid/response_bytes. Raw IPC responses, arbitrary fields, target data, tokens, wrong types, booleans-as-integers and oversized numbers are omitted. This changes reporting only; all guards and test prerequisites remain intact.
- Five pure adapter fixture cases PASS in 0.214 seconds: `/tmp/zarp-parity-adapter-blocker-details-unit.log`. The existing unknown-state case now proves preserved timeout phase/peer/zero-byte evidence, unchanged SKIP/cleanup, no system child/route command and secret exclusion. A new case covers socket-error errno, unsupported/private code/phase, malformed containers and numeric bounds. Python syntax, shell syntax, local documentation links, new-text punctuation and `git diff --check` pass. Go/Swift/app inputs are unchanged in this reporting unit; their previous checked results remain applicable. No live mode, production IPC query, network observation/action, app/service operation or VPN change was performed autonomously.
- Continue after the user's setup clarification. If unregister was never attempted, the user still needs to establish the previously stated test prerequisite when appropriate for their connection. If it showed Not installed or an error, investigate that specific new fact safely before preparing another command. No test is requested in the same unchanged state merely to obtain the new details.

### User clarified the test setup

- The user disconnected only Happ, their own VPN, before testing. They did not report using Zarp Settings > zarpd daemon > Uninstall. This explains why removing the Happ conflict did not establish the separate Zarp daemon's state; it does not establish the cause of that daemon's stalled IPC.
- Preserve Happ during autonomous work. No app launch, service unregister/restart, process control, network observation or route/DNS change was performed for this clarification. No further unchanged diagnostic is needed.
- The next user-controlled prerequisite is Zarp's background service, via Settings > zarpd daemon > Uninstall, when the user chooses an appropriate test window. Wait for Not installed; if it fails, return that error rather than repeat the live test. Only after the user establishes the prerequisite and chooses a state without a foreign VPN conflict should they run `scripts/test-parity-system-adapter.sh --run`. It requests sudo, uses one private utun/owned host route, preserves default routes/system DNS and retains its 180-second build/120-second worker limits. This is the same prepared gate, not a bypass or an accepted PASS.
- Documentation-only clarification: local links/anchors and `git diff --check` pass. Prior source checks remain applicable; no source or tests changed.

### Daemon removed by user, stale socket identified

- Reviewed the supplied version 1 backend-system-adapter live-phase RESULT for `zarp-parity-adapter-tph69ga5`, path `/private/tmp/zarp-parity-adapter-tph69ga5/report.json`: SKIP/production_status_unknown, cleanup PASS, 0.56 seconds, checks empty, live_test_started=false and no default-route/system-DNS configuration. The newly preserved details show ipc_socket_error/errno 61. The matching file was not independently read. This differs from the preceding response timeouts; it is not live acceptance.
- The user reports installing Zarp and removing its daemon before this test. Fresh read-only `launchctl print system/io.github.zarp.mac.zarpd` returned service not found (113). A complete read-only ps inventory reported no malformed rows and no zarpd accounting name. The sandbox denied ps; the authorized metadata-only retry succeeded. Metadata on /var/run/zarpd.sock still shows a root-owned 0660 socket, not a symlink. These snapshots plus the user's refused connection identify a stale production endpoint after their removal action. They do not retroactively establish the earlier PID's cause or pass any tunnel test.
- Context7 had no relevant launchctl documentation; local launchctl/ps manuals and their limitations were checked. No process was signaled or controlled, no service was started/stopped/reconfigured, no production IPC probe was repeated and no network state was changed. Happ remains untouched.
- Keep the existing production and foreign-VPN guards unchanged. Do not add an ECONNREFUSED exception, force flag, automatic production-socket cleanup or service-state inference to the test. Human-readable service/process metadata is a current diagnostic observation, not an ongoing lease or authority to bypass a guard.
- Concrete user-run setup, only while Zarp's background service remains uninstalled: `sudo /bin/rm /var/run/zarpd.sock`. This deletes exactly the observed stale socket pathname, with no recursion/wildcards or process/service action. The agent does not execute it. This explicit production-path cleanup is separate from the test's cleanup of owned resources. The ordinary test will recheck all existing guards after the user's setup action.
- Next command in the user's chosen test window with Happ disconnected by the user: `sudo /bin/rm /var/run/zarpd.sock && scripts/test-parity-system-adapter.sh --run`, from this repository. The test remains isolated and user-run, with the same one private utun/host-route resources, unchanged default routes/system DNS, sudo and pinned-engine prerequisites, 180-second build and 120-second worker limits. Paste RESULT; if stale-file removal fails, return the error instead. No live gate passes until its selected/excluded TCP/UDP/DNS checks and actual cleanup are reviewed.

### Direct interface host-route ownership correction

- Latest supplied RESULT for `zarp-parity-adapter-cd58br0g`: FAIL/route_ownership, live_test_started=true, checks empty, 1.65 seconds, cleanup PASS and network_baseline_matches=true. No default routes or system DNS configured. This establishes startup past preflight and successful reported cleanup, not process-policy acceptance. Its root-owned 0700 report directory was observed, but the report was not independently read. The earlier stale-socket setup step is complete; no removal is requested again.
- Reproduced the test defect with a fake Darwin `route get` direct-host response lacking a gateway line. The new regression failed against the old matcher: `/tmp/zarp-parity-adapter-direct-route-reproduction.log`. Apple's [route source](https://github.com/apple-oss-distributions/network_cmds/blob/main/route.tproj/route.c#L1773) prints that field only for RTF_GATEWAY; local route documentation confirms `-interface` creates a direct route. Context7 had no matching formatter documentation, so this conclusion uses the official source and local manual. The failed user run did not retain its native route fields in RESULT; the defect is reproduced, but that exact observation is not claimed.
- Corrected only the private adapter's owned-route identity and normalized missing gateway to an empty journal value. Require the exact measurement address, a bounded private utun name in the worker's generated range, UP/HOST/STATIC, an allowlisted direct-route flag set and no gateway. Actual and journal identities must both validate and retain the same canonical flags. Changed interfaces/destinations/flags, indirect/reject/blackhole/dynamic/unknown routes and invalid journals cannot authorize deletion. Invalid journals fail before any command. Production and foreign-VPN guards are unchanged.
- Added sanitized RESULT route_ownership comparisons and known flag names. No raw route output, addresses, private paths or arbitrary flag text are echoed. Nine pure tests PASS, including absent-gateway parsing, exact owned cleanup, external replacement preservation, malformed metadata/redaction and a completely fake six-case live-worker lifecycle: `/tmp/zarp-parity-adapter-direct-route-final-unit.log`. That fake lifecycle is not live evidence.
- Reviewed `--loopback-check` before running: clears inherited socket/engine overrides, builds privately, validates pinned engine configuration without Start and uses numeric loopback HTTPS/UDP/DNS only. Actual safe RESULT PASS, cleanup PASS, three selected fixture payloads, 1.26 seconds, live_test_started=false: `/tmp/zarp-parity-adapter-direct-route-loopback.log`. Independently read its matching private report `/private/tmp/zarp-parity-adapter-dimcampo/report.json`; only restricted manifest/report remain after cleanup. No TUN, system route/DNS changes, production IPC or service operations were executed autonomously.
- Python syntax, shell syntax, launcher help, documentation links/anchors (18 Markdown files), prohibited-punctuation checks and `git diff --check` pass. No Go/Swift/app changes in this unit; earlier safe race, vet, 263 Swift tests and unsigned app build remain applicable. The real TUN/process gate still requires a new user RESULT, all six selected/excluded checks and actual owned cleanup.
- Exact next user command from this repository: `scripts/test-parity-system-adapter.sh --run`. macOS arm64, Go, pinned sing-box 1.13.14 and sudo required. Temporary resources: one private utun, reserved 198.18.0.2/32 host route and private engines/producers/fixtures. Default routes/system DNS unchanged. Build limit 180 seconds; worker limit 120 seconds, excluding sudo authorization. Choose the network window yourself and paste RESULT. No stale-socket removal or unchanged production diagnostic is requested.

### Startup failure and bounded guardian diagnostics

- Received supplied version 1 RESULT for `zarp-parity-adapter-covd51sy`, report path `/private/tmp/zarp-parity-adapter-covd51sy/report.json`: FAIL/startup, 1.63 seconds, live_test_started=true, zero checks, cleanup PASS and network_baseline_matches=true. No default routes or system DNS configured. Observed its root-owned 0700 directory only; matching report not independently read. Live startup began, but a working TUN or native route is not established by this result. Neither this gate nor T04/T05 is passed.
- Inspection found both guardian errors and engine stderr discarded. The existing cleanup marker recorded only engine_stopped, so the supplied RESULT cannot recover the cause or distinguish guardian refusal from an engine startup error. No cause or startup fix is claimed. Kept all production/foreign guards, route ownership, process selection and cleanup requirements intact.
- Added nonblocking draining of the exact owned child's stderr. At most 32 KiB is retained in memory, with bounded work per watchdog turn; further bytes are discarded without blocking the child. Raw bytes never enter files or reports. Enable only error-level engine logs. Guardian cleanup records allowlisted phase, spawned boolean, child exit code or spawn errno, capture facts and fixed error markers. The worker applies a second allowlist before including engine_diagnostics in RESULT. Unknown/private message text, paths and arbitrary fields are discarded. Phase running means spawned, not ready; markers are observational and cannot certify a cause or successful traffic.
- Context7 consulted for pinned sing-box 1.13.14 logging. Critical stderr/defaults and startup failure behavior checked against the official [log implementation](https://github.com/SagerNet/sing-box/blob/v1.13.14/log/log.go) and [run entrypoint](https://github.com/SagerNet/sing-box/blob/v1.13.14/cmd/sing-box/cmd_run.go). No upstream implementation copied. No daemon/service, current VPN, production socket or system network was modified autonomously.
- Fourteen safe tests PASS in 0.230 seconds: `/tmp/zarp-parity-adapter-startup-final-unit.log`. Added real anonymous-pipe bound/nonblocking/EOF/redaction coverage, allowlisted report validation, fake guardian refusal without a child, early child exit without signaling a reaped process, and fake live-worker startup failure with no route mutation or traffic and verified cleanup. Existing direct-route, parent-death and six-case fake lifecycle cases still pass. These are not system-TUN evidence.
- Reviewed safe --loopback-check entrypoint and cleared inherited production socket/engine overrides. First sandboxed loopback attempt failed with PermissionError at fixture binding, cleanup PASS and live_test_started=false: `/tmp/zarp-parity-adapter-startup-loopback.log`. This is a tool restriction, not a user startup diagnosis. The reviewed loopback-only check then passed with socket permission: all three real HTTPS/UDP/DNS payloads, cleanup PASS, 1.23 seconds, live_test_started=false: `/tmp/zarp-parity-adapter-startup-loopback-verified.log`. Its report is `/private/tmp/zarp-parity-adapter-xnh4nehf/report.json`. No TUN or engine Start was used autonomously.
- No Go/Swift/app changes; earlier race/vet/263 Swift tests/unsigned build remain applicable. Next required check remains user-only: `scripts/test-parity-system-adapter.sh --run` from this repository, then paste RESULT including the new engine_diagnostics if startup fails. Same macOS arm64/Go/pinned sing-box/sudo prerequisites, one private utun/reserved host route/private fixtures, unchanged default routes/system DNS, 180-second build and 120-second worker limits excluding authorization. No socket deletion, production diagnostic or user VPN disconnection by the agent is requested. Dependent runtime activation waits for all six real selected/excluded checks and owned cleanup.
- Final verification: Python/shell syntax, launcher help, documentation links/anchors across 18 Markdown files, prohibited-punctuation checks and `git diff --check` PASS. Independently read the matching loopback report for xnh4nehf; only restricted manifest/report remain after cleanup. No test child or tool session remains running.
- This is documentation/setup clarification only. Prior source checks remain applicable; local links/anchors, new text punctuation and `git diff --check` pass. No real test or production-path mutation was executed autonomously.
