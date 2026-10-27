# Backend parity PoC

This is Stage 2 evidence, not an enabled production server mode. Stage 1 live WARP checks
remain pending. No real TUN, routes, DNS or process-routing acceptance is claimed.

## Reproduce the safe loopback check

On macOS arm64 with Go 1.27.1 installed, run from the repository:

```sh
python3 scripts/test-parity-backend-loopback.py --fetch
```

`--fetch` obtains the pinned release through the existing connection only when missing.
For the pinned Xray candidate, use:

```sh
python3 scripts/test-parity-backend-loopback.py --engine xray --fetch
```

No sudo is used. The script checks the archive and executable hashes, then runs the
reviewed Go relay suite. All listeners and targets are loopback. Server routes permit
only the private HTTPS and UDP markers, rejecting other destinations. Each listener
uses private session credentials. Certificates and keys live in restricted temporary
storage and are removed during cleanup. The supervisor owns an isolated process group,
handles SIGINT/SIGTERM and a 180-second suite limit, and stops only its private children.
Individual engine cases have a 20-second context deadline. It prints a sanitized RESULT
and retains a restricted test log. A missing engine without `--fetch` gives SKIP.

## Pin and provenance

- Compatibility PoC: sing-box 1.13.14, revision `25a600db24f7680ad9806ce5427bd0ab8afe1114`.
- [Official release](https://github.com/SagerNet/sing-box/releases/tag/v1.13.14).
- [Darwin arm64 archive](https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-darwin-arm64.tar.gz).
- Archive SHA-256: `73e8967b0fc08e17bce4263ca56ebc394822401a16497a1c4e02316c888202ab`.
- Executable SHA-256: `813d8effd02a19572a8d75aef29fc073101404ca535b2496be86f21827c7684d`.

GitHub reported 1.14.3 as the latest stable sing-box release on 2026-10-13. This PoC
uses the reference-compatible 1.13.14 rather than silently changing configurations.
The official Xray stable endpoint reported 26.3.27; the reference candidates
[26.7.28](https://github.com/XTLS/Xray-core/releases/tag/v26.7.28) and
[26.9.30](https://github.com/XTLS/Xray-core/releases/tag/v26.9.30) are marked prerelease.
Xray 26.9.30 is now a checksum-pinned loopback PoC choice, not a production
backend selection. Its prerelease status is retained explicitly.

The binary stays under ignored `build/parity-backends`; it is not bundled or installed.
The [upstream license](https://github.com/SagerNet/sing-box/blob/v1.13.14/LICENSE) is
GPL3 or later with an additional derivative naming/association clause. The MIT project
contains an independently written transport relay and tests, not copied GPL code.
Using separate processes does not alone remove license obligations. Distribution needs
a reviewed source/notices/license plan and signing before a backend is packaged.

Version-specific design evidence:

- [Detour implementation](https://github.com/SagerNet/sing-box/blob/v1.13.14/common/dialer/detour.go): both stream dialing and packet listeners use the selected outbound.
- [SOCKS outbound](https://github.com/SagerNet/sing-box/blob/v1.13.14/docs/configuration/outbound/socks.md): TCP and UDP support.
- [TLS implementation](https://github.com/SagerNet/sing-box/blob/v1.13.14/common/tls/std_client.go): certificate trust and public-key pin configurations are mutually exclusive. Pins have a dedicated peer-key verifier.
- [Route actions](https://github.com/SagerNet/sing-box/blob/v1.13.14/docs/configuration/route/rule_action.md): rejection after the allowed private targets.

Context7 version-specific documentation was consulted and critical detour/TLS behavior
was checked against the pinned source. Moving documentation is not treated as proof
that the pinned binary accepts an option; each generated configuration runs `check`
and then carries actual traffic.

## Evidence obtained

The explicit pinned-engine race suite passed on this working machine, including IPv4
and IPv6 outer-server cases for all three protocols:

| Backend | Real payload | Outer technique | Failure checks |
|---|---|---|---|
| VLESS TLS | Two fresh HTTPS transfers and UDP echo | Three outer TLS stream writes, SNI and ALPN observed on new flows | Wrong backend pin and UUID reject transfer |
| Trojan TLS | Two fresh HTTPS transfers and UDP echo | Three outer TLS stream writes, SNI and ALPN observed on new flows | Wrong backend pin and password reject transfer |
| Hysteria2 TLS | HTTPS and UDP echo, separate fresh-session case | Invalid loopback fake before first real outer QUIC datagram on its own socket | Wrong backend pin and password reject transfer |

Valid generated public-key pins also carried real payloads on all three backends.
Ordinary TLS cases use a dedicated trusted certificate; inner HTTPS verification stays
enabled. The outer TCP SNI is `outer.example.test`, distinct from the numeric inner
HTTPS destination. TCP observers report `http/1.1`. Hysteria2 client/server configure
`h3` and complete an actual TLS-protected QUIC transfer; this does not claim extraction
of encrypted QUIC SNI from a packet capture.

Independent IPv4/IPv6 UDP receiver tests establish fake-first ordering, matching source
address/port, real reverse datagrams and no repeated fake within one association.
SOCKS fragmentation, wrong targets and wrong credentials are rejected. Real Go TLS
ClientHello tests cover partial reads and a hostname crossing TLS records without
rewriting original bytes. Cancellation before the TLS handshake and during a UDP
association closes blocked workers. The runner's isolated process-group stop was
also checked with its own temporary sleeping child.

TCP write counters do not establish exact kernel packet boundaries or ISP effectiveness.
The UDP fake is deliberately invalid test data, not yet a portable production strategy.
Hysteria2 can reuse a QUIC session for multiple application requests. A new application
request must not be misreported as a new outer session. New authenticated associations
get separate sockets and a fresh fake; integration explicitly starts a fresh backend
session to verify this property.

## Remaining gates

- Live IPv6 control/data-plane acceptance. External backend loopback IPv6 now passes.
- Production fake shape, expiration on a routed path and ISP effect. User IPv4/IPv6
  loopback kernel split/order and temporary UDP TTL/hop-limit proofs have passed.
- ECH and the remaining XHTTP parameter/downloadSettings combinations. The minimal
  pinned Xray detour and stream-one H2/H3 loopback cases now pass.
- Production supervisor integration, signed predefined binary locations, whole-chain
  ownership, daemon-death child cleanup, GUI adoption/lease renewal, daemon/client
  typed IPC, imports and settings migration. Draft contracts advertise WARP only.
- User-run real macOS TUN, DNS, routes, selected-app TCP/UDP/DNS and crash recovery.
  Prepare an isolated automated manual scenario before requesting these results.
- Packaging, licensing review and visual UI checks.

These gates prevent enabling production server capability. Successful loopback transfer
is evidence for the external relay architecture, not completion of T04 or T05.

The earlier user system-adapter run `zarp-parity-adapter-g0nc0trg` skipped with
`production_status_unknown` before any live check. Cleanup passed; no TUN or
default-route/system-DNS configuration started. Its root-owned report remains
unread by the unprivileged agent. The user's 2026-10-19 privileged inspector RESULT
confirms the restricted report has zero checks, no live start and cleanup PASS.
Inspection itself is SKIP: native code metadata remains unknown (errno 85), the
process path is unavailable (errno 3), and PID 96212 is still launchd-owned with
about 196% CPU. None of these observations establishes idle or a cause of the
stalled IPC. No unchanged diagnostic or live retry is warranted in that state.
A separate
[installation inspector](DEVELOPMENT.md) collects only read-only, redacted metadata
without repeating stalled production IPC requests. Its diagnostic status never
passes this live gate. The guard and production WARP-only capability stay intact.

The current daemon adds explicit networkBusy status for opening/scan/closing work
and known recovery failures. The manual guard requires that field to be explicitly
false alongside connected=false; legacy absence is unknown. Joined teardown and
terminal shutdown are checked with fake connections, including late-dial cleanup.
Failed route/DNS rollbacks and journal deletion errors retain uncertainty rather
than becoming warnings or losing recovery evidence. These fixes are local source
changes, not a deployment or a repair of PID 96212. The user must establish an
absent or observable idle production service before the prepared TUN check can run.

The later user run `zarp-parity-adapter-o_f8tzdy` also returned
production_status_unknown: SKIP, cleanup PASS, 3.56 seconds, no live start and zero
checks. The user's unregister outcome needs clarification before another attempt.
The worker now preserves only bounded, allowlisted IPC blocker facts in RESULT
details, distinguishing a timeout, refused socket or missing activity metadata
without raw responses or secrets. This reporting refinement does not change any
guard or establish a safe state. No unchanged rerun is requested for it.

The user subsequently removed Zarp's daemon. Earlier run `zarp-parity-adapter-tph69ga5`
remains SKIP with zero checks, but now reports ipc_socket_error/errno 61 in 0.56
seconds. Read-only service/process observations find no registered service or
zarpd process; its root-owned socket pathname remains. This separate stale IPC
setup issue was followed by the user's manual cleanup and another guarded run.
No endpoint was removed by the agent and no production/foreign-VPN guard was changed.

Earlier user run `zarp-parity-adapter-cd58br0g` passed preflight and started its
private TUN, then returned FAIL/route_ownership in 1.65 seconds with zero traffic
checks. Cleanup and the final network baseline matched; default routes and system
DNS were not configured. The supplied RESULT is reviewed, but the matching
root-owned report is not independently read. A direct-route formatter assumption
in the test has been corrected as described below. Its exact failed native route
metadata was not retained in RESULT; a new user-only live run is required.

Latest user run `zarp-parity-adapter-covd51sy` entered live startup but returned
FAIL/startup in 1.63 seconds before route/traffic checks. Cleanup and the reported
network baseline passed; zero checks ran. Its root-owned report was not
independently read. The previous runner discarded engine stderr and guardian
errors, so the supplied RESULT cannot establish the cause or confirm a working
TUN. The test now captures only bounded diagnostic facts described below; another
user-only run is needed. No production/foreign guard or route identity was relaxed.

Inspector implementation references are the local SDK's libproc.h/proc_info.h,
the local launchctl/ps manuals and Apple's current
[read-only csops declarations](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
and [kernel implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c).
Only fixed operation CS_OPS_CDHASH is callable. Observed PID/path/code information
is advisory, may race replacement and never grants adoption, signaling or idle
authority. No upstream implementation is copied.

## Xray 26.9.30 evidence

The official [26.9.30 release](https://github.com/XTLS/Xray-core/releases/tag/v26.9.30)
is a prerelease. The Darwin arm64 archive was verified against release-asset metadata
and only the executable member was retained:

- Archive SHA-256: `4b363bd924df5bf09f87bd445755ff8e5742b9a8a0480cda261061416c3c7dce`.
- Executable SHA-256: `118d6c6c8c2fb913c4b2aeb056a58936016b36813c38d9b75653311787c0f93c`.
- Executable version/revision: 26.9.30 / `b26a91d`, Go 1.27.1, darwin/arm64.
- [Upstream license](https://github.com/XTLS/Xray-core/blob/v26.9.30/LICENSE): MPL2.
  No upstream implementation was copied into the MIT project. Distribution still needs
  the appropriate notices/source availability and signing; no backend was bundled.

All 18 pinned-engine race cases pass: VLESS raw TLS, XHTTP stream-one H2 and H3, each
with IPv4/IPv6 outer loopback targets, valid certificate pin, incorrect pin and incorrect
credential. Positive cases transfer two HTTPS responses and a real UDP echo. Negative
cases must reach the selected outer relay before rejection. New raw outer flows,
including the connection carrying UDP payloads, produce split observations. HTTP
pooling is accounted for; pooled application requests are not fresh outer handshakes.

The pinned [transport dialer](https://github.com/XTLS/Xray-core/blob/v26.9.30/transport/internet/dialer.go)
forwards stream/packet transport through `sockopt.dialerProxy`. Actual raw/H2 TLS SNI
was observed by the outer relay, and H3 traffic reaches its authenticated UDP association.
These observations verify the transport detour, not an application-only SOCKS bridge.

The pinned [freedom outbound](https://github.com/XTLS/Xray-core/blob/v26.9.30/proxy/freedom/freedom.go)
blocks private targets by default for VLESS inbounds. The isolated test therefore
requires exact loopback IP/marker-port allow rules followed by Block, in addition to
its server routing restrictions. This is confined to generated test configurations.
All other destinations are denied; no system policy is changed.

Xray's [certificate pin](https://github.com/XTLS/Xray-core/blob/v26.9.30/transport/internet/tls/pin.go)
hashes certificate DER, while the earlier sing-box test pin hashes public-key DER.
The tests use each backend's actual semantics and verify incorrect-pin failure.
No `allowInsecure` option is used. Inner HTTPS trust remains enabled.

The actual pinned XHTTP H2 outer offer is `[h2,http/1.1]` even when configured as `[h2]`.
The server permits only h2, and real traffic succeeds, so negotiation is h2. The
observer asserts that actual offer rather than claiming literal ALPN forwarding.
H3 uses exactly `[h3]`; the pinned [listener](https://github.com/XTLS/Xray-core/blob/v26.9.30/transport/internet/splithttp/hub.go)
selects its UDP/HTTP3 branch for that exact list, and actual HTTPS/UDP payload transfer
through the fake relay succeeds. Encrypted QUIC SNI is not claimed to be packet-decoded.

The shared test supervisor validates configurations with the pinned CLI, uses private
restricted configs/keys, owns exact child process handles and has bounded cleanup.
Raw diagnostics are capped at 32 KiB in memory and never printed. Only fixed event
category counts appear on failure. Concurrency/bounds/redaction tests pass.
Archive fixture tests cover fixed-member extraction, symlink refusal, checksum failure
retaining the prior binary, and no engine execution or network during these tests.

Xray reproduction RESULT: PASS, cleanup PASS, duration 8.29 seconds. The sing-box
regression runner also passes after sharing supervision. These are loopback results.
Production capabilities remain WARP-only; TUN/DNS/process and full T08 gates remain.

The user's privileged production-status diagnostic also timed out for both ping and
status. Live WARP tests remain blocked until installed Zarp status is observable.
The installed daemon was not restarted or stopped, and this PoC does not bypass that
guard or touch the user's VPN.

## Restricted compiler and owned-child supervisor

[plan.go](../zarpd/proxy/plan.go) now compiles typed loopback plans for the verified
sing-box VLESS/Trojan/Hysteria2 TLS and Xray VLESS raw TLS/XHTTP stream-one H2/H3
combinations. It requires numeric loopback targets, a fixed authenticated relay,
authenticated SOCKS listener and a dedicated engine-specific pin. Unsupported
combinations fail. It does not represent TUN, DNS, shell commands, raw configuration,
argv or client-controlled filesystem paths. SNI, credentials and pin bounds are
validated; display and errors are redacted. This is not wired to production IPC.
Reality uses its required public key, short ID and fingerprint instead of a TLS
certificate pin. It cannot silently switch to the ordinary TLS plan.

[supervisor.go](../zarpd/proxy/supervisor.go) uses a trusted daemon-construction
inventory directory with fixed versioned members and executable digests. It rejects
symlinks, FIFOs and group/world-writable binaries, copies a size-bounded executable
snapshot into its private directory and verifies that snapshot before execution.
It checks version and configuration using fixed CLI arguments. Paths never come
from a profile or IPC request. These development pins are not a signed packaging plan.

Private directory/config/executable permissions are 0700/0600/0500. Child environment
is a fixed allowlist. Validation/runtime diagnostics are discarded with bounded byte
counts only; the separate version probe privately retains at most 32 KiB. Startup has
a shared deadline, readiness requires authenticated SOCKS negotiation, and the runtime
has a lease and parent cancellation. Listener readiness does not certify outer TLS or
traffic. Stop targets only the exact owned process handle, with bounded TERM/KILL
cleanup. Config removal follows verified exit; cleanup failures are reported.

Fake-only race tests cover startup hangs, authentication failure, early exit, lease
expiry, TERM-ignoring cancellation, permissions/environment, checksum tampering,
wrong versions, symlinks/FIFOs, diagnostics and source replacement after snapshotting.
The ordinary Go suite needs no external binary. Existing loopback runners now exercise
the supervisor in all 18 Xray and 18 sing-box pin/credential cases, with actual HTTPS,
UDP, outer relay observations and incorrect-pin/credential failures. Separate sing-box
private-CA cases remain. Both complete runners pass with cleanup PASS: Xray 16.73
seconds, sing-box 15.73 seconds; system_network_changed=false.

The [chain supervisor](../zarpd/proxy/chain.go) now owns the pinned engine and its
approved outer relay together. Startup failure, child exit, lease expiry and cancellation
close both pieces; cleanup failure is not reported as success. Fake race tests cover
exactly-once resource cleanup and concurrent Close. The real loopback clients use this
chain: Xray PASS/cleanup PASS in 20.01 seconds, sing-box PASS/cleanup PASS in 18.00 seconds.

Frontend/system adapters, descendants, daemon-crash recovery, production GUI/IPC
adoption and signed bundle loading remain pending. The private ownership and renewal
foundation described below does not activate those production guarantees.
Ping/status now report WARP-only capabilities and
the actual WARP mode; neither a compiled backend nor a loopback proof enables server mode.

## WS, gRPC and HTTPUpgrade TLS evidence

The restricted sing-box compiler now also supports VLESS/Trojan WS, gRPC and
HTTPUpgrade TLS plans. Paths/host headers apply only to WS/HTTPUpgrade; service names
apply only to gRPC. Unsupported or inapplicable options fail. Raw TCP omits the
transport block. This follows the pinned [transport schema](https://github.com/SagerNet/sing-box/blob/v1.13.14/docs/configuration/shared/v2ray-transport.md)
and is verified by actual pinned-engine configuration checks and traffic.

All six combinations carry HTTPS and UDP through the outer TLS splitter on loopback
IPv4/IPv6. Positive pins pass, and incorrect pins/credentials fail after reaching
the outer relay. gRPC actually offers `[h2]` and can pool its HTTP/2 session; separate
fresh-session cases prove the splitter is applied again to a new outer connection.
Multiple inner requests are not counted as independent outer handshakes.

The expanded matrix passes all 65 sing-box cases with cleanup PASS in 64.57 seconds,
system_network_changed=false. This adds transport evidence without enabling production
server mode or claiming system TUN, DNS, process matching or ISP effectiveness.

## Vision, Reality, fingerprints and Salamander

The pinned sing-box matrix now passes 123 cases over loopback IPv4/IPv6. New cases
cover VLESS Vision with TLS, VLESS Reality with and without Vision, Chrome TLS for
VLESS/Trojan, and Hysteria2 Salamander. Positive cases carry real HTTPS and UDP;
separate sessions repeat the outer technique. Negative cases require an observed
outer connection before rejecting incorrect pins, credentials, Vision flow, Reality
keys/short IDs, and incorrect or missing Salamander passwords.

All typed sing-box clients now decode the shared profile JSON, use
[profile.go](../zarpd/proxy/profile.go) to compile its proven loopback subset, and
start through the chain supervisor. The compiler refuses mismatched destinations,
plain security, unsupported fingerprints and ALPN values. Profile validity alone
does not certify a runtime combination. The private test access object provides
the dedicated test pin and owned loopback resources, never executable/argv paths.

Reality's camouflage TLS server is also loopback, with a separate response marker.
Its fallback cannot satisfy the authenticated HTTPS/UDP probes. The pinned Chrome
Reality handshake actually offers `[h2,http/1.1]`; the PoC requires that observed set.
The source contract can represent other admissible ALPN/fingerprint choices, but
the private compiler rejects those whose behavior this PoC has not established.
Configuration follows the pinned [TLS schema](https://github.com/SagerNet/sing-box/blob/v1.13.14/docs/configuration/shared/tls.md),
[VLESS schema](https://github.com/SagerNet/sing-box/blob/v1.13.14/docs/configuration/outbound/vless.md)
and [Hysteria2 schema](https://github.com/SagerNet/sing-box/blob/v1.13.14/docs/configuration/outbound/hysteria2.md).

Salamander does not disable TLS verification. Its UDP relay still injects an invalid
test datagram before the first real datagram, using the association's own socket.
This is loopback ordering evidence, not a production low-hop fake or a QUIC SNI capture.
The runner rejects an empty/skipped external test selection and reports the actual
external case count. Server fixtures now clear inherited configuration/preload variables
as well as the client supervisor. `--suite options` selects the 58 advanced cases.

Latest full sing-box RESULT: PASS, cleanup PASS, 130.85 seconds, 123 external cases,
system_network_changed=false. Xray regression: PASS, cleanup PASS, 18.01 seconds,
18 external cases. The pins and licenses are unchanged. No backend was installed,
bundled or enabled in production; capabilities still advertise only WARP.

## User-run IPv4 TUN and process check

The isolated test is ready at [test-parity-system-adapter.sh](../scripts/test-parity-system-adapter.sh).
Its safe `--loopback-check` mode has passed the private build, pinned configuration
check and actual HTTPS/UDP/DNS payloads, with cleanup PASS and live_test_started=false.
The pinned [check command](https://github.com/SagerNet/sing-box/blob/v1.13.14/cmd/sing-box/cmd_check.go)
constructs/closes its configuration; interface creation belongs to
[Start](https://github.com/SagerNet/sing-box/blob/v1.13.14/protocol/tun/inbound.go), which that mode never calls.

The live system gate is pending. Only the user runs this command from the repository:

```sh
scripts/test-parity-system-adapter.sh --run
```

Prerequisites: macOS arm64, Go, sudo and the already pinned sing-box 1.13.14 binary.
No WARP account or terms are needed. The launcher reads network state before its
private build; the root worker and separate engine guardian both check the existing
foreign-VPN and production-session guards before TUN startup. An active or uncertain
production daemon prevents the test. Those guards are not weakened or bypassed.

Temporary changes: one uniquely named utun with `198.18.0.1/32`, its interface-address
routes, and a manual `198.18.0.2/32` host route. Existing routes covering that test
address are refused. There are no default routes, system DNS/proxy settings, account
changes or installed services. The root frontend forwards only the selected private
executable's three test destinations to authenticated loopback fixtures. Other flows
are rejected. Both selected/excluded producer programs run as the original user;
their actual UID and real payload/fixture counters are checked. DNS uses a direct
synthetic query through the test route, not the system resolver configuration.

Secret fixture files stay in a private 0700 directory. Test producer executables are
sealed to root ownership with group execute/traverse permission for the original user;
that directory contains no credentials. A bounded inherited pipe supplies the nonce
and dedicated trusted certificate, keeping them out of argv/environment/public files.
Pinned engine and test config paths are fixed private resources, not IPC/profile input.

Build limit is 180 seconds, excluding sudo authorization. The worker budget is 120
seconds, reserving 45 seconds for cleanup; engine lifetime is capped independently.
SIGINT/SIGTERM and parent death stop only the test's own engine. The separate guardian
owns the exact unreaped child, so PID/name searches cannot select an installed process.
Cleanup deletes only the exact reserved destination on its chosen private interface,
with UP/HOST/STATIC flags, no GATEWAY flag or displayed gateway, and the same
allowlisted flag set as its journal. Darwin's
[route formatter](https://github.com/apple-oss-distributions/network_cmds/blob/main/route.tproj/route.c#L1773)
prints a gateway only with RTF_GATEWAY; this worker adds a direct `-interface`
host route. An absent gateway field is therefore expected for this specific route.
Changed interfaces, destinations or flags and indirect/reject/unknown routes are
refused. This is an owned-test-route check, not an exemption for foreign routes.
RESULT includes bounded comparisons and known flag names, never raw route output.
Externally replaced routes are left alone, and no old baseline
is restored over outside changes. Success requires stopped children, vanished owned
interface, matching route/DNS baseline and six real process/traffic results.
Credentials, configs, private caches and binary snapshots are removed after verified
cleanup; bounded private reports remain. Failed cleanup retains recovery evidence.

The pinned engine uses error-level stderr logging. Its guardian drains a
nonblocking pipe with bounded work per watchdog turn, retaining at most 32 KiB
in memory and discarding raw bytes after classification. RESULT engine_diagnostics
contains only allowlisted phases, child exit code or spawn errno, bounded byte
counts, boolean capture facts and fixed error markers. Markers are observations,
not a proven root cause. Arbitrary messages, private paths and credentials are
never copied into reports or raw log files. A guardian refusal before spawning
is distinguished from an engine exit; phase running means a child was spawned,
not that TUN/traffic readiness passed. Process stopping and route cleanup remain
restricted to the same owned resources.

Fourteen safe tests cover stale/empty selection, direct-route parsing and strict
ownership, exact cleanup and external replacements, diagnostic redaction, a fake
six-case worker lifecycle, unknown production state, guardian parent death,
bounded real pipe draining and startup-failure diagnostics. The latest script's
loopback/config check passed all three real fixture payloads and cleanup in
1.23 seconds, with live_test_started=false. These checks establish no
TUN/process result. User-run live PASS must still be reviewed. This IPv4 frontend PoC
does not prove full-tunnel DNS policy, IPv6, .app helper discovery or the integrated
server/strategy production chain.

## Renewable private runtime ownership

[owner.go](../zarpd/proxy/owner.go) keeps one validated private backend chain under a
daemon context. Request cancellation applies during startup; after readiness its
callback is detached. A replacement client can inspect/adopt the same run's server
ID, strategy fingerprint and random generation without starting another process.
Stop/renew require the current generation, preventing stale requests from acting on
a replacement. Concurrent admission permits one run. Failed cleanup remains visible
and blocks replacement. Snapshots contain no credentials, endpoints or process IDs.

Lease renewal is a trusted daemon operation with the original duration cap of one
minute and the parent deadline. Adoption/status never renew automatically. Expiry,
cancellation, stopping and observed child exit cannot be revived; readiness and
renewal use the same lock as expiry. Missing renewal still tears down the whole chain.
This code is a loopback foundation, with no production IPC caller or health-based
renewal policy. It does not recover after daemon death or adopt arbitrary processes.

Fake-engine races verify client disappearance, same-child adoption, stale requests,
startup/daemon cancellation, renewed and parent expiry, simultaneous starts and
exactly-once cleanup. The final safe Go suite and vet pass. All shared-profile
sing-box cases now detach their request, adopt and renew before real HTTPS/UDP.
The full runner passes 123 cases in 136.02 seconds with cleanup PASS and no system
network change. Xray lease regression passes 18 cases in 22.99 seconds. These are
private loopback results. The user's system-adapter attempt remains SKIP because
production status is unknown; no TUN/process gate passed.

## Signed inventory boundary

[inventory.go](../zarpd/proxy/inventory.go) adds a separate signed-bundle loader.
Only fixed Contents/MacOS sing-box/Xray members and pinned versions are possible.
Expected team and final signed-file digests are trusted release construction data,
never profile/IPC fields or an unsigned manifest. The private executable snapshot
must pass both its digest and bounded `/usr/bin/codesign` verification before even
the version/configuration probes execute. Signing changes file bytes; upstream
archive/binary hashes remain development pins, not signed-release pins.

The native requirement includes Apple's generic anchor, Developer ID CA/application
certificate markers, the expected team and a fixed per-engine identifier. This
excludes ad-hoc/development/unrelated signatures. Native requirements compile, and a
valid ad-hoc fixture with the correct identifier is rejected. Fake-verifier tests
cover ordering and replacement safety only. Developer ID acceptance and release
catalog generation/signing/distribution are unverified and not activated.
The policy follows [Apple's canonical Developer ID requirement](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/StaticCode.cpp)
and the installed macOS codesign/csreq manuals.

## Isolated inherited-pipe guardian

[guardian.go](../zarpd/proxy/guardian.go) runs a private loopback engine under a
separate owner. Its anonymous inherited pipe accepts a bounded versioned plan and
renew/stop actions. It has no binary/config path, raw argv, system interface, route,
DNS or arbitrary process-identity field. EOF or invalid controls cancel startup
or tear down the exact owned child. Duplicate/normalized/unknown fields fail;
secret data never appears in reports or argv/environment.

Native nonblocking reads avoid the inherited-FIFO polling limitation in Go on
Darwin. Idle waits prevent spin, writes have a two-second deadline, descriptors
are close-on-exec, and the PoC has a two-minute cap. SIGINT/SIGTERM cooperatively
cancel cleanup. A real test kills only its temporary fake daemon; the surviving
guardian detects EOF, stops its authenticated engine, removes its private files
and closes reports while preserving an independent listener. Races also verify
renewal, malformed frames, explicit stop and backpressure.

Pinned VLESS/Hysteria2 cases prove actual HTTPS/UDP through the outer relays over
IPv4/IPv6 before control loss and verified private cleanup. The safe selection is
`scripts/test-parity-backend-loopback.py --engine sing-box --suite guardian`.
These checks require no sudo, TUN or network changes. They do not establish system
process matching or ISP effect. The PoC is separate from production IPC/frontend
activation and owns no system routes/DNS. Its lease timer is in the guardian
process, not inside the external engine.

Final checks pass: safe Go vet/races, six inventory cases and five fake guardian
cases. The complete sing-box runner passes 128 cases in 140.36 seconds, including
five real guardian traffic/EOF/SIGTERM cases. Xray regression passes 18 cases in
24.22 seconds. Both report cleanup PASS and system_network_changed=false. The
unsigned arm64 app build also passes. No release signature acceptance or live
system TUN result is implied.

The development typed launcher now verifies a fixed helper snapshot and retains
its private session leader with native waitid(WNOWAIT) until ordinary group and
session cleanup is verified. Signals and the final reap share a lock, so a saved
object cannot signal a reused group. The guardian's engine/probe children stay
inside that private group; parent survival permits cleanup after guardian-only
SIGKILL, including before readiness. Changed-group members prevent a clean result;
detached sessions are outside this proof. Native-disabled builds refuse launch.

Five launcher race cases verify request detachment/adoption, acknowledged renewal,
startup/ready crashes with TERM-ignoring descendants, integrity refusal and bounded
reports. The pinned guardian selection now has nine actual traffic cases, including
four typed-owner VLESS/Hysteria2 IPv4/IPv6 HTTPS/UDP cases, with cleanup PASS.
The watchdog never signals its numeric group after reaping; an interrupted suite
cannot certify every private session and reports cleanup FAIL.

Signed guardian construction, owner-death descendant/file recovery, simultaneous
owner/guardian death, detached-session recovery and production system-resource
ownership remain pending. The older standalone parent-EOF check does not establish
those guarantees. No system-adapter or signed-release gate has passed.

## Passive outer packet proof

[parity-packet-probe](../zarpd/cmd/parity-packet-probe/main.go) now uses the same
external TCP/UDP relay code with fixed IPv4 numeric-loopback fixtures. Two fresh
authenticated outer TCP flows carry real HTTPS with the intended SNI and negotiated
ALPN. Two fresh UDP associations require the deliberately invalid fake followed by
the real marker on the same tuple, with reverse echo. Certificates and authentication
remain private in memory. This childless helper contains no production IPC, TUN,
route/DNS/proxy/interface operations or arbitrary capture interface/target options.

Its user-run capture mode opens a read-only, nonblocking BPF descriptor, installs
reject-all before attaching existing lo0, and admits only the two reserved fixture
ports with complete loopback source/destination and protocol checks. IPv4 is the
default; `--family ipv6` selects only ::1. The fixed IPv6 decoder refuses extension
headers, fragments, jumbograms and malformed lengths. IPv6 reports carry an explicit
family that must match the requested check; unlabeled historical reports remain IPv4. SDK-native
BPF headers/alignment are validated; truncation, malformed/foreign/fragmented frames,
buffer limits and capture drops prevent a passing proof. Reader completion precedes
descriptor close. Capture buffers never leave bounded memory.

The loopback driver exposes an output tap in Apple's
[if_loop.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_loop.c).
The descriptor must see sent packets. This choice does not change interface flags or
broaden the port/address filter. Repeated UDP datagrams fail verification; TCP proof
checks the exact expected split payload lengths, continuous sequence and complete
original ClientHello bytes for each fresh outer tuple. Stream write counters alone
cannot satisfy the packet proof.

The runner, [test-parity-outer-packets.sh](../scripts/test-parity-outer-packets.sh),
builds its private helper and accepts only fixed arguments. Unprivileged fixture
mode is safe with the current VPN. `--run` is user-run only and asks for sudo solely
for passive BPF access. The worker has a 30-second cap after authorization, with
exclusive-parent-pipe EOF and cooperative signal cleanup. No saved numeric PID is
signaled. Temporary work is removed after verified completion; a restricted sanitized
JSON report remains. Unknown cleanup is FAIL and retains work.

Current evidence: actual unprivileged IPv4/IPv6 HTTPS/UDP fixtures and synthetic filter,
decoder/boundary/order and runner ownership/evidence checks pass. Kernel capture
now passes the separate user-run IPv4 and IPv6 checks: each captured 54 packets,
zero drops, two fresh HTTPS flows
each with exact `[1, 116, 1420]` split payloads, and two UDP fake-first associations
on their original tuples. Cleanup passes and system_network_changed=false. The
version/run ID/helper pin and matching restricted JSON report were reviewed.
Exact packet behavior on another platform can require a relay adjustment if its
kernel coalesces writes; the test fails rather than certifying that as split.
This does not pass live TUN, selected-process, production fake
hop-limit, crash-recovery or ISP-effect gates.

## Armed private-session recovery

[recovery.go](../zarpd/proxy/recovery.go) adds a childless recovery member in a
separate group of the same freshly isolated session. Its exclusively inherited
pipes and directory capability must validate before the guardian starts any
engine/probe. The helper derives its SID from the kernel; messages contain only
fixed engine/version identity. They accept no target PID, group, executable,
argv or directory path. The current verified helper snapshot is re-executed.

Apple's [PID allocation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c)
excludes existing session/group IDs. A live recovery member therefore retains its
original SID after its former leader dies. The helper signals only that original
session-leader group, never scanned PIDs or changed groups. After control EOF,
malformed extra input, cooperative termination or its independent cap, it checks
remaining members and the held root's inode/owner/private permissions before
removing that directory. Native readers retain their file owners until close.

The original parent keeps its reserved leader while the recovery member finishes,
without signaling an empty zombie-only group. Fake daemon-only, daemon/guardian
and in-progress startup crashes pass with TERM-ignoring descendants and an
independent engine preserved. Changed-group members cause failed cleanup and file
retention. Their independently capped fixture is never targeted by observed PID;
its later exit does not turn the failed status into success.

A separate bounded `--owner-probe` bootstrap permits actual pinned-engine crash
checks through anonymous pipes. Its generated directory/session metadata is
read-only evidence, never adoption or signal authority. Real VLESS/Hysteria2
HTTPS/UDP passes over IPv4/IPv6 before the exact unreaped owner is killed. The
native session becomes empty, the listener closes and private files disappear.
The guardian selection now passes 13 cases, cleanup PASS, with no system network
changes. Failed/incomplete runner suites retain their private work and report
cleanup FAIL; a wrapper exit or deleted working tree cannot certify descendants.

These results are development recovery after arming. Detached sessions,
pre-arming simultaneous loss, recovery-helper death, signed guardian acceptance,
frontend/system-resource ownership and the user's live TUN/process gates remain
pending. The older standalone EOF proof does not establish these extra guarantees.


## Signed guardian release construction

[guardian_inventory.go](../zarpd/proxy/guardian_inventory.go) adds a separate
trusted bundle constructor. The fixed helper is copied into the private directory,
its final signed-file digest is checked, then its Developer ID Application
requirement is verified before control pipes or code execution. The requirement
pins the team and `io.github.zarp.backend.guardian`; matching ad-hoc identifiers
are rejected. Backends keep their separate fixed identifiers and versions.

The fixed `--release-session` bootstrap uses team/engine digests compiled into
the guardian. It derives the app bundle from its launcher-selected working
directory and requires a fresh private session leader. Empty or malformed build
policy fails. Environment values, imported profiles, inherited control messages
and unsigned manifests cannot replace it or trigger development fallback.
Plans remain loopback-only and recovery uses the same verified helper snapshot.

Release construction order is acyclic: sign engines, embed their final digests
and team in the guardian, sign the guardian, then embed its final digest in the
trusted daemon catalog. Signing the application and final catalog generation
remain distribution work. The command's build variables are `main.releaseTeamID`,
`main.releaseSingBoxDigest` and `main.releaseXrayDigest`. A normal development
build leaves them empty. No release identity was queried or used in these tests.

Private tests check digest/signature ordering, immutable finite policy, a
fake-approved release-mode launch independent of later source replacement,
native requirement compilation, valid matching-identifier ad-hoc refusal and
bootstrap refusal outside a private session. These do not establish positive
Developer ID acceptance, signed distribution or production activation.

## Outer UDP temporary TTL and hop limit

The loopback-only UDP relay accepts an optional bounded `FakeHopLimit`, applied
only before the first fake datagram on each association's connected outer socket.
Its sole upstream writer reads the original socket policy, attempts the temporary
value, sends the fake, and restores the original before real data. Read/set/write,
short-write or restoration failures end the association; a restoration error is
retained even if the fake write also fails. Zero leaves existing behavior intact.
The shared [socket operations](../zarpd/internal/socketopts/hoplimit.go) are also
used by the existing WARP TCP/UDP helpers, without changing their interface.

Darwin IPv6 supports `-1` as the inherited kernel default. The initial draft
wrongly rejected it. Corrected code restores it verbatim instead of forcing an
assumed value. Apple's [IPv6 socket option implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/ip6_output.c)
confirms the sentinel; real private tests cover both inherited policy and an
explicit nondefault value. Four pinned Hysteria2 IPv4/IPv6 cases transfer actual
HTTPS/UDP with the new option and reject incorrect certificate pins.

The user-only packet command adds `--fake-hop-limit`. For each of two fresh
associations, it requires the same-tuple fake with header TTL/hop limit 1 followed
by real data with a restored value greater than 1. It reports only the bounded
pairs of header values, counts and proof flags, with no packet payload/address
or credentials. Stream tests and socket-option readback cannot pass that kernel
proof. The user-run IPv4 and IPv6 results each pass with `[1, 64]` on both
fresh associations, zero capture drops, verified cleanup and no system network
change. These fixtures still use a deliberately invalid fake. They do not prove
a production fake shape, routed expiration, endpoint invisibility or ISP effect.


## Owned bounded HTTPS verification

[probe.go](../zarpd/proxy/probe.go) adds a development-only owner method that
requires the exact ready run generation. Its target, dedicated certificate/name,
marker and shared deadline are trusted private construction data. Each of two
confirmations opens a fresh authenticated SOCKS connection to that run, validates
normal TLS plus the exact leaf certificate and HTTP/1.1 ALPN, and reads an actual
bounded HTTPS response. The timing covers SOCKS/TLS through its first response
byte and is returned only when both complete responses validate.

The strict SOCKS greeting admits no unauthenticated downgrade. Numeric target
and bind-address checks prevent alternate destinations or resolver use. Complete
decrypted response/body limits, fixed GET/identity encoding and no redirect or
direct fallback keep the operation bounded. Errors and results exclude targets,
credentials, certificate bytes, bodies and raw TLS/HTTP diagnostics.

One probe is admitted per run. Request cancellation affects that probe only;
Stop, lease loss and Close cancel and join all admitted work before owner cleanup.
Admission and cancellation serialize under the same lock, terminal state drops
retained probe access, and stale generations cannot measure replacements. The
method does not renew leases, start reconnect loops or mark tunnel health.

Private IPv4/IPv6 TLS/SOCKS and race tests pass. Eight pinned VLESS/Hysteria2
IPv4/IPv6 cases also use this method through the typed guardian owner, confirm
actual HTTPS or reject wrong inner name/marker, and clean up their engines and
relays. This is loopback evidence only. Production server IPC, post-TUN probe
policy and real process/routing/DNS acceptance remain gated by user system tests.
