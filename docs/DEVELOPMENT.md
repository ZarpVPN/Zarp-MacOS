# Development guide

How to build, run and test Zarp for macOS, and how the repository is organised. For *why* it is built this
way read [ARCHITECTURE.md](ARCHITECTURE.md); for how to contribute, [../CONTRIBUTING.md](../CONTRIBUTING.md).

- [What you need](#what-you-need)
- [Repository layout](#repository-layout)
- [Tests](#tests)
- [Building the app](#building-the-app)
- [Signing with your own team](#signing-with-your-own-team)
- [Running the daemon by hand](#running-the-daemon-by-hand)
- [The real-network test](#the-real-network-test)
- [Localization](#localization)
- [Other generated files](#other-generated-files)
- [Continuous integration](#continuous-integration)

## What you need

- An Apple Silicon Mac on macOS 14 or later. The daemon uses macOS-only APIs (utun, `IP_BOUND_IF`, routing
  and `networksetup` tooling), so there is no Linux or Intel build.
- Xcode 16 or later (the Swift 5.9+ toolchain and the macOS SDK; it is also what signs the app).
- Go: the version in [`zarpd/go.mod`](../zarpd/go.mod). `brew install go` is enough.
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`. `Zarp.xcodeproj` is generated
  from [`project.yml`](../project.yml) and is not committed.

```sh
brew install go xcodegen
git clone https://github.com/feg55/Zarp-MacOS.git && cd Zarp-MacOS
make test
```

`make help` lists every target.

## Repository layout

The tree is described in [ARCHITECTURE.md §2](ARCHITECTURE.md#2-code-layout). The pieces you will touch most:

| Path | What |
|---|---|
| `App/Sources/Zarp` | the SwiftUI app |
| `Packages/ZarpCore` | strategy, scan, settings, localization, logging and the IPC client; tested with plain `swift test` |
| `zarpd` | the Go daemon and `zarpctl`; its own Go module |
| `Resources/Lang`, `Resources/blobs`, `Resources/Licenses` | strings, decoy-packet captures, licence texts |
| `scripts` | packaging, the real-network test, icon and notices generators, the documentation link check |
| `docs` | this guide, the architecture, troubleshooting, release steps, and `history/` (the development record) |

## Tests

```sh
make test          # all three below
make test-go       # cd zarpd && gofmt check, go vet, go test -race -count=1 ./...
make test-swift    # cd Packages/ZarpCore && swift test
make check-docs    # every relative link and anchor in the Markdown files resolves
```

None of these needs root or a network: the Go tests drive routes and DNS through a fake command runner, the
dial and desync code over loopback sockets, and the IPC server over a Unix socket in a temporary directory;
the Swift tests use scripted fakes, a fake Unix-socket daemon, intercepted URLSession requests and a fixed
numeric-loopback HTTPS fixture. The latter builds one standard-library Go helper with private certificates,
stops it on inherited pipe EOF, and has an independent 40-second cap. Its CA is used only in a per-session
test trust evaluation and is never installed. It checks real gzip expansion, redirects and TLS rejection
without production URLs or network settings. Run a single Go package or Swift test with
the usual `go test ./route -run TestName` and `swift test --filter TestName`.

What they cannot cover (root, a real routing table, a real WARP endpoint) is covered by
[the real-network test](#the-real-network-test).

## Building the app

```sh
make build         # an unsigned Release build into build/DerivedData (what CI checks)
```

or generate the project and use Xcode:

```sh
make project       # xcodegen generate
open Zarp.xcodeproj
```

The Xcode target runs a script phase that builds `zarpd` with `go build` and embeds it, with its LaunchDaemon
property list, into the app bundle. An unsigned build is fine for working on the UI and the engine, but it
cannot install the daemon (see below).

## Signing with your own team

The daemon is registered with `SMAppService`, which needs the app and the daemon to be signed by the same
Apple Development team. A free "Personal Team" works. Your Team ID is deliberately not in the repository:

```sh
cp Config/Local.xcconfig.example Config/Local.xcconfig     # git-ignored
# edit it: DEVELOPMENT_TEAM = <your 10-character Team ID>
```

Find the ID in Xcode > Settings > Accounts, or with `security find-identity -v -p codesigning` (it is in
parentheses after the certificate name). Xcode builds and `make dmg` both read the file; the environment
variable `DEVELOPMENT_TEAM=<id> make dmg` works too.

A **Debug** build may register the daemon from anywhere (Xcode's DerivedData included); a **Release** build
registers it only from `/Applications` (it is a root executable, so it must not live in a folder you can
write; see [ARCHITECTURE.md §7](ARCHITECTURE.md#7-the-privileged-daemon-install-and-update)).

## Running the daemon by hand

You can develop the app against a daemon you started yourself instead of the installed one. A **Debug** app
honours the environment variable `ZARP_SOCKET`:

```sh
cd zarpd && go build -o /tmp/zarpd ./cmd/zarpd && go build -o /tmp/zarpctl ./cmd/zarpctl

# 1. the daemon (root, because creating a utun and changing routes needs it)
sudo /tmp/zarpd -socket /tmp/zarpd-dev.sock -config /tmp/zarpd-dev-config.json \
     -blobs "$PWD/../Resources/blobs" -log - \
     -dns-backup /tmp/zarpd-dev-dns.json -route-journal /tmp/zarpd-dev-routes.json

# 2. the Debug app against it (another terminal)
ZARP_SOCKET=/tmp/zarpd-dev.sock /path/to/Debug/Zarp.app/Contents/MacOS/Zarp

# 3. or talk to it directly
/tmp/zarpctl -socket /tmp/zarpd-dev.sock ping
/tmp/zarpctl -socket /tmp/zarpd-dev.sock register
/tmp/zarpctl -socket /tmp/zarpd-dev.sock open -transport h3 -fake quic_google:6 -endpoint isolated-0
```

Without root the daemon still starts and answers `ping`, `status`, `register` and `logs` (and `zarpctl` needs
no `sudo` to talk to it), which is enough for most UI work; it just cannot open a tunnel. Keep the socket path
short: a Unix socket path is limited to about 100 bytes on macOS, and a longer one fails with `bind: invalid
argument`. Release builds ignore `ZARP_SOCKET`. `zarpctl` prints the daemon's
JSON answer, or `error [code]: message` on stderr; its header comment lists every command and flag.

Use the private files above (`-config`, `-dns-backup`, `-route-journal`) rather than the defaults, so that your
experiments never share state with an installed daemon.

## The real-network test

[`scripts/test-integration.sh`](../scripts/test-integration.sh) checks what unit tests cannot: that a real
tunnel comes up, that every route and DNS change is undone, and that a daemon killed mid-tunnel leaves the
machine working. **Turn off every other VPN, and Cloudflare's WARP app, first**; the script refuses to start
when the default route is on a `utun`.

```sh
scripts/test-integration.sh            # HTTP/3 + quic_google x6; asks for your password once (sudo)
scripts/test-integration.sh --h2       # the HTTP/2 transport with a ClientHello split
scripts/test-integration.sh --no-tunnel   # skip the tests that route all traffic
```

It builds `zarpd` and `zarpctl` from your tree, starts its **own** daemon on a private socket in `/tmp` (the
installed one is untouched), and runs the checks listed in its header: protocol and validation, the leak of
file descriptors on failed dials, a real test connection, orphaned connections and leases, the full tunnel
with and without the DNS override (IPv4, IPv6, an 8 MB download, exact restore), `kill -9` and SIGTERM
recovery. Whatever happens (Ctrl-C included) an exit handler stops the daemon and then **verifies that the
default route, DNS and connectivity are as they were**, printing the repair commands if they are not. A
watchdog ends the run after 15 minutes. It prints a `RESULT` block with the daemon log, which is what to paste
into a pull request.

## Parity manual checks

The Stage 1 runner is [test-parity-manual.sh](../scripts/test-parity-manual.sh). Its supervisor is
[parity_manual.py](../scripts/parity_manual.py). It builds a separate daemon, registers dedicated test
credentials after explicit terms acceptance, and refuses VPN conflicts or uncertain production state.
It observes routes and DNS, watches for external changes, stops only its own verified child, and emits
a sanitized RESULT plus a private JSON report. DNS is never overridden. It never disconnects a VPN.
Each worker has a 600-second budget including reserved cleanup time; build has a separate 180-second limit.

Safe autonomous checks:

```sh
bash -n scripts/test-parity-manual.sh
scripts/test-parity-manual.sh --self-test
scripts/test-parity-manual.sh --help
```

If a live scenario skips before starting, use the read-only diagnostic mode and share its RESULT:

```sh
scripts/test-parity-manual.sh --preflight
```

This mode never builds, requests sudo, starts a daemon or changes network settings. Its report identifies
the exact preflight blocker using sanitized route/service/command metadata. A preflight PASS only
confirms the guard accepted the observed state; it does not pass a live WARP/TUN check.

User-run commands, when the user chooses an appropriate network state:

```sh
scripts/test-parity-manual.sh --scenario warp-h3 --full-tunnel --accept-warp-terms
scripts/test-parity-manual.sh --scenario warp-h2 --full-tunnel --accept-warp-terms
scripts/test-parity-manual.sh --scenario warp-account-ipv6 --full-tunnel --accept-warp-terms
```

`warp-custom --endpoint '[IPv6]:port' --transport h2` additionally permits a user-supplied public
numeric H2-capable IPv6 endpoint. The current usque dependency does not supply a default H2 IPv6
address. Never substitute a guessed address and describe it as working.

The live modes require sudo and temporarily create a private utun and measurement host route.
`--full-tunnel` also adds /1 routes and an endpoint host exclusion. Reports include source/binary
identity and cleanup status. Private account material is removed during cleanup. No live scenario
has passed until a user RESULT is reviewed. The historical integration script is not a substitute
for this supervised runner and is not run autonomously.

When production ping/status have already timed out, do not keep repeating the same
diagnostic or retry the live runner unchanged. The separate read-only inspector
collects installation and code identity evidence without connecting to production
IPC:

```sh
scripts/test-parity-production-inspect.sh --inspect
```

If metadata or a user-run adapter report is inaccessible, the user can run:

```sh
sudo scripts/test-parity-production-inspect.sh --inspect --adapter-run zarp-parity-adapter-g0nc0trg
```

The optional argument accepts only a fixed-format adapter run ID under /private/tmp.
Only that directory's bounded, protected report.json is decoded and reduced to a
small allowlist of fields. Account/socket inspection uses file metadata only;
account contents, logs, launchd environment/arguments and raw executable paths are
never printed. Fixed read-only launchctl/ps/codesign commands and kernel path/code
metadata compare the observed executable with an existing local build where
available. The inspector never executes either binary, queries IPC, attaches a
debugger, acts on an observed PID, changes a service or alters network settings.
No temporary files are created. Your VPN may remain connected. Each external
read tool has a three-second limit; the overall cooperative observation budget
is 25 seconds, plus at most one second to reap each owned read-tool child.

This diagnostic's PASS means metadata collected. It never implies an idle daemon,
passes a TUN gate or authorizes bypassing the guard. Missing code metadata is
reported explicitly. launchctl's human-readable output is advisory and version
dependent; neither that output nor a PID/path/hash comparison is process-control
authority. Tests use private fixtures and fake tools only:
`python3 -I -B scripts/test_parity_production_inspect.py`.

The account loader separately refuses final symlinks, nonregular sources, files
writable by group or others, and files larger than 64 KiB. A nonblocking open and byte bound keep
FIFO/unbounded inputs from stalling account presence checks or leaking private
input through errors. Regular-file storage I/O has no hard kernel deadline.
These checks address a source-level risk; they do not establish the cause of an
already running daemon's timeout or deploy a fix to that daemon.

## Passive outer-packet check

[test-parity-outer-packets.sh](../scripts/test-parity-outer-packets.sh) prepares a fixed,
private numeric-loopback TLS/UDP worker. It exercises two fresh authenticated TCP
flows with actual HTTPS, SNI/ALPN checks, and two fresh UDP associations with reverse
echo. Its unprivileged mode uses no packet capture:

```sh
python3 -I -B scripts/test_parity_outer_packets.py
scripts/test-parity-outer-packets.sh --loopback-check
scripts/test-parity-outer-packets.sh --loopback-check --family ipv6
```

The following capture command is for the user to run. The current VPN may remain
connected. It needs macOS arm64, Go, Xcode command-line tools and sudo for a passive,
read-only BPF descriptor on existing `lo0`. There is no TUN, route/DNS/proxy/firewall
change, physical interface binding, installed-daemon query or VPN disconnection.

```sh
scripts/test-parity-outer-packets.sh --run
scripts/test-parity-outer-packets.sh --run --family ipv6
```

Capture selects one fixed family: IPv4 127.0.0.1 by default, or IPv6 ::1 with
`--family ipv6`. Both complete source/destination addresses, TCP/UDP and the two
newly reserved fixture ports are checked. IPv6 extension headers, fragments and
jumbograms are refused. Reports label IPv6 explicitly; historical unlabeled reports
remain IPv4, and cannot certify an IPv6 request. A reject-all filter precedes attachment; the bounded
packet buffer stays in RAM. Promiscuous mode and injection are absent. XNU's loopback
output tap must be enabled on that private descriptor; duplicate UDP datagrams are
never collapsed into a passing order result. TCP proof requires exact payload
boundaries, sequence continuity and original ClientHello bytes on each outer tuple.
Coalesced stream writes fail that proof.

Build limit: 180 seconds. Worker limit: 30 seconds, excluding sudo authorization.
The childless worker cancels on parent input EOF, SIGINT/SIGTERM or its deadline;
descriptor reads join before close. Only private binaries/cache/logs are removed.
An owned 0700 directory retains a sanitized 0600 `report.json`, with its path in the
RESULT. Unknown worker/build cleanup retains private work and reports FAIL. No raw
packet, certificate, key, credential or complete URI is persisted in the report.

A safe fixture PASS proves stream traffic only. The user's IPv4 and IPv6 capture RESULTs
now pass exact split and same-tuple ordering with zero drops and cleanup PASS.
Each new capture remains pending until its RESULT is reviewed. This fixture does not establish production
fake hop limits, real TUN/process policy or ISP effect.

The optional temporary-limit kernel check is also user-run only. It applies TTL
or hop limit 1 only to the private UDP socket's first fake, restores its original
policy before real traffic, and requires both values in captured packet headers:

```sh
scripts/test-parity-outer-packets.sh --run --fake-hop-limit
scripts/test-parity-outer-packets.sh --run --family ipv6 --fake-hop-limit
```

Use `--loopback-check` in place of `--run` for safe stream/socket verification
without sudo or BPF. That result has no kernel packet proof. The new capture
RESULT must include `udp_fake_hop_limit_requested=true`,
`udp_fake_hop_limit_verified=true` and two `udp_packet_hop_limits` rows, each
`[1, N]` with `N > 1`. The user-run IPv4 and IPv6 checks now pass with captured `[1, 64]` pairs, zero
drops and verified cleanup. Further changed captures remain pending until reviewed;
the earlier separate IPv4/IPv6 split/order results also remain accepted.
The fixture cannot establish expiration along a routed path or ISP effectiveness.

The signed guardian constructor and embedded release bootstrap are described in
[the backend PoC](BACKEND_PARITY_POC.md#signed-guardian-release-construction).
Its ordinary build refuses release mode. No environment/profile/control input
can configure release pins, and no signed identity or production activation is
part of the safe tests.

The owned backend HTTPS probe has a safe pinned regression selection:

```sh
python3 -I -B scripts/test-parity-backend-loopback.py --suite owned-https
```

It uses only private loopback VLESS/Hysteria2 fixtures and the existing pinned
engine, without TUN, production IPC or system settings. It validates two fresh
HTTPS responses for the exact owned run, inner TLS/name/marker failure and
cleanup. See [the probe evidence](BACKEND_PARITY_POC.md#owned-bounded-https-verification).
The next system-adapter gate remains user-run only. Its earlier uncertain
production-daemon status prevented startup. The latest user run passed preflight
and entered live startup, then its private guardian or engine exited before
route/traffic checks. Cleanup and the final network baseline matched. Live acceptance
remains pending.

Current status distinguishes a persistent GUI connection from network work:
`connected: false` alone is insufficient. A present production daemon must also
reply with the explicit boolean `networkBusy: false`. Opening/scan/closing work,
shutdown and known cleanup/recovery failures keep that field true. Missing or
malformed activity metadata from an older daemon is unknown and the manual
runner refuses it. The GUI may still decode legacy replies for reconciliation;
that compatibility does not authorize a live test.

The user's privileged `production-inspect` RESULT on 2026-10-19 still reports
unknown code metadata and confirms the adapter never started. Do not repeat
unchanged diagnostics or another live attempt in that same state. The user must
choose a safe state themselves. Closing a Zarp window does not unregister its
background daemon. The installed app at that time exposed Settings > zarpd daemon >
Uninstall. Current builds prepare the service automatically and no longer expose
service-maintenance controls. These historical runs do not authorize an agent to
install or recover a production service during autonomous checks.
The agent does not invoke it, start the GUI, restart the daemon or disconnect
their VPN. Once the production daemon is absent or observably idle, the prepared
command is `scripts/test-parity-system-adapter.sh --run`. No SKIP passes its gate.

After the user's daemon removal, run `zarp-parity-adapter-tph69ga5` reported
ipc_socket_error/errno 61 instead of the previous timeout. Fresh read-only
observations found the fixed launchd service absent, no zarpd accounting name in
the process inventory, and a root-owned 0660 socket still at /var/run/zarpd.sock.
The user performed the case-specific stale-path cleanup and the next run passed
preflight. Do not repeat that removal. No production endpoint was removed by the
agent. The test retains all existing production/foreign-VPN checks; no
refused-connection exception, force flag or automatic production-socket deletion
is added.

Earlier run `zarp-parity-adapter-cd58br0g` returned FAIL/route_ownership after a
live start, with zero traffic checks. The test required a nonempty displayed
gateway, but Darwin omits it for direct `-interface` host routes. The matcher now
requires the exact reserved destination and chosen private utun, UP/HOST/STATIC,
no gateway, and unchanged allowlisted flags before deletion. Foreign guards are
unchanged. Nine fake tests and the safe loopback/config check pass. The supplied
failed RESULT had no native route metadata; the corrected script adds sanitized
ownership comparisons and known flags for the next run.

Latest run `zarp-parity-adapter-covd51sy` returned FAIL/startup in 1.63 seconds,
with live_test_started=true, zero checks, cleanup PASS and matching network
baseline. The supplied RESULT cannot identify its cause because engine stderr
and guardian errors were discarded. The runner now emits sanitized
engine_diagnostics: guardian phase, whether a child was spawned, exit code or
spawn errno, capture counts/booleans and fixed error markers. Error-level stderr
is drained without blocking the watchdog; retained memory is capped at 32 KiB.
Raw messages and private paths never enter reports or log files. Phase running
does not certify a ready TUN. Fourteen safe tests cover bounds, redaction,
guardian refusal, early exit and worker cleanup as well as the earlier route
cases. The live gate remains pending.

From this repository, the next user-only command is:

```sh
scripts/test-parity-system-adapter.sh --run
```

It needs macOS arm64, Go, the pinned sing-box 1.13.14 and sudo. It creates one
private utun, one reserved host route and private engines/fixtures; default
routes and system DNS remain unchanged. Build limit is 180 seconds; worker limit
is 120 seconds, excluding sudo authorization. The user chooses the network state.
Send its RESULT; only a real live start, all six selected/excluded HTTPS/UDP/DNS
checks and verified cleanup can pass this gate.

Rollback faults are tested using fake route/DNS tables only. A failed setup
command may already have changed state: if its rollback also fails, the error
cannot become an ordinary warning or a successful IPv4-only tunnel. DNS recovery
data is retained until restoration and backup removal succeed. Failed exclusion
deletions likewise retain only their failed journal entries. Corrupt recovery
data is kept and reported rather than silently discarded or overwritten by a new
session. These source fixes are
not installed and do not establish live cleanup or recovery on this Mac.

## Localization

All strings are in `Resources/Lang/<code>.txt`; see [CONTRIBUTING.md](../CONTRIBUTING.md#translations) for the
rules and [`en.txt`](../Resources/Lang/en.txt)'s header for the format. The tests keep the eight files in
step with each other and with the code (no missing keys, no leftover keys, same placeholders).

## Other generated files

| Command | Produces |
|---|---|
| `make notices` | `Resources/Licenses/THIRD_PARTY_NOTICES.md` (from the Go modules actually linked into `zarpd`) and the bundled copy of `LICENSE`. CI fails when they are stale |
| `make icon` | the app icon set, `docs/images/icon.png` and `docs/images/social-preview.png`, drawn by `scripts/make-icon.swift` |
| `make dmg-art` | the disk image's window background, `scripts/dmg/background.png` and `background@2x.png` (also drawn by `scripts/make-icon.swift`); the icon positions on it are in `scripts/dmg/settings.py` |
| `make dmg` | `build/Zarp-<version>-arm64.dmg` and its `.sha256`; see [RELEASING.md](RELEASING.md) |

## Continuous integration

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on an Apple Silicon macOS runner for every
push to `main` and every pull request: `gofmt`, `go vet` and the Go tests with the race detector, the Swift
tests, the notices check, the documentation link check, and an unsigned Release build of the app. It does not
run the real-network test (a hosted runner has no business rewriting its own routes).
