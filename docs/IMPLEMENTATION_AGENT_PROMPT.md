# Prompt for sequential Zarp macOS implementation

You are working in the Zarp-MacOS repository. You have access to the filesystem, shell, Git, Context7, documentation, a browser, and the other coding-agent tools. Carry out the implementation. Do not stop at another analysis or an offer to continue.

Objective: bring macOS up to the functional level of the current Windows and Android versions, step by step. Implement the main parity scope T01-T15 first. Then research and implement the additional Windows capabilities in T16 wherever they can be demonstrably implemented on macOS. Never describe an unsupported technique as working.

Working directory: `/Users/andrumoskow/Documents/Zarp-MacOS`. If the environment uses a different path, locate this repository by its files. Do not create a replacement project.

## 1. Required source material

Start by reading:

1. Applicable AGENTS.md files and the user's instructions.
2. `docs/FEATURE_PARITY_ANALYSIS.md`, especially the architecture, T01-T16, dependencies, and acceptance criteria.
3. `docs/parity-snapshot.json`.
4. `README.md`, `docs/ARCHITECTURE.md`, `docs/DEVELOPMENT.md`, and `CHANGELOG.md`.
5. The actual current code and tests for the stage you are working on.

If the saved analysis or snapshot is missing in a new environment, do not invent its contents. Follow the sequence and constraints in this prompt, reconstruct the acceptance criteria from the reference source code, and record a new baseline. A missing historical file alone is not a reason to stop safe work.

Local references:

- `_reference/Zarp`: Windows.
- `_reference/Zarp-Android`: Android.
- `_reference/Zarp-MacOS`: a saved snapshot of the remote macOS version.

Repositories:

- `https://github.com/ZarpVPN/Zarp.git`.
- `https://github.com/ZarpVPN/Zarp-Android.git`.

The analysis recorded Windows `07406eb`, Android `9399fd4`, and the working macOS checkout `f942a4b`. The saved remote macOS main has a different SHA, `dca673a`, but the same file tree. These are historical snapshots, not a guarantee that they are current when you begin. If the code has changed, first establish the differences and update the working plan while retaining the original analysis as a historical document.

If a reference is missing, obtain it under `_reference/`. If it already exists, inspect its local changes and version first. Do not overwrite a modified checkout. Do not silently update a reference snapshot during a stage. Record the SHAs you use. Keep `_reference/` in `.gitignore`; do not add nested repositories to the main Git repository.

## 2. Preserve my VPN

My current VPN and network connection must continue working. This is an explicit user constraint and a mandatory condition for all work, including testing.

You must not independently:

- Disconnect, replace, restart, or reconfigure my VPN, its application, daemon, service, or extension.
- Kill VPN processes, the installed Zarp application, or its production daemon.
- Modify active routes, DNS, proxy settings, the firewall, pf, network services, interfaces, or the default route for testing.
- Start a real tunnel, a full-tunnel scan, a Zarp connection, the production GUI with auto-connect, daemon installation/registration, or a live integration script that could affect the network.
- Bypass my VPN by binding a test outbound to the physical interface, disable VPN auto-reconnect, or try to exploit a moment when the VPN temporarily disappears.
- Use `killall`, broadly targeted `pkill`, bulk utun/route removal, or restoration of the entire network configuration.

Do not bypass this rule through sudo, sandbox escalation, automatic approval review, or another tool. Approval to access the shell does not authorize touching my VPN. Do not ask for permission to disconnect the VPN yourself.

Do not remove or weaken foreign-VPN guards in the application or tests to make a check pass.

You may independently read network state, perform ordinary downloads through the existing connection, build, run static checks, run unit tests with a fake network runner, use temporary IPC sockets, and run loopback protocol tests without TUN or system changes.

Before running a test suite, read its entrypoint and verify that inherited environment variables, default flags, or an aggregate Makefile target cannot enable live cases. Permission to run loopback tests does not authorize arbitrary network scenarios.

## 3. Checks that require no VPN or a real TUN

Instead of running such a check, prepare an automated test that I will run myself. Make it concrete and reviewable before asking me.

Test requirements:

1. A separate script, such as `scripts/test-parity-manual.sh`, with selectable scenarios, clear help, and an exact execution command.
2. No automatic VPN disconnection. Before system changes, check for a foreign VPN and an active production Zarp session. If a conflict is detected or a safe state cannot be established reliably, exit with a clear explanation.
3. Explain the temporary changes, whether sudo is required, the prerequisites, and the timeout.
4. Use separate temporary binaries, configuration, sockets, logs, caches, and journals, a unique run ID, and dedicated test credentials. Do not modify my production account, settings, or subscription files.
5. Before changes, capture a sufficient read-only routes/DNS baseline. During cleanup, remove only resources owned by the test, not the entire network state.
6. Implement cleanup for success, errors, SIGINT/SIGTERM, and the watchdog. Verify the PID and ownership of a process before stopping it.
7. If a foreign VPN or another external network change appears during the test, stop your own test resources. Do not disconnect the other session or restore the old baseline over its new settings.
8. A kill -9 scenario may kill only the test's own daemon. SIGKILL does not run a trap: recovery must be provided by a separate supervising process or verified startup recovery.
9. Print a final `RESULT` and a machine-readable report with PASS/FAIL/SKIP, duration, and cleanup results. Never include passwords, private keys, UUIDs, subscription tokens, or complete secret URIs in reports.
10. Check syntax, builds, and fake/loopback portions yourself. Do not run the system-level scenario.

Once the test is ready, send me:

```text
<Test name> requires a manual run: <why it needs no other VPN or a system TUN>.
The test is ready: <path>.
Command: <exact command>.
Temporary changes: <specific resources>.
Time limit: <timeout>.
It does not disconnect your VPN. Run it yourself when you choose, and send back the RESULT block or a sanitized report.
```

If a question tool is available, use it for this request after preparing the script. Do not request a file upload through a tool that accepts only text; ask for the RESULT block to be pasted instead.

While waiting for the result, continue safe, independent work within the current stage. Do not describe a pending check as passed. If the next step depends on the result, do not take that step blindly. When no independent work remains, leave a clear continuation point and wait for my result.

## 4. Language, punctuation, and communication

Use English as your working language. Interpret the task, develop implementation plans, and write technical notes, progress updates, documentation, comments, and final responses in English. Do not translate instructions back into Russian. Keep the application's eight supported UI languages and translate product strings into their respective languages.

Do not use long dashes. In your own new messages, documentation, comments, and UI strings, do not use U+2013 or U+2014. Use the ASCII hyphen `-`, a colon, a comma, or a separate sentence.

Check new and changed text for prohibited characters. Do not rewrite historical documents or upstream files solely for punctuation, and do not change binary fixtures.

Be concise and concrete. At the start of each stage, explain the user-visible result. During work, regularly state what you have established and what you are checking next. During extended work, do not leave me without an update for more than one minute.

Do not request permission for routine code reading, local implementation, building, or safe tests. Do not stop after the first fix with an offer to continue. Hand over required manual network checks using the protocol above.

## 5. Code and documentation workflow

- Run `git status` before editing and account for existing uncommitted changes. Do not delete or revert my work.
- Do not perform destructive reset/clean, commit/push/merge, release publication, or system installation without a separate instruction.
- Use `rg` and `rg --files` for searches. Follow the existing structure and make small, reviewable changes.
- Before using library/API/SDK/CLI/cloud capabilities, retrieve current documentation through Context7: resolve-library-id first, then query-docs. If suitable information is unavailable, use official primary sources. Do not rely on remembered parameters from another version.
- Read and follow applicable skills. Prefer verified, version-specific sources over moving main/testing documentation.
- Preserve SwiftUI, ZarpCore, ZarpdClient, and zarpd as the main project boundaries. Do not rewrite the entire application without a technical need.
- Preserve the main project's MIT license. Do not copy Android GPL code into the MIT core. Directly linking sing-box and using separate processes have different implications; a separate process alone does not establish that there are no licensing obligations.
- Do not disable TLS verification, WARP pinning, IPC bounds, or input validation to make a test pass. Use a dedicated test CA/pin for test certificates.
- Do not add stubs that report success instead of an actual connection or traffic transfer.
- Settings and subscriptions contain secrets: use restricted storage, atomic writes, and safe diagnostics.
- Write meaningful tests for changed algorithms, migrations, and runtime behavior. Do not add tests that merely repeat implementation constants.
- Complete the required checks after changes. Do not repeat the entire suite indefinitely without new changes or unresolved problems.

## 6. Implementation sequence

Follow the stages below. Within each stage, establish the contract and acceptance criteria, implement the smallest complete unit, verify it, and update the progress log. Verify critical architectural assumptions before building production features that depend on them.

### Stage 0. Establish the baseline

Read the materials, compare them with the code and current SHAs, and inspect safe test entrypoints. Run authorized baseline checks. Create `docs/IMPLEMENTATION_PROGRESS.md` with stages, statuses, decisions, checks, and the next action.

If the baseline fails, establish whether the cause is the code, the environment, or a tool restriction. Do not call an environment limitation a project regression. Do not run live tests just in case.

### Stage 1. WARP, T01-T03

1. Add `warp-q-google12`, `warp-t-split-host`, `warp-t-split-sld`, `warp-t-split-endhost`, and the portable Windows `warp-q-google11`.
2. Add country tags, All/RU/IR/CN multi-select, and a fourth custom-strategy column while preserving the original three-column format.
3. Apply the filter to every operation, including auto-connect, rechecks, and fallback. Do not delete hidden results.
4. Quick Scan must continue until N confirmed results or list exhaustion. Two successes and endpoint independence are separate properties.
5. Move custom identity and results to configuration fingerprints with unambiguous migration of legacy IDs. Country tags must not change identity.
6. Implement a custom WARP endpoint list, rotation, pinning of the successful endpoint, IPv4/IPv6 control connections, and an honest single-endpoint indicator.
7. Test cancellation, finite pools, and the absence of false independent status when an H2 address repeats. Hand live WARP checks over to me as a separate script.

### Stage 2. Contracts and backend PoC, T04-T05

1. Design typed ConnectionMode, ServerProfile, ConnectionOptions, RuntimeCapabilities, ProbeKind, and versioned IPC. Preserve a separate WARP validator.
2. Select pinned sing-box/Xray versions and document licensing and distribution. Reference versions are recorded in the snapshot; check currency and compatibility against documentation.
3. Implement a minimal loopback PoC for a custom server with the strategy applied to its outer TCP/UDP connection.
4. Verify the external transport relay/detour. A proxy bridge above user traffic does not prove that split/fake modifies the outer handshake.
5. Prove strategy application to every new flow, SNI/ALPN behavior, TCP/UDP, cancellation, and cleanup.
6. Implement a bounded supervisor for test/production runtime. IPC must not accept shell commands, arbitrary argv, or binary paths.
7. Prepare a manual test for real macOS TUN/DNS/routes/process matching. Do not run it yourself. Keep decisions that critically depend on it pending until I return the result.

### Stage 3. Custom servers and pairs, T06

1. Implement VLESS, Trojan, Hysteria2/hy2, and applicable TCP/WS/gRPC/HTTPUpgrade/TLS/Reality/Vision/Salamander combinations.
2. Reject unsupported parameters with an error naming the field, without its secret value.
3. Build `strategyId@serverId` and strategy-major testing order for compatible pairs only. Unsupported/WG/WARP-direct entries must not become desync pairs.
4. Measure connection time through the first real HTTPS response; double verification uses a fresh connection; score is connect + 4 * ping.
5. Connect order: saved pair, confirmed pairs by score, then search. Cache DNS resolution successes/failures per operation.
6. Server mode does not require a WARP account/terms or `warp=on`, but it requires real HTTPS through the selected server backend.
7. Verify actual strategy application, post-TUN traffic, and teardown on failure. Keep the plain option explicit, off by default, and shown with a yellow status without claiming DPI bypass.

### Stage 4. Subscriptions and XHTTP/ECH, T07-T08

1. HTTPS-only subscriptions: plain/base64/URL-safe lists, 200 servers, 2 MiB after decompression, five HTTPS-only redirects, and a shared 25-second deadline.
2. Atomic source-bound cache, offline restart, Save/Refresh/Delete, stale refresh after 12 hours, and retention of the previous list on failure.
3. Automatic and explicit server ID selection. A disappeared selection becomes unavailable instead of being silently replaced. Refresh does not change the active pair.
4. XHTTP VLESS: supported modes, TLS/Reality, ALPN, pins/names, and extra/xmux/padding. Verify actual configurations and traffic with the pinned version.
5. ECH must not fall back to ordinary TLS; an incorrect pin/ECH/key must fail and clean up.
6. Select H3 only when ALPN is exactly `[h3]`. Validate same-server downloadSettings by host/port/transport/security. Reject secondary targets and unsupported combinations.
7. Check import support and runtime combinations using golden vectors and real loopback engines, not JSON parsing alone.

### Stage 5. Routing rules and Geo data, T09-T10

1. Implement Direct/Proxy/Block, Block > Proxy > Direct priority, editable LAN/RU/IR/CN presets, and custom presets.
2. Support domain/full/keyword/regexp, IP/CIDR, geoip/geosite, and attributes. Errors include line numbers; unknown categories are not ignored.
3. Implement the correct DNS path, reverse mapping, and sniffing; force the health probe through the target tunnel.
4. Do not let LAN route exclusions bypass explicit Block/Proxy rules. Disabled rules preserve the previous behavior.
5. Convert Geo `.dat` protobuf into native rules, not removed legacy sing-box fields.
6. Explicit downloads: HTTPS, 64 MiB, three minutes, cancellation, complete validation, atomic replacement, and source-specific caches. Bundled country data includes revision/checksum/license.
7. Do not send entire large databases through bounded IPC; do not allow arbitrary root filesystem paths.

### Stage 6. Applications, WARP adapter, and resilience, T11-T13

1. Add .app selection, icons/search/manual addition, and matching of actual executables/helpers. A bundle ID is not the owner of a network connection.
2. Empty or stale selection must not become all applications. Check TCP, UDP, and DNS separately for selected/excluded apps.
3. For WARP, implement a separate L4/SOCKS adapter to the MASQUE IP session and a policy frontend. The current CONNECT-IP packet pump does not provide that adapter.
4. Routing rules and per-app selection must work in both server and WARP modes. Do not stop at the narrower Windows server-only scope.
5. One frontend owns system routes/TUN in a given mode. Outer control connections must not loop back into their own tunnel.
6. Add DNS/IPv6 policy, bounded real health probes, debounced sleep/wake/network events, correct backoff, and reconnect cancellation.
7. Do not run competing reconnect loops in the GUI and daemon. A restarted GUI must adopt the actual active pair.
8. Prepare system-adapter, sleep/wake, route/DNS, and crash checks for my manual execution.

### Stage 7. UI, migrations, and distribution, T14-T15

Implement UI and verification incrementally during each earlier stage; finish the complete set here.

1. New source/endpoints, server-selection, routing/preset, Geo-download, and application screens.
2. Pair list, country filter, progress/Cancel, confirmation/independence, and clear limits for mode-specific parameters.
3. Eight languages, key/placeholder parity, layout checks, and no long dashes in new text.
4. Migration checks, preservation of preferences/cache/active pairs, and safe diagnostics.
5. Safe Swift/Go suites, real loopback protocol tests, and generated-configuration checks against pinned engines.
6. Reproducible arm64 application/DMG, checksums/signing/notices. Building is authorized; daemon installation and publishing are not part of autonomous execution.
7. Complete manual checks after I return results. Do not claim release-level network readiness without them.

### Stage 8. Additional Windows capabilities, T16

Separately research IP fragmentation, raw TCP techniques, exact multidisorder, and custom WG. Start with Darwin capabilities, licensing/signing constraints, and controlled PoCs. Require evidence of the exact packet modification and a working transport.

Do not treat a catalog entry or `wireguard-go/tun` dependency as a WireGuard implementation. If a mechanism requires unavailable external conditions, finish the research you can perform, record the concrete dependency, and continue other independent work. Do not reintroduce every old unsupported profile as working.

## 7. Progress log, gates, and continuation

Maintain `docs/IMPLEMENTATION_PROGRESS.md`. For each T-task, record:

- Status: planned, in_progress, implemented, awaiting_user_test, verified, or blocked with a concrete reason.
- Changes and affected files.
- Selected versions and architectural decisions.
- Commands executed and their results.
- What was checked with fakes/loopback, what I checked manually, and what remains unverified.
- The prepared test script and command for a pending manual check.
- The next concrete safe operation.

Proceed to the next dependent stage after the required contracts and checks. `implemented` is not `verified`. Compilation does not prove traffic; traffic does not prove desync; localhost does not prove ISP DPI bypass. If a critical PoC or required user-run test is pending, do not mark its gate as passed.

Update the log before finishing each major block and before stopping. After compaction, a new message, or resumption, read the log and continue from the nearest unfinished operation. Do not restart the project from scratch.

When I send a RESULT, verify the version/run ID, PASS/FAIL/SKIP, cleanup, and scenario coverage. An incomplete log is not an overall PASS. Fix any identified issue, prepare the test again, and continue according to dependencies.

The final report must identify implemented features, checks that actually passed, pending manual checks, and remaining limitations. Only consider scope complete when it meets the relevant acceptance criteria in the analysis. Do not claim full Windows packet parity without a proven T16 implementation.

Start now with Stage 0, then proceed to Stage 1. Preserve my VPN throughout the entire task.
