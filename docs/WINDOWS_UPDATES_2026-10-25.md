# Windows update review: 2026-10-25

The current Windows main branch and latest stable release are both
`d6695efb64030f37cbe1a52f74c742e1fc61f3da` (v1.7.0). Since the previously
reviewed prerelease, two commits changed 30 files, with 1,284 additions and
53 deletions. The important additions are Persian/RTL support, registration
recovery and a protected registration path for a device that has no account.
WARP+ license support already existed in that prerelease and in this macOS tree.

The fresh source checkout is `_reference/Zarp-Win-2026-10-25`, clean and ignored
by the parent repository. The previous Windows references were preserved.
Release metadata and file fingerprints are recorded in
[the dated snapshot](windows-update-snapshot-2026-10-25.json). The historical
`parity-snapshot.json` remains unchanged.

## Releases actually checked

GitHub's web reader returned a cached release index from five days earlier.
The current list and full release descriptions were therefore fetched directly
from the public GitHub REST API and checked against actual Git tags.

| Release | Published in Moscow time | Commit | Changes since the preceding reviewed revision |
|---|---|---|---|
| [v1.6.0](https://github.com/ZarpVPN/Zarp/releases/tag/v1.6.0) | 2026-10-23 17:49:22 +03:00 | `f98dc8e5275f0e8b2331a6fe0c26b4655de42502` | 27 files, +819/-48 from `1.6.0_Pre-release_2`: registration recovery, Persian/RTL and route-aware VPN warnings; stable WARP+ support |
| [v1.7.0](https://github.com/ZarpVPN/Zarp/releases/tag/v1.7.0) | 2026-10-23 20:12:58 +03:00 | `d6695efb64030f37cbe1a52f74c742e1fc61f3da` | 17 files, +466/-6 from v1.6.0: registration through temporary zapret2 protection, with WARP+ completion under that protection |

Release binaries and actual Cloudflare accounts were not used in this review.
The snapshot's asset checksums are published metadata, not independently verified
downloads or evidence that registration works on a particular ISP.

## What changed in v1.6.0

In [Warp.cs](https://github.com/ZarpVPN/Zarp/blob/f98dc8e5275f0e8b2331a6fe0c26b4655de42502/src/Zarp/Core/Warp.cs),
registration is read again after transient IPC failures and after a creation
attempt. Reads can be attempted three times with a one-second pause between
attempts. A delayed successful registration is reused. Responses indicating an
old registration, and an unresponsive local service, do not authorize deletion
or immediate account replacement. A pending-creation window helps avoid issuing
another create command while the first one may still be running. Diagnostics
distinguish service, read, pending and creation failures.

WARP+ still uses the official local `warp-cli` and Cloudflare service. The key
is validated, masked and omitted from Zarp settings and logs. The account type
is checked after applying it. Existing registrations and premium subscriptions
are retained during recovery.

Persian is exposed as `fa` / `فارسی`, with RTL reading/alignment in labels,
menus, dialogs, dropdowns and toggle captions. Technical inputs, paths, license
keys, IPs and logs retain LTR direction. The implementation also handles language
changes while the app is open. Relevant source: [L.cs](https://github.com/ZarpVPN/Zarp/blob/d6695efb64030f37cbe1a52f74c742e1fc61f3da/src/Zarp/Core/L.cs#L30),
[Theme.cs](https://github.com/ZarpVPN/Zarp/blob/d6695efb64030f37cbe1a52f74c742e1fc61f3da/src/Zarp/UI/Theme.cs#L47)
and [FormControls.cs](https://github.com/ZarpVPN/Zarp/blob/d6695efb64030f37cbe1a52f74c742e1fc61f3da/src/Zarp/UI/FormControls.cs#L63).

VPN warnings now use Windows route lookup for WARP destinations after identifying
a candidate VPN adapter. A LAN overlay that does not carry that traffic can be
excluded from the warning. Unknown routing information retains conservative
behavior. See [NetCheck.cs](https://github.com/ZarpVPN/Zarp/blob/d6695efb64030f37cbe1a52f74c742e1fc61f3da/src/Zarp/Core/NetCheck.cs#L20).

## Protected registration in v1.7.0

The implementation is split across
[Engine.EnsureWarpRegistrationAsync](https://github.com/ZarpVPN/Zarp/blob/d6695efb64030f37cbe1a52f74c742e1fc61f3da/src/Zarp/Core/Engine.cs#L764),
[Warp's registration state](https://github.com/ZarpVPN/Zarp/blob/d6695efb64030f37cbe1a52f74c742e1fc61f3da/src/Zarp/Core/Warp.cs#L106),
[the API destinations](https://github.com/ZarpVPN/Zarp/blob/d6695efb64030f37cbe1a52f74c742e1fc61f3da/src/Zarp/Core/WarpRegistrationApi.cs)
and [Zapret.BuildRegistrationArgs](https://github.com/ZarpVPN/Zarp/blob/d6695efb64030f37cbe1a52f74c742e1fc61f3da/src/Zarp/Core/Zapret.cs#L511).

1. Read the existing registration. Reuse it when present.
2. If registration is confirmed missing, try the ordinary registration command.
3. Read registration again, including after a timeout. Search for a protection
   strategy only if creation had a qualifying network failure and registration
   is still confirmed missing. The source tests cover service failures, an old
   registration, quota and HTTP 429 without starting a strategy search.
4. Refuse this search while a tunnel/proxy/zapret process is already active or a
   foreign VPN is detected. Existing connections are preserved.
5. Select only eligible zapret TLS strategies, represented by `MasqueH2` in the
   catalog. Apply the selected country filter. Prioritize the selected strategy,
   then confirmed successful ones. QUIC tunnel techniques are not API candidates.
6. Resolve a fixed hostname list, combine public results with four fixed API
   addresses, deduplicate and bound the list to 64 entries. DNS waiting is capped
   at five seconds. Start a temporary TCP-443 filter with both IP and hostname
   restrictions, then retry registration.
7. For WARP+ on a new device, retain the successful API protection until the
   license command and account-type read complete. Stop the temporary process
   in `finally`, including on failure and cancellation.
8. Restore the previous progress/state and run normal tunnel discovery or
   connection separately. API success does not change saved tunnel results or
   certify that the same strategy can carry WARP traffic.

The protected hostnames are `api.cloudflareclient.com`,
`api.devices.cloudflare.com`, `zero-trust-client.cloudflareclient.com` and
`notifications.cloudflareclient.com`. The fixed addresses are `162.159.137.105`,
`162.159.138.105`, `2606:4700:7::a29f:8969` and `2606:4700:7::a29f:8a69`.
The latter are listed in Cloudflare's current
[client orchestration documentation](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/#client-orchestration-api).
That documentation describes the official Cloudflare One Client; it does not
establish compatibility of every address with macOS Zarp's consumer REST API.
That combination must retain the correct SNI/Host and ordinary certificate checks
and obtain separate response evidence before becoming a native fallback target.

## Boundaries found in the Windows implementation

**Downloading the WARP installer is a separate path.**
[WarpInstaller.cs](https://github.com/ZarpVPN/Zarp/blob/d6695efb64030f37cbe1a52f74c742e1fc61f3da/src/Zarp/Core/WarpInstaller.cs#L45)
did not change in these two commits. It uses a normal `HttpClient` to download
the official MSI, with retries, size bounds, partial-file cleanup and Cloudflare
signature verification. A manually supplied MSI is supported. Installation runs
before protected registration, and the new filter does not include
`downloads.cloudflareclient.com`. Thus v1.7.0 does not add a protected download
bootstrap when the installer itself is blocked by DPI.

**Existing-account API failures have narrower coverage.** If registration already
exists, the registration helper invokes the license callback directly. Reading
an account also goes directly to `Warp.ReadAccountAsync`. The new strategy search
does not activate solely because an existing account's license/status request
fails. The successful fresh-registration case is the one explicitly protected
through license application and confirmation.

**Retry eligibility currently depends on CLI text.** Distinguishing missing
registration from service/network errors is substantially safer than treating
every failure as a missing account, but depends on the official client's output.
The routine has per-command/DNS limits and cancellation; it does not itself set
one overall registration-search deadline. These are points to handle explicitly
in the native port, not demonstrated ISP failures in this review.

## Current macOS gaps

| Behavior | Current native implementation | Required change |
|---|---|---|
| WARP+ input, apply and account status | Already present in `WarpPlusView`, typed IPC and `AccountAPI` | Retain it; share the protected API transport with setup |
| Registration through zapret | Missing: `warp.Register` calls usque registration/enrollment directly | Route the real API TLS connection through eligible native techniques |
| Protection through license confirmation | Missing: setup and WARP+ use separate ordinary HTTP operations | Keep one owned API-protection scope through all required steps |
| Recover delayed/partial registration | Existing-file check and atomic final config; incomplete transaction state | Add explicit account state, pending enrollment and safe resumption |
| Persian and RTL | Eight languages; no `fa` resource or layout-direction model | Complete translation and RTL/LTR behavior for SwiftUI and AppKit |
| Route-aware VPN warning | Default-utun and active-utun-with-IPv4 detection | Refine warnings using actual destinations while preserving daemon guards |
| Install official Cloudflare WARP | Unnecessary: native WARP client is bundled | Keep the current native architecture |

Two native design issues need to be fixed before adding a retry loop:

- [FileAccounts.Register](../zarpd/daemon/accounts.go) returns on timeout or
  cancellation while its worker can keep running. The pinned usque
  [registration/enrollment functions](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12/api/cloudflare.go)
  use `http.DefaultClient` and requests without a caller context. Merely timing
  out the wrapper does not cancel those requests. A subsequent retry could
  overlap or finish late and overwrite state.
- [warp.Register](../zarpd/warp/account.go) persists the usable config after both
  account creation and MASQUE enrollment. If creation succeeds but enrollment
  fails, its current wrapper has no durable checkpoint from which to resume.
  Blindly restarting the whole operation under each strategy risks creating
  additional accounts. A lost POST response also has an uncertain outcome unless
  the API provides a verified recovery/idempotency mechanism.

Also, [ZarpdClient.isAccountRegistered](../Packages/ZarpCore/Sources/ZarpdIPC/ZarpdClient.swift)
maps omitted account metadata to `false`. The account contract should distinguish
missing from unavailable/unknown. Invalid or unreadable existing account storage
must not authorize replacement. Its current 75-second registration IPC budget
also needs coordination with a multi-attempt operation's overall deadline.

## Concrete port sequence

1. **Make account setup cancellable and resumable.** Introduce a dedicated,
   injected, context-aware HTTP client for registration, MASQUE enrollment,
   license application and account reads. Avoid changing `http.DefaultClient`
   globally. Use fixed API origins, bounded bodies, checked redirects and
   ordinary HTTPS verification. Add typed account/error states and one serialized
   account operation. Preserve current files and subscriptions. Commit private
   checkpoints after a confirmed account creation, then resume enrollment using
   that identity. Report ambiguous creation outcomes explicitly.
2. **Add protected API dialing.** Reuse the native ClientHello desynchronization
   primitives in [desync.go](../zarpd/warp/desync.go) and the lifecycle patterns in
   [outer.go](../zarpd/relay/outer.go). Apply them to API TCP/TLS itself, before
   any WARP tunnel exists. Keep a fixed host/port allowlist, supported TLS-only
   candidates, country filtering and selected/confirmed ordering. Use finite
   overall and per-attempt deadlines. Propagate cancellation and join all owned
   work before releasing setup ownership. No TUN, default routes, system proxy
   or DNS replacement is required for these HTTP requests.
3. **Integrate one setup flow with the engine and IPC.** Update
   [ZarpEngine](../Packages/ZarpCore/Sources/ZarpCore/Engine/ZarpEngine.swift),
   [daemon registration](../zarpd/daemon/manager.go),
   [account IPC](../Packages/ZarpCore/Sources/ZarpdIPC/ZarpdClient.swift) and
   [WARP+ operations](../zarpd/daemon/plus.go). Obtain terms consent before account
   creation. Keep successful protection until enrollment, any requested license
   and its confirmation finish. Advertise typed daemon capability so old daemons
   cannot silently ignore requested protection. Preserve existing active tunnels.
   Registration progress/results stay separate from tunnel strategy results.
4. **Add Persian as a complete language.** Add `fa` to
   [Localization](../Packages/ZarpCore/Sources/ZarpCore/Localization/Localization.swift)
   and provide `Resources/Lang/fa.txt`. Windows has 378 English and 378 Persian
   keys; the current macOS English table has 280. Only 142 key names overlap;
   138 current macOS keys need additional translations, before new setup labels
   are added. Shared keys still need a meaning/placeholder review. Apply RTL to
   natural-language UI and search, keep links, endpoints, keys, logs, paths and
   technical tables LTR, and adapt native `NSTableView` controls explicitly.
   Verify language changes without restart and the compact window layout.
5. **Refine warnings without weakening connection guards.** Review
   [SystemNetworkInspector](../App/Sources/Zarp/SystemNetworkInspector.swift)
   against actual WARP/API/server destinations, including IPv6. Keep conservative
   handling of failed observations and existing daemon conflict refusal.
   Never stop or reconfigure another VPN to make setup succeed.

This transfers the Windows behavior into the existing native client. It does
not require installing the official Cloudflare app or running WinDivert on macOS.

## Verification required for that port

The Windows source contains new registration recovery and protected-registration
tests, plus Persian direction and Windows route-lookup checks. Reviewed files:
[WarpRegistrationTests.cs](https://github.com/ZarpVPN/Zarp/blob/d6695efb64030f37cbe1a52f74c742e1fc61f3da/tests/Zarp.Tests/WarpRegistrationTests.cs)
and [WarpRegistrationProtectedTests.cs](https://github.com/ZarpVPN/Zarp/blob/d6695efb64030f37cbe1a52f74c742e1fc61f3da/tests/Zarp.Tests/WarpRegistrationProtectedTests.cs).
They were read, not executed on this Mac.

For the native implementation, use fakes and private loopback TLS fixtures to
check direct failure/protected success, actual ClientHello treatment, resumed
enrollment, late cancellation, quota/rate-limit refusal, unknown account state,
preserved existing subscriptions and protection through license confirmation.
Check that API success leaves tunnel results unchanged and that cleanup joins
all owned connections/workers. Use the inert appearance fixture for Persian and
LTR technical inputs. Real ISP effectiveness requires a later bounded user-run
check; no such test or VPN disconnection is requested by this source review.

This review changed documentation and ignored reference material only. No
production API calls, account creation, installer execution, application launch,
service control or system-network changes were performed.
