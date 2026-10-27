# Windows releases and macOS implementation

Newer source/release analysis is in
[the 2026-10-25 review](WINDOWS_UPDATES_2026-10-25.md), covering stable v1.6.0
and v1.7.0, Persian/RTL and protected WARP registration. The review below records
the earlier 2026-10-20 implementation baseline.

Reviewed on 2026-10-20. This supplements the historical parity snapshot, which
remains unchanged. The release list was checked as well as GitHub's latest
stable endpoint, because the latter omits prereleases.

## References

- Stable [v1.5.0](https://github.com/ZarpVPN/Zarp/releases/tag/v1.5.0): the
  original ignored Windows reference remains at
  `07406eb5af0a2ad1812fde3692965313cc2798fc`.
- [1.6.0_Pre-release_2](https://github.com/ZarpVPN/Zarp/releases/tag/1.6.0_Pre-release_2),
  published 2026-10-14: separately saved under
  `_reference/Zarp-Win-1.6.0_Pre-release_2`, commit
  `3e78f4dff74d03d06c4115bf43865de016f04340`.
- `_reference/` is git-ignored. Neither historical reference was reset or replaced.

## Behaviors carried into macOS

| Windows behavior | macOS implementation |
|---|---|
| Strategy-major compatible server pairs | `ServerPairs` builds TCP or UDP pairs from the profile's outer transport; excludes WARP direct controls and unsupported techniques |
| `strategyId@serverId` identity | Pair identity plus source and executable configuration fingerprints; results and remembered selections are scoped to their source |
| Inline confirmation before selecting a winner | Existing two-attempt scan/confirmation now accepts server pairs; only current compatible pairs can connect or fall back |
| Saved manual servers and HTTPS subscriptions | Shared private `ConnectionLibrary`, import/refresh/delete/selection UI and main-window source picker |
| Twelve-hour refresh with offline cache | `refreshIfNeeded` runs before a server connection; failed refresh retains the previous list and reports a warning |
| XHTTP modes and options | Import, Swift/Go contracts, Xray compiler and runtime for auto, packet-up, stream-up and stream-one; exact h3 ALPN selects UDP |
| XHTTP separate download leg | Same-server and same-outer-transport validation; compiler injects the resolved destination, verification and mandatory outer-relay detour into the download leg |
| WARP+ license and account type UI | Secure input, typed account IPC, format validation, key acceptance separated from premium confirmation; key is not stored in settings or the account file |

Windows applies WARP+ with the official `warp-cli registration license` command.
macOS Zarp owns an account through its pinned usque integration, so its daemon
uses the corresponding fixed Cloudflare account API. It does not invoke or
reconfigure another installed VPN. Account operations preserve the current
Zarp tunnel, strategy, routes and DNS. Registration, if needed, still requires
the existing terms-consent flow. A paid license was not used for verification.

## Actual server connection path

The app sends a validated profile and parsed strategy through the separate
`openServer` IPC method. An older WARP-only daemon cannot receive server
credentials through this path. The daemon resolves the chosen server before
opening a tunnel, refuses foreign VPN routes, fixes the physical socket policy
and starts an authenticated private outer relay. The relay splits the actual
outer TLS ClientHello or sends UDP fakes on the same socket before real traffic.
The selected sing-box or Xray process must detour through that relay.

A real HTTPS request through the private backend and nonzero strategy-application
evidence are required before creating the daemon-owned utun. A gVisor userspace
bridge forwards TCP, UDP and DNS through the backend. The daemon verifies its
measurement route before and after a second HTTPS check through the new tunnel.
Server checks accept a valid trace with `warp=off`. WARP checks still require
`warp=on` or `warp=plus`.

The app bundle contains checksum-pinned sing-box 1.13.14 and Xray 26.9.30, plus
the separately owned guardian. Its signed executable hash is embedded into the
daemon during the build. The guardian and independent recovery helper use
renewable leases for product sessions. Finite loopback PoCs keep their original
caps. Temporary engine configuration is removed after authenticated readiness.

## Verification and remaining limits

- Swift: 283 tests passed, including source isolation, missing-server refusal,
  no WARP registration for server mode, WARP+ preservation and XHTTP import.
- Product compiler, production guardian and outer relay: real private HTTPS and
  UDP passed for VLESS, Trojan, Hysteria2, all four XHTTP modes, HTTP/3,
  XHTTP extra and a separate download leg. Wrong credentials were rejected.
- A 130-second private VLESS run renewed its leases and carried fresh HTTPS
  beyond the original two-minute PoC cap.
- The userspace IP bridge passed IPv4/IPv6 TCP, UDP and DNS tests without a
  system interface. Go race checks and vet passed for the changed components.
- The app builds without installation or GUI launch.

XHTTP extra is a validated, bounded set of pinned-engine fields. An alternate
download host or outer transport, arbitrary socket settings and unknown fields
are refused. ECH, certificate verification names/pins and Reality options are
compiled from typed profiles; real ECH and Reality-XHTTP combinations still need
separate traffic evidence. Neither local success nor a compiled option establishes
ISP bypass effectiveness.

The previous user system-adapter FAIL remains unpassed. Its external sing-box
TUN frontend is separate from the new daemon-owned Go utun/userspace bridge.
No actual product TUN, signed installation or production route/DNS cleanup was
tested autonomously. The existing VPN was preserved.

The 0.3.0 continuation implements own-server application inclusion/exclusion,
installed-app and executable selection, original-flow owner lookup, physically
bound direct forwarding and strict IPC capability checks. The server/endpoints
window accepts links/subscriptions directly and exposes IPv6 and DNS. Actual
TCP/UDP separation passes in the in-memory IPv4/IPv6 stack, and Darwin owner
lookup passes on owned loopback sockets. System-TUN/kernel acceptance remains
unverified. Shared system DNS uses the chosen server resolver when override is
enabled; this limitation is explained in the application selector.

Full cross-platform parity still includes Geo/domain policies, broader raw-packet
techniques and WireGuard work described in the historical analysis. See
[the implementation record](IMPLEMENTATION_PROGRESS.md#application-routing-and-direct-server-setup-2026-10-20)
for the new behavior and exact verification limits.
