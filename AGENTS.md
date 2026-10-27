# Project purpose and user requirements

## Product direction

- Prepare the bundled service automatically at startup and before connection/account actions. Service installation, updating and recovery are app-owned. Do not expose maintenance windows or install/restore/restart/remove buttons to users. macOS authorization remains an OS-controlled step when required.
- Zarp wraps WARP and configured server tunnels with an additional zapret strategy. The core deliverable is a working tunnel/server plus strategy combination, with discovery, confirmation, saved selection and fallback among compatible combinations.
- Apply the selected zapret strategy to the outer TCP/TLS or UDP/QUIC connection to the server, below the tunnel protocol. On macOS, use the portable implementation of supported zapret techniques. Modifying only inner application traffic does not establish strategy application to the tunnel.
- Happ is the user's reference for subscription management and server selection. Imported and subscribed servers must feed the same strategy/server workflow. Connect the source selection and server list to that workflow.
- Track source, server, strategy and configuration identity together. Confirm both real traffic through the selected backend and actual application of the required outer strategy. An engine starting successfully is insufficient.
- Plain connections are an explicit optional mode, off by default. Never silently bypass a failed strategy or describe plain transport success as DPI bypass.
- The user states that XHTTP works. Pinned Xray now carries real private HTTPS/UDP through the product compiler/guardian/outer relay in all four modes, H3, bounded extra and a separate download leg. Shared import, typed options, main source selection and GUI/IPC/native frontend code are implemented. Actual product TUN, real ECH and Reality-XHTTP combinations, complete extra-field compatibility and signed-release acceptance remain unverified. Do not describe all XHTTP support as absent or treat local success as a passed system test.
- Prioritize connecting the backend, outer relay, strategy/server pairs and subscription selection to the app's connection lifecycle. Independent implementation must continue while a separate system test remains unverified.

## Preserve the user's VPN

- Never independently disconnect, restart, replace, bypass or reconfigure the user's current VPN, its processes or services.
- Do not modify active routes, DNS, proxy settings, firewall, network services or interfaces for autonomous testing. Do not launch a real TUN, the production GUI with auto-connect, daemon installation or live integration scripts.
- Use fakes, temporary storage/IPC and reviewed loopback tests for autonomous checks. Keep foreign-VPN guards intact.
- When actual system testing is necessary, prepare a bounded automated test and give the user the exact command to run themselves. Do not count it as passed without their result.
- Avoid repeated requests for the same manual test and do not block unrelated implementation on it. Investigate existing evidence first.

## Communication and continuity

- Do not use U+2013 or U+2014 in new prose, comments, UI strings or documentation. Use an ASCII hyphen, a colon or separate sentences.
- Keep implementation instructions and progress records in English. Respond to the user in their language.
- Keep docs/IMPLEMENTATION_PROGRESS.md current. Separate implemented behavior, local transport evidence, actual strategy evidence and unverified system integration.
- Preserve existing work and the historical analysis/reference snapshots. Do not replace the project or discard uncommitted changes.

## Context7

Use Context7 MCP for current library, framework, SDK, API, CLI tool and cloud-service documentation, even for familiar APIs. Prefer it over web search for library documentation.

1. Start with resolve-library-id using the library name and the question, unless an exact /org/project ID was provided.
2. Select the best match by name, relevance, source reputation, snippet coverage and benchmark score. Use version-specific IDs when a version is specified.
3. Call query-docs with that ID and a specific, complete question.
4. Use the returned documentation for the implementation or answer.

This is unnecessary for refactoring, scripts written from scratch, business-logic debugging, code review and general programming concepts.
