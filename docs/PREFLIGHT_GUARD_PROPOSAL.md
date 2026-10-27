# Proposed preflight classification change

Status: user approved the narrow change, conditional on never disconnecting their VPN.
Applied to the isolated manual runner and verified with fake tests. No autonomous live
test or system configuration change was performed.

The user supplied two different states: an active VPN with default/effective IPv4 on
`utun4` and one connected service; then a physical default/effective IPv4 on `en0`,
zero connected services and an explicit missing IPv6 route. The latter still has eight
scoped IPv6 defaults and eight scoped multicast entries with link-local gateways.
Those original reports did not include interface addresses or prove each owner.
A later live-command preflight observed link-local-only profiles for all eight
interfaces and accepted their self-address multicast routes. Read-only investigation
then identified the exact bare `fe80::%utunN` form used by their scoped defaults.

The original user instruction in [IMPLEMENTATION_AGENT_PROMPT.md](IMPLEMENTATION_AGENT_PROMPT.md)
section 2 says: "Do not remove or weaken foreign-VPN guards in the application or tests
to make a check pass." The user subsequently approved this concrete criterion while retaining the constraint
that the assistant must not disconnect or change the VPN.

## Concrete proposal

A foreign route may be excluded from the test guard's conflict list only when all
these conditions have been freshly observed by read-only commands:

- The default interface is a physical `enN`, and effective IPv4 uses that interface.
  During the test, its reported owned interface may instead carry effective traffic.
- IPv6 explicitly reports no route to the numeric measurement destination. During
  the test, only its owned interface may instead carry that effective route.
- The route is exactly a scoped IPv6 `default` with flags `UGcIg`, or `ff00::/8`
  with flags `UmCI`, on a numeric `utunN` interface.
- Its scoped gateway is the same interface's own link-local IPv6 address. A scoped
  default may instead use exactly `fe80::%utunN` only when the same interface has
  a matching scoped multicast route through its own link-local address. No other
  link-local peer or prefix is permitted.
- The interface is point-to-point and has at least one link-local IPv6 address,
  with no IPv4, global IPv6, unique-local IPv6 or malformed address entry.

Every other foreign route remains a conflict. Connected VPN services, active/uncertain
production Zarp, failed observations and external route/DNS changes still block or stop
the test. No fixed interface whitelist or force flag is proposed. Routes and interfaces
are never removed by preflight. The main daemon/application guard is not changed.

The prepared classifier is `interface_metadata_routes` in
[parity_manual.py](../scripts/parity_manual.py). It contributes `self_gateway_candidate_count` to read-only diagnostics and derives
the exact metadata rows excluded from the isolated manual runner conflict list. Interface profiles expose
only interface names and a link-local-only boolean; raw addresses remain private.

The applied change is confined to deriving the conflict list in
`guard_network`: remove exactly rows returned by that helper before running the
existing foreign-route validator. Production Zarp and service checks remain in place.
The same classifier would re-evaluate fresh interface data throughout the test.

## Evidence and limits

Pure regression fixtures pass for matching candidates, addressed/global/unique-local
interfaces, non-self gateways, missing profiles, unknown IPv6 observations, active
IPv4/IPv6 tunnels, connected services, split/private/unicast routes and test-owned
full-tunnel observations. Tests also prove that active/uncertain production Zarp and connected VPN services
remain blocked after the narrow route classification succeeds. The user's actual candidate count is not known until interface
observations are provided; approval would not automatically pass those observations.

[Apple's IPv6 address setup](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/in6.c)
creates scoped multicast routes as part of interface addressing.
[Apple's routing implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/route.c)
marks default routes as potentially leading to the Internet and notifies policy clients.
The scoped flag alone, or even a matching self-gateway, does not prove the owner is
inactive under every per-app policy. The proposal would relax the existing conservative
criterion for a narrowly observed case. It was enabled only after the user approved the proposal. All other VPN protections
and the ban on autonomous real network testing remain in place.

No live WARP/TUN scenario has passed. Autonomous checks remain pure/fake/loopback.
