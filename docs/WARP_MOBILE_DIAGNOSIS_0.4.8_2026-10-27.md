# WARP mobile-path diagnosis and 0.4.9 changes

Analysis date: 2026-10-27, Europe/Moscow. The observed user session is from
2026-10-26, app and daemon 0.4.8, 14:22:48-14:27:41. The user clarified that
the request concerns WARP QUIC and the other WARP strategies.

Only existing application and daemon logs were read. No production GUI, IPC,
service, real TUN, route, DNS or account operation was started by the agent.
Sanitized source hashes and counts are recorded in
`build/hotspot-0.4.8-analysis-2026-10-27.json`.

## Observations from the user's session

| Group | Count | Evidence |
| --- | --- | --- |
| HTTP2 with vk.com and www.google.com | 2 strategies | Both pass two independent traffic checks. |
| Persistent HTTP2 with vk.com | 1 | Verification succeeds at 14:25:59; the app closes it at 14:27:41. No spontaneous loss is logged. |
| HTTP2 split with the standard WARP name | 4 | Timeout after local CONNECT header writes. |
| HTTP2 disorder with the standard name | 1 | Timeout during TLS, after one reported ClientHello split. |
| QUIC sessions ending in stateless reset | 9 | CONNECT-IP opens, then the packet pump reports transport loss. This includes both alternate names. |
| QUIC TTL variants | 2 | One handshake timeout and one CONNECT-IP timeout. |

All eleven QUIC attempts report three decoy bursts. Retry coverage is active;
missing retry decoys do not explain the remaining resets. There is no logged
access-network change during the scan.

The alternate HTTP2 names succeed between failing standard-name attempts on
the same TCP endpoint. This supports an inference that the outer TLS name or
its resulting handshake fingerprint matters on this path. The logs do not
identify the network device enforcing such a policy. They also do not prove
that every TCP split position will work with the alternate names.

QUIC handshakes and CONNECT-IP succeed before the nine resets. This is not
evidence that UDP is completely unreachable. A validated stateless reset ends
the transport, but these logs cannot distinguish endpoint state loss, path/NAT
effects or network interference. Do not attribute its issuer to carrier DPI.

WireGuard and historical raw-packet techniques remain explicitly unavailable
in this daemon. They were not failed mobile-network attempts in this session.

## Reproduced packet-size defect

The native interface MTU is 1280, while a 1280-byte outer QUIC packet must also
carry connection IDs, authentication and HTTP DATAGRAM framing. A full-size
inner TCP packet can therefore exceed the available DATAGRAM budget. The
pinned CONNECT-IP library returns an ICMP response advertising 1280 again,
which does not reduce a 1280-byte inner path. Small packets can pass while
TLS and HTTPS payloads stall.

The regression fixture uses the actual product H3 dialer and packet pump,
ephemeral pinned TLS keys, two userspace IP stacks and a numeric loopback UDP
relay that drops payloads above 1280 bytes. It creates no OS interface. HTTPS
with an approximately 17 KB request and matching response times out before
the fix on both IPv4 and IPv6:
`/tmp/zarp-049-path-mtu-reproduction-final.log`.

The first fixture used a synchronous netstack notification channel and stalled
during ICMP feedback. A bounded independent queue corrected the fixture before
the above reproduction. That fixture issue is not counted as a product defect.

The fix caps TCP MSS in SYN and SYN-ACK packets in both directions, reserving
80 bytes inside the initial 1280-byte QUIC packet. The resulting inner TCP
packet budget is 1200. The OS interface MTU stays 1280, and HTTP2 packet sizing
is unchanged. IPv4/IPv6, extension headers, odd option offsets, duplicate MSS
options and checksum preservation are covered. Fragmented, malformed, AH and
encrypted packets pass through unchanged. The checksum adjustment follows
[RFC 1624](https://www.rfc-editor.org/rfc/rfc1624).

The same HTTPS transfer passes after the fix. This establishes a separate
packet-size failure and its correction. It does not prove that this defect
caused the nine stateless resets. Large UDP packet fragmentation or a hidden
stream fallback was not added.

## Other changes

- Six additional HTTP2 profiles pair host, sld and endhost splitting with
  vk.com and www.google.com. Each has a separate identity and requires fresh
  traffic confirmation. The existing working midsld profiles retain their
  configuration identity. Standard-name strategies remain available for other
  access networks. Disorder was not silently converted to split.
- Every new profile retains the enrolled Cloudflare key pin and mandatory
  outer strategy. Imported-server pairs and registration origins keep their
  existing behavior. Plain WARP remains unavailable.
- QUIC logs now record bounded socket packet-size samples, MSS changes,
  generated Packet Too Big counts and the typed closure class. Sampling stops
  at 256 sends and 256 receives. Decoy sends are excluded; receives on the
  shared socket may include replies to decoys. No packet contents, connection
  IDs, reset tokens, TLS secrets or peer-provided error strings enter the new
  statistics. Original OOB, ECN and batch reads are retained.
- The WARP H3 configuration fingerprint is now v3. Old QUIC confirmations
  require a fresh check. H2 v3 identity is unchanged.

Full validation, artifact identity and remaining system-test limits are recorded
in [IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md).
