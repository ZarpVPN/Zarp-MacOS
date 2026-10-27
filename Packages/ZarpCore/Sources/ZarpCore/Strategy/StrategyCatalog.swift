/// Portable WARP profiles from the pinned MIT Windows catalog, retaining useful macOS variants.
/// Unsupported historical profiles are available separately for diagnostics.
public enum StrategyCatalog {
    public static let builtIn: [Strategy] = [
        // ---------- MASQUE / HTTP3 (default protocol of the WARP client) ----------
        Strategy(id: "warp-q-google6", name: "WARP QUIC: fake google ×6", transport: .masqueH3,
                 args: "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=6"),
        // Alternate outer names keep the WARP key pin and the requested fake
        // strategy. Discover and confirm them independently on each network.
        Strategy(id: "warp-q-vk-name", name: "WARP QUIC: vk.com + fake vk ×6", transport: .masqueH3,
                 args: "--payload=quic_initial --lua-desync=fake:blob=quic_vk:repeats=6", warpTLSName: .vk),
        Strategy(id: "warp-q-google-name", name: "WARP QUIC: www.google.com + fake google ×6", transport: .masqueH3,
                 args: "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=6", warpTLSName: .google),
        Strategy(id: "warp-q-google3", name: "WARP QUIC: fake google ×3", transport: .masqueH3,
                 args: "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=3"),
        Strategy(id: "warp-q-vk6", name: "WARP QUIC: fake vk ×6", transport: .masqueH3,
                 args: "--payload=quic_initial --lua-desync=fake:blob=quic_vk:repeats=6"),
        Strategy(id: "warp-q-google-vk", name: "WARP QUIC: fakes google + vk", transport: .masqueH3,
                 args: "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=3 --lua-desync=fake:blob=quic_vk:repeats=3"),
        Strategy(id: "warp-q-google10", name: "WARP QUIC: fake google ×10", transport: .masqueH3,
                 args: "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=10"),
        Strategy(id: "warp-q-google-ttl", name: "WARP QUIC: fake google ttl=4 ×6", transport: .masqueH3,
                 args: "--payload=quic_initial --lua-desync=fake:blob=quic_google:ip_ttl=4:ip6_ttl=4:repeats=6"),
        Strategy(id: "warp-q-vk-ttl", name: "WARP QUIC: fake vk ttl=4 ×6", transport: .masqueH3,
                 args: "--payload=quic_initial --lua-desync=fake:blob=quic_vk:ip_ttl=4:ip6_ttl=4:repeats=6"),


        // Android Zarp addition: plain TCP segmentation, no raw-socket trick beyond the send itself.
        Strategy(id: "warp-t-split", name: "WARP TLS: split 1,midsld", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multisplit:pos=1,midsld"),
        Strategy(id: "warp-t-vk-name", name: "WARP TLS: vk.com + split 1,midsld", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multisplit:pos=1,midsld", warpTLSName: .vk),
        Strategy(id: "warp-t-google-name", name: "WARP TLS: www.google.com + split 1,midsld", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multisplit:pos=1,midsld", warpTLSName: .google),
        Strategy(id: "warp-t-disorder", name: "WARP TLS: disorder 1,midsld", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multidisorder:pos=1,midsld"),

        Strategy(id: "warp-q-google11", name: "WARP QUIC: fake google ×11", transport: .masqueH3,
                 args: "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=11"),
        Strategy(id: "warp-q-google12", name: "WARP QUIC: fake google ×12", transport: .masqueH3,
                 args: "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=12"),
        Strategy(id: "warp-t-split-host", name: "WARP TLS: split 1,host", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multisplit:pos=1,host"),
        Strategy(id: "warp-t-split-sld", name: "WARP TLS: split 1,sld", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multisplit:pos=1,sld"),
        Strategy(id: "warp-t-host-vk-name", name: "WARP TLS: vk.com + split 1,host", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multisplit:pos=1,host", warpTLSName: .vk),
        Strategy(id: "warp-t-host-google-name", name: "WARP TLS: www.google.com + split 1,host", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multisplit:pos=1,host", warpTLSName: .google),
        Strategy(id: "warp-t-sld-vk-name", name: "WARP TLS: vk.com + split 1,sld", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multisplit:pos=1,sld", warpTLSName: .vk),
        Strategy(id: "warp-t-sld-google-name", name: "WARP TLS: www.google.com + split 1,sld", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multisplit:pos=1,sld", warpTLSName: .google),
        Strategy(id: "warp-t-endhost-vk-name", name: "WARP TLS: vk.com + split 1,endhost", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multisplit:pos=1,endhost", warpTLSName: .vk),
        Strategy(id: "warp-t-endhost-google-name", name: "WARP TLS: www.google.com + split 1,endhost", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multisplit:pos=1,endhost", warpTLSName: .google),
        Strategy(id: "warp-t-split-endhost", name: "WARP TLS: split 1,endhost", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multisplit:pos=1,endhost"),

    ].map { tagged($0) }

    /// Historical entries retained for diagnostics and explicit advanced display. Never scanned.
    public static let unavailable: [Strategy] = [
        Strategy(id: "warp-q-google-bad", name: "WARP QUIC: fake google badsum ×6", transport: .masqueH3,
                 args: "--payload=quic_initial --lua-desync=fake:blob=quic_google:badsum:repeats=6"),

        // ---------- WireGuard ----------
        Strategy(id: "warp-wg-google6", name: "WARP WireGuard: fake QUIC google ×6", transport: .wireGuard,
                 args: "--payload=wireguard_initiation --lua-desync=fake:blob=quic_google:repeats=6"),
        Strategy(id: "warp-wg-stun", name: "WARP WireGuard: fake STUN ×6", transport: .wireGuard,
                 args: "--payload=wireguard_initiation --lua-desync=fake:blob=stun_fake:repeats=6"),
        Strategy(id: "warp-wg-vk10", name: "WARP WireGuard: fake QUIC vk ×10", transport: .wireGuard,
                 args: "--payload=wireguard_initiation --lua-desync=fake:blob=quic_vk:repeats=10"),
        Strategy(id: "warp-wg-google-ttl", name: "WARP WireGuard: fake google ttl=4", transport: .wireGuard,
                 args: "--payload=wireguard_initiation --lua-desync=fake:blob=quic_google:ip_ttl=4:ip6_ttl=4:repeats=6"),

        Strategy(id: "warp-t-google-md5", name: "WARP TLS: fake google md5 + split", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=fake:blob=tls_google:tcp_md5:repeats=6 --lua-desync=multisplit:pos=1,midsld"),
        Strategy(id: "warp-t-seqovl", name: "WARP TLS: seqovl google", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=multisplit:pos=2:seqovl=681:seqovl_pattern=tls_google"),
        Strategy(id: "warp-t-vk-seq", name: "WARP TLS: fake vk badseq + disorder", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=fake:blob=tls_vk:tcp_seq=-3000:repeats=6 --lua-desync=multidisorder:pos=1,midsld"),
        Strategy(id: "warp-t-hostfake", name: "WARP TLS: hostfakesplit vk.com", transport: .masqueH2,
                 args: "--payload=tls_client_hello --lua-desync=hostfakesplit:host=vk.com:tcp_md5"),
    ].map { tagged($0) }

    private static func tagged(_ s: Strategy) -> Strategy {
        let tags: Set<StrategyCountry> = !s.requiresDesync ? [] : s.args.contains("vk") ? [.ru] : Set(StrategyCountry.allCases)
        return Strategy(id: s.id, name: s.name(using: Localization(tables: [:])), transport: s.transport,
                        args: s.args, nameKey: s.nameKey, countries: tags, warpTLSName: s.warpTLSName)
    }

    /// Portable built-in strategies plus the user's `strategies.txt`, in that order (matches Windows/Android).
    public static func load(customText: String, onSkipped: (String) -> Void = { _ in }) -> [Strategy] {
        builtIn + CustomStrategyFile.parse(customText, onSkipped: onSkipped)
    }
}
