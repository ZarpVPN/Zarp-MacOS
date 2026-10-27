# Troubleshooting

Start here when something does not work. If it is still stuck, open an issue with the **Bug report** form and
include the log (see [Where the logs are](#where-the-logs-are)).

- [macOS will not open Zarp](#macos-will-not-open-zarp)
- [Connection preparation or macOS approval](#connection-preparation-or-macos-approval)
- [Zarp refuses because of another VPN](#zarp-refuses-because-of-another-vpn)
- [No strategy works](#no-strategy-works)
- [It connected, then the internet stopped](#it-connected-then-the-internet-stopped)
- [Checking and repairing the network by hand](#checking-and-repairing-the-network-by-hand)
- [Where the logs are](#where-the-logs-are)
- [Starting over](#starting-over)

## macOS will not open Zarp

The release is not notarized by Apple (there is no paid Apple Developer membership behind the project), so
Gatekeeper blocks the first launch with "Zarp was blocked to protect your Mac" or "cannot be opened because
the developer cannot be verified". That is expected. **With screenshots:**
[Why won't Zarp open?](../README.md#why-wont-zarp-open) in the README.

1. Make sure Zarp is in **/Applications** (drag it there from the disk image, then eject the image).
2. Open Zarp once; it is refused.
3. **System Settings > Privacy & Security**, scroll to *Security*, click **Open Anyway** next to Zarp, and
   confirm with your password or Touch ID. (On macOS 15 the older Control-click > Open shortcut no longer
   works.)

If there is no *Open Anyway* button, remove the quarantine flag:

```sh
xattr -dr com.apple.quarantine /Applications/Zarp.app
```

Check the download first if you did not build it yourself: compare `shasum -a 256 ~/Downloads/Zarp-*.dmg`
with the value in the release notes.

## Connection preparation or macOS approval

Zarp prepares its bundled background component automatically at launch and
before connection, scan and WARP+ actions. There is no service-management screen.
Registration, replacement after an update and recovery from a missing IPC socket
are handled by the app. A responding component with active or unknown network
work is preserved.

- Keep the app at `/Applications/Zarp.app`, eject the disk image and open the installed
  copy. Zarp cannot prepare a privileged component from a temporary location.
- Approve macOS authorization if requested. If background approval is needed,
  Zarp opens **System Settings > General > Login Items & Extensions**. Allow Zarp
  under *Allow in the Background*. An app cannot grant itself this permission.
- Preparation has bounded readiness checks and does not repeatedly display
  authorization requests. If it fails, the main window shows a connection message.
  Press the usual power button to retry; no manual service commands are needed.
- If preparation still fails, include the app log in a bug report. Zarp does not
  reset other background items or disable another VPN to make preparation succeed.

Starting in 0.4.3, the journal records preparation phases and a bounded native
error domain/code or `startup_timeout`. It excludes error UserInfo, account data
and license keys. The release manifest specifies the absolute executable path
instead of relying on a cached background-item container to resolve BundleProgram.

## A scan reports QUIC reset or a server-key mismatch

From 0.4.5, the journal records the resolved endpoint and failing connection
phase. A recently closed scan handle retains its original reason, including a
QUIC stateless reset, instead of reporting only `no open connection`. A reset
does not by itself identify carrier DPI as its source.

HTTP2 tests use the account's dedicated TCP endpoint. An explicit key-mismatch
message means the peer did not match the trusted enrolled key; changing a split
position or extending the timeout does not repair that trust failure. Pin
verification stays enabled. HTTP2 results created under the older shared-pool
selection policy require fresh verification after the update.

Include the app journal and matching daemon interval when reporting these
errors. No license key, private account file or subscription link is needed.

## Zarp refuses because of another VPN

Zarp builds its tunnel by adding routes that must be the only ones of their kind; another VPN (Happ,
WireGuard, v2rayN, Clash, AmneziaVPN, Cloudflare's own WARP app, a corporate client...) that owns the default
route makes a scan measure the wrong thing and a full tunnel impossible. Zarp warns you when it sees one. Turn
it off, then connect. If you continue anyway, the daemon still refuses a full tunnel while another VPN owns the
default route.

## No strategy works

- Run a **Full scan** (Settings): the quick scan stops early and may not have reached the strategy that works.
- Raise the **Connection timeout** in Settings (slow or congested networks need more than 15 seconds).
- Make sure no other VPN is on, and that you are not behind a captive portal.
- Try a different network (a phone hotspot is the quickest check): if WARP works there, your network's DPI is
  the cause, and an issue with your provider and country and the **Strategy report** form helps everyone.
- Add your own strategies (*Custom strategies...*): the syntax is in the
  [README](../README.md#how-it-works). Strategies marked "not available on macOS" need raw sockets or WireGuard
  and cannot work here.
- Some networks block Cloudflare's WARP addresses outright, regardless of the handshake; no desync strategy
  can help with that.

## It connected, then the internet stopped

First, wait about 30 seconds if the Mac just woke from sleep or changed networks: the old tunnel has to be
noticed as dead before Zarp re-establishes it (see
[ARCHITECTURE.md](ARCHITECTURE.md#13-known-limitations)). Zarp reconnects by itself a few times; if it gives
up, press the button.

If the connection stays broken, press **Disconnect**, or quit Zarp: that removes the routes and restores DNS.
If even that does not bring the internet back (a crash at the worst moment), use the next section.

## Checking and repairing the network by hand

Everything Zarp changes while connected is undone when it disconnects, and a crashed daemon recovers the rest
at its next start (the daemon starts at boot). Routes do not survive a reboot at all; the DNS setting does,
which is why the daemon restores it from its backup as soon as it starts. To look at the state:

```sh
netstat -rn -f inet | grep -E '^(0/1|128.0/1)'     # the full-tunnel routes, via a utunN
netstat -rn -f inet | grep -E '^162\.159\.'         # the host route that keeps Zarp's own connection off the tunnel
scutil --dns | grep -m1 nameserver                  # the active resolver; 1.1.1.1 while Zarp's DNS override is on
networksetup -getdnsservers Wi-Fi                   # your service's own DNS setting (use your service name)
```

If something is left behind after Zarp is gone, these commands are safe to run (each removes only what Zarp
adds, and tells you if it was not there):

```sh
sudo route -n delete -inet 0.0.0.0/1;  sudo route -n delete -inet 128.0.0.0/1
sudo route -n delete -inet6 ::/1;      sudo route -n delete -inet6 8000::/1
sudo route -n delete -host 1.1.1.1
# the host route for the WARP endpoint, if one is listed by the second command above:
sudo route -n delete -host <that address>
# DNS back to "automatic" for your network service (see `networksetup -listallnetworkservices`):
sudo networksetup -setdnsservers "Wi-Fi" Empty
```

If you had set your own DNS servers on that service before using Zarp, put them back with
`sudo networksetup -setdnsservers "Wi-Fi" <server> <server>`. Zarp's own backup of your original setting is
`/var/db/zarpd/dns-backup.json` while it is overridden; it is restored automatically at the next daemon
start.

## Where the logs are

| Log | Where |
|---|---|
| The app (what the log view in the main window shows) | `~/Library/Logs/Zarp/zarp.log` |
| The daemon | `/Library/Logs/Zarp/zarpd.log` (and `/Library/Logs/zarpd.log` for anything it printed outside its own log) |

The logs contain WARP endpoint addresses, strategy names and error text, and nothing about the sites you
visit. Read them before posting and remove anything you would rather not share.

## Starting over

- **Reset settings and results:** quit Zarp and delete `~/Library/Application Support/Zarp/zarp.json`.
- **Reset the WARP account:** with the app disconnected, delete
  `/Library/Application Support/Zarp/zarp-warp-config.json` (it holds the device's private key, so keep it
  private if you copy it anywhere). The next connection registers a new anonymous account after asking you.
- **Remove everything:** see *Uninstall* in the [README](../README.md#uninstall).
