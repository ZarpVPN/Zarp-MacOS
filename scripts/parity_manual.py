#!/usr/bin/env python3
"""Supervised, user-run Stage 1 WARP checks. Safe autonomous modes: --help, --self-test, --preflight.

Scenarios: warp-h3 (google x11/x12), warp-h2 (split host/sld/endhost), warp-account-ipv6 (new test account IPv6), warp-custom
(a supplied public IPv4/IPv6 endpoint). Each checks two fresh sessions and a persistent
connection pinned to the last successful endpoint. --full-tunnel additionally tests the
temporary /1 routes and endpoint exclusion. DNS settings are never changed.

Requires macOS arm64, Go, sudo, internet access, and explicit Cloudflare terms acceptance.
Never disconnects a VPN. Refuses foreign tunnel routes, connected network services,
an active production Zarp connection, or uncertain production state. Watches for conflicts
and external route/DNS changes. Uses its own new WARP registration, not production credentials.
The worker watchdog is 600 seconds including cleanup; each connection has a 15-second dial
timeout and each IPC request a bounded deadline. Build and sudo authorization precede it.
Reports contain no daemon responses, account IDs, keys, tokens, or secret configuration.
"""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

REPO = Path(__file__).resolve().parent.parent
TIME_LIMIT = 600


class CheckStopped(Exception):
    def __init__(self, message, *, code="check_stopped", details=None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


def command(args, timeout=8):
    tool = Path(args[0]).name
    try:
        result = subprocess.run(args, check=True, capture_output=True, text=True,
                                timeout=timeout, env=dict(os.environ, LC_ALL="C"))
        # Darwin route GET can return zero with no stdout and a routing-socket error
        # on stderr. Do not turn that into an unexplained missing interface or success.
        if tool == "route" and "get" in args and not result.stdout.strip() and result.stderr.strip():
            missing = "not in table" in result.stderr.lower()
            raise CheckStopped("route lookup found no entry" if missing else "route lookup returned a diagnostic",
                               code="route_not_found" if missing else "route_lookup_diagnostic",
                               details={"tool": tool, "returncode": result.returncode})
        return result.stdout
    except subprocess.CalledProcessError as error:
        raise CheckStopped("read-only command failed: " + tool, code="observation_failed",
                           details={"tool": tool, "returncode": error.returncode}) from None
    except subprocess.TimeoutExpired:
        raise CheckStopped("read-only command timed out: " + tool, code="observation_timeout",
                           details={"tool": tool}) from None
    except OSError as error:
        raise CheckStopped("read-only command unavailable: " + tool, code="observation_unavailable",
                           details={"tool": tool, "errno": error.errno}) from None


def rpc(path, method, params=None, timeout=10, abort=None):
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(min(timeout, 3))
        peer.connect(str(path))
        peer_pid = None
        if platform.system() == "Darwin":
            try:
                # Darwin sys/un.h: SOL_LOCAL=0, LOCAL_PEERPID=2. Kernel metadata only.
                value = peer.getsockopt(0, 2)
                if type(value) is int and value > 0:
                    peer_pid = value
            except OSError:
                pass
        peer.sendall(json.dumps({"id": 1, "method": method, "params": params or {}}).encode() + b"\n")
        answer = bytearray()
        while b"\n" not in answer:
            if abort is not None and abort.is_set():
                raise CheckStopped("conflict, cancellation, or watchdog", code="ipc_cancelled")
            if time.monotonic() >= deadline:
                raise CheckStopped("IPC deadline", code="ipc_timeout",
                                   details={"ipc_phase": "await_response", "response_bytes": len(answer),
                                            "peer_pid": peer_pid})
            if not select.select([peer], [], [], min(0.2, deadline - time.monotonic()))[0]:
                continue
            chunk = peer.recv(8192)
            if not chunk:
                raise CheckStopped("IPC peer closed without a complete response", code="ipc_peer_closed")
            if len(answer) + len(chunk) > 262144:
                raise CheckStopped("IPC response exceeded limit", code="ipc_response_limit")
            answer.extend(chunk)
        response = json.loads(answer.split(b"\n", 1)[0])
        if response.get("id") != 1 or "error" in response:
            # Raw responses can contain secrets. Only expose a bounded known error code.
            code = response.get("error", {}).get("code", "connection_failed")
            allowed = {"foreign_vpn", "no_account", "bad_request", "unsupported", "cancelled"}
            raise CheckStopped(code if code in allowed else "connection_failed")
        return response["result"]


def route_rows(text):
    rows = []
    for raw in text.splitlines():
        fields = raw.split()
        if len(fields) >= 4 and fields[0] not in {"Destination", "Routing", "Internet:", "Internet6:"}:
            rows.append(fields)
    return rows


def foreign_route_details(text, own_interface=None):
    conflicts = []
    for row in route_rows(text):
        interfaces = [part for part in row if part.startswith(("utun", "tun", "ppp", "ipsec"))]
        if any(iface != own_interface for iface in interfaces):
            # Link-local interface routes alone do not establish an active tunnel.
            if not row[0].startswith(("fe80", "ff01", "ff02")):
                destination = row[0].split("%", 1)[0].split("/", 1)[0]
                try:
                    address = ipaddress.ip_address(destination)
                    kind = "multicast" if address.is_multicast else "unicast"
                except ValueError:
                    kind = "default" if destination == "default" else "other"
                gateway = row[1].split("%", 1)[0]
                try:
                    address = ipaddress.ip_address(gateway)
                    gateway_kind = "link_local" if address.is_link_local else "numeric"
                except ValueError:
                    gateway_kind = "link" if gateway.startswith("link#") else "other"
                conflicts.append({"interface": interfaces[0], "flags": row[2],
                                  "destination_kind": kind, "scoped": "I" in row[2],
                                  "family": "ipv6" if ":" in row[0] or ":" in row[1] else "ipv4",
                                  "gateway_kind": gateway_kind})
    return conflicts


def foreign_routes(text, own_interface=None):
    return bool(foreign_route_details(text, own_interface))


def stable_routes(text, own_interface=None, own_hosts=()):
    result = []
    for row in route_rows(text):
        if own_interface in row or row[0] in own_hosts:
            continue
        # Neighbor/cloned entries may appear from ordinary traffic during the test.
        flags = row[2]
        if "W" in flags or "L" in flags:
            continue
        result.append(" ".join(row))
    return sorted(result)


def source_digest():
    files = sorted((REPO / "zarpd").rglob("*.go"))
    files += [REPO / "zarpd/go.mod", REPO / "zarpd/go.sum", Path(__file__).resolve()]
    digest = hashlib.sha256()
    for path in files:
        digest.update(str(path.relative_to(REPO)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def route_fields(text):
    fields = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.strip().split(":", 1)
            fields[key] = value.strip()
    return fields


def network_snapshot():
    snapshot = {"routes": command(["/usr/sbin/netstat", "-rn"], timeout=3),
            "dns": command(["/usr/sbin/scutil", "--dns"], timeout=3),
            "services": command(["/usr/sbin/scutil", "--nc", "list"], timeout=3),
            "default": command(["/sbin/route", "-n", "get", "default"], timeout=3)}
    # Read interface addresses privately. A route's gateway being link-local is not enough:
    # it must be this interface's own sole address before it can be interface metadata.
    candidates = sorted({item["interface"] for item in foreign_route_details(snapshot["routes"])
                         if item["interface"].startswith("utun")})
    if candidates:
        snapshot["effective_routes"] = effective_route_diagnostics()
        snapshot["tunnel_interfaces"] = {}
        for interface in candidates:
            if not interface.removeprefix("utun").isdecimal():
                continue
            snapshot["tunnel_interfaces"][interface] = command(["/sbin/ifconfig", interface], timeout=3)
    return snapshot


def self_link_local_addresses(text, interface):
    lines = text.splitlines()
    if not lines or not lines[0].startswith(interface + ":") or "POINTOPOINT" not in lines[0]:
        return set()
    addresses = set()
    for line in lines[1:]:
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "inet":
            return set()
        if fields[0] == "inet6":
            if len(fields) < 2:
                return set()
            raw = fields[1].split("%", 1)
            try:
                address = ipaddress.IPv6Address(raw[0])
            except ValueError:
                return set()
            if not address.is_link_local or (len(raw) > 1 and raw[1] != interface):
                return set()
            addresses.add(address)
    return addresses


def interface_metadata_routes(snapshot, own_interface=None):
    # User-approved narrow classification for the isolated manual test only. Recheck
    # interface addresses and effective routes on every snapshot; never whitelist names
    # or infer inactivity from scoped flags alone. The production guard is unchanged.
    effective = snapshot.get("effective_routes", {})
    default = route_fields(snapshot["default"]).get("interface", "")
    ipv4, ipv6 = effective.get("ipv4", {}), effective.get("ipv6", {})
    if not default.startswith("en") or not default[2:].isdecimal() or \
       ipv4.get("status") != "observed" or ipv4.get("interface") not in {default, own_interface} or \
       not (ipv6.get("status") == "no_route" and ipv6.get("reason_code") == "route_not_found" or
            ipv6.get("status") == "observed" and own_interface is not None and ipv6.get("interface") == own_interface):
        return []
    profiles = snapshot.get("tunnel_interfaces", {})
    rows = route_rows(snapshot["routes"])
    metadata = []
    for row in rows:
        if row[0] not in {"default", "ff00::/8"} or row[2] not in {"UGcIg", "UmCI"}:
            continue
        interfaces = [part for part in row if part.startswith("utun")]
        if len(interfaces) != 1:
            continue
        interface = interfaces[0]
        if interface == own_interface or not interface.removeprefix("utun").isdecimal():
            continue
        if row[0] == "default" and row[2] != "UGcIg" or row[0] == "ff00::/8" and row[2] != "UmCI":
            continue
        gateway = row[1].split("%", 1)
        if len(gateway) != 2 or gateway[1] != interface:
            continue
        try:
            address = ipaddress.IPv6Address(gateway[0])
        except ValueError:
            continue
        own_addresses = self_link_local_addresses(profiles.get(interface, ""), interface)
        matches_self = address in own_addresses
        # Observed macOS scoped defaults can use the exact bare fe80:: marker rather
        # than the interface address. Require its paired self-address multicast route
        # as well as the independent egress/address checks above. Never allow a peer
        # gateway, a generic link-local prefix, or a scoped default solely by flags.
        paired_multicast = any(
            peer[0] == "ff00::/8" and peer[2] == "UmCI" and interface in peer and
            peer[1] in {str(own) + "%" + interface for own in own_addresses}
            for peer in rows)
        matches_marker = row[0] == "default" and address == ipaddress.IPv6Address("fe80::") \
            and bool(own_addresses) and paired_multicast
        if matches_self or matches_marker:
            metadata.append(row)
    return metadata


def guard_network(snapshot, own_interface=None):
    metadata = interface_metadata_routes(snapshot, own_interface)
    routes = "\n".join(" ".join(row) for row in route_rows(snapshot["routes"]) if row not in metadata)
    conflicts = foreign_route_details(routes, own_interface)
    connected = snapshot["services"].count("(Connected)")
    if conflicts or connected:
        code = "foreign_tunnel_routes" if conflicts else "connected_vpn_service"
        raise CheckStopped("tunnel routes or connected VPN services detected; nothing will be disconnected",
                           code=code, details={"default_interface": route_fields(snapshot["default"]).get("interface"),
                                               "connected_vpn_services": connected,
                                               "verified_interface_metadata_count": len(metadata),
                                               "conflicting_route_count": len(conflicts), "routes": conflicts[:32],
                                               "routes_truncated": len(conflicts) > 32,
                                               "route_categories": {
                                                   kind: sum(item["destination_kind"] == kind for item in conflicts)
                                                   for kind in sorted({item["destination_kind"] for item in conflicts})}})
    if not any(line.strip().startswith("interface:") for line in snapshot["default"].splitlines()):
        raise CheckStopped("physical default route could not be established", code="default_route_unknown")


def guard(snapshot, own_interface=None):
    guard_network(snapshot, own_interface)
    production = Path("/var/run/zarpd.sock")
    if production.exists():
        try:
            status = rpc(production, "status", timeout=3)
        except Exception as error:
            raise CheckStopped("production Zarp status is uncertain", code="production_status_unknown",
                               details=ipc_failure_details(error)) from None
        if not isinstance(status, dict) or type(status.get("connected")) is not bool:
            raise CheckStopped("production Zarp status is invalid", code="production_status_unknown",
                               details={"status_error_code": "invalid_status"})
        if status.get("connected"):
            raise CheckStopped("production Zarp session is active", code="production_session_active")
        if type(status.get("networkBusy")) is not bool:
            raise CheckStopped("production Zarp cannot establish idle network ownership", code="production_status_unknown",
                               details={"status_error_code": "network_activity_unknown"})
        if status["networkBusy"]:
            raise CheckStopped("production Zarp network work is active", code="production_session_active")
    # A daemon without its expected socket could own an unobservable session.
    processes = command(["/bin/ps", "-axo", "command="], timeout=3)
    for line in processes.splitlines():
        executable = line.strip().split(" ", 1)[0]
        if Path(executable).name == "zarpd" and "/zarp-parity-" not in executable and not production.exists():
            raise CheckStopped("another Zarp daemon has no observable production socket", code="production_socket_missing")


def ipc_failure_details(error):
    result = {"error_type": type(error).__name__}
    if isinstance(error, CheckStopped):
        result["status_error_code"] = error.code
        if error.details.get("ipc_phase") in {"connect", "send", "await_response"}:
            result["ipc_phase"] = error.details["ipc_phase"]
        for key, lower, upper in [("response_bytes", 0, 262144), ("peer_pid", 1, 2147483647)]:
            value = error.details.get(key)
            if type(value) is int and lower <= value <= upper:
                result[key] = value
    elif isinstance(error, TimeoutError):
        result["status_error_code"] = "ipc_timeout"
    elif isinstance(error, OSError):
        result.update(status_error_code="ipc_socket_error", errno=error.errno)
    else:
        result["status_error_code"] = "ipc_invalid_response"
    return result


def production_status_report():
    # This entrypoint deliberately does not call network_snapshot, build, sudo or
    # any mutating RPC. User-invoked sudo only changes the caller credentials.
    started = time.monotonic()
    report = {"version": 1, "scenario": "production-status", "phase": "diagnostic",
              "run_id": "not-started", "live_test_started": False, "cleanup": "PASS",
              "privileged_caller": os.geteuid() == 0, "methods": {}}
    path = Path("/var/run/zarpd.sock")
    try:
        info = path.lstat()
        report["socket"] = {"is_socket": stat.S_ISSOCK(info.st_mode), "is_symlink": stat.S_ISLNK(info.st_mode),
                            "owner_is_root": info.st_uid == 0, "mode": oct(stat.S_IMODE(info.st_mode))}
        if not stat.S_ISSOCK(info.st_mode):
            report.update(status="SKIP", reason_code="production_socket_invalid")
        else:
            for method in ["ping", "status"]:
                try:
                    result = rpc(path, method, timeout=3)
                    if not isinstance(result, dict) or method == "status" and type(result.get("connected")) is not bool:
                        raise CheckStopped("invalid production response", code="ipc_invalid_response")
                    fields = {"status": "received"}
                    if method == "status":
                        fields["connected"] = result["connected"]
                        if type(result.get("networkBusy")) is bool:
                            fields["networkBusy"] = result["networkBusy"]
                    elif type(result.get("protocol")) is int:
                        fields["protocol"] = result["protocol"]
                    report["methods"][method] = fields
                except Exception as error:
                    report["methods"][method] = {"status": "unavailable", **ipc_failure_details(error)}
            received = all(item["status"] == "received" for item in report["methods"].values())
            report.update(status="PASS" if received else "SKIP",
                          reason_code="readonly_status_received" if received else "production_status_unknown")
    except OSError as error:
        report.update(status="SKIP", reason_code="production_socket_unavailable", errno=error.errno)
    report["duration_seconds"] = round(time.monotonic() - started, 2)
    return report


def effective_route_diagnostics():
    # RTM_GET lookups inspect routing decisions only. Numeric destinations avoid DNS;
    # no packets are sent and no physical-interface binding or route change is used.
    result = {}
    for family, destination in [("ipv4", "1.1.1.1"), ("ipv6", "2606:4700:4700::1111")]:
        args = ["/sbin/route", "-n", "get"]
        if family == "ipv6":
            args.append("-inet6")
        try:
            fields = route_fields(command([*args, destination], timeout=3))
            interface = fields.get("interface", "")
            # Only interface names and route flags leave the observer. Addresses, hostnames,
            # command output and service identifiers never enter the shared report.
            valid_interface = interface.startswith(("en", "utun", "tun", "ppp", "ipsec", "lo", "bridge")) \
                and interface.isalnum() and len(interface) <= 32
            if not valid_interface:
                result[family] = {"status": "unknown", "reason_code": "route_interface_unknown"}
            else:
                flags = fields.get("flags", "")
                result[family] = {"status": "observed", "interface": interface,
                                  "tunnel": interface.startswith(("utun", "tun", "ppp", "ipsec")),
                                  "scoped": "IFSCOPE" in flags}
        except CheckStopped as error:
            # No route to this destination does not mean all IPv6 or a per-app VPN is disabled.
            result[family] = {"status": "no_route" if error.code == "route_not_found" else "unknown",
                              "reason_code": error.code, **error.details}
    return result


def preflight_report(scenario, detailed=False):
    started = time.monotonic()
    report = {"version": 1, "run_id": "not-started", "scenario": scenario,
              "phase": "preflight", "live_test_started": False, "cleanup": "PASS"}
    snapshot = None
    try:
        snapshot = network_snapshot()
        guard(snapshot)
        report.update(status="PASS", reason="read-only preflight passed; no live check was run")
    except CheckStopped as error:
        report.update(status="SKIP", reason=str(error), reason_code=error.code, details=error.details)
    except Exception as error:
        # Unexpected exceptions also stay visible without exposing raw responses or secrets.
        report.update(status="SKIP", reason="preflight failed unexpectedly; nothing changed",
                      reason_code="internal_preflight_error", details={"error_type": type(error).__name__})
    if detailed:
        details = report.setdefault("details", {})
        details["effective_routes"] = snapshot.get("effective_routes", {}) if snapshot is not None \
            and "effective_routes" in snapshot else effective_route_diagnostics()
        if snapshot is not None:
            details["self_gateway_candidate_count"] = len(interface_metadata_routes(snapshot))
            details["interface_profiles"] = [
                {"interface": interface, "link_local_only": bool(self_link_local_addresses(text, interface))}
                for interface, text in sorted(snapshot.get("tunnel_interfaces", {}).items())]
    report["duration_seconds"] = round(time.monotonic() - started, 2)
    return report


def endpoint(value):
    if value.startswith("[") and "]:" in value:
        host, port = value[1:].split("]:", 1)
    else:
        host, port = value.split(":")
    addr = ipaddress.ip_address(host)
    if not addr.is_global or not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("public numeric endpoint required")
    return f"[{addr}]:{int(port)}" if addr.version == 6 else f"{addr}:{int(port)}"


class Supervisor:
    def __init__(self, work, scenario, custom, full, transport="h3"):
        self.work = work
        self.scenario = scenario
        self.custom = custom
        self.full = full
        self.transport = transport
        self.abort = threading.Event()
        self.done = threading.Event()
        self.proc = None
        self.started = time.monotonic()
        self.deadline = self.started + TIME_LIMIT
        self.own_interface = None
        self.own_hosts = set()
        self.expected_paths = {}
        self.baseline = None
        self.rows = []
        self.sock = work / "test.sock"
        self.log = None
        self.monitor = None

    def remaining(self):
        return max(0.1, self.deadline - time.monotonic())

    def call(self, method, params=None, timeout=10):
        return rpc(self.sock, method, params, min(timeout, self.remaining()), self.abort)

    def start_daemon(self):
        if self.log is None:
            self.log = open(self.work / "daemon.log", "ab", buffering=0)
        args = [str(self.work / "zarpd"), "-socket", str(self.sock),
                "-config", str(self.work / "account.json"), "-blobs", str(REPO / "Resources/blobs"),
                "-log", "-", "-dns-backup", str(self.work / "dns.json"),
                "-route-journal", str(self.work / "routes.json"), "-test-lease", "30s"]
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=self.log)
        end = time.monotonic() + min(10, self.remaining())
        while time.monotonic() < end:
            if self.proc.poll() is not None:
                raise CheckStopped("private test daemon exited")
            try:
                if rpc(self.sock, "ping", timeout=1).get("protocol") == 3:
                    return
            except (OSError, CheckStopped):
                pass
            time.sleep(0.1)
        raise CheckStopped("private daemon startup deadline")

    def stop_owned_process(self):
        if self.proc is None or self.proc.poll() is not None:
            return
        # A live, unreaped Popen child cannot have its PID recycled. Check executable/socket too.
        label = command(["/bin/ps", "-ww", "-p", str(self.proc.pid), "-o", "command="], timeout=2)
        if not label.startswith(str(self.work / "zarpd") + " ") or str(self.sock) not in label:
            raise CheckStopped("test process ownership could not be verified")
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.proc.kill()  # Only this verified child. Supervisor performs recovery below.
            self.proc.wait(timeout=3)

    def watch(self):
        while not self.done.wait(1):
            try:
                if time.monotonic() >= self.deadline - 90:
                    raise CheckStopped("watchdog reserved cleanup time")
                current = network_snapshot()
                guard(current, self.own_interface)
                for host, expected in list(self.expected_paths.items()):
                    args = ["/sbin/route", "-n", "get"]
                    if ":" in host:
                        args.append("-inet6")
                    actual = route_fields(command([*args, "-host", host], timeout=3))
                    if actual.get("destination") == host and "HOST" in actual.get("flags", ""):
                        if actual.get("interface") != expected.get("interface") or actual.get("gateway") != expected.get("gateway"):
                            raise CheckStopped("external endpoint exclusion change")
                if current["dns"] != self.baseline["dns"]:
                    raise CheckStopped("external DNS change")
                if stable_routes(current["routes"], self.own_interface, self.own_hosts) != stable_routes(self.baseline["routes"]):
                    raise CheckStopped("external route change")
            except Exception:
                self.abort.set()
                return

    def parameters(self, name, value, persistent=False):
        p = {"strategyId": "parity-" + name, "transport": "masqueH2" if "split" in name else "masqueH3",
             "endpoint": value, "timeoutMs": 15000, "persistent": persistent,
             "routeAll": persistent and self.full, "overrideDNS": False}
        if self.custom:
            p["endpointPolicy"] = "customWarp"
        if "split" in name:
            p["tcpDesync"] = {"mode": "split", "positions": ["1", name.removeprefix("split-")]}
        else:
            p["fakeSteps"] = [{"blob": "quic_google", "repeats": int(name.removeprefix("google"))}]
        return p

    def session(self, name, value, persistent=False):
        # Routes/DNS baseline exists before open. Allow only the interface/host reported by our
        # own bounded open response; startup monitoring cannot mistake that change for a VPN.
        current = network_snapshot()
        guard(current, self.own_interface)
        if persistent and self.full:
            target = endpoint(value)
            host = target.split("]:")[0][1:] if target.startswith("[") else target.split(":")[0]
            family = ["-inet6"] if ":" in host else []
            self.expected_paths[host] = route_fields(command(["/sbin/route", "-n", "get", *family, "default"], timeout=3))
            self.own_hosts.add(host)
        opened = self.call("open", self.parameters(name, value, persistent), timeout=45)
        self.own_interface = opened.get("utunName")
        try:
            actual = endpoint(opened.get("endpoint", ""))
            if self.custom and actual != self.custom:
                raise CheckStopped("custom endpoint was not actually dialed")
            observed = network_snapshot()
            guard(observed, self.own_interface)
            if stable_routes(observed["routes"], self.own_interface, self.own_hosts) != stable_routes(self.baseline["routes"]):
                raise CheckStopped("external route change during open")
            if observed["dns"] != self.baseline["dns"]:
                raise CheckStopped("external DNS change during open")
            measured = self.call("measure", {"connectionId": opened["connectionId"], "samples": 1}, timeout=25)
            if measured.get("kind") != "ok" or measured.get("warp") not in {"on", "plus"}:
                raise CheckStopped("actual WARP traffic was not verified")
            if persistent:
                # Verify data plane after route changes have settled, not just open/status.
                self.abort.wait(2)
                measured = self.call("measure", {"connectionId": opened["connectionId"], "samples": 1}, timeout=25)
                if measured.get("kind") != "ok":
                    raise CheckStopped("persistent WARP data plane failed")
                if self.full:
                    if not opened.get("routeAll"):
                        raise CheckStopped("full tunnel not reported")
                    routes = network_snapshot()["routes"]
                    own = [row[0] for row in route_rows(routes) if self.own_interface in row]
                    if "0/1" not in own or "128.0/1" not in own:
                        raise CheckStopped("full tunnel IPv4 routes were not observed")
                    for host, expected in self.expected_paths.items():
                        family = ["-inet6"] if ":" in host else []
                        actual_route = route_fields(command(["/sbin/route", "-n", "get", *family, "-host", host], timeout=3))
                        if actual_route.get("destination") != host or "HOST" not in actual_route.get("flags", "") \
                            or actual_route.get("interface") != expected.get("interface") or actual_route.get("gateway") != expected.get("gateway"):
                            raise CheckStopped("owned endpoint exclusion was not observed")
            return actual
        finally:
            # Independent cleanup call still runs when the monitor has requested cancellation.
            rpc(self.sock, "close", {"connectionId": opened["connectionId"]}, timeout=10)
            self.own_interface = None
            self.own_hosts.clear()
            self.expected_paths.clear()
            guard(network_snapshot())

    def run(self):
        cleanup = "FAIL"
        failure = None
        try:
            self.baseline = network_snapshot()
            guard(self.baseline)
            (self.work / "network-before.json").write_text(json.dumps(self.baseline))
            self.start_daemon()
            self.monitor = threading.Thread(target=self.watch, daemon=True)
            self.monitor.start()
            self.call("register", timeout=75)
            if self.scenario == "warp-account-ipv6":
                account = json.loads((self.work / "account.json").read_text())
                self.custom = endpoint("[" + account.get("endpoint_v6", "") + "]:443")
            names = {"warp-h3": ["google11", "google12"],
                     "warp-h2": ["split-host", "split-sld", "split-endhost"],
                     "warp-account-ipv6": ["google12"],
                     "warp-custom": ["split-host" if self.transport == "h2" else "google12"]}[self.scenario]
            # The monitor conservatively aborts if a new tunnel's ownership is uncertain,
            # including a change observed before our bounded open response arrives.
            for index, name in enumerate(names):
                if self.abort.is_set():
                    raise CheckStopped("cancelled")
                first = self.session(name, self.custom or f"isolated-{index * 2}")
                second = self.session(name, self.custom or f"isolated-{index * 2 + 1}")
                pinned = self.session(name, second, persistent=True)
                if pinned != second:
                    raise CheckStopped("persistent endpoint differs from confirmed endpoint")
                self.rows.append({"name": name, "status": "PASS", "confirmed": True,
                                  "independent": first != second, "endpoint_reused": first == second})
        except Exception as error:
            failure = str(error) if isinstance(error, CheckStopped) else "bounded test operation failed"
            self.rows.append({"name": self.scenario, "status": "FAIL", "reason": failure})
        finally:
            self.done.set()
            if self.monitor is not None:
                self.monitor.join(timeout=12)
            try:
                self.stop_owned_process()
                # After SIGKILL/crash, recovery runs in a separate supervised private process.
                # Its journal deletion now checks exact route/interface/gateway ownership.
                if (self.work / "routes.json").exists():
                    self.start_daemon()
                    self.stop_owned_process()
                current = network_snapshot()
                (self.work / "network-after.json").write_text(json.dumps(current))
                same = self.baseline is not None and current["dns"] == self.baseline["dns"] \
                    and stable_routes(current["routes"]) == stable_routes(self.baseline["routes"])
                cleanup = "PASS" if same else "FAIL"
            except Exception:
                cleanup = "FAIL"
            if self.log:
                self.log.close()
            # Destroy this test's credentials without touching the production account.
            try:
                (self.work / "account.json").unlink(missing_ok=True)
            except OSError:
                cleanup = "FAIL"
        status = "PASS" if failure is None and cleanup == "PASS" else "FAIL"
        report = {"run_id": self.work.name, "version": 1, "ipc_protocol": 3,
                  "source_sha": command(["/usr/bin/git", "-C", str(REPO), "rev-parse", "HEAD"], timeout=3).strip(),
                  "source_digest": source_digest(),
                  "binary_sha256": hashlib.sha256((self.work / "zarpd").read_bytes()).hexdigest(),
                  "scenario": self.scenario, "transport": self.transport if self.custom else self.scenario.removeprefix("warp-"), "full_tunnel": self.full, "control_ip_version": 6 if self.custom and self.custom.startswith("[") else 4, "dns_changed": False,
                  "status": status, "duration_seconds": round(time.monotonic() - self.started, 2),
                  "cleanup": cleanup, "checks": self.rows}
        (self.work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print("RESULT " + json.dumps(report, sort_keys=True))
        print("Private report: " + str(self.work / "report.json"))
        return 0 if status == "PASS" else 1


def self_test():
    import io
    from contextlib import redirect_stdout
    from unittest.mock import patch

    assert endpoint("[2606:4700:0000::1]:443") == "[2606:4700::1]:443"
    assert foreign_routes("0/1 1.2.3.4 UGSc utun99")
    assert not foreign_routes("0/1 1.2.3.4 UGSc utun99", "utun99")
    assert stable_routes("default 1.2.3.4 UGSc en0\n0/1 1.2.3.4 UGSc utun99", "utun99") == ["default 1.2.3.4 UGSc en0"]
    baseline = {"routes": "default 1.2.3.4 UGSc en0", "services": "(Disconnected)",
                "default": "interface: en0\n", "dns": "fixture"}
    guard_network(baseline)
    # Diagnostics do not bypass scoped, residual, or active tunnel routes to make a test pass.
    for route, expected_kind in [("default fe80::%utun9 UGcIg utun9", "default"),
                                 ("0/1 1.2.3.4 UGSc utun9", "other"),
                                 ("ff00::/8 link#9 UmCI utun9", "multicast")]:
        snapshot = dict(baseline, routes=route)
        try:
            guard_network(snapshot)
        except CheckStopped as error:
            assert error.code == "foreign_tunnel_routes"
            assert error.details["routes"][0]["destination_kind"] == expected_kind
        else:
            raise AssertionError("tunnel guard was bypassed")
    try:
        guard_network(dict(baseline, services="(Connected)"))
    except CheckStopped as error:
        assert error.code == "connected_vpn_service"
    else:
        raise AssertionError("connected service was ignored")

    # Reproduce the user's otherwise physical network with many scoped tunnel defaults.
    # Report every category instead of hiding later unicast/multicast rows; keep refusing.
    residual = "\n".join(f"default fe80::%utun{n} UGcIg utun{n}" for n in range(8))
    residual += "\n" + "\n".join(f"ff00::/8 link#{n} UmCI utun{n}" for n in range(8))
    try:
        guard_network(dict(baseline, routes=baseline["routes"] + "\n" + residual))
    except CheckStopped as error:
        assert error.code == "foreign_tunnel_routes"
        assert error.details["default_interface"] == "en0"
        assert error.details["conflicting_route_count"] == len(error.details["routes"]) == 16
        assert error.details["route_categories"] == {"default": 8, "multicast": 8}
        assert not error.details["routes_truncated"]
        assert error.details["routes"][0]["family"] == "ipv6"
        assert error.details["routes"][0]["gateway_kind"] == "link_local"
        assert "fe80" not in json.dumps(error.details) and "link#" not in json.dumps(error.details)
    else:
        raise AssertionError("residual tunnel guard was bypassed")

    # The reported self-gateway routes are metadata only after independent interface
    # address and effective-route evidence. Never infer inactivity from flags alone.
    self_gateway = "default fe80::1234%utun9 UGcIg utun9\nff00::/8 fe80::1234%utun9 UmCI utun9"
    profile = "utun9: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n\tinet6 fe80::1234%utun9 prefixlen 64 scopeid 0x9\n"
    verified = dict(baseline, routes=baseline["routes"] + "\n" + self_gateway,
                    tunnel_interfaces={"utun9": profile}, effective_routes={
                        "ipv4": {"status": "observed", "interface": "en0", "tunnel": False},
                        "ipv6": {"status": "no_route", "reason_code": "route_not_found"}})
    guard_network(verified)
    assert len(interface_metadata_routes(verified)) == 2
    marker = dict(verified, routes=verified["routes"].replace(
        "default fe80::1234%utun9", "default fe80::%utun9"))
    guard_network(marker)
    assert len(interface_metadata_routes(marker)) == 2
    assert stable_routes(marker["routes"]) == sorted(" ".join(row) for row in route_rows(marker["routes"]))
    reported = dict(verified, routes=baseline["routes"], tunnel_interfaces={})
    for index in [0, 1, 2, 3, 7, 8, 10, 11]:
        interface = "utun" + str(index)
        address = "fe80::" + str(100 + index)
        reported["routes"] += f"\ndefault fe80::%{interface} UGcIg {interface}\nff00::/8 {address}%{interface} UmCI {interface}"
        reported["tunnel_interfaces"][interface] = f"{interface}: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\ninet6 {address}%{interface} prefixlen 64\n"
    guard_network(reported)
    assert len(interface_metadata_routes(reported)) == 16
    active = dict(reported, routes=reported["routes"] + "\ndefault link#44 UCSg utun4\n10.0.0/8 link#44 UCSI utun4",
                  default="interface: utun4\n", services="(Connected)")
    try:
        guard_network(active)
    except CheckStopped as error:
        assert error.code == "foreign_tunnel_routes"
        assert error.details["verified_interface_metadata_count"] == 0
        assert error.details["connected_vpn_services"] == 1
    else:
        raise AssertionError("reported active VPN state was allowed")
    unsafe = [dict(verified, services="(Connected)"),
              dict(verified, tunnel_interfaces={}),
              dict(verified, tunnel_interfaces={"utun9": profile + "\tinet 10.0.0.2 netmask 0xffffffff\n"}),
              dict(verified, tunnel_interfaces={"utun9": profile + "\tinet6 2001:db8::2 prefixlen 64\n"}),
              dict(verified, tunnel_interfaces={"utun9": profile + "\tinet6 fd00::2 prefixlen 64\n"}),
              dict(verified, routes=verified["routes"].replace("fe80::1234%", "fe80::5678%")),
              dict(verified, routes=verified["routes"].replace("UGcIg", "UGcg")),
              dict(verified, routes=verified["routes"] + "\n0/1 link#9 UCS utun9"),
              dict(verified, routes=verified["routes"] + "\n10.0.0/8 link#9 UCSI utun9"),
              dict(verified, routes=verified["routes"] + "\n2001:db8::/32 link#9 UCSI utun9"),
              dict(verified, effective_routes={"ipv4": {"status": "observed", "interface": "utun4"},
                                                "ipv6": verified["effective_routes"]["ipv6"]}),
              dict(verified, effective_routes={"ipv4": verified["effective_routes"]["ipv4"],
                                                "ipv6": {"status": "unknown"}}),
              dict(verified, effective_routes={"ipv4": verified["effective_routes"]["ipv4"],
                                                "ipv6": {"status": "observed", "interface": "utun9"}})]
    unsafe += [dict(marker, routes=baseline["routes"] + "\ndefault fe80::%utun9 UGcIg utun9"),
               dict(marker, routes=marker["routes"].replace("default fe80::%", "default fe80::1%")),
               dict(marker, routes=marker["routes"].replace("default fe80::%utun9", "default fe80::%utun8")),
               dict(marker, routes=marker["routes"].replace("ff00::/8 fe80::1234%", "ff00::/8 fe80::5678%")),
               dict(marker, services="(Connected)"),
               dict(marker, tunnel_interfaces={"utun9": profile + "\tinet 10.0.0.2 netmask 0xffffffff\n"}),
               dict(marker, effective_routes={"ipv4": {"status": "observed", "interface": "utun4"},
                                              "ipv6": marker["effective_routes"]["ipv6"]}),
               dict(marker, effective_routes={"ipv4": marker["effective_routes"]["ipv4"],
                                              "ipv6": {"status": "unknown"}})]
    for snapshot in unsafe:
        try:
            guard_network(snapshot)
        except CheckStopped:
            pass
        else:
            raise AssertionError("active or unverified tunnel guard was bypassed")
    # Only the test's reported interface may own effective routes while full tunnel is up.
    own = dict(verified, effective_routes={"ipv4": {"status": "observed", "interface": "utun100"},
                                          "ipv6": {"status": "observed", "interface": "utun100"}})
    assert len(interface_metadata_routes(own, "utun100")) == 2
    guard_network(own, "utun100")
    try:
        guard_network(own)
    except CheckStopped:
        pass
    else:
        raise AssertionError("a foreign full tunnel was mistaken for test ownership")

    fixture_routes = {"ipv4": {"status": "observed", "interface": "en0", "tunnel": False, "scoped": False},
                      "ipv6": {"status": "observed", "interface": "utun9", "tunnel": True, "scoped": False}}
    # CLI diagnostics need no terms, scenario, build, elevation or process startup.
    for snapshot, expected_status in [(baseline, "PASS"), (verified, "PASS"), (marker, "PASS"),
                                      (dict(baseline, routes="default 1.2.3.4 UGSc utun9"), "SKIP"),
                                      (dict(verified, services="(Connected)"), "SKIP")]:
        output = io.StringIO()
        with patch.dict(globals(), network_snapshot=lambda: snapshot, guard=guard_network,
                        effective_route_diagnostics=lambda: fixture_routes), \
             patch.object(sys, "argv", ["parity_manual.py", "--preflight"]), \
             patch("subprocess.Popen") as spawn, patch("subprocess.run") as run_command, \
             patch("os.execvp") as elevate, redirect_stdout(output):
            result_code = main()
        report = json.loads(output.getvalue().removeprefix("RESULT "))
        assert report["phase"] == "preflight" and not report["live_test_started"]
        assert report["details"]["effective_routes"] == snapshot.get("effective_routes", fixture_routes)
        assert report["status"] == expected_status
        assert result_code == (0 if expected_status == "PASS" else 3)
        if snapshot == verified:
            assert report["details"]["self_gateway_candidate_count"] == 2
            assert report["details"]["interface_profiles"] == [{"interface": "utun9", "link_local_only": True}]
            assert "fe80" not in json.dumps(report)
        spawn.assert_not_called()
        run_command.assert_not_called()
        elevate.assert_not_called()

    # Interface metadata never bypasses production Zarp status or missing-socket checks.
    for unavailable in [False, True]:
        def production_status(*_args, **_kwargs):
            if unavailable:
                raise OSError("private socket diagnostic")
            return {"connected": True}
        with patch.object(Path, "exists", return_value=True), patch.dict(globals(), rpc=production_status):
            try:
                guard(verified)
            except CheckStopped as error:
                assert error.code == ("production_status_unknown" if unavailable else "production_session_active")
                assert "private" not in str(error)
            else:
                raise AssertionError("production Zarp guard was bypassed")
    with patch.object(Path, "exists", return_value=False), \
         patch.dict(globals(), command=lambda *_args, **_kw: "/usr/local/bin/zarpd\n"):
        try:
            guard(verified)
        except CheckStopped as error:
            assert error.code == "production_socket_missing"
        else:
            raise AssertionError("unobservable production Zarp was ignored")

    fake_info = os.stat_result((stat.S_IFSOCK | 0o660, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    for broken in [False, True]:
        calls = []
        def readonly_status(_path, method, timeout):
            calls.append(method)
            if broken:
                raise CheckStopped("private diagnostic", code="ipc_timeout")
            return {"protocol": 3, "connected": False, "endpoint": "private-address", "token": "private-token"}
        with patch.object(Path, "lstat", return_value=fake_info), \
             patch.dict(globals(), rpc=readonly_status), patch("subprocess.Popen") as spawn, \
             patch("subprocess.run") as run_command, patch("os.execvp") as elevate:
            report = production_status_report()
        assert calls == ["ping", "status"]
        assert report["status"] == ("SKIP" if broken else "PASS")
        assert not report["live_test_started"] and "private" not in json.dumps(report)
        if broken:
            assert report["methods"]["status"]["status_error_code"] == "ipc_timeout"
        else:
            assert report["methods"]["status"]["connected"] is False
        spawn.assert_not_called()
        run_command.assert_not_called()
        elevate.assert_not_called()
    metadata = ipc_failure_details(CheckStopped("private diagnostic", code="ipc_timeout", details={
        "ipc_phase": "await_response", "response_bytes": 0, "peer_pid": 123,
        "response": "private-token", "endpoint": "private-address"}))
    assert metadata == {"error_type": "CheckStopped", "status_error_code": "ipc_timeout",
                        "ipc_phase": "await_response", "response_bytes": 0, "peer_pid": 123}
    for bad_size, bad_pid in [(True, True), (-1, 0), (262145, 2147483648), ("12", "123")]:
        rejected = ipc_failure_details(CheckStopped("private diagnostic", code="ipc_timeout", details={
            "ipc_phase": "private-token", "response_bytes": bad_size, "peer_pid": bad_pid}))
        assert rejected == {"error_type": "CheckStopped", "status_error_code": "ipc_timeout"}
    for invalid in [{}, {"connected": "false"}, [], None]:
        with patch.object(Path, "exists", return_value=True), patch.dict(globals(), rpc=lambda *_args, **_kw: invalid):
            try:
                guard(verified)
            except CheckStopped as error:
                assert error.code == "production_status_unknown"
                assert error.details["status_error_code"] == "invalid_status"
            else:
                raise AssertionError("invalid status was treated as idle")
    for activity in [None, "false", 0, [], True, False]:
        status = {"connected": False}
        if activity is not None:
            status["networkBusy"] = activity
        with patch.object(Path, "exists", return_value=True), \
             patch.dict(globals(), rpc=lambda *_args, **_kw: status, command=lambda *_args, **_kw: ""), \
             patch("subprocess.Popen") as spawn, patch("subprocess.run") as run_command:
            if activity is False:
                guard(verified)
            else:
                try:
                    guard(verified)
                except CheckStopped as error:
                    assert error.code == ("production_session_active" if activity is True else "production_status_unknown")
                else:
                    raise AssertionError("missing, invalid or active network ownership was treated as idle")
            spawn.assert_not_called()
            run_command.assert_not_called()
    output = io.StringIO()
    with patch.object(sys, "argv", ["parity_manual.py", "--production-status"]), \
         patch.dict(globals(), production_status_report=lambda: {"status": "SKIP", "live_test_started": False}), \
         patch("subprocess.Popen") as spawn, patch("subprocess.run") as run_command, \
         patch("os.execvp") as elevate, redirect_stdout(output):
        assert main() == 3
    spawn.assert_not_called()
    run_command.assert_not_called()
    elevate.assert_not_called()

    # Real diagnostic entrypoint only constructs numeric RTM_GET commands, without DNS,
    # route mutations or packets. IPv6 lookup failures remain unknown rather than safe.
    observations = []
    def route_observer(args, timeout):
        observations.append(args)
        if "-inet6" in args:
            raise CheckStopped("fixture lookup failed", code="observation_failed",
                               details={"tool": "route", "returncode": 1})
        return "gateway: private-address\ninterface: en0\nflags: <UP,GATEWAY,DONE>\n"
    with patch.dict(globals(), command=route_observer):
        observed = effective_route_diagnostics()
    assert observations == [["/sbin/route", "-n", "get", "1.1.1.1"],
                            ["/sbin/route", "-n", "get", "-inet6", "2606:4700:4700::1111"]]
    assert observed["ipv4"] == fixture_routes["ipv4"]
    assert observed["ipv6"]["status"] == "unknown"
    assert "private" not in json.dumps(observed)
    with patch.dict(globals(), command=lambda *_args, **_kw: "interface: utun8\nflags: <UP,GATEWAY,IFSCOPE>\n"):
        observed = effective_route_diagnostics()
    assert observed["ipv6"]["tunnel"] and observed["ipv6"]["scoped"]

    for message, expected in [("route: writing to routing socket: not in table", "route_not_found"),
                              ("private unknown diagnostic", "route_lookup_diagnostic")]:
        completed = subprocess.CompletedProcess(["/sbin/route"], 0, stdout="", stderr=message)
        with patch("subprocess.run", return_value=completed) as run_command:
            try:
                command(["/sbin/route", "-n", "get", "-inet6", "2606:4700:4700::1111"])
            except CheckStopped as error:
                assert error.code == expected
                assert error.details == {"tool": "route", "returncode": 0}
                assert "private" not in str(error)
            else:
                raise AssertionError("zero-exit route error was swallowed")
            assert run_command.call_args.kwargs["env"]["LC_ALL"] == "C"
        with patch("subprocess.run", return_value=completed):
            observed = effective_route_diagnostics()
        assert observed["ipv6"]["status"] == ("no_route" if expected == "route_not_found" else "unknown")
        assert "private" not in json.dumps(observed)

    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(
            71, ["/sbin/route"], output="private-token", stderr="private-key")):
        try:
            command(["/sbin/route", "-n", "get", "default"])
        except CheckStopped as error:
            assert error.code == "observation_failed" and error.details == {"tool": "route", "returncode": 71}
            assert "private" not in str(error)
        else:
            raise AssertionError("observation failure was hidden")
    for value in ["127.0.0.1:443", "example.com:443", "8.8.8.8:0", "[::1]:443"]:
        try:
            endpoint(value)
        except ValueError:
            continue
        raise AssertionError("invalid endpoint accepted")
    # Exercise the real bounded IPC reader with a temporary fake daemon. No production sockets.
    with tempfile.TemporaryDirectory(prefix="zpm-", dir="/tmp") as folder:
        path = Path(folder) / "fake.sock"
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(path))
            listener.listen(1)
            def answer():
                with listener.accept()[0] as peer:
                    request = json.loads(peer.recv(4096))
                    assert request["method"] == "ping"
                    peer.sendall(b'{"id":1,"result":{"protocol":3}}\n')
            thread = threading.Thread(target=answer)
            thread.start()
            assert rpc(path, "ping", timeout=1) == {"protocol": 3}
            thread.join(timeout=2)
            assert not thread.is_alive()
        with socket.socket(socket.AF_UNIX) as listener:
            stalled_path = Path(folder) / "stalled.sock"
            listener.bind(str(stalled_path))
            listener.listen(1)
            release = threading.Event()
            def stall():
                with listener.accept()[0] as peer:
                    _ = peer.recv(4096)
                    release.wait(1)
            thread = threading.Thread(target=stall)
            thread.start()
            try:
                rpc(stalled_path, "status", timeout=0.05)
            except CheckStopped as error:
                assert error.code == "ipc_timeout"
                details = ipc_failure_details(error)
                assert details["ipc_phase"] == "await_response" and details["response_bytes"] == 0
                if "peer_pid" in details:
                    assert details["peer_pid"] == os.getpid()
            else:
                raise AssertionError("stalled socket was treated as idle")
            finally:
                release.set()
                thread.join(timeout=2)
            assert not thread.is_alive()
    print("RESULT self-test PASS: diagnostic CLI, redaction, parsing/ownership guards and temporary fake IPC; no daemon or network changes")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=["warp-h3", "warp-h2", "warp-account-ipv6", "warp-custom"])
    parser.add_argument("--endpoint", help="public IPv4:port or [IPv6]:port for warp-custom")
    parser.add_argument("--transport", choices=["h3", "h2"], default="h3", help="control transport for warp-custom")
    parser.add_argument("--full-tunnel", action="store_true", help="temporarily add /1 routes and an endpoint host exclusion; no DNS override")
    parser.add_argument("--accept-warp-terms", action="store_true", help="accept Cloudflare WARP terms for this isolated test account")
    parser.add_argument("--self-test", action="store_true", help="pure parsing/guard checks only; no system observation or changes")
    parser.add_argument("--preflight", action="store_true", help="read-only diagnostics only; no build, sudo, daemon startup, or system changes")
    parser.add_argument("--production-status", action="store_true", help="read-only production ping/status diagnostic; may be run with sudo, never starts/stops a daemon or changes the network")
    parser.add_argument("--worker", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.production_status:
        if args.worker or args.preflight or args.self_test or args.scenario or args.accept_warp_terms or args.full_tunnel or args.endpoint:
            parser.error("--production-status must be used alone")
        report = production_status_report()
        print("RESULT " + json.dumps(report, sort_keys=True))
        return 0 if report["status"] == "PASS" else 3
    if args.self_test:
        self_test()
        return 0
    if args.preflight:
        if args.worker:
            parser.error("--preflight cannot be combined with --worker")
        report = preflight_report(args.scenario or "preflight", detailed=True)
        print("RESULT " + json.dumps(report, sort_keys=True))
        return 0 if report["status"] == "PASS" else 3
    if not args.scenario or not args.accept_warp_terms:
        parser.error("choose a scenario and explicitly accept the WARP terms")
    if args.scenario == "warp-custom":
        try:
            args.endpoint = endpoint(args.endpoint or "")
        except ValueError:
            parser.error("warp-custom requires a public numeric --endpoint")
    elif args.endpoint:
        parser.error("--endpoint is only used by warp-custom")
    elif args.transport != "h3":
        parser.error("--transport is only used by warp-custom; other scenarios choose their own transport")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("macOS arm64 is required")
    if args.worker:
        work = Path(args.worker).resolve()
        if os.geteuid() != 0 or work.parent != Path("/tmp").resolve() or not work.name.startswith("zarp-parity-"):
            parser.error("invalid private worker directory")
        os.umask(0o077)
        if work.is_symlink() or (work / "zarpd").is_symlink() or not (work / "zarpd").is_file():
            parser.error("private worker must contain a regular test binary")
        os.chown(work, 0, 0)
        os.chmod(work, 0o700)
        os.chown(work / "zarpd", 0, 0)
        supervisor = Supervisor(work, args.scenario, args.endpoint, args.full_tunnel, args.transport)
        signal.signal(signal.SIGINT, lambda *_: supervisor.abort.set())
        signal.signal(signal.SIGTERM, lambda *_: supervisor.abort.set())
        # A separate watchdog enforces the overall deadline even during registration or startup.
        def watchdog():
            if not supervisor.done.wait(TIME_LIMIT - 90):
                supervisor.abort.set()
        threading.Thread(target=watchdog, daemon=True).start()
        return supervisor.run()
    if os.geteuid() == 0:
        parser.error("run as your normal user; this script requests sudo after building")
    preflight_started = time.monotonic()
    report = preflight_report(args.scenario, detailed=True)
    if report["status"] != "PASS":
        print("RESULT " + json.dumps(report, sort_keys=True))
        return 3
    os.umask(0o077)
    work = Path(tempfile.mkdtemp(prefix="zarp-parity-" + os.urandom(4).hex() + "-", dir="/tmp"))
    env = dict(os.environ, GOCACHE=str(work / "go-cache"), GOTOOLCHAIN="local")
    try:
        subprocess.run(["go", "build", "-trimpath", "-ldflags", "-X main.version=parity-manual-v1", "-o", str(work / "zarpd"), "./cmd/zarpd"],
                       cwd=REPO / "zarpd", env=env, check=True, timeout=180)
    except (subprocess.SubprocessError, OSError, KeyboardInterrupt):
        print("RESULT " + json.dumps({"version": 1, "run_id": work.name, "scenario": args.scenario,
                                      "status": "FAIL", "cleanup": "PASS", "duration_seconds": round(time.monotonic() - preflight_started, 2),
                                      "reason": "private build failed or was interrupted; no system changes"}))
        return 1
    print("Private worker time limit: 600 seconds. Temporary TUN and measurement route; full routes only with --full-tunnel. DNS untouched.", flush=True)
    # Replace this launcher so sudo forwards signals directly to the supervised worker.
    os.execvp("sudo", ["sudo", sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], "--worker", str(work)])


if __name__ == "__main__":
    sys.exit(main())
