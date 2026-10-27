#!/usr/bin/env python3
"""User-run Stage 2 IPv4 TUN/process PoC. Autonomous mode: --loopback-check only.

--run requires macOS arm64, Go, the pinned sing-box binary and sudo. It refuses a
foreign VPN or unknown/active production Zarp. It creates one private utun and one
198.18.0.2 host route. No default routes, DNS/proxy settings or production files
change. Selected/excluded private executables test TCP, UDP and a direct DNS query.
All forwarded destinations are authenticated loopback fixtures, not the internet.
Build limit: 180 seconds. Root worker: 120 seconds including cleanup. A separate
engine guardian stops its exact child if the worker dies, expires or is interrupted.
--loopback-check builds, checks configuration without Start, and tests only loopback.
It never starts a TUN and does not count as passing the live system gate.
"""
import argparse
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("adapter_safety", ROOT / "scripts/parity_manual.py")
safety = importlib.util.module_from_spec(spec)
spec.loader.exec_module(safety)
BINARY = ROOT / "build/parity-backends/sing-box-1.13.14/sing-box"
PIN = "813d8effd02a19572a8d75aef29fc073101404ca535b2496be86f21827c7684d"
MEASUREMENT = "198.18.0.2"
WORKER_LIMIT = 120
ENGINE_OUTPUT_LIMIT = 32768
ENGINE_MARKERS = {
    "tun": (b"configure tun", b"create tun", b"open tun", b"start tun", b"inbound/tun"),
    "permission": (b"operation not permitted", b"permission denied"),
    "address_in_use": (b"address already in use",),
    "invalid_argument": (b"invalid argument",),
    "resource_limit": (b"too many open files", b"no buffer space", b"cannot allocate memory"),
    "configuration": (b"read config", b"decode config", b"create service"),
    "service_start": (b"start service",),
    "panic": (b"panic:", b"fatal error:"),
}
GUARDIAN_PHASES = {"guard", "interface", "spawn", "running"}
GUARDIAN_REASONS = {"ownership", "production_status_unknown", "production_session_active",
                    "foreign_tunnel_routes", "connected_vpn_service"}


class EngineOutput:
    """Drain only the owned child's stderr, with bounded memory and no raw report."""
    def __init__(self, stream):
        self.stream = stream
        self.data = bytearray()
        self.capped = False
        self.eof = False
        self.failed = False
        os.set_blocking(stream.fileno(), False)

    def drain(self):
        # Bound each turn too: noisy output cannot starve the guardian watchdog.
        for _ in range(8):
            if self.eof or self.failed:
                break
            try:
                data = os.read(self.stream.fileno(), 4096)
            except BlockingIOError:
                break
            except InterruptedError:
                continue
            except OSError:
                self.failed = True
                break
            if not data:
                self.eof = True
                break
            remaining = ENGINE_OUTPUT_LIMIT - len(self.data)
            self.data.extend(data[:remaining])
            self.capped |= len(data) > remaining

    def report(self):
        data = bytes(self.data).lower()
        return {"output_bytes": len(self.data), "output_capped": self.capped,
                "output_eof": self.eof, "output_read_failed": self.failed,
                "error_markers": sorted(key for key, patterns in ENGINE_MARKERS.items()
                                        if any(pattern in data for pattern in patterns))}

    def close(self):
        self.stream.close()
        self.data.clear()


def guardian_diagnostics(data):
    """Allowlist again at the worker/report boundary, including all numeric bounds."""
    if not isinstance(data, dict):
        return {}
    result = {}
    for key, choices in (("phase", GUARDIAN_PHASES), ("reason_code", GUARDIAN_REASONS)):
        value = data.get(key)
        if isinstance(value, str) and value in choices:
            result[key] = value
    for key, lower, upper in (("exit_code", -127, 255), ("errno", 0, 255),
                              ("output_bytes", 0, ENGINE_OUTPUT_LIMIT)):
        value = data.get(key)
        if type(value) is int and lower <= value <= upper:
            result[key] = value
    for key in ("engine_spawned", "guardian_error", "output_capped", "output_eof", "output_read_failed"):
        if type(data.get(key)) is bool:
            result[key] = data[key]
    values = data.get("error_markers")
    if isinstance(values, list) and len(values) <= len(ENGINE_MARKERS):
        result["error_markers"] = sorted({value for value in values if isinstance(value, str) and value in ENGINE_MARKERS})
    return result


def production_blocker_details(error):
    """Preserve bounded IPC facts only, never arbitrary guard data or responses."""
    if error.code != "production_status_unknown" or not isinstance(error.details, dict):
        return {}
    data, result = error.details, {}
    codes = {"ipc_timeout", "ipc_socket_error", "ipc_response_limit", "ipc_peer_closed", "ipc_invalid_response",
             "ipc_cancelled", "invalid_status", "network_activity_unknown"}
    value = data.get("status_error_code")
    if isinstance(value, str) and value in codes:
        result["status_error_code"] = value
    value = data.get("ipc_phase")
    if isinstance(value, str) and value in {"connect", "send", "await_response"}:
        result["ipc_phase"] = value
    for key, lower, upper in (("errno", 0, 255), ("peer_pid", 1, 2147483647), ("response_bytes", 0, 262144)):
        value = data.get(key)
        if type(value) is int and lower <= value <= upper:
            result[key] = value
    return result


def write_json(path, value):
    temporary = path.with_suffix(".new")
    with open(temporary, "w") as output:
        os.chmod(temporary, 0o600)
        json.dump(value, output, sort_keys=True)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def private_environment(work):
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(work)}


def source_digest():
    digest = hashlib.sha256(safety.source_digest().encode())
    digest.update(Path(__file__).read_bytes())
    digest.update(Path(__file__).with_suffix(".sh").read_bytes())
    return digest.hexdigest()


def snapshot_engine(work):
    info = BINARY.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024 or info.st_mode & 0o022:
        raise safety.CheckStopped("pinned engine file is unsafe", code="engine_integrity")
    with open(BINARY, "rb") as binary:
        data = binary.read(64 * 1024 * 1024 + 1)
    if hashlib.sha256(data).hexdigest() != PIN:
        raise safety.CheckStopped("pinned engine checksum mismatch", code="engine_integrity")
    path = work / "engine"
    with open(path, "xb") as output:
        output.write(data)
    os.chmod(path, 0o500)


def prepare():
    if not BINARY.exists():
        raise safety.CheckStopped("pinned sing-box 1.13.14 is missing", code="engine_missing")
    work = Path(tempfile.mkdtemp(prefix="zarp-parity-adapter-", dir="/tmp")).resolve()
    producers = Path(tempfile.mkdtemp(prefix="zarp-parity-producers-", dir="/tmp")).resolve()
    os.chmod(work, 0o700)
    try:
        source_before = source_digest()
        environment = dict(os.environ, GOTOOLCHAIN="local", GOENV="off", GOFLAGS="", GOOS="darwin", GOARCH="arm64", GOCACHE=str(work / "go-cache"))
        environment.pop("ZARP_PARITY_SING_BOX", None)
        environment.pop("ZARP_PARITY_XRAY", None)
        subprocess.run(["go", "build", "-trimpath", "-o", str(work / "selected-probe"), "./cmd/parity-adapter-probe"],
                       cwd=ROOT / "zarpd", env=environment, check=True, timeout=180,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.copyfile(work / "selected-probe", work / "excluded-probe")
        for name in ("selected-probe", "excluded-probe"):
            os.chmod(work / name, 0o500)
            shutil.copyfile(work / name, producers / name)
            os.chmod(producers / name, 0o500)
        generated = subprocess.run([str(work / "selected-probe"), "-fixture", str(work), "-generate"],
                                   env=private_environment(work), capture_output=True, timeout=10)
        if generated.returncode != 0 or not json.loads(generated.stdout).get("ok"):
            raise safety.CheckStopped("private fixture generation failed", code="fixture")
        snapshot_engine(work)
        if source_before != source_digest():
            raise safety.CheckStopped("test source changed during build", code="source_changed")
        write_json(work / "manifest.json", {"version": 1, "source_sha256": source_before,
                    "probe_sha256": hashlib.sha256((work / "selected-probe").read_bytes()).hexdigest(),
                    "original_uid": os.getuid(), "original_gid": os.getgid(), "producer_directory": str(producers)})
        return work
    except BaseException:
        shutil.rmtree(work)
        shutil.rmtree(producers)
        raise


def validate_work(work, root=False):
    if work.parent != Path("/tmp").resolve() or not work.name.startswith("zarp-parity-adapter-") or work.is_symlink():
        raise safety.CheckStopped("invalid private worker directory", code="ownership")
    info = work.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise safety.CheckStopped("unsafe private worker directory", code="ownership")
    expected = ("manifest.json", "selected-probe", "excluded-probe", "engine", "nonce", "cert.pem", "key.pem")
    for name in expected:
        info = (work / name).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise safety.CheckStopped("unsafe private worker member", code="ownership")
    manifest = json.loads((work / "manifest.json").read_text())
    if manifest.get("source_sha256") != source_digest():
        raise safety.CheckStopped("test source changed after build", code="source_changed")
    for name in ("selected-probe", "excluded-probe"):
        if hashlib.sha256((work / name).read_bytes()).hexdigest() != manifest.get("probe_sha256"):
            raise safety.CheckStopped("private probe integrity failed", code="ownership")
    producers = Path(manifest["producer_directory"])
    if type(manifest.get("original_uid")) is not int or manifest["original_uid"] <= 0 or type(manifest.get("original_gid")) is not int or manifest["original_gid"] < 0:
        raise safety.CheckStopped("invalid originating user", code="ownership")
    sealed = work.stat().st_uid == 0
    producer_owner = 0 if sealed else manifest["original_uid"]
    producer_mode = 0o710 if sealed else 0o700
    executable_mode = 0o510 if sealed else 0o500
    if producers.parent != Path("/tmp").resolve() or not producers.name.startswith("zarp-parity-producers-") or producers.is_symlink() or \
            not producers.is_dir() or producers.stat().st_uid != producer_owner or stat.S_IMODE(producers.stat().st_mode) != producer_mode or \
            sealed and producers.stat().st_gid != manifest["original_gid"]:
        raise safety.CheckStopped("unsafe private producer directory", code="ownership")
    for name in ("selected-probe", "excluded-probe"):
        info = (producers / name).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != producer_owner or stat.S_IMODE(info.st_mode) != executable_mode or \
                sealed and info.st_gid != manifest["original_gid"] or \
                hashlib.sha256((producers / name).read_bytes()).hexdigest() != manifest["probe_sha256"]:
            raise safety.CheckStopped("private user probe integrity failed", code="ownership")
    if hashlib.sha256((work / "engine").read_bytes()).hexdigest() != PIN:
        raise safety.CheckStopped("private engine integrity failed", code="engine_integrity")
    if root:
        os.chown(work, 0, 0)
        for name in expected:
            os.chown(work / name, 0, 0)
        # Only the original user's group can traverse/execute these test binaries.
        # Root owns the directory and files, preventing producer replacement after validation.
        os.chown(producers, 0, manifest["original_gid"])
        os.chmod(producers, 0o710)
        for name in ("selected-probe", "excluded-probe"):
            os.chown(producers / name, 0, manifest["original_gid"])
            os.chmod(producers / name, 0o510)


def configuration(work, interface, ports):
    manifest = json.loads((work / "manifest.json").read_text())
    selected = Path(manifest["producer_directory"]) / "selected-probe"
    if not interface.startswith("utun") or not interface[4:].isdecimal() or not selected.is_file() or selected.is_symlink():
        raise safety.CheckStopped("missing explicit process selection or invalid test interface", code="configuration")
    rules = []
    for kind, network, target_port in (("https", "tcp", 443), ("udp", "udp", 9999), ("dns", "udp", 53)):
        port = ports[kind]
        if type(port) is not int or not 1 <= port <= 65535:
            raise safety.CheckStopped("invalid private fixture port", code="configuration")
        rules.append({"process_path": [str(selected)], "ip_cidr": [MEASUREMENT + "/32"],
                      "network": network, "port": [target_port], "action": "route", "outbound": "private",
                      "override_address": "127.0.0.1", "override_port": port})
    rules.append({"action": "reject"})
    return {"log": {"disabled": False, "level": "error", "timestamp": False}, "inbounds": [{"type": "tun", "tag": "private-test",
        "interface_name": interface, "address": ["198.18.0.1/32"], "mtu": 1500,
        "auto_route": False, "stack": "gvisor"}], "outbounds": [{"type": "direct", "tag": "private", "bind_interface": "lo0"}],
        "route": {"find_process": True, "auto_detect_interface": False, "rules": rules, "final": "private"}}


class Fixtures:
    def __init__(self, work):
        self.nonce = (work / "nonce").read_bytes()
        self.counts = {"https": 0, "udp": 0, "dns": 0}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.threads = []
        self.sockets = []
        self.http = None
        try:
            self.initialize(work)
        except BaseException:
            self.close()
            raise

    def initialize(self, work):
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/probe" or self.headers.get("X-Zarp-Probe", "").encode() != parent.nonce:
                    self.send_error(403)
                    return
                with parent.lock:
                    parent.counts["https"] += 1
                marker = b"private-adapter-https"
                self.send_response(200)
                self.send_header("Content-Length", str(len(marker)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(marker)

            def log_message(self, *_args):
                pass

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(work / "cert.pem", work / "key.pem")
        class TLSServer(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self):
                connection, peer = super().get_request()
                connection.settimeout(1)
                try:
                    return context.wrap_socket(connection, server_side=True), peer
                except BaseException:
                    connection.close()
                    raise

        self.http = TLSServer(("127.0.0.1", 0), Handler)
        self.ports = {"https": self.http.server_address[1]}
        self.threads.append(threading.Thread(target=self.http.serve_forever, daemon=True))
        for kind in ("udp", "dns"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0))
            sock.settimeout(0.2)
            self.sockets.append(sock)
            self.ports[kind] = sock.getsockname()[1]
            self.threads.append(threading.Thread(target=self.serve_udp, args=(sock, kind), daemon=True))
        for thread in self.threads:
            thread.start()

    def serve_udp(self, sock, kind):
        question = b"".join(bytes([len(label)]) + label for label in (self.nonce[:24], b"probe", b"example", b"test")) + b"\x00\x00\x01\x00\x01"
        while not self.stop.is_set():
            try:
                data, peer = sock.recvfrom(512)
                if kind == "udp":
                    if data != b"private-adapter-udp-" + self.nonce:
                        continue
                    reply = data
                else:
                    if len(data) < 12 or data[2:12] != b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" or data[12:] != question:
                        continue
                    reply = data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\xc0\x00\x02\x01"
                with self.lock:
                    self.counts[kind] += 1
                sock.sendto(reply, peer)
            except socket.timeout:
                continue
            except OSError:
                return

    def counters(self):
        with self.lock:
            return dict(self.counts)

    def close(self):
        self.stop.set()
        if self.http is not None:
            if self.threads and self.threads[0].is_alive():
                self.http.shutdown()
            self.http.server_close()
        for sock in self.sockets:
            sock.close()
        for thread in self.threads:
            if thread.ident is not None:
                thread.join(timeout=2)
        return not any(thread.is_alive() for thread in self.threads)


def probe(work, name, kind, fixtures, live):
    manifest = json.loads((work / "manifest.json").read_text())
    args = [str(Path(manifest["producer_directory"]) / name), "-fixture", str(work), "-probe", kind, "-network", "system-tun" if live else "loopback"]
    args += ["-fixture-stdin"]
    payload = json.dumps({"nonce": fixtures.nonce.decode(), "certificate": (work / "cert.pem").read_text()}).encode()
    if live:
        # Producers run as the original user. Secrets travel in one inherited pipe,
        # never argv, public files, the environment or a production socket.
        args = ["/usr/bin/sudo", "-n", "-u", "#" + str(manifest["original_uid"]), "-g", "#" + str(manifest["original_gid"]), *args]
    if not live:
        args += ["-loopback-port", str(fixtures.ports[kind])]
    result = subprocess.run(args, env=private_environment(work), input=payload, capture_output=True, timeout=5)
    report = json.loads(result.stdout)
    if type(report.get("ok")) is not bool or report.get("case") != kind or report.get("uid") != manifest["original_uid"] or result.returncode not in (0, 1):
        raise safety.CheckStopped("private probe returned invalid evidence", code="probe")
    return report["ok"] and result.returncode == 0


DIRECT_ROUTE_FLAGS = {"UP", "HOST", "DONE", "STATIC", "IFSCOPE", "IFREF"}


def route_identity(fields):
    """Exact direct host route added by this worker, not an indirect gateway route.

    Darwin route.c prints gateway only for RTF_GATEWAY. Our -interface route
    deliberately has no such flag. Require positive host/static/interface facts
    instead of manufacturing a gateway. This is not a foreign-route exemption.
    """
    if not isinstance(fields, dict) or fields.get("destination") != MEASUREMENT:
        return None
    interface, text = fields.get("interface", ""), fields.get("flags", "")
    if not isinstance(interface, str) or len(interface) != 9 or not interface.startswith("utun") or not interface[4:].isascii() or \
            not interface[4:].isdecimal() or not 30000 <= int(interface[4:]) < 40000:
        return None
    if not isinstance(text, str) or len(text) > 256 or not text.startswith("<") or not text.endswith(">"):
        return None
    tokens = [value.strip() for value in text[1:-1].split(",")]
    flags = set(tokens)
    if len(tokens) != len(flags) or not {"UP", "HOST", "STATIC"} <= flags or not flags <= DIRECT_ROUTE_FLAGS:
        return None
    if fields.get("gateway", "") != "":
        return None
    return MEASUREMENT, interface, tuple(sorted(flags))


def route_matches(actual, expected):
    identity = route_identity(expected)
    return identity is not None and route_identity(actual) == identity


def route_observation(fields, interface):
    """Only comparisons and known flag names; no raw route output/addresses."""
    text = fields.get("flags", "")
    shaped = isinstance(text, str) and len(text) <= 256 and text.startswith("<") and text.endswith(">")
    tokens = {value.strip() for value in text[1:-1].split(",")} if shaped else set()
    known = DIRECT_ROUTE_FLAGS | {"GATEWAY", "REJECT", "BLACKHOLE", "DYNAMIC", "MODIFIED", "WASCLONED", "LLINFO"}
    return {"destination_matches": fields.get("destination") == MEASUREMENT,
            "interface_matches": fields.get("interface") == interface,
            "gateway_displayed": bool(fields.get("gateway")), "flags_format_valid": shaped,
            "known_flags": sorted(tokens & known), "unknown_flags": bool(tokens - known),
            "direct_host_route": route_identity(fields) is not None}


def remove_owned_route(work):
    journal = work / "route.json"
    if not journal.exists():
        return True
    expected = json.loads(journal.read_text())
    if route_identity(expected) is None:
        raise safety.CheckStopped("private route journal is invalid; route left unchanged", code="route_ownership")
    actual = safety.route_fields(safety.command(["/sbin/route", "-n", "get", "-host", MEASUREMENT], timeout=3))
    if route_matches(actual, expected):
        safety.command(["/sbin/route", "-n", "delete", "-host", MEASUREMENT, "-interface", expected["interface"]], timeout=3)
        after = safety.route_fields(safety.command(["/sbin/route", "-n", "get", "-host", MEASUREMENT], timeout=3))
        return not route_matches(after, expected)
    # Removed or externally replaced routes are preserved. Never restore the baseline.
    return True


def stop_child(child, grace=3):
    if child is None or child.poll() is not None:
        return
    # This unreaped Popen handle belongs to this Start call. No PID/name lookup can select a VPN.
    child.terminate()
    try:
        child.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=3)


def engine_guard(work):
    validate_work(work)
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    parent = os.getppid()
    authorization = json.loads((work / "live-authorization.json").read_text())
    if os.geteuid() != 0 or authorization.get("worker_pid") != parent or work.stat().st_uid != 0:
        raise safety.CheckStopped("guardian has no owning root worker", code="ownership")
    child, output = None, None
    diagnostic = {"phase": "guard", "engine_spawned": False}
    cleanup = False
    failed = False
    try:
        safety.guard(safety.network_snapshot())
        diagnostic["phase"] = "interface"
        interface = authorization["interface"]
        if interface in safety.command(["/sbin/ifconfig", "-l"], timeout=3).split() or os.getppid() != parent:
            raise safety.CheckStopped("guardian interface or parent conflict", code="ownership")
        diagnostic["phase"] = "spawn"
        child = subprocess.Popen([str(work / "engine"), "run", "-c", str(work / "frontend.json")],
                                 env=private_environment(work), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        diagnostic["engine_spawned"] = True
        output = EngineOutput(child.stderr)
        write_json(work / "engine-ready.json", {"pid": child.pid})
        diagnostic["phase"] = "running"
        deadline = time.monotonic() + WORKER_LIMIT - 25
        while child.poll() is None and not stopped.wait(0.2):
            output.drain()
            if time.monotonic() >= deadline or os.getppid() != parent:
                break
    except safety.CheckStopped as error:
        failed = True
        diagnostic["reason_code"] = error.code
    except OSError as error:
        failed = True
        diagnostic["errno"] = error.errno
    except Exception:
        failed = True
        diagnostic["guardian_error"] = True
    finally:
        try:
            remove_owned_route(work)
        finally:
            try:
                stop_child(child)
                cleanup = child is None or child.poll() is not None
            finally:
                if child is not None:
                    diagnostic["exit_code"] = child.returncode
                if output is not None:
                    try:
                        output.drain()
                        diagnostic.update(output.report())
                    finally:
                        output.close()
                write_json(work / "engine-cleanup.json", {"engine_stopped": cleanup,
                           "diagnostics": guardian_diagnostics(diagnostic)})
    return 0 if cleanup and not failed else 1


def execute(work, live):
    started = time.monotonic()
    result = {"version": 1, "run_id": work.name, "scenario": "backend-system-adapter", "phase": "live" if live else "loopback",
              "status": "FAIL", "cleanup": "PASS", "live_test_started": False, "system_dns_configured": False, "default_routes_configured": False, "checks": []}
    fixtures, guardian, baseline, interface = None, None, None, None
    abort, done = threading.Event(), threading.Event()
    monitor = None
    validated = False
    try:
        validate_work(work, root=live)
        validated = True
        signal.signal(signal.SIGINT, lambda *_: abort.set())
        signal.signal(signal.SIGTERM, lambda *_: abort.set())
        fixtures = Fixtures(work)
        interface = "utun60000"
        if live:
            baseline = safety.network_snapshot()
            safety.guard(baseline)
            existing = set(safety.command(["/sbin/ifconfig", "-l"], timeout=3).split())
            interface = "utun" + str(30000 + int.from_bytes(os.urandom(2), "big") % 10000)
            if interface in existing:
                raise safety.CheckStopped("chosen test interface already exists", code="interface_conflict")
            before_route = safety.route_fields(safety.command(["/sbin/route", "-n", "get", "-host", MEASUREMENT], timeout=3))
            if before_route.get("destination") != "default" or before_route.get("interface") != safety.route_fields(baseline["default"]).get("interface"):
                raise safety.CheckStopped("reserved measurement address is already routed or uncertain", code="route_conflict")
            write_json(work / "network-before.json", baseline)
        write_json(work / "frontend.json", configuration(work, interface, fixtures.ports))
        # Verified against pinned source: check constructs/closes a box; it never calls Start.
        checked = subprocess.run([str(work / "engine"), "check", "-c", str(work / "frontend.json")],
                                 env=private_environment(work), capture_output=True, timeout=15)
        if checked.returncode != 0:
            raise safety.CheckStopped("pinned engine rejected private frontend configuration", code="configuration")
        if live:
            safety.guard(safety.network_snapshot())
            if interface in safety.command(["/sbin/ifconfig", "-l"], timeout=3).split():
                raise safety.CheckStopped("chosen test interface appeared before startup", code="interface_conflict")
            write_json(work / "live-authorization.json", {"worker_pid": os.getpid(), "interface": interface})
            guardian = subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--engine-guard", str(work)],
                                        env=private_environment(work), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            result["live_test_started"] = True
            deadline = min(started + WORKER_LIMIT - 15, time.monotonic() + 10)
            while time.monotonic() < deadline and not abort.is_set():
                if guardian.poll() is not None:
                    raise safety.CheckStopped("private TUN guardian or engine exited during startup", code="startup")
                if (work / "engine-ready.json").exists() and interface in safety.command(["/sbin/ifconfig", "-l"], timeout=3).split():
                    break
                abort.wait(0.1)
            else:
                raise safety.CheckStopped("private TUN startup timed out or was interrupted", code="startup")
            safety.guard(safety.network_snapshot(), interface)
            safety.command(["/sbin/route", "-n", "add", "-host", MEASUREMENT, "-interface", interface], timeout=3)
            expected = safety.route_fields(safety.command(["/sbin/route", "-n", "get", "-host", MEASUREMENT], timeout=3))
            result["route_ownership"] = route_observation(expected, interface)
            if expected.get("interface") != interface or not route_matches(expected, expected):
                raise safety.CheckStopped("measurement route ownership is unverified", code="route_ownership")
            write_json(work / "route.json", {"destination": expected["destination"], "flags": expected["flags"],
                                             "gateway": expected.get("gateway", ""), "interface": expected["interface"]})

            def watch():
                while not done.wait(0.5):
                    try:
                        if time.monotonic() >= started + WORKER_LIMIT - 45 or guardian.poll() is not None:
                            raise safety.CheckStopped("private worker expired or engine exited", code="watchdog")
                        current = safety.network_snapshot()
                        safety.guard(current, interface)
                        actual = safety.route_fields(safety.command(["/sbin/route", "-n", "get", "-host", MEASUREMENT], timeout=3))
                        if not route_matches(actual, expected) or current["dns"] != baseline["dns"] or safety.stable_routes(current["routes"], interface, (MEASUREMENT,)) != safety.stable_routes(baseline["routes"]):
                            raise safety.CheckStopped("external network change detected", code="external_network_change")
                        # No broad IPv4 route is allowed even on the owned interface.
                        for row in safety.route_rows(current["routes"]):
                            if interface in row and row[0] in ("default", "0/1", "128/1", "128.0/1") and ":" not in row[1]:
                                raise safety.CheckStopped("unexpected broad test route", code="unexpected_route")
                    except Exception:
                        abort.set()
                        return
            monitor = threading.Thread(target=watch, daemon=True)
            monitor.start()
        for name in (["selected-probe", "excluded-probe"] if live else ["selected-probe"]):
            for kind in ("https", "udp", "dns"):
                if abort.is_set() or time.monotonic() >= started + WORKER_LIMIT - 45:
                    raise safety.CheckStopped("test interrupted, expired or external state changed", code="external_or_cancelled")
                before = fixtures.counters()
                transferred = probe(work, name, kind, fixtures, live)
                after = fixtures.counters()
                selected = name == "selected-probe"
                passed = transferred and after[kind] > before[kind] if selected else not transferred and after == before
                result["checks"].append({"process": "selected" if selected else "excluded", "protocol": kind, "status": "PASS" if passed else "FAIL"})
                if not passed:
                    raise safety.CheckStopped("process policy or real payload check failed", code="traffic")
        if abort.is_set():
            raise safety.CheckStopped("external state changed before verification completed", code="external_or_cancelled")
        result.update(status="PASS", reason_code="system_adapter_verified" if live else "loopback_only")
    except safety.CheckStopped as error:
        result.update(reason_code=error.code, reason=str(error))
        details = production_blocker_details(error)
        if details:
            result["details"] = details
        if not result["live_test_started"] and error.code in ("production_status_unknown", "production_session_active", "foreign_tunnel_routes", "connected_vpn_service", "interface_conflict", "route_conflict"):
            result["status"] = "SKIP"
    except BaseException as error:
        result.update(reason_code="test_error", error_type=type(error).__name__)
    finally:
        done.set()
        if monitor is not None:
            monitor.join(timeout=15)
            if monitor.is_alive():
                result["cleanup"] = "FAIL"
        try:
            if live and guardian is not None:
                try:
                    if not remove_owned_route(work):
                        result["cleanup"] = "FAIL"
                finally:
                    # Allow the guardian's bounded route/engine cleanup before considering KILL.
                    stop_child(guardian, grace=15)
                cleanup = json.loads((work / "engine-cleanup.json").read_text())
                result["engine_diagnostics"] = guardian_diagnostics(cleanup.get("diagnostics"))
                if not cleanup.get("engine_stopped") or not remove_owned_route(work) or interface in safety.command(["/sbin/ifconfig", "-l"], timeout=3).split():
                    result["cleanup"] = "FAIL"
        except Exception as error:
            result.update(cleanup="FAIL", cleanup_error_type=type(error).__name__)
        try:
            if fixtures is not None and not fixtures.close():
                result["cleanup"] = "FAIL"
            if live and result["live_test_started"]:
                current = safety.network_snapshot()
                unchanged = current["dns"] == baseline["dns"] and safety.stable_routes(current["routes"]) == safety.stable_routes(baseline["routes"])
                result["network_baseline_matches"] = unchanged
                write_json(work / "network-after.json", current)
                if result["status"] == "PASS" and not unchanged:
                    result.update(status="FAIL", reason_code="network_baseline_changed")
        except Exception as error:
            result.update(cleanup="FAIL", cleanup_error_type=type(error).__name__)
        if result["cleanup"] != "PASS":
            result["status"] = "FAIL"
        result["duration_seconds"] = round(time.monotonic() - started, 2)
        if result["duration_seconds"] > WORKER_LIMIT and result["status"] == "PASS":
            result.update(status="FAIL", reason_code="worker_budget_exceeded")
        if validated and result["cleanup"] == "PASS":
            try:
                for name in ("nonce", "cert.pem", "key.pem", "frontend.json", "engine", "selected-probe", "excluded-probe"):
                    (work / name).unlink(missing_ok=True)
                manifest = json.loads((work / "manifest.json").read_text())
                producers = Path(manifest["producer_directory"])
                for name in ("selected-probe", "excluded-probe"):
                    (producers / name).unlink(missing_ok=True)
                producers.rmdir()
                if (work / "go-cache").exists():
                    shutil.rmtree(work / "go-cache")
            except Exception as error:
                result.update(cleanup="FAIL", status="FAIL", cleanup_error_type=type(error).__name__)
        if validated:
            result["report_path"] = str(work / "report.json")
            write_json(work / "report.json", result)
        print("RESULT " + json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["status"] == "PASS" else 3 if result["status"] == "SKIP" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", action="store_true", help="USER-RUN ONLY: create the isolated TUN and reserved host route")
    parser.add_argument("--loopback-check", action="store_true", help="safe build/config/loopback validation; no TUN or route changes")
    parser.add_argument("--worker", help=argparse.SUPPRESS)
    parser.add_argument("--engine-guard", help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    if args.engine_guard:
        if args.run or args.loopback_check or args.worker or os.geteuid() != 0:
            parser.error("invalid private engine guardian")
        return engine_guard(Path(args.engine_guard))
    if args.run == args.loopback_check:
        parser.error("choose --run or --loopback-check")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("macOS arm64 is required")
    if args.worker:
        if not args.run or os.geteuid() != 0:
            parser.error("invalid private root worker")
        return execute(Path(args.worker), True)
    if os.geteuid() == 0:
        parser.error("run as your normal user; --run requests sudo after the private build")
    if args.run:
        try:
            safety.guard_network(safety.network_snapshot())
        except safety.CheckStopped as error:
            print("RESULT " + json.dumps({"version": 1, "scenario": "backend-system-adapter", "status": "SKIP", "cleanup": "PASS",
                  "live_test_started": False, "phase": "preflight", "reason_code": error.code, "reason": str(error)}, sort_keys=True))
            return 3
    try:
        work = prepare()
    except BaseException as error:
        report = {"version": 1, "scenario": "backend-system-adapter", "phase": "prepare", "status": "FAIL", "cleanup": "PASS", "live_test_started": False}
        if isinstance(error, safety.CheckStopped):
            report.update(reason=str(error), reason_code=error.code)
            if error.code == "engine_missing":
                report["status"] = "SKIP"
        else:
            report["error_type"] = type(error).__name__
        print("RESULT " + json.dumps(report, sort_keys=True))
        return 3 if report["status"] == "SKIP" else 1
    if args.loopback_check:
        return execute(work, False)
    print("User-run TUN/process PoC: one reserved host route, private utun/engines/fixtures. DNS/default routes unchanged. Worker limit 120 seconds.", flush=True)
    os.execvp("sudo", ["sudo", sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--run", "--worker", str(work)])


if __name__ == "__main__":
    sys.exit(main())
