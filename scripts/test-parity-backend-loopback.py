#!/usr/bin/env python3
"""Run only the reviewed, pinned loopback backend PoC. Never starts a TUN."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.13.14"
BINARY_SHA = "813d8effd02a19572a8d75aef29fc073101404ca535b2496be86f21827c7684d"
ARCHIVE_SHA = "73e8967b0fc08e17bce4263ca56ebc394822401a16497a1c4e02316c888202ab"
DESTINATION = ROOT / "build" / "parity-backends" / ("sing-box-" + VERSION)
BINARY = DESTINATION / "sing-box"
LIMIT = 64 * 1024 * 1024
URL = "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-darwin-arm64.tar.gz"
SING_BOX_PIN = (VERSION, BINARY_SHA, ARCHIVE_SHA, DESTINATION, BINARY, URL)


def fetch():
    """Download via the existing connection, validate before extracting one regular member."""
    DESTINATION.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile() as archive:
        digest = hashlib.sha256()
        total = 0
        deadline = time.monotonic() + 120
        with urllib.request.urlopen(URL, timeout=20) as response:
            if not response.geturl().startswith("https://"):
                raise RuntimeError("insecure download redirect")
            while True:
                if time.monotonic() > deadline:
                    raise RuntimeError("download deadline exceeded")
                chunk = response.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > LIMIT:
                    raise RuntimeError("download size limit exceeded")
                digest.update(chunk)
                archive.write(chunk)
        if digest.hexdigest() != ARCHIVE_SHA:
            raise RuntimeError("archive checksum mismatch")
        archive.seek(0)
        if URL.endswith(".zip"):
            with zipfile.ZipFile(archive) as package:
                member = package.getinfo("xray")
                if member.is_dir() or member.file_size > LIMIT or (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise RuntimeError("invalid pinned binary member")
                data = package.read(member)
        else:
            with tarfile.open(fileobj=archive, mode="r:gz") as package:
                member = package.getmember("sing-box-1.13.14-darwin-arm64/sing-box")
                if not member.isfile() or member.size > LIMIT:
                    raise RuntimeError("invalid pinned binary member")
                with package.extractfile(member) as stream:
                    data = stream.read(LIMIT + 1)
        if hashlib.sha256(data).hexdigest() != BINARY_SHA:
            raise RuntimeError("extracted binary checksum mismatch")
        fd, temporary = tempfile.mkstemp(prefix=".verified-", dir=DESTINATION)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o700)
            os.replace(temporary, BINARY)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def stop_group(child):
    # The single-threaded runner is the only waiter. Once wait/poll sets returncode,
    # the leader can be reused: never signal its saved numeric group afterward.
    if child.returncode is not None:
        return
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise RuntimeError("test child ownership cannot be established")
    # No wait/poll occurs between these signals. The unreaped child reserves the
    # freshly created private group ID, even if TERM has already ended its leader.
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    time.sleep(0.2)
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait(timeout=3)


def verified_case_count(log_path, engine_test):
    """A zero exit code or a skipped/no-test selection cannot certify backend traffic."""
    root = "Test" + engine_test
    completed, skipped, cases = False, False, 0
    with open(log_path, encoding="utf-8", errors="replace") as log:
        for line in log:
            stripped = line.lstrip()
            if stripped.startswith("--- PASS: " + root + " ("):
                completed = True
            if stripped.startswith("--- SKIP: " + root):
                skipped = True
            if stripped.startswith("--- PASS: " + root + "/"):
                cases += 1
    if not completed or skipped or cases == 0:
        raise RuntimeError("external backend traffic cases were not fully executed")
    return cases


def finish_private_run(result, directory):
    # A failing/incomplete Go run cannot certify every independent engine
    # session. Preserve its private files instead of deleting under an orphan.
    if result.get("status") != "PASS" or result.get("cleanup") != "PASS":
        result["status"] = "FAIL"
        result["cleanup"] = "FAIL"
        result["retained_private_directory"] = str(directory)
        return
    try:
        shutil.rmtree(directory)
    except OSError:
        result.update(status="FAIL", cleanup="FAIL", retained_private_directory=str(directory))


def main():
    global VERSION, BINARY_SHA, ARCHIVE_SHA, DESTINATION, BINARY, URL
    parser = argparse.ArgumentParser(description=__doc__, epilog="No sudo, production settings, routes, DNS or VPN changes. Temporary loopback sockets, private test configs/keys and owned engine processes only. Engines have a 20-second case deadline; suite limit is 180 seconds. --fetch uses ordinary HTTPS through your existing connection. This does not establish real TUN support or ISP effectiveness.")
    parser.add_argument("--engine", choices=["sing-box", "xray"], default="sing-box", help="select the pinned loopback PoC engine")
    parser.add_argument("--fetch", action="store_true", help="download the checksum-pinned Darwin arm64 PoC engine if missing")
    parser.add_argument("--fetch-only", action="store_true", help="verify or download the pinned engine, then exit without starting any processes")
    parser.add_argument("--suite", choices=["all", "options", "guardian", "udp-hop-limit", "owned-https"], default="all", help="run all transports, advanced sing-box options, guardian traffic/cleanup, UDP temporary-hop-limit traffic or owned HTTPS probes")
    args = parser.parse_args()
    if args.engine == "xray" and args.suite in ("options", "guardian", "udp-hop-limit", "owned-https"):
        parser.error("the options/guardian/udp-hop-limit/owned-https suites currently use sing-box only")
    VERSION, BINARY_SHA, ARCHIVE_SHA, DESTINATION, BINARY, URL = SING_BOX_PIN
    if args.engine == "xray":
        VERSION = "26.9.30"
        BINARY_SHA = "118d6c6c8c2fb913c4b2aeb056a58936016b36813c38d9b75653311787c0f93c"
        ARCHIVE_SHA = "4b363bd924df5bf09f87bd445755ff8e5742b9a8a0480cda261061416c3c7dce"
        URL = "https://github.com/XTLS/Xray-core/releases/download/v26.9.30/Xray-macos-arm64-v8a.zip"
        DESTINATION = ROOT / "build" / "parity-backends" / ("xray-" + VERSION)
        BINARY = DESTINATION / "xray"
    started = time.monotonic()
    result = {"version": 1, "scenario": "backend-loopback", "status": "FAIL", "cleanup": "PASS", "engine": args.engine, "engine_version": VERSION, "suite": args.suite, "binary_sha256": BINARY_SHA, "system_network_changed": False}
    child = None
    log_path = None
    private_directory = None
    try:
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            result.update(status="SKIP", reason="PoC binary pin requires macOS arm64")
            return result
        if (args.fetch or args.fetch_only) and not BINARY.exists():
            fetch()
        if not BINARY.exists():
            result.update(status="SKIP", reason="pinned engine missing; use --fetch")
            return result
        if BINARY.stat().st_size > LIMIT or hashlib.sha256(BINARY.read_bytes()).hexdigest() != BINARY_SHA:
            raise RuntimeError("binary checksum mismatch")
        if args.fetch_only:
            result.update(status="PASS", fetched_binary=str(BINARY))
            return result
        environment = dict(os.environ)
        environment.pop("ZARP_SOCKET", None)
        environment["GOTOOLCHAIN"] = "local"
        environment["GOENV"] = "off"
        environment["GOFLAGS"] = ""
        private_directory = Path(tempfile.mkdtemp(prefix="zarp-parity-private-"))
        os.chmod(private_directory, 0o700)
        environment["TMPDIR"] = str(private_directory)
        environment.pop("ZARP_PARITY_SING_BOX", None)
        environment.pop("ZARP_PARITY_XRAY", None)
        engine_variable = "ZARP_PARITY_XRAY" if args.engine == "xray" else "ZARP_PARITY_SING_BOX"
        engine_test = "PinnedXrayOuterTransports" if args.engine == "xray" else "PinnedBackendOuterTransports"
        test_pattern = "^Test(" + engine_test + "|HelloFragmentationAndWireMapping|RelayFixedTargetAndCancellation|UDPOrderingTupleAndCleanup|PrivateEngineDiagnosticsBoundedAndRedacted)$"
        if args.suite == "options":
            test_pattern = "^TestPinnedBackendOuterTransports$/^(vision|reality|reality-vision|salamander|vless-fingerprint|trojan-fingerprint)$"
        elif args.suite == "guardian":
            test_pattern = "^TestPinnedBackendOuterTransports$/^guardian-"
        elif args.suite == "udp-hop-limit":
            test_pattern = "^TestPinnedBackendOuterTransports$/^udp-hop-limit$"
        elif args.suite == "owned-https":
            test_pattern = "^TestPinnedBackendOuterTransports$/^owned-https-probe-"
        environment[engine_variable] = str(BINARY)
        fd, log_path = tempfile.mkstemp(prefix="zarp-parity-backend-", suffix=".log")
        with os.fdopen(fd, "wb") as log:
            child = subprocess.Popen(["go", "test", "-race", "-count=1", "-v", "-run=" + test_pattern, "-timeout=170s", "./relay"], cwd=ROOT / "zarpd", env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            code = child.wait(timeout=180)
        if code == 0:
            result["external_case_count"] = verified_case_count(log_path, engine_test)
            result.update(status="PASS", reason="pinned backend loopback tests passed")
        else:
            result.update(reason="loopback test failed", exit_code=code)
        result["log_path"] = log_path
        return result
    except (KeyboardInterrupt, subprocess.TimeoutExpired):
        result["reason"] = "loopback test interrupted or timed out"
        # The watchdog cannot verify every engine's private session after losing
        # its Go owner. Such a run never certifies descendant or file cleanup.
        result["cleanup"] = "FAIL"
        return result
    except Exception as error:
        # Avoid raw tool/config output. These controlled errors contain no credentials.
        result["reason"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        return result
    finally:
        if child is not None:
            try:
                stop_group(child)
            except Exception:
                result["cleanup"] = "FAIL"
                result["status"] = "FAIL"
        if private_directory is not None:
            finish_private_run(result, private_directory)
        result["duration_seconds"] = round(time.monotonic() - started, 2)


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    report = main()
    print("RESULT " + json.dumps(report, sort_keys=True))
    sys.exit(0 if report["status"] in ("PASS", "SKIP") else 1)
