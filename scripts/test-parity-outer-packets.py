#!/usr/bin/env python3
"""Verify private relay packets on lo0. --run is user-run only; your VPN may stay on."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def close_input(child):
    if child is not None and child.stdin is not None and not child.stdin.closed:
        try:
            child.stdin.close()
        except (OSError, ValueError):
            return False
    return True


def validate_report(data, code, capture, family="ipv4", fake_hop_limit=False):
    """Accept only the fixed helper's bounded, nonsecret evidence schema."""
    if len(data) > 32768:
        raise ValueError("bounded report missing")
    reports = [json.loads(line[7:]) for line in data.decode("utf-8").splitlines() if line.startswith("RESULT ")]
    if len(reports) != 1 or not isinstance(reports[0], dict):
        raise ValueError("bounded report missing")
    result = reports[0]
    required = {"version", "scenario", "phase", "status", "cleanup", "duration_seconds", "system_network_changed",
                "capture_started", "https_flows", "udp_associations", "captured_packets", "capture_drops",
                "tcp_packet_split_verified", "udp_fake_order_tuple_verified"}
    if set(result) - required - {"reason_code", "tcp_packet_payload_lengths", "capture_error", "bpf_open_errno", "ip_family", "udp_fake_hop_limit_requested", "udp_fake_hop_limit_verified", "udp_packet_hop_limits"} or not required <= set(result):
        raise ValueError("unexpected report shape")
    if type(result["version"]) is not int or result["version"] != 1 or result["scenario"] != "outer-packet-loopback" or result["phase"] != ("capture" if capture else "loopback"):
        raise ValueError("unexpected report identity")
    if family not in ("ipv4", "ipv6") or result.get("ip_family", "ipv4") != family:
        raise ValueError("unexpected IP family")
    if type(result.get("udp_fake_hop_limit_requested", False)) is not bool or type(result.get("udp_fake_hop_limit_verified", False)) is not bool:
        raise ValueError("invalid hop limit evidence type")
    if result.get("udp_fake_hop_limit_requested", False) != fake_hop_limit:
        raise ValueError("unexpected hop limit scenario")
    if result.get("udp_fake_hop_limit_verified", False) and (not capture or not fake_hop_limit):
        raise ValueError("unexpected hop limit proof")
    if result["status"] not in ("PASS", "FAIL", "SKIP") or result["cleanup"] not in ("PASS", "FAIL"):
        raise ValueError("unexpected report status")
    for key in ("capture_started", "tcp_packet_split_verified", "udp_fake_order_tuple_verified", "system_network_changed"):
        if type(result[key]) is not bool:
            raise ValueError("invalid evidence type")
    for key, maximum in (("https_flows", 2), ("udp_associations", 2), ("captured_packets", 4096), ("capture_drops", 1_000_000)):
        if type(result[key]) is not int or not 0 <= result[key] <= maximum:
            raise ValueError("invalid evidence count")
    duration = result["duration_seconds"]
    if type(duration) not in (int, float) or not math.isfinite(duration) or not 0 <= duration <= 60:
        raise ValueError("invalid duration")
    if "reason_code" in result and result["reason_code"] not in ("capture_requires_macos_arm64_root", "passive_bpf_unavailable",
            "private_loopback_check_failed", "tcp_packets_do_not_prove_split", "udp_packets_do_not_prove_order_tuple", "udp_packets_do_not_prove_hop_limit", "passive_capture_incomplete"):
        raise ValueError("unrecognized reason")
    if "capture_error" in result and result["capture_error"] not in ("capture_read_failed", "capture_limit", "capture_record_rejected",
            "capture_packet_rejected", "capture_stats_unknown", "capture_drops_detected", "capture_close_failed", "capture_unsupported"):
        raise ValueError("unrecognized capture error")
    if "bpf_open_errno" in result and (type(result["bpf_open_errno"]) is not int or not 1 <= result["bpf_open_errno"] <= 4096):
        raise ValueError("invalid capture errno")
    lengths = result.get("tcp_packet_payload_lengths", [])
    if not isinstance(lengths, list) or len(lengths) > 2 or any(not isinstance(row, list) or len(row) > 64 or
            any(type(value) is not int or not 1 <= value <= 65535 for value in row) for row in lengths):
        raise ValueError("unbounded packet lengths")
    hop_limits = result.get("udp_packet_hop_limits", [])
    if not isinstance(hop_limits, list) or len(hop_limits) > 2 or any(not isinstance(row, list) or len(row) > 2 or
            any(type(value) is not int or not 0 <= value <= 255 for value in row) for row in hop_limits):
        raise ValueError("unbounded hop limit evidence")
    if hop_limits and (not capture or not fake_hop_limit):
        raise ValueError("unexpected hop limit headers")
    if result["status"] == "PASS":
        if code != 0 or result["cleanup"] != "PASS" or result["https_flows"] != 2 or result["udp_associations"] != 2 or result["system_network_changed"]:
            raise ValueError("traffic/cleanup evidence missing")
        if capture and (not result["capture_started"] or not result["tcp_packet_split_verified"] or not result["udp_fake_order_tuple_verified"] or result["capture_drops"] != 0):
            raise ValueError("packet evidence missing")
        if capture and fake_hop_limit and (not result.get("udp_fake_hop_limit_verified", False) or len(hop_limits) != 2 or
                any(len(row) != 2 or row[0] != 1 or row[1] <= 1 for row in hop_limits)):
            raise ValueError("hop limit packet evidence missing")
        if "capture_error" in result or "bpf_open_errno" in result or "reason_code" in result:
            raise ValueError("failure metadata cannot certify success")
        if not capture and (result["capture_started"] or result["tcp_packet_split_verified"] or result["udp_fake_order_tuple_verified"] or result["captured_packets"] or result["capture_drops"]):
            raise ValueError("unexpected capture in safe check")
    return result


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog="macOS arm64, Go and Xcode command-line tools required. --run asks for sudo only to open a passive BPF descriptor attached to lo0. No promiscuous mode, packet injection, TUN, route/DNS/proxy/interface changes, installed daemon access or VPN disconnection. Capture is filtered to two newly reserved private TCP/UDP loopback ports, kept only in bounded memory, and closes with the worker. Build limit 180 seconds; worker limit 30 seconds, excluding sudo authorization. Temporary binary/cache/log/report only; certificates/keys/authentication remain in RAM. --fake-hop-limit temporarily sets only each private UDP socket to 1 for its fake and restores its original policy before real traffic. This tests selected IPv4/IPv6 relay packet boundaries, header limits and invalid-fake ordering, not ISP effect or a production fake technique.")
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--run", action="store_true", help="user-run passive BPF packet evidence; current VPN may remain connected")
    choice.add_argument("--loopback-check", action="store_true", help="safe real HTTPS/UDP fixture check without capture, sudo or system changes")
    parser.add_argument("--family", choices=("ipv4", "ipv6"), default="ipv4", help="fixed numeric loopback family; default ipv4")
    parser.add_argument("--fake-hop-limit", action="store_true", help="verify fake TTL/hop limit 1 and restored real traffic on private sockets")
    args = parser.parse_args(arguments)
    started = time.monotonic()
    result = {"version": 1, "scenario": "outer-packet-loopback", "status": "FAIL", "cleanup": "PASS", "system_network_changed": False, "capture_started": False, "ip_family": args.family, "udp_fake_hop_limit_requested": args.fake_hop_limit}
    run_directory = Path(tempfile.mkdtemp(prefix="zarp-parity-packets-"))
    os.chmod(run_directory, 0o700)
    work = run_directory / "work"
    work.mkdir(mode=0o700)
    result["run_id"] = run_directory.name
    child = None
    finished = True
    cleaning = False
    previous_handlers = {}

    def request_stop(_signal, _frame):
        if not cleaning:
            raise KeyboardInterrupt

    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[number] = signal.signal(number, request_stop)
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            result.update(status="SKIP", reason_code="macos_arm64_required")
            return result
        environment = {"PATH": "/opt/homebrew/bin:/usr/local/go/bin:/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(work),
                       "GOTOOLCHAIN": "local", "GOENV": "off", "GOFLAGS": "", "GOCACHE": str(work / "cache"),
                       "GOMODCACHE": str(Path.home() / "go/pkg/mod"), "GOPROXY": "off", "GOSUMDB": "off", "CGO_ENABLED": "1"}
        binary = work / "packet-probe"
        build_log = work / "build.log"
        with build_log.open("xb") as log:
            os.chmod(build_log, 0o600)
            # run() reaps its direct child on timeout, but cannot establish that
            # every compiler descendant stopped. Retain work on interruption.
            finished = False
            build = subprocess.run(["go", "build", "-trimpath", "-o", str(binary), "./cmd/parity-packet-probe"], cwd=ROOT / "zarpd",
                                   env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=180)
            finished = True
        if build.returncode:
            result["reason_code"] = "private_build_failed"
            return result
        os.chmod(binary, 0o500)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        command = [str(binary), "--loopback-check"]
        if args.run:
            # Authorization occurs before the bounded worker and does not change
            # any network setting. The privileged worker contains no subprocesses.
            finished = False
            authorization = subprocess.run(["sudo", "-v"])
            finished = True
            if authorization.returncode:
                result.update(status="SKIP", reason_code="sudo_unavailable")
                return result
            command = ["sudo", "-n", "--", str(binary), "--capture"]
        if args.family == "ipv6":
            command.append("--ipv6")
        if args.fake_hop_limit:
            command.append("--fake-hop-limit")
        run_log = work / "worker.log"
        with run_log.open("xb") as log:
            os.chmod(run_log, 0o600)
            child = subprocess.Popen(command, cwd=work, env=environment, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)
            finished = False
            result["cleanup"] = "FAIL"  # Only a verified helper report can establish cleanup.
            try:
                code = child.wait(timeout=40)
                finished = True
            except (KeyboardInterrupt, subprocess.TimeoutExpired):
                cleaning = True  # Repeated signals cannot interrupt owned cleanup.
                close_input(child)  # Exclusive parent EOF cancels only this worker.
                try:
                    child.wait(timeout=5)
                    finished = True
                except subprocess.TimeoutExpired:
                    pass
                result.update(reason_code="private_worker_interrupted", cleanup="FAIL")
                if finished:
                    try:
                        with run_log.open("rb") as output:
                            evidence = validate_report(output.read(32769), child.returncode, args.run, args.family, args.fake_hop_limit)
                        result["cleanup"] = evidence["cleanup"]
                    except (ValueError, OSError):
                        finished = False  # An exited sudo wrapper alone does not certify the helper.
                return result
        with run_log.open("rb") as output:
            result = validate_report(output.read(32769), code, args.run, args.family, args.fake_hop_limit)
        result["helper_sha256"] = digest
        return result
    except subprocess.TimeoutExpired:
        result.update(reason_code="private_build_timeout", cleanup="FAIL")
        return result
    except KeyboardInterrupt:
        result.update(reason_code="private_check_interrupted", cleanup="PASS" if finished else "FAIL")
        return result
    except Exception as error:
        if child is not None:
            finished = False
        result.update(status="FAIL", reason_code="private_check_failed", error_type=type(error).__name__)
        return result
    finally:
        cleaning = True
        if not close_input(child):
            result.update(status="FAIL", cleanup="FAIL", reason_code="private_input_close_failed")
        # Do not remove resources under an unverified still-running worker. The
        # capture descriptor belongs to that process and closes even on SIGKILL.
        if finished:
            try:
                shutil.rmtree(work)
            except OSError:
                result.update(status="FAIL", cleanup="FAIL", reason_code="private_file_cleanup_failed")
        else:
            result.update(status="FAIL", cleanup="FAIL", retained_private_directory=str(work))
        result["run_id"] = run_directory.name
        result["duration_seconds"] = round(time.monotonic() - started, 2)
        report_path = run_directory / "report.json"
        result["report_path"] = str(report_path)
        try:
            descriptor = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(result, output, sort_keys=True, allow_nan=False)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
        except (OSError, ValueError):
            result.update(status="FAIL", cleanup="FAIL", reason_code="private_report_failed")
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    report = main()
    print("RESULT " + json.dumps(report, sort_keys=True))
    sys.exit(0 if report["status"] in ("PASS", "SKIP") else 1)
