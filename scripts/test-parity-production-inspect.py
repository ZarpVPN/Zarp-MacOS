#!/usr/bin/env python3
"""Read-only installed Zarp metadata. No IPC queries, network observation or changes.

Inspects only the fixed launchd service, its reported process/code hash, fixed
account/socket metadata and the existing local build. Never starts/stops/restarts
or signs anything, attaches a debugger, reads account/log contents or connects to
an IPC socket. Observed PIDs are metadata only, never signal/adoption authority.
--inspect may be run with sudo if metadata is inaccessible. Command limit 3s;
overall budget 25s. No build/download or temporary files; sanitized RESULT only.
A diagnostic PASS means metadata collected, never idle or safe for a TUN test.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import select
import signal
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
SERVICE = "system/io.github.zarp.mac.zarpd"
ACCOUNT = Path("/Library/Application Support/Zarp/zarp-warp-config.json")
SOCKET = Path("/var/run/zarpd.sock")
BUILD = ROOT / "build/DerivedData/Build/Products/Release/Zarp.app/Contents/MacOS/zarpd"
LIMIT = 65536
CLEANING = False


class ObservationError(Exception):
    def __init__(self, code, cleanup=True, error_number=None):
        self.code, self.cleanup, self.error_number = code, cleanup, error_number


def read_tool(arguments, deadline):
    """Fixed read-only tools. Kill/reap only this exact unreaped tool on timeout."""
    global CLEANING
    allowed = arguments == ["/bin/launchctl", "print", SERVICE] or (
        len(arguments) == 5 and arguments[:2] == ["/bin/ps", "-p"] and
        arguments[2].isdigit() and arguments[3:] == ["-o", "pid=,uid=,ppid=,pcpu=,stat=,ucomm="]
    ) or (len(arguments) == 5 and arguments[:4] == ["/usr/bin/codesign", "-d", "--verbose=4", "--"] and Path(arguments[4]).is_absolute())
    if not allowed:
        raise ObservationError("invalid_readonly_command")
    expires = min(deadline, time.monotonic() + 3)
    if expires <= time.monotonic():
        raise ObservationError("observation_timeout")
    child = None
    try:
        child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        data = bytearray()
        while True:
            remaining = expires - time.monotonic()
            if remaining <= 0:
                raise ObservationError("observation_timeout")
            if not select.select([child.stdout], [], [], remaining)[0]:
                raise ObservationError("observation_timeout")
            chunk = os.read(child.stdout.fileno(), min(8192, LIMIT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > LIMIT:
                raise ObservationError("observation_limit")
        code = child.wait(timeout=max(0.001, expires - time.monotonic()))
        if code:
            raise ObservationError("observation_unavailable")
        return data.decode("utf-8", errors="strict")
    except (OSError, UnicodeError):
        raise ObservationError("observation_unavailable") from None
    except subprocess.TimeoutExpired:
        raise ObservationError("observation_timeout") from None
    finally:
        previous_cleaning = CLEANING
        CLEANING = True
        if child is not None:
            try:
                if child.returncode is None:
                    child.kill()  # Own unreaped tool only. Never the observed daemon PID.
                    child.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                raise ObservationError("observation_cleanup_unknown", cleanup=False) from None
            finally:
                try:
                    if child.stdout is not None:
                        child.stdout.close()
                finally:
                    CLEANING = previous_cleaning
        else:
            CLEANING = previous_cleaning


def service_fields(text):
    """Advisory only: launchctl explicitly has no stable machine output API."""
    if len(text.encode()) > LIMIT or not text.splitlines() or not text.splitlines()[0].startswith(SERVICE + " = {"):
        raise ObservationError("service_format_unknown")
    depth, result = 0, {}
    allowed = {"pid", "state", "program", "path", "runs", "active count", "last exit code"}
    for line in text.splitlines():
        stripped = line.strip()
        if depth == 1 and " = " in stripped:
            key, value = stripped.split(" = ", 1)
            if key in allowed:
                if key in result or any(c in value for c in ("\0", "\r", "\n", "{", "}")):
                    raise ObservationError("service_format_unknown")
                result[key] = value
        # Ignore nested arguments/environment data, never echo it into a report.
        if stripped.endswith("{"):
            depth += 1
        if stripped == "}":
            depth -= 1
        if depth < 0:
            raise ObservationError("service_format_unknown")
    if depth != 0:
        raise ObservationError("service_format_unknown")
    return result


def service_program(fields):
    program = Path(fields.get("program", ""))
    if program.is_absolute() and program.name == "zarpd":
        return program
    # SMAppService BundleProgram jobs can omit a standalone program field.
    # Recognize only this repository's fixed in-bundle launchd plist layout.
    path = Path(fields.get("path", ""))
    suffix = ("Contents", "Library", "LaunchDaemons", "io.github.zarp.mac.zarpd.plist")
    if path.is_absolute() and path.parts[-4:] == suffix and path.parents[3].suffix == ".app":
        return path.parents[3] / "Contents/MacOS/zarpd"
    raise ObservationError("service_program_unknown")


def metadata(path):
    try:
        info = path.lstat()
        kind = "other"
        for check, name in ((stat.S_ISREG, "regular"), (stat.S_ISDIR, "directory"), (stat.S_ISFIFO, "fifo"),
                            (stat.S_ISSOCK, "socket"), (stat.S_ISLNK, "symlink")):
            if check(info.st_mode):
                kind = name
                break
        return {"status": "observed", "kind": kind, "mode": oct(stat.S_IMODE(info.st_mode)),
                "owner_is_root": info.st_uid == 0,
                "bounded_regular": kind == "regular" and 0 < info.st_size <= LIMIT and not info.st_mode & 0o022}
    except OSError as error:
        return {"status": "missing" if error.errno == errno.ENOENT else "permission_denied" if error.errno in (errno.EACCES, errno.EPERM) else "unknown"}


def binary_digest(path, deadline):
    """Hash a bounded Mach-O file only. Never execute the observed program."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 64 * 1024 * 1024 or before.st_mode & 0o022:
            raise ObservationError("binary_metadata_unsafe")
        first = os.read(fd, 4)
        if first not in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            raise ObservationError("binary_format_unknown")
        digest, total = hashlib.sha256(first), len(first)
        while True:
            if time.monotonic() >= deadline:
                raise ObservationError("observation_timeout")
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > 64 * 1024 * 1024:
                raise ObservationError("binary_size_limit")
            digest.update(chunk)
        after = os.fstat(fd)
        named = os.lstat(path)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if total != before.st_size or identity(before) != identity(after) or identity(after) != identity(named):
            raise ObservationError("binary_changed_during_observation")
        return digest.hexdigest()
    finally:
        os.close(fd)


def disk_cdhash(text):
    values = [line[7:] for line in text.splitlines() if line.startswith("CDHash=")]
    if len(values) != 1 or re.fullmatch(r"[0-9a-f]{40}", values[0]) is None:
        raise ObservationError("signature_metadata_unknown")
    return values[0]


def kernel_cdhash(pid):
    # XNU codesign.h: CS_OPS_CDHASH=5 is read-only; CS_CDHASH_LEN is 20.
    # Do not expose an operation parameter or any mutating csops operation.
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    call = library.csops
    call.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_void_p, ctypes.c_size_t]
    call.restype = ctypes.c_int
    data = (ctypes.c_ubyte * 20)()
    if call(pid, 5, data, 20) != 0:
        number = ctypes.get_errno()
        raise ObservationError("kernel_metadata_permission" if number in (errno.EPERM, errno.EACCES) else "kernel_metadata_unknown",
                               error_number=number)
    return bytes(data).hex()


def process_path(pid):
    # libproc.h/proc_info.h: read-only executable path, at most 4*MAXPATHLEN.
    # A returned path is advisory and never authorizes process control.
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    call = library.proc_pidpath
    call.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    call.restype = ctypes.c_int
    data = ctypes.create_string_buffer(4096)
    length = call(pid, data, len(data))
    if not 0 < length < len(data):
        raise ObservationError("process_path_unavailable", error_number=ctypes.get_errno())
    raw = data.value
    if len(raw) != length or any(number < 32 or number == 127 for number in raw):
        raise ObservationError("process_path_unknown")
    path = Path(os.fsdecode(raw))
    if not path.is_absolute() or path.name != "zarpd":
        raise ObservationError("process_path_unknown")
    return path


def process_fields(text, pid):
    parts = text.split()
    if len(parts) != 6 or parts[0] != str(pid) or not parts[1].isdigit() or not parts[2].isdigit():
        raise ObservationError("process_format_unknown")
    try:
        cpu = float(parts[3])
    except ValueError:
        raise ObservationError("process_format_unknown") from None
    if not math.isfinite(cpu) or not 0 <= cpu <= 100000 or re.fullmatch(r"[A-Za-z+<N>]+", parts[4]) is None:
        raise ObservationError("process_format_unknown")
    return {"pid": pid, "owner_is_root": parts[1] == "0", "parent_is_launchd": parts[2] == "1",
            "cpu_percent": cpu, "process_state": parts[4], "name_is_zarpd": parts[5] == "zarpd"}


def sanitized_adapter_report(value, run_id):
    if not isinstance(value, dict) or type(value.get("version")) is not int or value.get("version") != 1 or value.get("scenario") != "backend-system-adapter" or value.get("run_id") != run_id:
        raise ObservationError("adapter_report_invalid")
    if value.get("status") not in ("PASS", "SKIP", "FAIL") or value.get("cleanup") not in ("PASS", "FAIL"):
        raise ObservationError("adapter_report_invalid")
    result = {"status": value["status"], "cleanup": value["cleanup"]}
    for key in ("live_test_started", "default_routes_configured", "system_dns_configured"):
        if type(value.get(key)) is not bool:
            raise ObservationError("adapter_report_invalid")
        result[key] = value[key]
    checks = value.get("checks")
    if not isinstance(checks, list) or len(checks) > 6:
        raise ObservationError("adapter_report_invalid")
    result["check_count"] = len(checks)
    known = {"production_status_unknown", "production_session_active", "foreign_tunnel_routes", "connected_vpn_service",
             "system_adapter_verified", "loopback_only"}
    code = value.get("reason_code")
    result["reason_code"] = code if isinstance(code, str) and code in known else "other"
    return result


def adapter_report(run_id):
    # The sole optional input is a strict run-directory basename, never a path.
    # Read only its bounded report, not route baselines, configs, keys or logs.
    if re.fullmatch(r"zarp-parity-adapter-[a-z0-9_]{8}", run_id) is None:
        raise ObservationError("adapter_run_invalid")
    directory = Path("/private/tmp") / run_id
    before = directory.lstat()
    if not stat.S_ISDIR(before.st_mode) or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o700:
        raise ObservationError("adapter_directory_invalid")
    path = directory / "report.json"
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= LIMIT:
            raise ObservationError("adapter_report_invalid")
        data = bytearray()
        while len(data) <= LIMIT:
            chunk = os.read(fd, min(8192, LIMIT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = directory.lstat()
        final = os.fstat(fd)
        named = path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (len(data) > LIMIT or len(data) != info.st_size or identity(info) != identity(final) or
                identity(final) != identity(named) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)):
            raise ObservationError("adapter_report_invalid")
        return sanitized_adapter_report(json.loads(data), run_id)
    finally:
        os.close(fd)


def inspect(adapter_run=None):
    started = time.monotonic()
    deadline = started + 25
    result = {"version": 1, "scenario": "production-inspect", "phase": "readonly_metadata", "status": "SKIP",
              "cleanup": "PASS", "privileged_caller": os.geteuid() == 0, "live_test_started": False,
              "system_network_changed": False, "production_state_inferred": False}
    try:
        if platform.system() != "Darwin":
            result["reason_code"] = "macos_required"
            return result
        if adapter_run is not None:
            result["adapter_report"] = adapter_report(adapter_run)
        result["socket"] = metadata(SOCKET)
        result["account_file"] = metadata(ACCOUNT)  # Never open or decode account contents.
        fields = service_fields(read_tool(["/bin/launchctl", "print", SERVICE], deadline))
        summary = {"format": "advisory", "state": fields.get("state") if fields.get("state") in
                   ("running", "waiting", "exited", "spawn scheduled", "not running") else "unknown"}
        for key in ("runs", "active count", "last exit code"):
            value = fields.get(key, "")
            if re.fullmatch(r"-?[0-9]{1,10}", value):
                summary[key.replace(" ", "_")] = int(value)
        result["service"] = summary
        value = fields.get("pid", "")
        if not value.isdigit() or not 1 < int(value) <= 2147483647:
            raise ObservationError("service_pid_unknown")
        pid = int(value)
        command = ["/bin/ps", "-p", str(pid), "-o", "pid=,uid=,ppid=,pcpu=,stat=,ucomm="]
        before = process_fields(read_tool(command, deadline), pid)
        if not before["name_is_zarpd"]:
            raise ObservationError("service_process_mismatch")
        result["process"] = before
        observed_path = None
        try:
            try:
                observed_path = process_path(pid)
                program = observed_path
                result["process"]["path_source"] = "kernel_metadata"
                result["process"]["path_is_local_build"] = program == BUILD
            except (OSError, ObservationError) as error:
                result["process"]["path_status"] = "unavailable"
                if isinstance(error, ObservationError) and error.error_number is not None:
                    result["process"]["path_errno"] = error.error_number
                program = service_program(fields)
                result["process"]["path_source"] = "advisory_launchd"
            result["on_disk_program"] = {"sha256": binary_digest(program, deadline), "cdhash": disk_cdhash(
                read_tool(["/usr/bin/codesign", "-d", "--verbose=4", "--", str(program)], deadline))}
        except (OSError, ObservationError) as error:
            if isinstance(error, ObservationError) and not error.cleanup:
                raise
            result["on_disk_program"] = {"status": "unavailable"}
        try:
            result["local_build"] = {"sha256": binary_digest(BUILD, deadline), "cdhash": disk_cdhash(
                read_tool(["/usr/bin/codesign", "-d", "--verbose=4", "--", str(BUILD)], deadline))}
            if "sha256" in result["on_disk_program"]:
                result["on_disk_matches_local_build"] = result["on_disk_program"]["sha256"] == result["local_build"]["sha256"]
        except (OSError, ObservationError) as error:
            if isinstance(error, ObservationError) and not error.cleanup:
                raise
            result["local_build"] = {"status": "unavailable"}
        code_hash = kernel_cdhash(pid)
        after = process_fields(read_tool(command, deadline), pid)
        # This is advisory metadata, not a race-free process capability. PID or
        # exec replacement cannot authorize signals, adoption or a tunnel start.
        if any(before[key] != after[key] for key in ("pid", "owner_is_root", "parent_is_launchd", "name_is_zarpd")):
            raise ObservationError("process_changed_during_observation")
        if observed_path is not None and process_path(pid) != observed_path:
            raise ObservationError("process_changed_during_observation")
        result["observed_process_cdhash"] = code_hash
        if "cdhash" in result["on_disk_program"]:
            result["observed_process_matches_on_disk"] = code_hash == result["on_disk_program"]["cdhash"]
        if "cdhash" in result["local_build"]:
            result["observed_process_matches_local_build"] = code_hash == result["local_build"]["cdhash"]
        if any(result[key]["status"] == "permission_denied" for key in ("socket", "account_file")):
            raise ObservationError("file_metadata_permission")
        result.update(status="PASS", reason_code="metadata_observed_only")
    except ObservationError as error:
        result["reason_code"] = error.code
        if error.error_number is not None:
            result["kernel_errno"] = error.error_number
        if not error.cleanup:
            result.update(status="FAIL", cleanup="FAIL")
    except KeyboardInterrupt:
        result["reason_code"] = "observation_interrupted"
    except OSError as error:
        result["reason_code"] = "file_metadata_permission" if error.errno in (errno.EACCES, errno.EPERM) else "file_metadata_unavailable"
    except Exception:
        result["reason_code"] = "metadata_unavailable"
    finally:
        result["duration_seconds"] = round(time.monotonic() - started, 2)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inspect", action="store_true", required=True, help="read fixed production metadata only; sudo optional for inaccessible metadata")
    parser.add_argument("--adapter-run", help="optional fixed-format user-run adapter ID; reads only its restricted sanitized report")
    args = parser.parse_args()
    if args.adapter_run is not None and re.fullmatch(r"zarp-parity-adapter-[a-z0-9_]{8}", args.adapter_run) is None:
        parser.error("invalid adapter run ID")
    previous = {}
    def interrupted(_signal, _frame):
        if not CLEANING:
            raise KeyboardInterrupt
    for number in (signal.SIGINT, signal.SIGTERM):
        previous[number] = signal.signal(number, interrupted)
    try:
        report = inspect(args.adapter_run)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    print("RESULT " + json.dumps(report, sort_keys=True, allow_nan=False))
    return 1 if report["status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
