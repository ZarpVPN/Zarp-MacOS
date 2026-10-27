#!/usr/bin/env python3
"""Private fixtures/fake tools only. Never inspect or control production here."""
import ctypes
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).with_name("test-parity-production-inspect.py")
SPEC = importlib.util.spec_from_file_location("production_inspect_tests", SOURCE)
inspector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inspector)


class InspectTests(unittest.TestCase):
    def assert_code(self, code, call, *args):
        with self.assertRaises(inspector.ObservationError) as raised:
            call(*args)
        self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_tool_allowlist_rejects_mutations_and_expired_budget_before_spawn(self):
        with patch.object(inspector.subprocess, "Popen") as spawn:
            for args in (["/bin/launchctl", "stop", inspector.SERVICE],
                         ["/bin/launchctl", "print", "system/foreign"],
                         ["/bin/ps", "-p", "1;kill", "-o", "pid=,uid=,ppid=,pcpu=,stat=,ucomm="],
                         ["/usr/bin/codesign", "-s", "-", "--", "/tmp/zarpd"],
                         ["/usr/bin/codesign", "-d", "--verbose=4", "--", "relative"],
                         ["/bin/sh", "-c", "anything"]):
                self.assert_code("invalid_readonly_command", inspector.read_tool, args, time.monotonic() + 1)
            self.assert_code("observation_timeout", inspector.read_tool,
                             ["/bin/launchctl", "print", inspector.SERVICE], time.monotonic() - 1)
            spawn.assert_not_called()

    def fake_tool(self, data, *, timeout=False, code=0, cleanup_failure=False):
        child = Mock(returncode=None, stdout=io.BytesIO())
        child.stdout.fileno = lambda: 123
        def wait(**_kwargs):
            if cleanup_failure:
                raise subprocess.TimeoutExpired("private fake", 1)
            child.returncode = code
            return code
        child.wait.side_effect = wait
        reads = [data, b""]
        return child, patch.object(inspector.subprocess, "Popen", return_value=child), \
            patch.object(inspector.select, "select", return_value=([], [], []) if timeout else ([child.stdout], [], [])), \
            patch.object(inspector.os, "read", side_effect=reads)

    def test_read_tools_are_bounded_sanitized_and_reaped(self):
        for data, timeout, code, expected in ((b"ok", False, 0, None), (b"private-key", True, 0, "observation_timeout"),
                                             (b"x" * (inspector.LIMIT + 1), False, 0, "observation_limit"),
                                             (b"private-key", False, 1, "observation_unavailable"),
                                             (b"\xffprivate-key", False, 0, "observation_unavailable")):
            child, spawning, selecting, reading = self.fake_tool(data, timeout=timeout, code=code)
            with spawning as spawn, selecting, reading:
                args = ["/bin/launchctl", "print", inspector.SERVICE]
                if expected:
                    error = self.assert_code(expected, inspector.read_tool, args, time.monotonic() + 1)
                    self.assertNotIn("private-key", str(error))
                else:
                    self.assertEqual(inspector.read_tool(args, time.monotonic() + 1), "ok")
                self.assertEqual(spawn.call_args.args, (args,))
                self.assertEqual(spawn.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                self.assertNotIn("shell", spawn.call_args.kwargs)
                self.assertIs(spawn.call_args.kwargs["stdin"], subprocess.DEVNULL)
                self.assertTrue(child.stdout.closed)
                child.wait.assert_called()
                self.assertFalse(inspector.CLEANING)
                if timeout or len(data) > inspector.LIMIT:
                    child.kill.assert_called_once_with()
                else:
                    child.kill.assert_not_called()

    def test_interruption_and_cleanup_failure_use_only_owned_child(self):
        child, spawning, selecting, reading = self.fake_tool(b"", timeout=True, cleanup_failure=True)
        with spawning, selecting, reading:
            error = self.assert_code("observation_cleanup_unknown", inspector.read_tool,
                                     ["/bin/launchctl", "print", inspector.SERVICE], time.monotonic() + 1)
        self.assertFalse(error.cleanup)
        self.assertTrue(child.stdout.closed)
        self.assertFalse(inspector.CLEANING)
        child, spawning, selecting, reading = self.fake_tool(b"")
        with spawning, selecting, reading, patch.object(inspector.select, "select", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                inspector.read_tool(["/bin/launchctl", "print", inspector.SERVICE], time.monotonic() + 1)
        child.kill.assert_called_once_with()
        self.assertEqual(child.returncode, 0)
        self.assertTrue(child.stdout.closed)

    def test_service_parser_ignores_nested_secrets_and_refuses_ambiguity(self):
        text = inspector.SERVICE + " = {\n\tstate = running\n\tprogram = /private/install/zarpd\n\targuments = {\n\t\tpid = 999\n\t\tprogram = private-key\n\t}\n\tpid = 123\n}\n"
        fields = inspector.service_fields(text)
        self.assertEqual(fields, {"state": "running", "program": "/private/install/zarpd", "pid": "123"})
        self.assertNotIn("private-key", json.dumps(fields))
        for changed in (text + "}\n", text[:-2], text.replace("pid = 123", "pid = 123\n pid = 456"),
                        text.replace(inspector.SERVICE, "system/foreign", 1), text.replace("pid = 123", "pid = {secret}")):
            self.assert_code("service_format_unknown", inspector.service_fields, changed)
        self.assertEqual(inspector.service_program({"path": "/Applications/Zarp.app/Contents/Library/LaunchDaemons/io.github.zarp.mac.zarpd.plist"}),
                         Path("/Applications/Zarp.app/Contents/MacOS/zarpd"))
        for path in ("(submitted by smd.509)", "/Library/LaunchDaemons/foreign.plist", "relative/Zarp.app/Contents/Library/LaunchDaemons/io.github.zarp.mac.zarpd.plist"):
            self.assert_code("service_program_unknown", inspector.service_program, {"path": path})

    def test_file_metadata_never_opens_contents_and_marks_unsafe_types(self):
        with tempfile.TemporaryDirectory(prefix="zarp-inspect-unit-") as directory:
            root = Path(directory)
            regular = root / "account"
            regular.write_bytes(b"private-key")
            regular.chmod(0o600)
            fifo = root / "fifo"
            os.mkfifo(fifo, 0o600)
            link = root / "link"
            link.symlink_to(regular)
            with patch.object(inspector.os, "open", side_effect=AssertionError("metadata cannot open files")):
                self.assertTrue(inspector.metadata(regular)["bounded_regular"])
                self.assertEqual(inspector.metadata(fifo)["kind"], "fifo")
                self.assertEqual(inspector.metadata(link)["kind"], "symlink")
                self.assertEqual(inspector.metadata(root / "missing"), {"status": "missing"})
            regular.chmod(0o666)
            self.assertFalse(inspector.metadata(regular)["bounded_regular"])

    def test_binary_hash_is_bounded_nonexecuting_and_refuses_replacement(self):
        with tempfile.TemporaryDirectory(prefix="zarp-inspect-unit-") as directory:
            path = Path(directory) / "zarpd"
            data = b"\xcf\xfa\xed\xfe" + b"private test-only bytes"
            path.write_bytes(data)
            path.chmod(0o500)
            self.assertEqual(inspector.binary_digest(path, time.monotonic() + 1), hashlib.sha256(data).hexdigest())
            real = path.lstat()
            fake = SimpleNamespace(st_dev=real.st_dev, st_ino=real.st_ino + 1, st_size=real.st_size,
                                   st_mtime_ns=real.st_mtime_ns, st_ctime_ns=real.st_ctime_ns)
            with patch.object(inspector.os, "lstat", return_value=fake):
                self.assert_code("binary_changed_during_observation", inspector.binary_digest, path, time.monotonic() + 1)
            path.chmod(0o666)
            self.assert_code("binary_metadata_unsafe", inspector.binary_digest, path, time.monotonic() + 1)
            path.chmod(0o600)
            path.write_bytes(b"not-a-binary")
            self.assert_code("binary_format_unknown", inspector.binary_digest, path, time.monotonic() + 1)
            path.unlink()
            os.mkfifo(path, 0o600)
            self.assert_code("binary_metadata_unsafe", inspector.binary_digest, path, time.monotonic() + 1)

    def test_signature_and_process_parsers_cannot_echo_foreign_input(self):
        self.assertEqual(inspector.disk_cdhash("secret=value\nCDHash=" + "a" * 40), "a" * 40)
        for text in ("CDHash=secret", "CDHash=" + "a" * 40 + "\nCDHash=" + "b" * 40):
            self.assert_code("signature_metadata_unknown", inspector.disk_cdhash, text)
        info = inspector.process_fields("123 0 1 198.1 R+ zarpd\n", 123)
        self.assertEqual(info["cpu_percent"], 198.1)
        self.assertTrue(info["owner_is_root"])
        for text in ("124 0 1 0 S zarpd", "123 0 1 nan S zarpd", "123 0 1 private-key S zarpd",
                     "123 0 1 0 @secret zarpd", "123 0 1 0 S private name"):
            self.assert_code("process_format_unknown", inspector.process_fields, text, 123)

    def test_kernel_operation_is_fixed_readonly_and_permission_is_unknown(self):
        library = Mock()
        def fill(pid, operation, data, size):
            self.assertEqual((pid, operation, size), (123, 5, 20))
            for index in range(size):
                data[index] = index
            return 0
        library.csops.side_effect = fill
        with patch.object(inspector.ctypes, "CDLL", return_value=library) as load:
            self.assertEqual(inspector.kernel_cdhash(123), bytes(range(20)).hex())
            load.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)
        library.csops.side_effect = None
        library.csops.return_value = -1
        with patch.object(inspector.ctypes, "CDLL", return_value=library), patch.object(inspector.ctypes, "get_errno", return_value=errno.EPERM):
            self.assert_code("kernel_metadata_permission", inspector.kernel_cdhash, 123)

    def test_process_path_is_bounded_readonly_metadata(self):
        library = Mock()
        output = b"/Applications/Zarp.app/Contents/MacOS/zarpd"
        def fill(pid, data, size):
            self.assertEqual((pid, size), (123, 4096))
            data.value = output
            return len(output)
        library.proc_pidpath.side_effect = fill
        with patch.object(inspector.ctypes, "CDLL", return_value=library) as load:
            self.assertEqual(inspector.process_path(123), Path(os.fsdecode(output)))
            load.assert_called_once_with("/usr/lib/libproc.dylib", use_errno=True)
        for changed in (b"relative/zarpd", b"/Applications/foreign", b"/Applications/private\nsecret/zarpd"):
            output = changed
            with patch.object(inspector.ctypes, "CDLL", return_value=library):
                self.assert_code("process_path_unknown", inspector.process_path, 123)
        library.proc_pidpath.side_effect = None
        library.proc_pidpath.return_value = 4096
        with patch.object(inspector.ctypes, "CDLL", return_value=library):
            self.assert_code("process_path_unavailable", inspector.process_path, 123)

    def report(self):
        return dict(version=1, scenario="backend-system-adapter", run_id="zarp-parity-adapter-g0nc0trg",
                    status="SKIP", cleanup="PASS", live_test_started=False, default_routes_configured=False,
                    system_dns_configured=False, reason_code="production_status_unknown", checks=[])

    def test_adapter_report_redaction_and_strict_schema(self):
        report = self.report()
        sanitized = inspector.sanitized_adapter_report(dict(report, reason="private-key", report_path="private-uri"), report["run_id"])
        self.assertNotIn("private", json.dumps(sanitized))
        self.assertEqual(sanitized["check_count"], 0)
        self.assertFalse(sanitized["live_test_started"])
        for key, value in (("version", True), ("live_test_started", 0), ("checks", [0] * 7),
                           ("run_id", "foreign"), ("cleanup", "unknown")):
            self.assert_code("adapter_report_invalid", inspector.sanitized_adapter_report, dict(report, **{key: value}), report["run_id"])
        self.assert_code("adapter_run_invalid", inspector.adapter_report, "../../private-key")

    def test_restricted_adapter_report_reads_only_owned_bounded_report(self):
        with tempfile.TemporaryDirectory(prefix="zarp-inspect-unit-") as temporary:
            root = Path(temporary)
            run_id = self.report()["run_id"]
            work = root / run_id
            work.mkdir(mode=0o700)
            report = work / "report.json"
            report.write_text(json.dumps(dict(self.report(), secret="private-key")))
            report.chmod(0o600)
            real_lstat, real_fstat = Path.lstat, os.fstat
            def pretend_root(value):
                names = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
                return SimpleNamespace(**{name: getattr(value, name) for name in names}, st_uid=0)
            with patch.object(inspector, "Path", return_value=root) as base, \
                 patch.object(Path, "lstat", lambda path: pretend_root(real_lstat(path))), \
                 patch.object(inspector.os, "fstat", lambda fd: pretend_root(real_fstat(fd))):
                result = inspector.adapter_report(run_id)
                base.assert_called_once_with("/private/tmp")
                self.assertEqual(result["reason_code"], "production_status_unknown")
                self.assertNotIn("private-key", json.dumps(result))
                report.chmod(0o644)
                self.assert_code("adapter_report_invalid", inspector.adapter_report, run_id)
                report.unlink()
                os.mkfifo(report, 0o600)
                self.assert_code("adapter_report_invalid", inspector.adapter_report, run_id)
                report.unlink()
                report.symlink_to(root / "foreign.json")
                with self.assertRaises(OSError):
                    inspector.adapter_report(run_id)

    def test_inspection_reports_partial_evidence_without_claiming_production_state(self):
        fields = dict(program="/private/install/zarpd", pid="123", state="running", runs="4")
        service = inspector.SERVICE + " = {\n" + "\n".join(f"{key} = {value}" for key, value in fields.items()) + "\n}\n"
        def output(args, _deadline):
            if args[0] == "/bin/launchctl":
                return service
            if args[0] == "/bin/ps":
                return "123 0 1 198.1 R zarpd"
            return "CDHash=" + ("b" if args[-1] == str(inspector.BUILD) else "a") * 40
        with patch.object(inspector.platform, "system", return_value="Darwin"), \
             patch.object(inspector, "metadata", return_value={"status": "observed", "kind": "regular"}), \
             patch.object(inspector, "read_tool", side_effect=output), \
             patch.object(inspector, "process_path", return_value=Path(fields["program"])), \
             patch.object(inspector, "binary_digest", side_effect=lambda path, _deadline: "b" * 64 if path == inspector.BUILD else "a" * 64), \
             patch.object(inspector, "kernel_cdhash", return_value="c" * 40):
            result = inspector.inspect()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["reason_code"], "metadata_observed_only")
        self.assertFalse(result["production_state_inferred"])
        self.assertFalse(result["live_test_started"])
        self.assertFalse(result["system_network_changed"])
        self.assertFalse(result["on_disk_matches_local_build"])
        self.assertFalse(result["observed_process_matches_on_disk"])
        self.assertNotIn("/private/install", json.dumps(result))

    def test_interruption_permissions_and_failed_cleanup_never_pass(self):
        for error, status, cleanup, reason in ((KeyboardInterrupt(), "SKIP", "PASS", "observation_interrupted"),
                (PermissionError(errno.EACCES, "private-key"), "SKIP", "PASS", "file_metadata_permission"),
                (inspector.ObservationError("observation_cleanup_unknown", cleanup=False), "FAIL", "FAIL", "observation_cleanup_unknown")):
            with patch.object(inspector.platform, "system", return_value="Darwin"), \
                 patch.object(inspector, "metadata", side_effect=error):
                result = inspector.inspect()
            self.assertEqual((result["status"], result["cleanup"], result["reason_code"]), (status, cleanup, reason))
            self.assertNotIn("private-key", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
