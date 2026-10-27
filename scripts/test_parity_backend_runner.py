#!/usr/bin/env python3
"""Pure archive integrity regressions. No network, engine execution or system changes."""
import hashlib
import io
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile
import signal

SOURCE = Path(__file__).with_name("test-parity-backend-loopback.py")
MODULE = {"__name__": "parity_runner_tests", "__file__": str(SOURCE)}
exec(compile(SOURCE.read_text(), str(SOURCE), "exec"), MODULE)


class Response(io.BytesIO):
    def geturl(self):
        return "https://example.invalid/pinned.zip"


class ArchiveIntegrityTests(unittest.TestCase):
    def archive(self, payload, kind="zip", symlink=False):
        stream = io.BytesIO()
        if kind == "zip":
            with zipfile.ZipFile(stream, "w") as package:
                member = zipfile.ZipInfo("xray")
                member.external_attr = ((stat.S_IFLNK if symlink else stat.S_IFREG) | 0o700) << 16
                package.writestr(member, payload)
                package.writestr("../must-not-extract", b"unexpected")
        else:
            with tarfile.open(fileobj=stream, mode="w:gz") as package:
                member = tarfile.TarInfo("sing-box-1.13.14-darwin-arm64/sing-box")
                member.size = len(payload)
                if symlink:
                    member.type = tarfile.SYMTYPE
                    member.linkname = "../unexpected"
                    package.addfile(member)
                else:
                    package.addfile(member, io.BytesIO(payload))
        return stream.getvalue()

    def run_fetch(self, archive, payload, directory, kind="zip", wrong_archive=False, wrong_binary=False):
        namespace = {"DESTINATION": directory, "BINARY": directory / "engine",
                     "URL": "https://example.invalid/pinned." + ("zip" if kind == "zip" else "tar.gz"),
                     "ARCHIVE_SHA": "0" * 64 if wrong_archive else hashlib.sha256(archive).hexdigest(),
                     "BINARY_SHA": "0" * 64 if wrong_binary else hashlib.sha256(payload).hexdigest()}
        with patch.dict(MODULE, namespace), patch("urllib.request.urlopen", return_value=Response(archive)), \
             patch("subprocess.Popen") as spawn:
            MODULE["fetch"]()
            spawn.assert_not_called()

    def test_fixed_member_only_and_restricted_atomic_binary(self):
        payload = b"fake test binary, never executed"
        for kind in ["zip", "tar"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="zarp-archive-unit-") as folder:
                destination = Path(folder) / "private"
                self.run_fetch(self.archive(payload, kind), payload, destination, kind)
                self.assertEqual((destination / "engine").read_bytes(), payload)
                self.assertEqual(stat.S_IMODE((destination / "engine").stat().st_mode), 0o700)
                self.assertEqual([file.name for file in destination.iterdir()], ["engine"])
                self.assertFalse((Path(folder) / "must-not-extract").exists())

    def test_integrity_failure_retains_previous_binary(self):
        payload = b"replacement binary"
        for wrong_archive in [False, True]:
            with self.subTest(archive=wrong_archive), tempfile.TemporaryDirectory(prefix="zarp-archive-unit-") as folder:
                destination = Path(folder)
                binary = destination / "engine"
                binary.write_bytes(b"previous verified binary")
                with self.assertRaises(RuntimeError):
                    self.run_fetch(self.archive(payload), payload, destination,
                                   wrong_archive=wrong_archive, wrong_binary=not wrong_archive)
                self.assertEqual(binary.read_bytes(), b"previous verified binary")
                self.assertEqual([file.name for file in destination.iterdir()], ["engine"])

    def test_link_members_are_refused(self):
        payload = b"link target"
        for kind in ["zip", "tar"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="zarp-archive-unit-") as folder:
                destination = Path(folder)
                with self.assertRaises(RuntimeError):
                    self.run_fetch(self.archive(payload, kind, symlink=True), payload, destination, kind)
                self.assertEqual(list(destination.iterdir()), [])


class TrafficEvidenceTests(unittest.TestCase):
    def evidence(self, text):
        with tempfile.TemporaryDirectory(prefix="zarp-evidence-unit-") as folder:
            path = Path(folder) / "private.log"
            path.write_text(text)
            return MODULE["verified_case_count"](path, "PinnedBackendOuterTransports")

    def test_zero_exit_empty_and_skipped_cases_do_not_prove_traffic(self):
        for text in ["PASS\n", "testing: warning: no tests to run\nPASS\n",
                     "--- SKIP: TestPinnedBackendOuterTransports (0.00s)\nPASS\n",
                     "--- PASS: TestPinnedBackendOuterTransports (0.00s)\nPASS\n",
                     "    --- PASS: TestPinnedBackendOuterTransports/positive (0.01s)\n    --- SKIP: TestPinnedBackendOuterTransports/negative (0.01s)\n--- PASS: TestPinnedBackendOuterTransports (0.01s)\nPASS\n"]:
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                self.evidence(text)

    def test_completed_external_subcases_are_counted(self):
        text = "    --- PASS: TestPinnedBackendOuterTransports/positive (0.01s)\n    --- PASS: TestPinnedBackendOuterTransports/negative (0.01s)\n--- PASS: TestPinnedBackendOuterTransports (0.02s)\nPASS\n"
        self.assertEqual(self.evidence(text), 2)


class ProcessOwnershipTests(unittest.TestCase):
    def test_failed_or_unknown_run_retains_private_files_without_certifying_cleanup(self):
        for status, cleanup in [("FAIL", "PASS"), ("PASS", "FAIL")]:
            with self.subTest(status=status, cleanup=cleanup), tempfile.TemporaryDirectory(prefix="zarp-retention-unit-") as parent:
                directory = Path(parent) / "private"
                directory.mkdir(mode=0o700)
                (directory / "owned-sentinel").write_text("private fake fixture")
                result = {"status": status, "cleanup": cleanup}
                MODULE["finish_private_run"](result, directory)
                self.assertEqual(result["cleanup"], "FAIL")
                self.assertEqual(result["status"], "FAIL")
                self.assertEqual(result["retained_private_directory"], str(directory))
                self.assertEqual((directory / "owned-sentinel").read_text(), "private fake fixture")
        with tempfile.TemporaryDirectory(prefix="zarp-retention-unit-") as parent:
            directory = Path(parent) / "private"
            directory.mkdir(mode=0o700)
            result = {"status": "PASS", "cleanup": "PASS"}
            MODULE["finish_private_run"](result, directory)
            self.assertFalse(directory.exists())
            self.assertNotIn("retained_private_directory", result)

    def test_reaped_leader_never_receives_a_saved_group_signal(self):
        child = Mock(pid=12345, returncode=0)
        with patch("os.killpg") as kill:
            MODULE["stop_group"](child)
            kill.assert_not_called()
            child.wait.assert_not_called()

    def test_private_leader_is_not_reaped_between_term_and_kill(self):
        child = Mock(pid=12345, returncode=None)
        events = []
        child.wait.side_effect = lambda **_kwargs: events.append("wait")
        with patch("signal.getsignal", return_value=signal.SIG_DFL), patch("time.sleep"), \
             patch("os.killpg", side_effect=lambda _pid, sig: events.append(sig)):
            MODULE["stop_group"](child)
        self.assertEqual(events, [signal.SIGTERM, signal.SIGKILL, "wait"])

    def test_unknown_reaping_policy_refuses_group_signals(self):
        child = Mock(pid=12345, returncode=None)
        with patch("signal.getsignal", return_value=signal.SIG_IGN), patch("os.killpg") as kill:
            with self.assertRaises(RuntimeError):
                MODULE["stop_group"](child)
            kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
