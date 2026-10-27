#!/usr/bin/env python3
"""Packet runner regressions: synthetic reports and one private stdin-EOF child.

No sudo, BPF device, relay, outbound connection or system network change.
"""
import io
import json
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).with_name("test-parity-outer-packets.py")
MODULE = {"__name__": "parity_packet_runner_tests", "__file__": str(SOURCE)}
exec(compile(SOURCE.read_text(), str(SOURCE), "exec"), MODULE)


def evidence(capture=False, status="PASS"):
    return {"version": 1, "scenario": "outer-packet-loopback", "phase": "capture" if capture else "loopback",
            "status": status, "cleanup": "PASS", "duration_seconds": 0.1, "system_network_changed": False,
            "capture_started": capture, "https_flows": 2, "udp_associations": 2, "captured_packets": 12 if capture else 0,
            "capture_drops": 0, "tcp_packet_split_verified": capture, "udp_fake_order_tuple_verified": capture}


def report_bytes(report):
    return ("RESULT " + json.dumps(report) + "\n").encode()


class EvidenceTests(unittest.TestCase):
    def test_capture_requires_packet_evidence_not_successful_streams(self):
        self.assertEqual(MODULE["validate_report"](report_bytes(evidence()), 0, False)["status"], "PASS")
        self.assertEqual(MODULE["validate_report"](report_bytes(evidence(True)), 0, True)["status"], "PASS")
        for changed in [evidence(), dict(evidence(True), tcp_packet_split_verified=False),
                        dict(evidence(True), udp_fake_order_tuple_verified=False), dict(evidence(True), capture_drops=1),
                        dict(evidence(True), https_flows=1), dict(evidence(True), cleanup="FAIL"),
                        dict(evidence(True), capture_error="capture_stats_unknown"), dict(evidence(True), bpf_open_errno=1)]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                MODULE["validate_report"](report_bytes(changed), 0, True)
        with self.assertRaises(ValueError):
            MODULE["validate_report"](report_bytes(evidence(True)), 1, True)

    def test_unknown_secret_fields_and_unbounded_or_ambiguous_reports_refuse(self):
        for changed in [dict(evidence(), raw_uri="trojan://test-secret@example.invalid"),
                        dict(evidence(), reason_code="raw-test-secret"), dict(evidence(), version=True),
                        dict(evidence(), https_flows=True), dict(evidence(), duration_seconds=float("nan")),
                        dict(evidence(), tcp_packet_payload_lengths=[[1] * 65])]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                MODULE["validate_report"](report_bytes(changed), 0, False)
        for text in [b"PASS\n", report_bytes(evidence()) * 2, b"x" * 32769]:
            with self.subTest(text=text[:50]), self.assertRaises(ValueError):
                MODULE["validate_report"](text, 0, False)

    def test_family_is_required_to_match_requested_capture(self):
        v6 = dict(evidence(True), ip_family="ipv6")
        self.assertEqual(MODULE["validate_report"](report_bytes(v6), 0, True, "ipv6")["status"], "PASS")
        for report, family in [(evidence(True), "ipv6"), (v6, "ipv4"), (dict(v6, ip_family=True), "ipv6"),
                               (dict(v6, ip_family="example.invalid"), "ipv6")]:
            with self.subTest(family=family, report=report), self.assertRaises(ValueError):
                MODULE["validate_report"](report_bytes(report), 0, True, family)

    def test_hop_limit_proof_is_distinct_from_tuple_or_stream_evidence(self):
        request = dict(evidence(True), udp_fake_hop_limit_requested=True, udp_fake_hop_limit_verified=True, udp_packet_hop_limits=[[1,64],[1,64]])
        self.assertEqual(MODULE["validate_report"](report_bytes(request), 0, True, "ipv4", True)["status"], "PASS")
        for report, capture, requested in [(evidence(True), True, True), (request, True, False),
                (dict(request, udp_fake_hop_limit_verified=False), True, True),
                (dict(evidence(), udp_fake_hop_limit_requested=True, udp_fake_hop_limit_verified=True), False, True),
                (dict(request, udp_fake_hop_limit_verified=1), True, True),
                (dict(request, udp_packet_hop_limits=[]), True, True),
                (dict(request, udp_packet_hop_limits=[[1,1],[1,64]]), True, True),
                (dict(request, udp_packet_hop_limits=[[64,1],[1,64]]), True, True)]:
            with self.subTest(report=report), self.assertRaises(ValueError):
                MODULE["validate_report"](report_bytes(report), 0, capture, "ipv4", requested)


class LifecycleTests(unittest.TestCase):
    def build(self, command, **options):
        self.assertEqual(command[:3], ["go", "build", "-trimpath"])
        self.assertEqual(command[-1], "./cmd/parity-packet-probe")
        self.assertEqual(options["env"]["GOPROXY"], "off")
        self.assertNotIn("ZARP_SOCKET", options["env"])
        self.assertNotIn("ZARP_PARITY_SING_BOX", options["env"])
        Path(command[4]).write_bytes(b"private fake helper, never executed")
        return subprocess.CompletedProcess(command, 0)

    def verify_artifact(self, result, retained=False):
        report = Path(result["report_path"])
        self.addCleanup(shutil.rmtree, report.parent)
        self.assertEqual(stat.S_IMODE(report.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
        self.assertEqual(json.loads(report.read_text()), result)
        self.assertEqual((report.parent / "work").exists(), retained)
        if not retained:
            self.assertEqual([path.name for path in report.parent.iterdir()], ["report.json"])

    def test_safe_check_fixed_command_environment_private_report_and_cleanup(self):
        def spawn(command, **options):
            self.assertEqual(command[1:], ["--loopback-check"])
            self.assertEqual(Path(command[0]).name, "packet-probe")
            options["stdout"].write(report_bytes(evidence()))
            options["stdout"].flush()
            return Mock(stdin=io.BytesIO(), returncode=0, wait=Mock(return_value=0))

        original = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="arm64"), \
             patch("subprocess.run", side_effect=self.build) as run, patch("subprocess.Popen", side_effect=spawn), \
             patch("os.kill") as kill, patch("os.killpg") as kill_group:
            result = MODULE["main"](["--loopback-check"])
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["cleanup"], "PASS")
            self.assertEqual(run.call_count, 1)  # No sudo authorization in the safe path.
            kill.assert_not_called(); kill_group.assert_not_called()
        self.assertEqual({number: signal.getsignal(number) for number in original}, original)
        self.verify_artifact(result)


    def test_ipv6_adds_only_fixed_family_switch_in_both_modes(self):
        for capture in (False, True):
            def run(command, **options):
                if command == ["sudo", "-v"]:
                    return subprocess.CompletedProcess(command, 0)
                return self.build(command, **options)
            def spawn(command, **options):
                expected = ["--capture", "--ipv6"] if capture else ["--loopback-check", "--ipv6"]
                self.assertEqual(command[-2:], expected)
                if capture: self.assertEqual(command[:3], ["sudo", "-n", "--"])
                options["stdout"].write(report_bytes(dict(evidence(capture), ip_family="ipv6")))
                options["stdout"].flush()
                return Mock(stdin=io.BytesIO(), returncode=0, wait=Mock(return_value=0))
            with self.subTest(capture=capture), patch("platform.system", return_value="Darwin"), \
                 patch("platform.machine", return_value="arm64"), patch("subprocess.run", side_effect=run), \
                 patch("subprocess.Popen", side_effect=spawn):
                result = MODULE["main"](["--run" if capture else "--loopback-check", "--family", "ipv6"])
            self.assertEqual((result["status"],result["ip_family"]), ("PASS","ipv6"))
            self.verify_artifact(result)


    def test_hop_limit_mode_has_only_fixed_arguments_and_requires_matching_report(self):
        for capture in (False, True):
            def run(command, **options):
                if command == ["sudo", "-v"]: return subprocess.CompletedProcess(command, 0)
                return self.build(command, **options)
            def spawn(command, **options):
                self.assertEqual(command[-3:], ["--capture" if capture else "--loopback-check", "--ipv6", "--fake-hop-limit"])
                proof = dict(evidence(capture), ip_family="ipv6", udp_fake_hop_limit_requested=True)
                if capture: proof.update(udp_fake_hop_limit_verified=True, udp_packet_hop_limits=[[1,64],[1,64]])
                options["stdout"].write(report_bytes(proof)); options["stdout"].flush()
                return Mock(stdin=io.BytesIO(), returncode=0, wait=Mock(return_value=0))
            with self.subTest(capture=capture), patch("platform.system", return_value="Darwin"), \
                 patch("platform.machine", return_value="arm64"), patch("subprocess.run", side_effect=run), \
                 patch("subprocess.Popen", side_effect=spawn):
                result = MODULE["main"](["--run" if capture else "--loopback-check", "--family", "ipv6", "--fake-hop-limit"])
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["udp_fake_hop_limit_requested"])
            self.verify_artifact(result)

    def test_build_timeout_retains_unverified_compiler_work_and_cannot_pass(self):
        with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="arm64"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["go", "build"], 180)), \
             patch("subprocess.Popen") as spawn:
            result = MODULE["main"](["--loopback-check"])
            spawn.assert_not_called()
        self.assertEqual((result["status"], result["cleanup"], result["reason_code"]), ("FAIL", "FAIL", "private_build_timeout"))
        self.verify_artifact(result, retained=True)

    def test_build_interrupt_and_unverified_worker_timeout_retain_private_work(self):
        for error in (KeyboardInterrupt(), subprocess.TimeoutExpired(["go", "build"], 180)):
            with self.subTest(error=type(error).__name__), patch("platform.system", return_value="Darwin"), \
                 patch("platform.machine", return_value="arm64"), patch("subprocess.run", side_effect=error):
                result = MODULE["main"](["--loopback-check"])
            self.assertEqual((result["status"], result["cleanup"]), ("FAIL", "FAIL"))
            self.verify_artifact(result, retained=True)
        fake = Mock(stdin=io.BytesIO(), wait=Mock(side_effect=subprocess.TimeoutExpired(["private helper"], 40)))
        with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="arm64"), \
             patch("subprocess.run", side_effect=self.build), patch("subprocess.Popen", return_value=fake), \
             patch("os.kill") as kill, patch("os.killpg") as kill_group:
            result = MODULE["main"](["--loopback-check"])
            kill.assert_not_called(); kill_group.assert_not_called()
        self.assertTrue(fake.stdin.closed)
        self.assertEqual((result["status"], result["cleanup"]), ("FAIL", "FAIL"))
        self.verify_artifact(result, retained=True)

    def test_exited_wrapper_without_helper_report_does_not_certify_cleanup(self):
        fake = Mock(stdin=io.BytesIO(), wait=Mock(return_value=0))
        with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="arm64"), \
             patch("subprocess.run", side_effect=self.build), patch("subprocess.Popen", return_value=fake):
            result = MODULE["main"](["--loopback-check"])
        self.assertEqual((result["status"], result["cleanup"]), ("FAIL", "FAIL"))
        self.assertEqual(result["reason_code"], "private_check_failed")
        self.verify_artifact(result, retained=True)

    def test_sigterm_cancels_only_owned_worker_with_eof_and_verified_join(self):
        child = None

        def spawn(_command, **options):
            nonlocal child
            raw = repr(report_bytes(dict(evidence(status="FAIL"), https_flows=0, udp_associations=0,
                                         reason_code="private_loopback_check_failed")))
            child = subprocess.Popen([sys.executable, "-I", "-c", "import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(" + raw + "); sys.stdout.flush()"],
                                     stdin=subprocess.PIPE, stdout=options["stdout"], stderr=subprocess.STDOUT)
            wait = child.wait
            proxy = Mock(stdin=child.stdin)

            def interrupted_wait(**kwargs):
                if kwargs.get("timeout") == 40:
                    signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                code = wait(**kwargs)
                proxy.returncode = code
                return code

            proxy.wait.side_effect = interrupted_wait
            return proxy

        # Save the real constructor before patching the runner's Popen.
        real_popen = subprocess.Popen
        def owned_spawn(command, **options):
            with patch("subprocess.Popen", real_popen):
                return spawn(command, **options)

        with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="arm64"), \
             patch("subprocess.run", side_effect=self.build), patch("subprocess.Popen", side_effect=owned_spawn), \
             patch("os.kill") as kill, patch("os.killpg") as kill_group:
            result = MODULE["main"](["--loopback-check"])
            kill.assert_not_called(); kill_group.assert_not_called()
        self.assertIsNotNone(child)
        self.assertIsNotNone(child.returncode)
        self.assertEqual((result["status"], result["cleanup"], result["reason_code"]), ("FAIL", "PASS", "private_worker_interrupted"))
        self.verify_artifact(result)

    def test_root_capture_command_is_fixed_and_authorized_only_after_build(self):
        events = []
        def run(command, **options):
            events.append(command[0])
            if command == ["sudo", "-v"]:
                return subprocess.CompletedProcess(command, 0)
            return self.build(command, **options)
        def spawn(command, **options):
            events.append("worker")
            self.assertEqual(command[:3], ["sudo", "-n", "--"])
            self.assertEqual(command[4:], ["--capture"])
            self.assertEqual(Path(command[3]).name, "packet-probe")
            options["stdout"].write(report_bytes(evidence(True)))
            options["stdout"].flush()
            return Mock(stdin=io.BytesIO(), returncode=0, wait=Mock(return_value=0))
        with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="arm64"), \
             patch("subprocess.run", side_effect=run), patch("subprocess.Popen", side_effect=spawn):
            result = MODULE["main"](["--run"])
        self.assertEqual(events, ["go", "sudo", "worker"])
        self.assertEqual(result["status"], "PASS")  # Synthetic schema test, never a live result.
        self.verify_artifact(result)


if __name__ == "__main__":
    unittest.main()
