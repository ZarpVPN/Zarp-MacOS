#!/usr/bin/env python3
"""Pure Stage 2 adapter guard/config/ownership tests. No system observations or changes."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

SOURCE = Path(__file__).with_name("test-parity-system-adapter.py")
spec = importlib.util.spec_from_file_location("adapter_tests", SOURCE)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class AdapterTests(unittest.TestCase):
    def test_owned_stderr_is_drained_bounded_and_never_reported_raw(self):
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "rb")
        output = adapter.EngineOutput(stream)
        try:
            output.drain()  # Empty live pipe must not block the watchdog.
            for data in (b"FATAL start service: configure ", b"tun: invalid argument private-key-secret\n",
                         *([b"x" * 2048] * 20)):
                os.write(write_fd, data)
                output.drain()
            os.close(write_fd)
            write_fd = None
            output.drain()
            report = output.report()
            self.assertEqual(report["output_bytes"], adapter.ENGINE_OUTPUT_LIMIT)
            self.assertTrue(report["output_capped"])
            self.assertTrue(report["output_eof"])
            self.assertFalse(report["output_read_failed"])
            self.assertEqual(report["error_markers"], ["invalid_argument", "service_start", "tun"])
            self.assertNotIn("private-key-secret", json.dumps(report))
        finally:
            if write_fd is not None:
                os.close(write_fd)
            output.close()
        self.assertTrue(stream.closed)
        self.assertEqual(output.data, b"")

    def test_guardian_diagnostics_reject_raw_data_and_invalid_types(self):
        self.assertEqual(adapter.guardian_diagnostics(None), {})
        report = adapter.guardian_diagnostics({"phase": "private-path", "reason_code": "private-key",
            "exit_code": True, "errno": 256, "output_bytes": adapter.ENGINE_OUTPUT_LIMIT + 1,
            "engine_spawned": "yes", "output_capped": 1, "error_markers": ["tun", "private-key", {}, "tun"],
            "raw_output": "private-key"})
        self.assertEqual(report, {"error_markers": ["tun"]})
        self.assertEqual(adapter.guardian_diagnostics({"exit_code": -9, "errno": 13, "phase": "spawn",
            "reason_code": "ownership", "engine_spawned": False}),
            {"exit_code": -9, "errno": 13, "phase": "spawn", "reason_code": "ownership", "engine_spawned": False})
        for code in (-128, 256, [], "private-token"):
            self.assertNotIn("exit_code", adapter.guardian_diagnostics({"exit_code": code}))

    def test_darwin_direct_interface_host_route_has_no_gateway_line(self):
        observed = adapter.safety.route_fields("""   route to: 198.18.0.2
destination: 198.18.0.2
  interface: utun30000
      flags: <UP,HOST,DONE,STATIC,IFSCOPE>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
""")
        self.assertNotIn("gateway", observed)
        self.assertTrue(adapter.route_matches(observed, observed))

    def prepare_fixture(self, work, producers):
        for name in ("selected-probe", "excluded-probe"):
            (producers / name).write_bytes(b"fake test-only executable, never launched")
        (work / "manifest.json").write_text(json.dumps({"producer_directory": str(producers)}))

    def test_stale_missing_and_symlink_selection_cannot_be_all_processes(self):
        with tempfile.TemporaryDirectory(prefix="zarp-adapter-unit-") as directory:
            work = Path(directory)
            producers = work / "producers"
            producers.mkdir()
            self.prepare_fixture(work, producers)
            ports = {"https": 8443, "udp": 8444, "dns": 8445}
            config = adapter.configuration(work, "utun30000", ports)
            rules = config["route"]["rules"]
            self.assertEqual(rules[-1], {"action": "reject"})
            for rule in rules[:-1]:
                self.assertEqual(rule["process_path"], [str(producers / "selected-probe")])
                self.assertEqual(rule["ip_cidr"], [adapter.MEASUREMENT + "/32"])
                self.assertEqual(rule["override_address"], "127.0.0.1")
            self.assertFalse(config["inbounds"][0]["auto_route"])
            self.assertNotIn("dns", config)
            self.assertEqual(config["outbounds"][0]["bind_interface"], "lo0")
            (producers / "selected-probe").unlink()
            with self.assertRaises(adapter.safety.CheckStopped):
                adapter.configuration(work, "utun30000", ports)
            (producers / "selected-probe").symlink_to(producers / "excluded-probe")
            with self.assertRaises(adapter.safety.CheckStopped):
                adapter.configuration(work, "utun30000", ports)
            (producers / "selected-probe").unlink()
            (producers / "selected-probe").write_bytes(b"fake")
            for interface, changed in [("en0", ports), ("utun-1", ports), ("utun30000", dict(ports, dns=True)),
                                       ("utun30000", dict(ports, dns=0)), ("utun30000", dict(ports, dns=65536))]:
                with self.subTest(interface=interface, ports=changed), self.assertRaises(adapter.safety.CheckStopped):
                    adapter.configuration(work, interface, changed)

    def test_replaced_borrowed_and_partial_route_metadata_is_not_owned(self):
        expected = {"destination": adapter.MEASUREMENT, "interface": "utun30000", "flags": "<UP,HOST,DONE,STATIC>"}
        self.assertTrue(adapter.route_matches(expected, expected))
        for changed in [dict(expected, interface="en0"), dict(expected, gateway="198.18.0.9"),
                        dict(expected, destination="default"), dict(expected, flags="<UP,GHOST>"),
                        dict(expected, flags="<UP,DONE>"), {"destination": adapter.MEASUREMENT, "flags": "HOST"},
                        dict(expected, flags="<UP,HOST,DONE,STATIC,GATEWAY>"), dict(expected, flags="<UP,HOST,DONE,STATIC,REJECT>"),
                        dict(expected, flags="<UP,HOST,DONE,STATIC,BLACKHOLE>"), dict(expected, flags="<UP,HOST,STATIC,DYNAMIC>"),
                        dict(expected, flags="<UP,HOST,DONE,STATIC,STATIC>"), dict(expected, flags="UP,HOST,DONE,STATIC"),
                        dict(expected, interface="utun٣٠٠٠٠"), dict(expected, interface="utun5"),
                        dict(expected, flags="<UP,HOST,DONE>"), dict(expected, flags="<HOST,DONE,STATIC>"),
                        dict(expected, flags="<UP,HOST,DONE,STATIC,IFREF>")]:
            self.assertFalse(adapter.route_matches(changed, expected))
        with tempfile.TemporaryDirectory(prefix="zarp-adapter-unit-") as directory:
            work = Path(directory)
            (work / "route.json").write_text(json.dumps(expected))
            replaced = "destination: 198.18.0.2\ninterface: en0\ngateway: 198.18.0.9\nflags: <UP,HOST>\n"
            with patch.object(adapter.safety, "command", return_value=replaced) as command:
                self.assertTrue(adapter.remove_owned_route(work))
                self.assertEqual(command.call_count, 1)
                self.assertNotIn("delete", command.call_args.args[0])

    def test_direct_route_cleanup_requires_exact_journal_and_preserves_changes(self):
        expected = {"destination": adapter.MEASUREMENT, "interface": "utun30000", "gateway": "", "flags": "<UP,HOST,DONE,STATIC,IFSCOPE>"}
        current = "destination: 198.18.0.2\ninterface: utun30000\nflags: <STATIC,UP,HOST,IFSCOPE,DONE>\n"
        default = "destination: default\ninterface: en0\ngateway: 192.0.2.254\nflags: <UP,GATEWAY,DONE,STATIC>\n"
        with tempfile.TemporaryDirectory(prefix="zarp-adapter-unit-") as directory:
            work = Path(directory)
            (work / "route.json").write_text(json.dumps(expected))
            with patch.object(adapter.safety, "command", side_effect=[current, "deleted fake route", default]) as command:
                self.assertTrue(adapter.remove_owned_route(work))
                self.assertEqual(command.call_count, 3)
                self.assertEqual(command.call_args_list[1].args[0], ["/sbin/route", "-n", "delete", "-host", adapter.MEASUREMENT, "-interface", "utun30000"])
            for changed in (current.replace("utun30000", "utun30001"), current.replace("IFSCOPE,DONE", "IFSCOPE,DONE,REJECT"),
                            current.replace("IFSCOPE,DONE", "DONE"), current.replace("198.18.0.2", "198.18.0.3"),
                            current + "gateway: 192.0.2.254\n", default):
                with patch.object(adapter.safety, "command", return_value=changed) as command:
                    self.assertTrue(adapter.remove_owned_route(work))
                    command.assert_called_once()
                    self.assertNotIn("delete", command.call_args.args[0])
            with patch.object(adapter.safety, "command", side_effect=[current, "", current]):
                self.assertFalse(adapter.remove_owned_route(work), "an owned route still present cannot pass cleanup")
            (work / "route.json").write_text(json.dumps({"destination": adapter.MEASUREMENT, "interface": "utun30000"}))
            with patch.object(adapter.safety, "command") as command:
                with self.assertRaises(adapter.safety.CheckStopped):
                    adapter.remove_owned_route(work)
                command.assert_not_called()

    def test_route_diagnostics_never_echo_raw_fields(self):
        details = adapter.route_observation({"destination": "private-target", "interface": "private-interface",
            "gateway": "private-address", "flags": "<UP,HOST,STATIC,private-secret>"}, "utun30000")
        self.assertEqual(details["known_flags"], ["HOST", "STATIC", "UP"])
        self.assertTrue(details["unknown_flags"])
        self.assertFalse(details["direct_host_route"])
        self.assertNotIn("private-", json.dumps(details))
        for fields in (None, [], {}, {"destination": adapter.MEASUREMENT, "interface": "utun" + "9" * 5000},
                       {"destination": adapter.MEASUREMENT, "interface": "utun30000", "flags": []}):
            self.assertIsNone(adapter.route_identity(fields))

    def test_fake_live_lifecycle_journals_gatewayless_route_and_joins_cleanup(self):
        # This exercises the real worker's journal/check/cleanup order with fake
        # state only. No child, interface, route command or network fixture runs.
        with tempfile.TemporaryDirectory(prefix="zarp-adapter-unit-") as directory:
            work = Path(directory)
            producers = work / "producers"
            producers.mkdir()
            self.prepare_fixture(work, producers)
            state = {"interface": False, "route": False}
            mutations = []

            class FakeFixtures:
                def __init__(self, _work):
                    self.ports = {"https": 8443, "udp": 8444, "dns": 8445}
                    self.counts = dict.fromkeys(self.ports, 0)
                def counters(self):
                    return dict(self.counts)
                def close(self):
                    return True

            def commands(args, **_kwargs):
                if args == ["/sbin/ifconfig", "-l"]:
                    return "lo0 en0" + (" utun30000" if state["interface"] else "")
                if args == ["/sbin/route", "-n", "get", "-host", adapter.MEASUREMENT]:
                    return ("destination: 198.18.0.2\ninterface: utun30000\nflags: <UP,HOST,DONE,STATIC,IFSCOPE>\n" if state["route"] else
                            "destination: default\ninterface: en0\ngateway: 192.0.2.254\nflags: <UP,GATEWAY,DONE,STATIC>\n")
                for verb in ("add", "delete"):
                    if args == ["/sbin/route", "-n", verb, "-host", adapter.MEASUREMENT, "-interface", "utun30000"]:
                        state["route"] = verb == "add"
                        mutations.append(verb)
                        return "fake command completed"
                raise AssertionError("unexpected fake system command")

            def snapshot():
                return {"dns": "fixture", "default": "interface: en0", "services": "(Disconnected)",
                        "routes": "default fixture UGSc en0" + ("\n198.18.0.2 link#42 UHSt utun30000" if state["route"] else "")}

            guardian = Mock()
            guardian.poll.side_effect = lambda: None if state["interface"] else 0
            def launch(*_args, **_kwargs):
                state["interface"] = True
                adapter.write_json(work / "engine-ready.json", {"pid": 123})
                return guardian
            def stop(child, **_kwargs):
                self.assertIs(child, guardian)
                self.assertFalse(state["route"], "route must be removed before its owned engine stops")
                state["interface"] = False
                adapter.write_json(work / "engine-cleanup.json", {"engine_stopped": True})
            def probe(_work, name, kind, fixtures, live):
                self.assertTrue(live)
                if name == "selected-probe":
                    fixtures.counts[kind] += 1
                    return True
                return False

            output = io.StringIO()
            with patch.object(adapter, "validate_work"), patch.object(adapter, "Fixtures", FakeFixtures), \
                 patch.object(adapter.safety, "network_snapshot", side_effect=snapshot), patch.object(adapter.safety, "guard"), \
                 patch.object(adapter.safety, "command", side_effect=commands), patch.object(adapter.signal, "signal"), \
                 patch.object(adapter.os, "urandom", return_value=b"\0\0"), \
                 patch.object(adapter.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                 patch.object(adapter.subprocess, "Popen", side_effect=launch), patch.object(adapter, "stop_child", side_effect=stop), \
                 patch.object(adapter, "probe", side_effect=probe), redirect_stdout(output):
                self.assertEqual(adapter.execute(work, True), 0)
            report = json.loads(output.getvalue().removeprefix("RESULT "))
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["cleanup"], "PASS")
            self.assertTrue(report["network_baseline_matches"])
            self.assertEqual(len(report["checks"]), 6)
            self.assertTrue(report["route_ownership"]["direct_host_route"])
            self.assertFalse(report["route_ownership"]["gateway_displayed"])
            self.assertEqual(mutations, ["add", "delete"])
            self.assertEqual(state, {"interface": False, "route": False})
            self.assertEqual(json.loads((work / "route.json").read_text())["gateway"], "")
            self.assertFalse(producers.exists())

    def test_unknown_production_state_prevents_any_tun_child_or_route_change(self):
        with tempfile.TemporaryDirectory(prefix="zarp-adapter-unit-") as directory:
            work = Path(directory)
            producers = work / "producers"
            producers.mkdir()
            self.prepare_fixture(work, producers)

            class FakeFixtures:
                def __init__(self, _work):
                    pass
                def close(self):
                    return True

            output = io.StringIO()
            with patch.object(adapter, "validate_work"), patch.object(adapter, "Fixtures", FakeFixtures), \
                 patch.object(adapter.safety, "network_snapshot", return_value={}), \
                 patch.object(adapter.safety, "guard", side_effect=adapter.safety.CheckStopped("production state is unknown", code="production_status_unknown", details={
                     "status_error_code": "ipc_timeout", "ipc_phase": "await_response", "peer_pid": 123, "response_bytes": 0,
                     "errno": True, "response": "private-key-or-token", "endpoint": "private-address"})), \
                 patch.object(adapter.subprocess, "Popen", side_effect=AssertionError("no system child allowed")) as child, \
                 patch.object(adapter.safety, "command", side_effect=AssertionError("no route command allowed")) as command, \
                 patch.object(adapter.signal, "signal"), redirect_stdout(output):
                self.assertEqual(adapter.execute(work, True), 3)
                child.assert_not_called()
                command.assert_not_called()
            result = json.loads(output.getvalue().removeprefix("RESULT "))
            self.assertEqual(result["status"], "SKIP")
            self.assertEqual(result["cleanup"], "PASS")
            self.assertFalse(result["live_test_started"])
            self.assertFalse(producers.exists())
            self.assertEqual(result["details"], {"status_error_code": "ipc_timeout", "ipc_phase": "await_response",
                                                  "peer_pid": 123, "response_bytes": 0})
            self.assertNotIn("private-key-or-token", output.getvalue())
            self.assertNotIn("private-address", output.getvalue())

    def test_blocker_details_refuse_private_values_wrong_types_and_unbounded_numbers(self):
        for values in ({"status_error_code": "private-token", "ipc_phase": ["private-token"], "peer_pid": True,
                        "response_bytes": 262145, "errno": -1},
                       {"status_error_code": [], "ipc_phase": "private-target", "peer_pid": 2147483648,
                        "response_bytes": -1, "errno": 256}):
            error = adapter.safety.CheckStopped("unused", code="production_status_unknown", details=values)
            self.assertEqual(adapter.production_blocker_details(error), {})
        error = adapter.safety.CheckStopped("unused", code="production_status_unknown", details={
            "status_error_code": "ipc_socket_error", "errno": 61, "raw_response": "private-token"})
        self.assertEqual(adapter.production_blocker_details(error), {"status_error_code": "ipc_socket_error", "errno": 61})
        error.code = "foreign_tunnel_routes"
        self.assertEqual(adapter.production_blocker_details(error), {})

    def test_parent_death_stops_only_the_guardians_owned_engine(self):
        with tempfile.TemporaryDirectory(prefix="zarp-adapter-unit-") as directory:
            work = Path(directory)
            (work / "live-authorization.json").write_text(json.dumps({"worker_pid": 123, "interface": "utun30000"}))
            child = Mock(pid=4242, returncode=0)
            child.poll.side_effect = [None, None, 0]
            with patch.object(adapter, "validate_work"), patch.object(adapter.os, "geteuid", return_value=0), \
                 patch.object(adapter.os, "getppid", side_effect=[123, 123, 1]), \
                 patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=0)), \
                 patch.object(adapter.safety, "network_snapshot", return_value={}), patch.object(adapter.safety, "guard"), \
                 patch.object(adapter.safety, "command", return_value="en0 lo0"), patch.object(adapter.signal, "signal"), \
                 patch.object(adapter, "EngineOutput") as output, \
                 patch.object(adapter, "remove_owned_route", return_value=True) as cleanup, \
                 patch.object(adapter.subprocess, "Popen", return_value=child) as spawn:
                output.return_value.report.return_value = {}
                self.assertEqual(adapter.engine_guard(work), 0)
                self.assertEqual(spawn.call_args.args[0], [str(work / "engine"), "run", "-c", str(work / "frontend.json")])
                child.terminate.assert_called_once()
                child.kill.assert_not_called()
                child.wait.assert_called_once_with(timeout=3)
                cleanup.assert_called_once_with(work)
            self.assertTrue(json.loads((work / "engine-cleanup.json").read_text())["engine_stopped"])

    def test_guardian_refusal_records_phase_without_starting_a_child(self):
        with tempfile.TemporaryDirectory(prefix="zarp-adapter-unit-") as directory:
            work = Path(directory)
            (work / "live-authorization.json").write_text(json.dumps({"worker_pid": 123, "interface": "utun30000"}))
            with patch.object(adapter, "validate_work"), patch.object(adapter.os, "geteuid", return_value=0), \
                 patch.object(adapter.os, "getppid", return_value=123), patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=0)), \
                 patch.object(adapter.signal, "signal"), patch.object(adapter.safety, "network_snapshot", return_value={}), \
                 patch.object(adapter.safety, "guard", side_effect=adapter.safety.CheckStopped("private-token", code="production_status_unknown")), \
                 patch.object(adapter.safety, "command") as command, patch.object(adapter.subprocess, "Popen") as child:
                adapter.engine_guard(work)
                command.assert_not_called()
                child.assert_not_called()
            report = json.loads((work / "engine-cleanup.json").read_text())
            self.assertTrue(report["engine_stopped"])
            self.assertEqual(report["diagnostics"], {"phase": "guard", "reason_code": "production_status_unknown", "engine_spawned": False})
            self.assertNotIn("private-token", json.dumps(report))

    def test_early_engine_exit_records_exit_code_and_only_fixed_markers(self):
        with tempfile.TemporaryDirectory(prefix="zarp-adapter-unit-") as directory:
            work = Path(directory)
            (work / "live-authorization.json").write_text(json.dumps({"worker_pid": 123, "interface": "utun30000"}))
            child = Mock(pid=4242, returncode=23)
            child.poll.return_value = 23
            with patch.object(adapter, "validate_work"), patch.object(adapter.os, "geteuid", return_value=0), \
                 patch.object(adapter.os, "getppid", return_value=123), patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=0)), \
                 patch.object(adapter.signal, "signal"), patch.object(adapter.safety, "network_snapshot", return_value={}), \
                 patch.object(adapter.safety, "guard"), patch.object(adapter.safety, "command", return_value="en0 lo0"), \
                 patch.object(adapter, "remove_owned_route", return_value=True), \
                 patch.object(adapter, "EngineOutput") as output, patch.object(adapter.subprocess, "Popen", return_value=child) as spawn:
                output.return_value.report.return_value = {"error_markers": ["tun", "invalid_argument"], "raw": "secret"}
                adapter.engine_guard(work)
                self.assertEqual(spawn.call_args.kwargs["stderr"], adapter.subprocess.PIPE)
                child.terminate.assert_not_called()
                child.kill.assert_not_called()
                output.return_value.close.assert_called_once()
            report = json.loads((work / "engine-cleanup.json").read_text())
            self.assertTrue(report["engine_stopped"])
            self.assertEqual(report["diagnostics"], {"phase": "running", "engine_spawned": True, "exit_code": 23,
                "error_markers": ["invalid_argument", "tun"]})
            self.assertNotIn("secret", json.dumps(report))

    def test_worker_startup_failure_surfaces_redacted_diagnostics_without_traffic_or_route_mutations(self):
        with tempfile.TemporaryDirectory(prefix="zarp-adapter-unit-") as directory:
            work = Path(directory)
            producers = work / "producers"
            producers.mkdir()
            self.prepare_fixture(work, producers)
            class FakeFixtures:
                def __init__(self, _work):
                    self.ports = {"https": 8443, "udp": 8444, "dns": 8445}
                def close(self):
                    return True
            snapshot = {"default": "interface: en0", "dns": "fixture", "routes": "default fixture UGSc en0"}
            def commands(args, **_kwargs):
                if args == ["/sbin/ifconfig", "-l"]:
                    return "lo0 en0"
                if args == ["/sbin/route", "-n", "get", "-host", adapter.MEASUREMENT]:
                    return "destination: default\ninterface: en0\n"
                raise AssertionError("no route mutation allowed on startup failure")
            child = Mock()
            child.poll.return_value = 1
            def launch(*_args, **_kwargs):
                adapter.write_json(work / "engine-cleanup.json", {"engine_stopped": True, "diagnostics": {
                    "phase": "running", "engine_spawned": True, "exit_code": 23,
                    "error_markers": ["tun", "private-token"], "stderr": "private-token"}})
                return child
            output = io.StringIO()
            with patch.object(adapter, "validate_work"), patch.object(adapter, "Fixtures", FakeFixtures), \
                 patch.object(adapter.safety, "network_snapshot", return_value=snapshot), patch.object(adapter.safety, "guard"), \
                 patch.object(adapter.safety, "command", side_effect=commands), patch.object(adapter.signal, "signal"), \
                 patch.object(adapter.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                 patch.object(adapter.subprocess, "Popen", side_effect=launch), patch.object(adapter, "stop_child"), \
                 patch.object(adapter, "probe") as probe, redirect_stdout(output):
                self.assertEqual(adapter.execute(work, True), 1)
                probe.assert_not_called()
            report = json.loads(output.getvalue().removeprefix("RESULT "))
            self.assertEqual(report["status"], "FAIL")
            self.assertEqual(report["reason_code"], "startup")
            self.assertEqual(report["cleanup"], "PASS")
            self.assertEqual(report["checks"], [])
            self.assertTrue(report["network_baseline_matches"])
            self.assertEqual(report["engine_diagnostics"], {"phase": "running", "engine_spawned": True,
                "exit_code": 23, "error_markers": ["tun"]})
            self.assertNotIn("private-token", output.getvalue())


if __name__ == "__main__":
    unittest.main()
