"""Offline lifecycle tests. No QEMU process, VM, or network service is launched."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from hunt_lab import runtime

PORTS = dict(qmp_port=31001, vnc_port=31002, console_websocket_port=31003,
             lab_port=31004, arkime_port=31005, kibana_port=31006)


class ScriptedSocket:
    def __init__(self, messages):
        self.stream = io.BytesIO(b"".join(json.dumps(message).encode() + b"\r\n" for message in messages))
        self.requests = []
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def makefile(self, mode):
        return self.stream

    def sendall(self, payload):
        self.requests.append(json.loads(payload))

    def close(self):
        self.closed = True


def qmp_script(name, tail=()):
    return ScriptedSocket([
        {"QMP": {"version": {}, "capabilities": []}},
        {"return": {}, "id": 1},
        {"return": {"name": name}, "id": 2},
        *tail,
    ])


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hermes-guest-tests-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.state_dir = self.root / "lifecycle"
        self.qemu = self.root / ("qemu-system-x86_64.exe" if os.name == "nt" else "qemu-system-x86_64")
        self.qemu.write_bytes(b"not executed")
        self.qemu.chmod(0o700)
        self.disk = self.root / "boot,prepared.qcow2"
        self.disk.write_bytes(b"QFI\xfb" + b"\0" * 128)
        self.seed = self.root / "cloud seed.iso"
        with self.seed.open("wb") as stream:
            stream.seek(32769)
            stream.write(b"CD001")

    def record(self, state="running", pid=424242):
        home, name = runtime._state_location(self.state_dir, runtime.PROFILE)
        record = dict(version=runtime.STATE_VERSION, profile=runtime.PROFILE,
                      vm_name=name, pid=pid, state=state, reason="qmp_running",
                      memory_mib=4096, cpus=2, accel="tcg", launch_started=0, **PORTS)
        runtime._urls(record)
        runtime._save(home, record)
        return home, name, record

    def start(self, **overrides):
        values = dict(state_dir=self.state_dir, qemu=self.qemu, disk=self.disk,
                      seed=self.seed, memory_mib=4096, cpus=2, accel="tcg")
        values.update(overrides)
        return runtime.invoke("start", **values)

    def launch_boundaries(self, stack, running=True):
        stack.enter_context(mock.patch.object(runtime, "_available_memory_mib", return_value=16384))
        stack.enter_context(mock.patch.object(runtime, "_reserved_ports", return_value=contextlib.nullcontext(PORTS.copy())))
        client = mock.Mock()
        client.execute.return_value = {"running": running, "status": "running" if running else "prelaunch"}
        stack.enter_context(mock.patch.object(runtime, "_owned", return_value=contextlib.nullcontext(client)))
        popen = stack.enter_context(mock.patch.object(runtime.subprocess, "Popen"))
        popen.return_value.pid = 424242
        popen.return_value.poll.return_value = None
        return popen, client

    def test_invalid_profile_is_rejected_without_echo_or_process(self):
        private = "../private-auth-value"
        with mock.patch.object(runtime.subprocess, "Popen") as popen:
            result = self.start(profile=private)
        self.assertEqual((result["state"], result["reason"]), ("error", "invalid_profile"))
        self.assertIsNone(result["profile"])
        self.assertNotIn(private, json.dumps(result))
        self.assertFalse(self.state_dir.exists())
        popen.assert_not_called()

    def test_state_inside_workspace_is_rejected_without_creating_it(self):
        forbidden = runtime.WORKSPACE_ROOT / "uncreated-runtime-test-state"
        with mock.patch.object(runtime.subprocess, "Popen") as popen:
            result = self.start(state_dir=forbidden)
        self.assertEqual(result["reason"], "state_inside_workspace")
        self.assertNotIn(str(forbidden), json.dumps(result))
        popen.assert_not_called()

    def test_state_inside_git_is_rejected(self):
        checkout = self.root / "checkout"
        checkout.mkdir()
        (checkout / ".git").mkdir()
        result = self.start(state_dir=checkout / "state")
        self.assertEqual((result["state"], result["reason"]), ("error", "state_inside_git"))
        self.assertFalse((checkout / "state").exists())

    def test_root_state_path_is_rejected(self):
        result = self.start(state_dir=Path(self.root.anchor))
        self.assertEqual(result["reason"], "invalid_state_dir")

    def test_busy_lifecycle_lock_refuses_concurrent_start(self):
        home, _ = runtime._state_location(self.state_dir, runtime.PROFILE)
        with runtime._locked(home), mock.patch.object(runtime.subprocess, "Popen") as popen:
            result = self.start()
        self.assertEqual((result["state"], result["reason"]), ("error", "busy"))
        popen.assert_not_called()

    def test_external_data_file_qcow2_is_refused(self):
        header = bytearray(104)
        header[:4] = b"QFI\xfb"
        header[4:8] = (3).to_bytes(4, "big")
        header[72:80] = (4).to_bytes(8, "big")
        self.disk.write_bytes(header)
        with mock.patch.object(runtime.subprocess, "Popen") as popen:
            result = self.start()
        self.assertEqual(result["reason"], "invalid_disk")
        popen.assert_not_called()

    def test_missing_or_invalid_assets_never_echo_path(self):
        private = self.root / "private-auth-value.qcow2"
        with mock.patch.object(runtime.subprocess, "Popen") as popen:
            result = self.start(disk=private)
        self.assertEqual(result["reason"], "invalid_disk")
        self.assertNotIn("private-auth-value", json.dumps(result))
        popen.assert_not_called()
        self.disk.write_bytes(b"not a disk")
        self.assertEqual(self.start()["reason"], "invalid_disk")
        self.disk.write_bytes(b"QFI\xfb")
        self.seed.write_bytes(b"not an ISO")
        self.assertEqual(self.start()["reason"], "invalid_seed")

    def test_only_explicit_qemu_executable_is_accepted(self):
        other = self.root / "shell.exe"
        other.write_bytes(b"not executed")
        with mock.patch.object(runtime.subprocess, "Popen") as popen:
            result = self.start(qemu=other)
        self.assertEqual(result["reason"], "invalid_qemu")
        popen.assert_not_called()

    def test_invalid_memory_cpus_and_accel_do_not_launch(self):
        with mock.patch.object(runtime.subprocess, "Popen") as popen:
            for changes, reason in (({"memory_mib": 0}, "invalid_memory"),
                                    ({"memory_mib": True}, "invalid_memory"),
                                    ({"cpus": 0}, "invalid_cpus"),
                                    ({"accel": "private-auth-value"}, "invalid_accel")):
                result = self.start(**changes)
                self.assertEqual(result["reason"], reason)
                self.assertNotIn("private-auth-value", json.dumps(result))
        popen.assert_not_called()

    def test_insufficient_available_physical_memory_refuses_launch(self):
        with mock.patch.object(runtime, "_available_memory_mib", return_value=4096), \
             mock.patch.object(runtime.subprocess, "Popen") as popen:
            result = self.start()
        self.assertEqual((result["state"], result["reason"]), ("error", "insufficient_memory"))
        self.assertNotIn(str(self.disk), json.dumps(result))
        popen.assert_not_called()
        self.assertFalse((self.state_dir / runtime.PROFILE / "state.json").exists())

    def test_unavailable_memory_measurement_refuses_launch(self):
        with mock.patch.object(runtime, "_available_memory_mib", side_effect=runtime.RuntimeFailure("memory_unavailable")), \
             mock.patch.object(runtime.subprocess, "Popen") as popen:
            result = self.start()
        self.assertEqual((result["state"], result["reason"]), ("error", "memory_unavailable"))
        popen.assert_not_called()

    def test_start_persists_stable_pid_and_duplicate_refuses(self):
        before = self.disk.read_bytes()
        with contextlib.ExitStack() as stack:
            popen, _ = self.launch_boundaries(stack)
            result = self.start()
            duplicate = self.start()
        self.assertEqual((result["state"], result["reason"]), ("running", "qmp_running"))
        self.assertEqual(result["pid"], 424242)
        stored = json.loads((self.state_dir / runtime.PROFILE / "state.json").read_text())
        self.assertEqual(stored["pid"], result["pid"])
        self.assertEqual(stored["vm_name"], result["vm_name"])
        self.assertEqual((duplicate["state"], duplicate["reason"]), ("error", "already_running"))
        popen.assert_called_once()
        self.assertIs(popen.call_args.kwargs["shell"], False)
        self.assertEqual(self.disk.read_bytes(), before)
        self.assertFalse(any(key in stored for key in ("env", "password", "key", "qemu", "disk", "seed")))
        for key in runtime.PORT_KEYS:
            self.assertEqual(result[key], PORTS[key])
        self.assertEqual(result["console_websocket_url"], "ws://127.0.0.1:31003")
        self.assertEqual(result["lab_url"], "http://127.0.0.1:31004")
        self.assertEqual(result["arkime_url"], "http://127.0.0.1:31005")
        self.assertEqual(result["kibana_url"], "http://127.0.0.1:31006")

    def test_a_vm_launched_before_the_kibana_forward_stays_manageable_without_a_kibana_url(self):
        home, _, record = self.record()
        legacy = {key: value for key, value in record.items() if key not in ("kibana_port", "kibana_url")}
        (home / "state.json").write_text(json.dumps(legacy))
        with mock.patch.object(runtime, "_owned", side_effect=runtime.QMPUnavailable), \
             mock.patch.object(runtime, "_process_alive", return_value=False):
            result = runtime.invoke("status", state_dir=self.state_dir)
        self.assertEqual((result["lab_url"], result["kibana_url"], result["kibana_port"]), ("http://127.0.0.1:31004", None, None))
        self.assertNotEqual(result["reason"], "invalid_state")

    def test_qmp_prelaunch_is_starting_not_fake_running(self):
        with contextlib.ExitStack() as stack:
            self.launch_boundaries(stack, running=False)
            result = self.start()
        self.assertEqual((result["state"], result["reason"]), ("starting", "qmp_not_running"))

    def test_unverified_live_process_blocks_duplicate(self):
        self.record()
        with mock.patch.object(runtime, "_owned", side_effect=runtime.QMPUnavailable), \
             mock.patch.object(runtime, "_process_alive", return_value=True), \
             mock.patch.object(runtime.subprocess, "Popen") as popen:
            result = self.start()
        self.assertEqual(result["reason"], "existing_instance_unverified")
        popen.assert_not_called()

    def test_interrupted_launch_intent_blocks_duplicate(self):
        self.record(state="starting", pid=None)
        with mock.patch.object(runtime, "_owned", side_effect=runtime.QMPUnavailable), \
             mock.patch.object(runtime.subprocess, "Popen") as popen:
            result = self.start()
        self.assertEqual(result["reason"], "existing_instance_unverified")
        popen.assert_not_called()

    def test_ownership_mismatch_refuses_stop_and_never_signals_pid(self):
        _, _, record = self.record()
        transport = qmp_script("another-owners-vm")
        with mock.patch.object(runtime.socket, "create_connection", return_value=transport) as connect, \
             mock.patch.object(runtime.os, "kill") as kill, \
             mock.patch.object(runtime, "_process_alive") as alive:
            result = runtime.invoke("stop", state_dir=self.state_dir)
        self.assertEqual((result["state"], result["reason"]), ("error", "ownership_mismatch"))
        self.assertEqual([message["execute"] for message in transport.requests], ["qmp_capabilities", "query-name"])
        connect.assert_called_once_with(("127.0.0.1", record["qmp_port"]), runtime.QMP_TIMEOUT_SECONDS)
        kill.assert_not_called()
        alive.assert_not_called()
        self.assertTrue(transport.closed)
        self.assertNotIn("another-owners-vm", json.dumps(result))

    def test_status_checks_live_qmp_name_not_just_pid_or_json(self):
        _, name, _ = self.record(state="starting")
        transport = qmp_script(name, [{"event": "RESUME"}, {"return": {"running": True, "status": "running"}, "id": 3}])
        with mock.patch.object(runtime.socket, "create_connection", return_value=transport), \
             mock.patch.object(runtime, "_process_alive") as alive:
            result = runtime.invoke("status", state_dir=self.state_dir)
        self.assertEqual(result["state"], "running")
        self.assertEqual([request["execute"] for request in transport.requests],
                         ["qmp_capabilities", "query-name", "query-status"])
        alive.assert_not_called()

    def test_stale_pid_with_wrong_qmp_owner_is_not_stopped_or_signaled(self):
        self.record()
        transport = qmp_script("foreign")
        with mock.patch.object(runtime.socket, "create_connection", return_value=transport), \
             mock.patch.object(runtime, "_process_alive", return_value=False) as alive:
            result = runtime.invoke("status", state_dir=self.state_dir)
        self.assertEqual(result["reason"], "ownership_mismatch")
        alive.assert_not_called()

    def test_dead_process_and_unreachable_qmp_are_stopped(self):
        self.record()
        with mock.patch.object(runtime, "_owned", side_effect=runtime.QMPUnavailable), \
             mock.patch.object(runtime, "_process_alive", return_value=False):
            result = runtime.invoke("status", state_dir=self.state_dir)
        self.assertEqual((result["state"], result["reason"]), ("stopped", "process_exited"))
        self.assertIsNone(result["pid"])

    def test_live_pid_without_qmp_is_not_reported_running(self):
        self.record()
        with mock.patch.object(runtime, "_owned", side_effect=runtime.QMPUnavailable), \
             mock.patch.object(runtime, "_process_alive", return_value=True):
            result = runtime.invoke("status", state_dir=self.state_dir)
        self.assertEqual((result["state"], result["reason"]), ("error", "qmp_unavailable"))

    def test_stop_requests_verified_qmp_powerdown_but_never_hard_kills(self):
        self.record()
        client = mock.Mock()
        with mock.patch.object(runtime, "_owned", return_value=contextlib.nullcontext(client)), \
             mock.patch.object(runtime, "STOP_WAIT_SECONDS", 0), \
             mock.patch.object(runtime.os, "kill") as kill:
            result = runtime.invoke("stop", state_dir=self.state_dir)
        self.assertEqual((result["state"], result["reason"]), ("stopping", "awaiting_powerdown"))
        client.execute.assert_called_once_with("system_powerdown")
        kill.assert_not_called()

    def test_stop_only_reports_stopped_after_process_exit(self):
        self.record()
        client = mock.Mock()
        with mock.patch.object(runtime, "_owned", side_effect=[contextlib.nullcontext(client), runtime.QMPUnavailable]), \
             mock.patch.object(runtime, "_process_alive", return_value=False):
            result = runtime.invoke("stop", state_dir=self.state_dir)
        self.assertEqual((result["state"], result["reason"]), ("stopped", "powered_down"))
        client.execute.assert_called_once_with("system_powerdown")

    def test_start_qmp_timeout_keeps_owned_pid_and_never_kills(self):
        with contextlib.ExitStack() as stack:
            popen, _ = self.launch_boundaries(stack)
            stack.enter_context(mock.patch.object(runtime, "_owned", side_effect=runtime.QMPUnavailable))
            stack.enter_context(mock.patch.object(runtime, "START_WAIT_SECONDS", 0))
            kill = stack.enter_context(mock.patch.object(runtime.os, "kill"))
            result = self.start()
        self.assertEqual(result["reason"], "qmp_start_timeout")
        self.assertEqual(result["pid"], popen.return_value.pid)
        stored = json.loads((self.state_dir / runtime.PROFILE / "state.json").read_text())
        self.assertEqual(stored["state"], "starting")
        kill.assert_not_called()

    def test_launch_failure_does_not_echo_os_error(self):
        with contextlib.ExitStack() as stack:
            popen, _ = self.launch_boundaries(stack)
            popen.side_effect = OSError("private-auth-value and sensitive host path")
            result = self.start()
        self.assertEqual((result["state"], result["reason"]), ("error", "launch_failed"))
        self.assertNotIn("private-auth-value", json.dumps(result))

    def test_corrupt_or_foreign_state_is_refused_without_echo(self):
        home, _, _ = self.record()
        (home / "state.json").write_text('{"private-auth-value": "not lifecycle metadata"}')
        result = runtime.invoke("status", state_dir=self.state_dir)
        self.assertEqual(result["reason"], "invalid_state")
        self.assertNotIn("private-auth-value", json.dumps(result))

    def test_argv_has_only_loopback_user_networking_and_fixed_guest_devices(self):
        home, _, record = self.record()
        argv = runtime.build_argv(self.qemu, self.disk, self.seed, record, home / "serial.log")
        for prohibited in ("-net", "-nic", "-fsdev", "-virtfs", "-spice", "-daemonize", "-snapshot", "-no-reboot"):
            self.assertNotIn(prohibited, argv)
        joined = " ".join(argv)
        for prohibited in ("bridge", "tap,", "hostfwd=tcp::", "0.0.0.0", "[::]", "9200", "-:22", "usb-host", "vfio", "clipboard"):
            self.assertNotIn(prohibited, joined)
        net = argv[argv.index("-netdev") + 1]
        self.assertEqual(net, "user,id=net0,hostfwd=tcp:127.0.0.1:31004-:8765,hostfwd=tcp:127.0.0.1:31005-:8005,"
                              "hostfwd=tcp:127.0.0.1:31006-:5601")
        self.assertEqual(argv[argv.index("-vnc") + 1], "127.0.0.1:25102,websocket=127.0.0.1:31003")
        self.assertEqual(argv[argv.index("-qmp") + 1], "tcp:127.0.0.1:31001,server=on,wait=off")
        self.assertEqual(argv[argv.index("-accel") + 1], "tcg")
        self.assertEqual(argv[argv.index("-machine") + 1], "q35")
        self.assertIn("-nodefaults", argv)
        self.assertIn("-no-user-config", argv)
        self.assertIn("virtio-net-pci,netdev=net0", argv)
        blocks = [json.loads(argv[index + 1]) for index, value in enumerate(argv) if value == "-blockdev"]
        self.assertEqual(blocks[0]["filename"], str(self.disk))
        self.assertEqual(blocks[1]["driver"], "qcow2")
        self.assertIsNone(blocks[1]["backing"])
        self.assertTrue(blocks[2]["read-only"])
        self.assertTrue(blocks[3]["read-only"])

    def test_qmp_arbitrary_command_is_not_available(self):
        transport = ScriptedSocket([{"QMP": {}}, {"return": {}, "id": 1}])
        with mock.patch.object(runtime.socket, "create_connection", return_value=transport):
            client = runtime.QMPClient(PORTS["qmp_port"])
            try:
                with self.assertRaises(runtime.QMPUnavailable):
                    client.execute("human-monitor-command")
            finally:
                client.close()
        self.assertEqual([request["execute"] for request in transport.requests], ["qmp_capabilities"])

    def test_cli_errors_are_json_and_nonzero_without_echo(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = runtime.main(["--state-dir", str(self.state_dir), "--profile", "private-auth-value", "status"])
        self.assertEqual(code, 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["reason"], "invalid_profile")
        self.assertNotIn("private-auth-value", output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = runtime.main(["--private-auth-value"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["reason"], "invalid_arguments")
        self.assertNotIn("private-auth-value", output.getvalue())

    def test_cli_status_without_vm_is_stopped_and_zero(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = runtime.main(["--state-dir", str(self.state_dir), "--profile", runtime.PROFILE, "status"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["state"], "stopped")


if __name__ == "__main__":
    unittest.main()
