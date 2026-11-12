"""Benign local process tests only; never lab transports or credentials."""
import copy
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import benchmark_process as transport


EXECUTABLE = os.path.realpath(sys.executable)
SUPPORTED = os.name == "nt" or (sys.platform.startswith("linux") and
                                hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"))


def child_env():
    # Explicit, secret-free platform prerequisites; never copy the parent env.
    return {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "TEMP", "TMP")
            if os.name == "nt" and key in os.environ}


def run_child(source, **kwargs):
    settings = {"env": child_env(), "timeout": 10, "max_output_bytes": 4096}
    settings.update(kwargs)
    return transport.run_process([EXECUTABLE, "-I", "-S", "-c", source], **settings)


@unittest.skipUnless(SUPPORTED, "Owned transport requires Windows jobs or Linux pidfd/proc")
class ProcessTests(unittest.TestCase):
    def test_actual_stdout_stdin_and_explicit_environment(self):
        source = ("import os,sys; data=sys.stdin.buffer.read(); "
                  "sys.stdout.buffer.write(data+b'|'+os.environ['BENCH_TEST'].encode()); "
                  "sys.stderr.write('PRIVATE_DIAGNOSTIC')")
        env = child_env()
        env["BENCH_TEST"] = "bounded"
        with mock.patch.dict(os.environ, {"BENCH_SECRET_NOT_FOR_CHILD": "secret"}):
            result = run_child(source, input_bytes=b"hello", env=env)
            isolation = run_child("import os; print('BENCH_SECRET_NOT_FOR_CHILD' in os.environ)")
        self.assertEqual(result["status"], "succeeded", result["failure_reason"])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"], b"hello|bounded")
        self.assertEqual(isolation["stdout"].strip(), b"False")
        self.assertNotIn("PRIVATE_DIAGNOSTIC", repr(result))
        self.assertEqual(set(result["process_identity"]), {"pid", "creation_utc", "process_group_id"})
        self.assertIs(result["local_stopped"], True)

    def test_nonzero_exit_is_not_success(self):
        result = run_child("raise SystemExit(7)")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["exit_code"], 7)
        self.assertEqual(result["failure_reason"], "process_exit_nonzero")

    def test_timeout_and_output_cap_are_unknown(self):
        timeout = run_child("import time; time.sleep(30)", timeout=0.5)
        self.assertEqual(timeout["status"], "unknown")
        self.assertEqual(timeout["failure_reason"], "process_timeout")
        # Remote effects stay unknown, but verified local teardown releases ownership.
        self.assertIs(timeout["local_stopped"], True)
        capped = run_child("import sys; sys.stdout.buffer.write(b'x'*65536)", max_output_bytes=128)
        self.assertEqual(capped["status"], "unknown")
        self.assertEqual(capped["failure_reason"], "process_output_limit")
        self.assertEqual(capped["stdout"], b"")

    def test_exact_output_cap_is_allowed(self):
        result = run_child("import sys; sys.stdout.buffer.write(b'x'*128)", max_output_bytes=128)
        self.assertEqual(result["status"], "succeeded", result["failure_reason"])
        self.assertEqual(len(result["stdout"]), 128)

    def test_persisted_identity_precedes_any_target_action(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "started"
            identities = []

            def persist(identity):
                self.assertFalse(marker.exists())
                identities.append(copy.deepcopy(identity))
                time.sleep(0.1)
                self.assertFalse(marker.exists())

            result = run_child("from pathlib import Path; Path({!r}).write_text('ran')".format(str(marker)),
                               on_started=persist)
            self.assertEqual(result["status"], "succeeded", result["failure_reason"])
            self.assertTrue(marker.exists())
            self.assertEqual(identities, [result["process_identity"]])

    def test_persistence_failure_prevents_target_action(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "must-not-exist"

            def fail(identity):
                raise RuntimeError("PRIVATE_CALLBACK_DIAGNOSTIC")

            result = run_child("from pathlib import Path; Path({!r}).write_text('ran')".format(str(marker)),
                               on_started=fail)
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["failure_reason"], "process_persistence_failed")
            self.assertFalse(marker.exists())
            self.assertNotIn("PRIVATE_CALLBACK_DIAGNOSTIC", repr(result))

    def test_persistence_timeout_prevents_target_action(self):
        release = threading.Event()
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "must-not-exist"
            try:
                result = run_child("from pathlib import Path; Path({!r}).write_text('ran')".format(str(marker)),
                                   on_started=lambda identity: release.wait(10), timeout=0.3)
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["failure_reason"], "process_persistence_failed")
                self.assertFalse(marker.exists())
            finally:
                release.set()

    def test_identity_and_group_mismatch_do_not_kill_owner(self):
        rejected = []

        def persist(identity):
            changed = dict(identity, creation_utc="2000-01-01T00:00:00.0000000+00:00")
            rejected.append(transport.stop_owned(changed))
            changed = dict(identity, process_group_id="unowned-group")
            rejected.append(transport.stop_owned(changed))

        result = run_child("print('survived')", on_started=persist)
        self.assertEqual(result["status"], "succeeded", result["failure_reason"])
        self.assertEqual(result["stdout"].strip(), b"survived")
        self.assertEqual([entry["status"] for entry in rejected], ["unknown", "unknown"])

    def test_stop_from_another_controller_process(self):
        # Separate process verifies this is OS ownership, not an in-memory PID set.
        import json
        records = []

        def persist(identity):
            source = ("import json,sys; sys.path.insert(0, {!r}); "
                      "import benchmark_process as p; "
                      "r=p.stop_owned(json.loads(sys.stdin.read())); "
                      "print(json.dumps([r['status'], r['local_stopped']]))").format(
                          str(Path(transport.__file__).resolve().parent))
            result = subprocess.run([EXECUTABLE, "-I", "-S", "-c", source],
                                    input=json.dumps(identity).encode(), stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, env=child_env(), timeout=10, check=False)
            records.append(json.loads(result.stdout))

        result = run_child("import time; time.sleep(30)", on_started=persist, timeout=5)
        self.assertEqual(records, [["succeeded", True]])
        # An external stop is never an ordinary nonzero exit.
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["failure_reason"], "process_stopped_externally")
        self.assertIsNone(result["exit_code"])
        self.assertIs(result["local_stopped"], True)

    def test_child_exiting_with_reserved_code_is_not_an_ordinary_failure(self):
        # os._exit takes a signed C int; this is the same 32-bit exit status.
        result = run_child("import os; os._exit({})".format(transport._STOP_EXIT_CODE - (1 << 32))
                           if os.name == "nt" else "raise SystemExit(3)")
        if os.name == "nt":
            self.assertEqual((result["status"], result["failure_reason"]),
                             ("unknown", "process_stopped_externally"))
        else:
            self.assertEqual(result["failure_reason"], "process_exit_nonzero")
        self.assertIs(result["local_stopped"], True)

    def test_timeout_kills_descendant_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            escaped = Path(directory) / "escaped"
            descendant = ("import time; from pathlib import Path; "
                          "Path({!r}).write_text('started'); time.sleep(4); "
                          "Path({!r}).write_text('not-killed')").format(str(ready), str(escaped))
            source = ("import subprocess,sys,time; "
                      "subprocess.Popen([sys.executable,'-I','-S','-c',{!r}]); "
                      "time.sleep(30)").format(descendant)
            result = run_child(source, timeout=2)
            self.assertTrue(ready.exists(), "benign descendant did not start within fixture window")
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["failure_reason"], "process_timeout")
            time.sleep(2.5)
            self.assertFalse(escaped.exists(), "descendant survived owned-tree timeout")

    def test_successful_leader_exit_still_tears_down_descendants(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            escaped = Path(directory) / "escaped"
            descendant = ("import time; from pathlib import Path; "
                          "Path({!r}).write_text('started'); time.sleep(2); "
                          "Path({!r}).write_text('not-killed')").format(str(ready), str(escaped))
            source = ("import subprocess,sys,time; from pathlib import Path\n"
                      "subprocess.Popen([sys.executable,'-I','-S','-c',{!r}], "
                      "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                      "while not Path({!r}).exists(): time.sleep(0.01)\n"
                      "print('done')").format(descendant, str(ready))
            result = run_child(source)
            self.assertEqual(result["status"], "succeeded", result["failure_reason"])
            self.assertTrue(ready.exists())
            time.sleep(2.2)
            self.assertFalse(escaped.exists(), "descendant outlived successful owned-tree teardown")

    def test_output_read_failure_is_unknown_and_secret_safe(self):
        backend_name = "_WindowsProcess" if os.name == "nt" else "_LinuxProcess"
        original = getattr(transport, backend_name)

        class BrokenReader:
            def __init__(self, stream):
                self.stream = stream

            def read(self, size):
                raise OSError("PRIVATE_READ_DIAGNOSTIC")

            def close(self):
                self.stream.close()

        def create(*args, **kwargs):
            owned = original(*args, **kwargs)
            owned.process.stdout = BrokenReader(owned.process.stdout)
            return owned

        with mock.patch.object(transport, backend_name, side_effect=create):
            result = run_child("import time; time.sleep(30)")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["failure_reason"], "process_read_failed")
        self.assertNotIn("PRIVATE_READ_DIAGNOSTIC", repr(result))


class ValidationTests(unittest.TestCase):
    def test_refuses_pid_only_stop(self):
        result = transport.stop_owned({"pid": os.getpid()})
        self.assertEqual(result["failure_reason"], "invalid_process_identity")
        self.assertIs(result["local_stopped"], False)

    def test_no_shell_batch_or_ambient_environment(self):
        for argv in (["cmd.exe", "/c", "echo unsafe"], ["/tmp/file.bat"], ["/bin/sh", "-c", "true"]):
            result = transport.run_process(argv, env={}, timeout=1, max_output_bytes=10)
            self.assertEqual(result["failure_reason"], "unsupported_process_executable")
        result = run_child("print('never')", env=None)
        self.assertEqual(result["failure_reason"], "invalid_process_environment")

    def test_bad_limits_and_input_never_spawn(self):
        with mock.patch.object(transport, "_WindowsProcess") as windows, \
                mock.patch.object(transport, "_LinuxProcess") as linux:
            for overrides in ({"timeout": 0}, {"timeout": float("nan")},
                              {"max_output_bytes": 0}, {"input_bytes": b"x" * (1024 * 1024 + 1)}):
                result = run_child("print('never')", **overrides)
                self.assertEqual(result["status"], "failed")
                # Nothing was created, so no local ownership remains.
                self.assertIs(result["local_stopped"], True)
            windows.assert_not_called()
            linux.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux supervisor setup path")
    def test_linux_setup_failure_closes_report_pipe_once(self):
        pipes, closed = [], []
        real_pipe, real_close = os.pipe, os.close

        def pipe():
            pair = real_pipe()
            pipes.append(pair)
            return pair

        def close(fd):
            closed.append(fd)
            real_close(fd)

        with mock.patch.object(transport.os, "pipe", side_effect=pipe), \
                mock.patch.object(transport.os, "close", side_effect=close), \
                mock.patch.object(transport, "_linux_identity",
                                  side_effect=transport._TransportError("process_identity_unavailable")):
            with self.assertRaises(transport._TransportError):
                transport._LinuxProcess([EXECUTABLE, "-I", "-S", "-c", "pass"], child_env())
        report_read = pipes[1][0]
        # The FileIO wrapper owns report_read; os.close must never close it again.
        self.assertNotIn(report_read, closed)

    def test_unsupported_platform_fails_closed(self):
        with mock.patch.object(transport, "_supported", return_value=False):
            result = run_child("print('never')")
        self.assertEqual(result["failure_reason"], "unsupported_process_platform")


if __name__ == "__main__":
    unittest.main()
