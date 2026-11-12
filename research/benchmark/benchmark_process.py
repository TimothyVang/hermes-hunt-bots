"""Bounded, private campaign transport; not a sandbox for hostile executables.

Only Windows jobs and Linux /proc + pidfd process groups are supported. Windows
children are created suspended, assigned to a KILL_ON_JOB_CLOSE job, persisted,
then resumed using the documented thread APIs. Linux uses an isolated Python
supervisor: it gates dispatch, retains the session leader until final teardown,
and kills its group on controller pipe closure. A descendant deliberately
escaping a POSIX session is outside process-group containment; enrolled executors
must not daemonize. No result asserts anything about remote effects.

The caller supplies an already allowlisted environment and pinned argv. Returned
stdout is private parser input, never a log. Failures discard partial stdout.
Identity UTC preserves Windows FILETIME precision; Linux group tokens additionally
bind the kernel boot UUID and exact /proc start ticks, not a rounded timestamp.
"""
import ctypes
import datetime
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid


_MAX_INPUT = 1024 * 1024
_GROUP_PREFIX = "Local\\BenchmarkCampaign-"
# Reserved Windows job exit code for controller stops (STATUS_CONTROL_C_EXIT). A
# leader exiting with it is reported unknown/process_stopped_externally, never as
# an ordinary nonzero exit.
_STOP_EXIT_CODE = 0xC000013A
_TEARDOWN_SECONDS = 2
_LINUX_SUPERVISOR = r'''import os,select,signal,subprocess,sys
control,report=int(sys.argv[1]),int(sys.argv[2])
def end():
    os.killpg(os.getpid(),signal.SIGKILL)
try:
    if os.read(control,1)!=b'G': end()
    child=subprocess.Popen(sys.argv[3:],close_fds=True)
    while child.poll() is None:
        if select.select([control],[],[],0.02)[0]: end()
    os.write(report,str(child.returncode).encode('ascii')+b'\n')
    os.close(report)
    os.close(0)
    os.close(1)
    os.close(2)
    os.read(control,1)
finally:
    end()
'''


class _TransportError(Exception):
    def __init__(self, code):
        self.code = code


def _result(status, reason=None, identity=None, exit_code=None, stdout=b"", local_stopped=False):
    return {"exit_code": exit_code, "stdout": stdout, "status": status,
            "failure_reason": reason, "process_identity": identity,
            "local_stopped": local_stopped}


def _regular_executable(path):
    value = Path(path)
    if not value.is_absolute():
        return False
    for part in (value,) + tuple(value.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            return False
    return value.is_file()


def _validate(argv, input_bytes, env, timeout, max_output_bytes, on_started):
    if (not isinstance(argv, (list, tuple)) or not argv or
            any(not isinstance(x, str) or not x or "\x00" in x for x in argv)):
        raise _TransportError("invalid_process_arguments")
    if (Path(argv[0]).suffix.lower() in {".bat", ".cmd"} or
            Path(argv[0]).name.lower() in {"cmd", "cmd.exe", "sh", "bash", "dash", "zsh"}):
        raise _TransportError("unsupported_process_executable")
    if not _regular_executable(argv[0]):
        raise _TransportError("invalid_process_executable")
    if not isinstance(input_bytes, bytes) or len(input_bytes) > _MAX_INPUT:
        raise _TransportError("invalid_process_input")
    if (not isinstance(env, dict) or any(
            not isinstance(k, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) is None or
            not isinstance(v, str) or "\x00" in v for k, v in env.items())):
        raise _TransportError("invalid_process_environment")
    if os.name == "nt" and len({k.upper() for k in env}) != len(env):
        raise _TransportError("invalid_process_environment")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or
            not math.isfinite(timeout) or timeout <= 0 or
            type(max_output_bytes) is not int or max_output_bytes <= 0 or
            (on_started is not None and not callable(on_started))):
        raise _TransportError("invalid_process_limits")


def _linux_stat(pid):
    text = Path("/proc/{}/stat".format(pid)).read_text(encoding="ascii")
    fields = text[text.rfind(")") + 2:].split()
    return {"state": fields[0], "group": int(fields[2]), "session": int(fields[3]),
            "ticks": int(fields[19])}


def _linux_identity(pid):
    info = _linux_stat(pid)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    uuid.UUID(boot)
    boot_seconds = None
    for line in Path("/proc/stat").read_text(encoding="ascii").splitlines():
        if line.startswith("btime "):
            boot_seconds = int(line.split()[1])
            break
    if boot_seconds is None or info["group"] != pid or info["session"] != pid:
        raise _TransportError("process_identity_unavailable")
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    created = epoch + datetime.timedelta(seconds=boot_seconds,
                                         microseconds=info["ticks"] * 1000000 // os.sysconf("SC_CLK_TCK"))
    return {"pid": pid, "creation_utc": created.isoformat(timespec="microseconds"),
            "process_group_id": "linux:{}:{}:{}".format(boot, pid, info["ticks"])}


def _linux_owned(identity):
    pid = identity["pid"]
    if _linux_identity(pid) != identity:
        raise _TransportError("process_identity_mismatch")
    cmdline = Path("/proc/{}/cmdline".format(pid)).read_bytes().split(b"\x00")
    if (len(cmdline) < 9 or cmdline[1:4] != [b"-I", b"-S", b"-c"] or
            cmdline[4] != _LINUX_SUPERVISOR.encode("utf-8")):
        raise _TransportError("process_not_owned")


def _linux_stop(identity):
    # pidfd binds the stop signal to the inspected kernel process, not a reused PID.
    descriptor = os.pidfd_open(identity["pid"], 0)
    try:
        _linux_owned(identity)
        signal.pidfd_send_signal(descriptor, signal.SIGSTOP, None, 0)
        deadline = time.monotonic() + 1
        while _linux_stat(identity["pid"])["state"] not in {"T", "t"}:
            if time.monotonic() >= deadline:
                raise _TransportError("process_stop_unconfirmed")
            time.sleep(0.005)
        _linux_owned(identity)
        os.killpg(identity["pid"], signal.SIGKILL)
    finally:
        os.close(descriptor)


def _linux_group_alive(pgid):
    # The context manager closes the directory descriptor on the early return;
    # this check runs in a tight polling loop during teardown.
    with os.scandir("/proc") as entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                info = _linux_stat(int(entry.name))
            except (OSError, ValueError, IndexError):
                continue  # Exited while scanning.
            if info["group"] == pgid and info["state"] not in {"Z", "X"}:
                return True
    return False


def _linux_wait_empty(pgid):
    """Verify no live member remains in the owned group; zombies hold no execution."""
    deadline = time.monotonic() + _TEARDOWN_SECONDS
    while _linux_group_alive(pgid):
        if time.monotonic() >= deadline:
            raise _TransportError("process_stop_unconfirmed")
        time.sleep(0.005)



class _LinuxProcess:
    def __init__(self, argv, env):
        self.process = None
        self.identity = None
        self.control = None
        self.stopped_externally = False
        self.report = None
        self.exit_code = None
        self.report_error = False
        self.report_done = threading.Event()
        control_read, control_write = os.pipe()
        report_read, report_write = os.pipe()
        try:
            self.process = subprocess.Popen(
                [os.path.realpath(sys.executable), "-I", "-S", "-c", _LINUX_SUPERVISOR,
                 str(control_read), str(report_write)] + list(argv),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=env, shell=False, close_fds=True, start_new_session=True,
                pass_fds=(control_read, report_write), bufsize=0)
            self.control = control_write
            self.report = os.fdopen(report_read, "rb", buffering=0)
            self.identity = _linux_identity(self.process.pid)
        except BaseException:
            if self.process is not None:
                # Closing the control pipe kills the waiting owned supervisor.
                os.close(control_write)
                self.control = None
                self.process.wait(timeout=2)
                for stream in (self.process.stdin, self.process.stdout):
                    if stream is not None:
                        stream.close()
            else:
                os.close(control_write)
            # The FileIO owns report_read once created; never close that fd twice.
            if self.report is not None:
                self.report.close()
                self.report = None
            else:
                os.close(report_read)
            raise
        finally:
            os.close(control_read)
            os.close(report_write)

    def resume(self):
        os.write(self.control, b"G")
        threading.Thread(target=self._report, daemon=True).start()

    def _report(self):
        try:
            data = self.report.readline(32)
            if not data:
                # Supervisor killed before reporting: an external owned-group stop.
                self.stopped_externally = True
                self.report_error = True
            elif re.fullmatch(rb"-?[0-9]{1,10}\n", data) is None:
                self.report_error = True
            else:
                self.exit_code = int(data)
        except Exception:
            self.report_error = True
        finally:
            self.report_done.set()

    def poll(self):
        return self.exit_code if self.report_done.is_set() else None

    def terminate(self):
        if self.identity is not None:
            _linux_stop(self.identity)

    def wait_stopped(self):
        _linux_wait_empty(self.identity["pid"])

    def close(self):
        if self.control is not None:
            os.close(self.control)
            self.control = None
        if self.report is not None:
            self.report.close()


def _windows_api():
    from ctypes import wintypes as w
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
        "QueryInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD,
                                       ctypes.POINTER(w.DWORD)], w.BOOL),
        "OpenJobObjectW": ([w.DWORD, w.BOOL, w.LPCWSTR], w.HANDLE),
        "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
        "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
        "IsProcessInJob": ([w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)], w.BOOL),
        "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
        "OpenProcess": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
        "GetProcessTimes": ([w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4, w.BOOL),
        "CloseHandle": ([w.HANDLE], w.BOOL),
        "CreateToolhelp32Snapshot": ([w.DWORD, w.DWORD], w.HANDLE),
        "Thread32First": ([w.HANDLE, ctypes.c_void_p], w.BOOL),
        "Thread32Next": ([w.HANDLE, ctypes.c_void_p], w.BOOL),
        "OpenThread": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
        "ResumeThread": ([w.HANDLE], w.DWORD),
    }
    for name, (args, result) in signatures.items():
        fn = getattr(api, name)
        fn.argtypes, fn.restype = args, result
    return api


def _windows_created(api, process):
    from ctypes import wintypes as w
    created, ended, kernel, user = (w.FILETIME() for _ in range(4))
    if not api.GetProcessTimes(process, ctypes.byref(created), ctypes.byref(ended),
                               ctypes.byref(kernel), ctypes.byref(user)):
        raise _TransportError("process_identity_unavailable")
    ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
    seconds, fractional = divmod(ticks, 10000000)
    date = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=seconds)
    return date.strftime("%Y-%m-%dT%H:%M:%S") + ".{:07d}+00:00".format(fractional)


def _windows_set_limit(api, job):
    from ctypes import wintypes as w

    class Basic(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", w.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", w.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", w.DWORD),
                    ("SchedulingClass", w.DWORD)]

    class Counters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in
                    ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                     "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class Extended(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", Counters),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    limits = Extended()
    limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not api.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        raise _TransportError("process_containment_failed")


def _windows_wait_empty(api, job):
    """Verify the job has no active process (TerminateJobObject is asynchronous)."""
    from ctypes import wintypes as w

    class Accounting(ctypes.Structure):
        _fields_ = [("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
                    ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                    ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                    ("TotalPageFaultCount", w.DWORD), ("TotalProcesses", w.DWORD),
                    ("ActiveProcesses", w.DWORD), ("TotalTerminatedProcesses", w.DWORD)]

    deadline = time.monotonic() + _TEARDOWN_SECONDS
    while True:
        info = Accounting()
        if not api.QueryInformationJobObject(job, 1, ctypes.byref(info), ctypes.sizeof(info), None):
            raise _TransportError("process_stop_unconfirmed")  # JobObjectBasicAccountingInformation
        if info.ActiveProcesses == 0:
            return
        if time.monotonic() >= deadline:
            raise _TransportError("process_stop_unconfirmed")
        time.sleep(0.005)


def _windows_resume(api, pid):
    from ctypes import wintypes as w

    class ThreadEntry(ctypes.Structure):
        _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("th32ThreadID", w.DWORD),
                    ("th32OwnerProcessID", w.DWORD), ("tpBasePri", w.LONG),
                    ("tpDeltaPri", w.LONG), ("dwFlags", w.DWORD)]

    snapshot = api.CreateToolhelp32Snapshot(4, 0)  # TH32CS_SNAPTHREAD
    if snapshot == ctypes.c_void_p(-1).value:
        raise _TransportError("process_resume_failed")
    threads = []
    try:
        entry = ThreadEntry()
        entry.dwSize = ctypes.sizeof(entry)
        found = api.Thread32First(snapshot, ctypes.byref(entry))
        while found:
            if entry.th32OwnerProcessID == pid:
                threads.append(entry.th32ThreadID)
            found = api.Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        api.CloseHandle(snapshot)
    if len(threads) != 1:
        raise _TransportError("process_resume_failed")
    thread = api.OpenThread(0x0002, False, threads[0])  # THREAD_SUSPEND_RESUME
    if not thread:
        raise _TransportError("process_resume_failed")
    try:
        if api.ResumeThread(thread) != 1:
            raise _TransportError("process_resume_failed")
    finally:
        api.CloseHandle(thread)


class _WindowsProcess:
    def __init__(self, argv, env):
        self.api = _windows_api()
        self.process = None
        self.identity = None
        self.handle = None
        self.report_error = False
        self.stopped_externally = False
        name = _GROUP_PREFIX + uuid.uuid4().hex
        self.job = self.api.CreateJobObjectW(None, name)
        if not self.job:
            raise _TransportError("process_containment_failed")
        try:
            if ctypes.get_last_error() == 183:  # Never adopt an existing named job.
                raise _TransportError("process_containment_failed")
            _windows_set_limit(self.api, self.job)
            self.process = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=env, shell=False, close_fds=True, bufsize=0,
                creationflags=0x00000004 | 0x08000000)  # CREATE_SUSPENDED | CREATE_NO_WINDOW
            self.handle = self.api.OpenProcess(0x0100 | 0x0001 | 0x1000, False, self.process.pid)
            if not self.handle or not self.api.AssignProcessToJobObject(self.job, self.handle):
                raise _TransportError("process_containment_failed")
            self.identity = {"pid": self.process.pid,
                             "creation_utc": _windows_created(self.api, self.handle),
                             "process_group_id": name}
        except BaseException:
            if self.process is not None:
                self.process.kill()  # Still suspended; could not create descendants.
                self.process.wait(timeout=2)
                self.process.stdin.close()
                self.process.stdout.close()
            self.close()
            raise

    def resume(self):
        _windows_resume(self.api, self.process.pid)

    def poll(self):
        return self.process.poll()

    def terminate(self):
        if not self.api.TerminateJobObject(self.job, _STOP_EXIT_CODE):
            raise _TransportError("process_stop_failed")

    def wait_stopped(self):
        _windows_wait_empty(self.api, self.job)

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None
        if self.job:
            self.api.CloseHandle(self.job)
            self.job = None


def _windows_stop(identity):
    from ctypes import wintypes as w
    name = identity["process_group_id"]
    if re.fullmatch(re.escape(_GROUP_PREFIX) + r"[0-9a-f]{32}", name) is None:
        raise _TransportError("process_not_owned")
    api = _windows_api()
    job = api.OpenJobObjectW(0x0004 | 0x0008, False, name)  # QUERY | TERMINATE
    process = api.OpenProcess(0x1000, False, identity["pid"])
    try:
        if not job or not process:
            raise _TransportError("process_identity_unavailable")
        if _windows_created(api, process) != identity["creation_utc"]:
            raise _TransportError("process_identity_mismatch")
        member = w.BOOL()
        if not api.IsProcessInJob(process, job, ctypes.byref(member)) or not member.value:
            raise _TransportError("process_not_owned")
        if not api.TerminateJobObject(job, _STOP_EXIT_CODE):
            raise _TransportError("process_stop_failed")
        _windows_wait_empty(api, job)
    finally:
        if process:
            api.CloseHandle(process)
        if job:
            api.CloseHandle(job)


def _supported():
    if os.name == "nt":
        return True
    if not (sys.platform.startswith("linux") and hasattr(os, "pidfd_open") and
            hasattr(signal, "pidfd_send_signal")):
        return False
    try:
        descriptor = os.pidfd_open(os.getpid(), 0)
        os.close(descriptor)
        return Path("/proc/sys/kernel/random/boot_id").is_file()
    except OSError:
        return False


def stop_owned(identity):
    """Stop a recorded local job/group; this never verifies remote effects.

    A vanished leader, changed creation identity, or unavailable job is unknown,
    not evidence that all descendants or remote actions have stopped. Success
    means the owned job/group was terminated and verified empty (`local_stopped`).
    """
    if (not isinstance(identity, dict) or set(identity) !=
            {"pid", "creation_utc", "process_group_id"} or
            type(identity["pid"]) is not int or identity["pid"] <= 0 or
            not isinstance(identity["creation_utc"], str) or
            not isinstance(identity["process_group_id"], str)):
        return _result("failed", "invalid_process_identity")
    if not _supported():
        return _result("failed", "unsupported_process_platform", identity)
    try:
        if os.name == "nt":
            _windows_stop(identity)
        else:
            _linux_stop(identity)
            _linux_wait_empty(identity["pid"])
        return _result("succeeded", identity=identity, local_stopped=True)
    except _TransportError as exc:
        return _result("unknown", exc.code, identity)
    except Exception:
        return _result("unknown", "process_stop_unconfirmed", identity)


def _stopped_externally(owned):
    """True when the owned leader already ended by a controller stop, not by itself."""
    try:
        if os.name == "nt":
            code = owned.process.poll()
            return code is not None and code & 0xFFFFFFFF == _STOP_EXIT_CODE
        return owned.stopped_externally or owned.process.poll() == -signal.SIGKILL
    except Exception:
        return False


def run_process(argv, *, input_bytes=b"", env, timeout, max_output_bytes, on_started=None):
    """Run a pinned argv with explicit environment, bounded output, and no shell.

    on_started(identity) must durably record the exact identity and return before
    dispatch. Exceptions/timeouts are unknown and kill the owned local tree.
    The deadline covers creation, persistence and pipe I/O; OS process creation
    itself cannot be interrupted by Python and is checked immediately afterward.

    Returns {exit_code, stdout, status: succeeded|failed|unknown, failure_reason,
    process_identity, local_stopped}. `local_stopped` is True when no owned process
    was created or the owned job/group teardown was verified empty; callers may then
    release local process ownership even when `status` is unknown. Remote effects
    remain unknown either way. A leader stopped by another controller (stop_owned)
    is unknown/process_stopped_externally, never an ordinary nonzero exit.
    """
    try:
        _validate(argv, input_bytes, env, timeout, max_output_bytes, on_started)
    except _TransportError as exc:
        return _result("failed", exc.code, local_stopped=True)
    except Exception:
        return _result("failed", "invalid_process_configuration", local_stopped=True)
    if not _supported():
        return _result("failed", "unsupported_process_platform", local_stopped=True)
    deadline = time.monotonic() + timeout
    owned = None
    identity = None
    output = bytearray()
    read_done, write_done = threading.Event(), threading.Event()
    io_errors = []
    threads = []
    result = None

    def reader():
        try:
            while True:
                chunk = owned.process.stdout.read(min(65536, max_output_bytes + 1 - len(output)))
                if not chunk:
                    break
                if len(output) + len(chunk) > max_output_bytes:
                    io_errors.append("process_output_limit")
                    break
                output.extend(chunk)
        except Exception:
            io_errors.append("process_read_failed")
        finally:
            read_done.set()

    def writer():
        try:
            view = memoryview(input_bytes)
            while view:
                written = owned.process.stdin.write(view[:65536])
                if not written:
                    raise OSError()
                view = view[written:]
        except Exception:
            io_errors.append("process_write_failed")
        finally:
            try:
                owned.process.stdin.close()
            except Exception:
                io_errors.append("process_write_failed")
            write_done.set()

    try:
        owned = _WindowsProcess(argv, env) if os.name == "nt" else _LinuxProcess(argv, env)
        identity = dict(owned.identity)
        if on_started is not None:
            callback_done = threading.Event()
            callback_failed = []

            def persist():
                try:
                    on_started(dict(identity))
                except BaseException:
                    callback_failed.append(True)
                finally:
                    callback_done.set()

            thread = threading.Thread(target=persist, daemon=True)
            thread.start()
            if not callback_done.wait(max(0, deadline - time.monotonic())) or callback_failed:
                raise _TransportError("process_persistence_failed")
        if time.monotonic() >= deadline:
            raise _TransportError("process_timeout")
        owned.resume()
        for target in (reader, writer):
            thread = threading.Thread(target=target, daemon=True)
            threads.append(thread)
            thread.start()
        while True:
            if io_errors:
                raise _TransportError(io_errors[0])
            if owned.report_error:
                raise _TransportError("process_stopped_externally" if owned.stopped_externally
                                      else "process_read_failed")
            code = owned.poll()
            if code is not None and os.name == "nt" and code & 0xFFFFFFFF == _STOP_EXIT_CODE:
                raise _TransportError("process_stopped_externally")
            if code is not None and read_done.is_set() and write_done.is_set():
                if io_errors:
                    raise _TransportError(io_errors[0])
                result = _result("succeeded" if code == 0 else "failed",
                                 None if code == 0 else "process_exit_nonzero", identity, code,
                                 bytes(output) if code == 0 else b"")
                break
            if time.monotonic() >= deadline:
                raise _TransportError("process_timeout")
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
    except _TransportError as exc:
        result = _result("unknown" if owned is not None else "failed", exc.code, identity)
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            result = _result("unknown", "process_interrupted", identity)
        else:
            result = _result("unknown" if owned is not None else "failed", "process_transport_failed", identity)
    finally:
        if (owned is not None and result is not None and result["status"] == "unknown"
                and result["failure_reason"] != "process_interrupted" and _stopped_externally(owned)):
            # Our own teardown has not run yet: another controller stopped the owned tree.
            result = _result("unknown", "process_stopped_externally", identity)
        local_stopped = owned is None
        if owned is not None:
            stop_failed = False
            try:
                owned.terminate()
            except Exception:
                stop_failed = True
            try:
                owned.wait_stopped()
                local_stopped = True
            except Exception:
                local_stopped = False
            finally:
                owned.close()
            if stop_failed and not local_stopped:
                result = _result("unknown", "process_stop_unconfirmed", identity)
            teardown_failed = False
            try:
                owned.process.wait(timeout=2)
                for thread in threads:
                    thread.join(timeout=0.25)
            except Exception:
                teardown_failed = True
            # Close both pipes even when waiting failed so no descriptor leaks.
            for stream in (owned.process.stdin, owned.process.stdout):
                try:
                    stream.close()
                except Exception:
                    teardown_failed = True
            if teardown_failed:
                local_stopped = False
                result = _result("unknown", "process_stop_unconfirmed", identity)
        result["local_stopped"] = local_stopped
    return result
