"""Owned, unprivileged QEMU lifecycle for the native Hermes network lab.

Call invoke(action, state_dir=..., ...) from a plugin, or use the CLI.  The
caller supplies an installed qemu-system-x86_64 executable, an existing qcow2
boot disk, and a NoCloud ISO.  No assets are downloaded or guest credentials
handled here.  ``running`` describes the verified QMP machine, not readiness of
its HTTP services.  Runtime state and serial output must live outside source
workspaces and Git repositories.  Shutdown never escalates to a host PID kill.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time
import uuid

PROFILE = "framework-network-analyst"
_SOURCE_ROOT = Path(__file__).resolve().parent
# A packaged plugin lives under the profile; its parent is not a workspace.
WORKSPACE_ROOT = (
    _SOURCE_ROOT.parents[1]
    if _SOURCE_ROOT.name == "hunt_lab" and _SOURCE_ROOT.parent.name == "framework"
    else _SOURCE_ROOT
)
MEMORY_HEADROOM_MIB = 1024
START_WAIT_SECONDS = 12.0
STOP_WAIT_SECONDS = 5.0
QMP_TIMEOUT_SECONDS = 1.0
POLL_SECONDS = 0.2
STATE_VERSION = 1
PORT_KEYS = ("qmp_port", "vnc_port", "console_websocket_port", "lab_port", "arkime_port", "kibana_port")
# A VM launched before the Kibana forward existed has no kibana_port; it stays manageable without one.
OPTIONAL_PORT_KEYS = ("kibana_port",)


class RuntimeFailure(Exception):
    """An intentionally non-sensitive public reason code."""


class QMPUnavailable(Exception):
    pass


class OwnershipMismatch(Exception):
    pass


def _base(profile=PROFILE):
    return {
        "profile": PROFILE if profile == PROFILE else None,
        "state": "stopped", "reason": "not_started", "vm_name": None,
        "pid": None, "console_websocket_url": None, "vnc_port": None,
        "qmp_port": None, "lab_url": None, "arkime_url": None, "kibana_url": None,
        "memory_mib": None, "accel": None, "cpus": None,
        "console_websocket_port": None, "lab_port": None, "arkime_port": None, "kibana_port": None,
    }


def _view(record, state=None, reason=None):
    result = _base()
    for key in result:
        if key in record:
            result[key] = record[key]
    if state is not None:
        result["state"] = state
    if reason is not None:
        result["reason"] = reason
    if result["state"] == "stopped":
        result["pid"] = None
    return result


def _path(value, reason):
    try:
        value = os.fspath(value)
        if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
            raise ValueError
        # Device paths and network shares are not ordinary application assets.
        if value.startswith(("\\\\", "//")):
            raise ValueError
        return Path(value).resolve()
    except (TypeError, ValueError, OSError, RuntimeError):
        raise RuntimeFailure(reason) from None


def _under(path, parent):
    return path == parent or parent in path.parents


def _state_location(state_dir, profile, *, create=True):
    if profile != PROFILE:
        raise RuntimeFailure("invalid_profile")
    root = _path(state_dir, "invalid_state_dir")
    if root == root.parent:
        raise RuntimeFailure("invalid_state_dir")
    if _under(root, WORKSPACE_ROOT):
        raise RuntimeFailure("state_inside_workspace")
    if any((ancestor / ".git").exists() for ancestor in (root, *root.parents)):
        raise RuntimeFailure("state_inside_git")
    home = root / profile
    if not create:
        name = "hermes-" + profile + "-" + hashlib.sha256(os.fsencode(home)).hexdigest()[:16]
        return home, name
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not root.is_dir():
            raise OSError
        home = root / profile
        if home.is_symlink():
            raise OSError
        home.mkdir(mode=0o700, exist_ok=True)
        if not home.is_dir() or home.resolve().parent != root:
            raise OSError
        if os.name != "nt":
            os.chmod(home, 0o700)
    except OSError:
        raise RuntimeFailure("invalid_state_dir") from None
    name = "hermes-" + profile + "-" + hashlib.sha256(os.fsencode(home)).hexdigest()[:16]
    return home, name


def _safe_file(path):
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeFailure("invalid_state")
    except FileNotFoundError:
        return
    except OSError:
        raise RuntimeFailure("invalid_state") from None


@contextlib.contextmanager
def _locked(home):
    path = home / "lifecycle.lock"
    _safe_file(path)
    fd = None
    acquired = False
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
        os.lseek(fd, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError:
                raise RuntimeFailure("busy") from None
        else:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise RuntimeFailure("busy") from None
        acquired = True
        yield
    except OSError:
        raise RuntimeFailure("invalid_state_dir") from None
    finally:
        if fd is not None:
            if acquired:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _load(home, name):
    path = home / "state.json"
    _safe_file(path)
    try:
        with path.open("rb") as stream:
            payload = stream.read(65537)
        if len(payload) > 65536:
            raise ValueError
        record = json.loads(payload)
        if not isinstance(record, dict) or record.get("version") != STATE_VERSION:
            raise ValueError
        if record.get("profile") != PROFILE or record.get("vm_name") != name:
            raise ValueError
        if record.get("state") not in ("starting", "running", "stopping", "stopped"):
            raise ValueError
        if record.get("reason") not in (
            "qmp_starting", "qmp_running", "qmp_not_running", "process_exited",
            "awaiting_powerdown", "powered_down", "launch_failed", "qemu_exited",
        ):
            raise ValueError
        if type(record.get("pid")) is not int and record.get("pid") is not None:
            raise ValueError
        if record.get("pid") is not None and record["pid"] <= 0:
            raise ValueError
        ports = [record.get(key) for key in PORT_KEYS if key in record or key not in OPTIONAL_PORT_KEYS]
        if any(type(port) is not int or not 1024 <= port <= 65535 for port in ports):
            raise ValueError
        if len(set(ports)) != len(ports) or record["vnc_port"] < 5900:
            raise ValueError
        _parameters(record.get("memory_mib"), record.get("cpus"), record.get("accel"))
        if not isinstance(record.get("launch_started"), (int, float)):
            raise ValueError
        # Output URLs are derived from validated ports, never trusted JSON strings.
        _urls(record)
        return record
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError, RuntimeFailure):
        raise RuntimeFailure("invalid_state") from None


def _save(home, record):
    target = home / "state.json"
    _safe_file(target)
    temp = home / (".state-" + uuid.uuid4().hex + ".tmp")
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(record, stream, ensure_ascii=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, target)
    except (OSError, ValueError):
        raise RuntimeFailure("state_write_failed") from None
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _parameters(memory_mib, cpus, accel):
    if type(memory_mib) is not int or not 512 <= memory_mib <= 131072:
        raise RuntimeFailure("invalid_memory")
    if type(cpus) is not int or not 1 <= cpus <= 64:
        raise RuntimeFailure("invalid_cpus")
    if accel not in ("tcg", "whpx", "kvm"):
        raise RuntimeFailure("invalid_accel")
    if accel == "whpx" and os.name != "nt":
        raise RuntimeFailure("accel_unavailable")
    if accel == "kvm" and not sys.platform.startswith("linux"):
        raise RuntimeFailure("accel_unavailable")


def _assets(qemu, disk, seed):
    executable = _path(qemu, "invalid_qemu")
    boot = _path(disk, "invalid_disk")
    cloud = _path(seed, "invalid_seed")
    try:
        if executable.name.lower() not in ("qemu-system-x86_64", "qemu-system-x86_64.exe"):
            raise OSError
        if not executable.is_file() or (os.name != "nt" and not os.access(executable, os.X_OK)):
            raise OSError
    except OSError:
        raise RuntimeFailure("invalid_qemu") from None
    for asset, reason, offset, signature in (
        (boot, "invalid_disk", 0, b"QFI\xfb"),
        (cloud, "invalid_seed", 32769, b"CD001"),
    ):
        try:
            if not stat.S_ISREG(asset.stat().st_mode):
                raise OSError
            with asset.open("rb") as stream:
                stream.seek(offset)
                if stream.read(len(signature)) != signature:
                    raise OSError
                if asset == boot:
                    stream.seek(0)
                    header = stream.read(80)
                    # QCOW2 external-data-file metadata must not open host files.
                    if int.from_bytes(header[4:8], "big") == 3:
                        if len(header) < 80 or int.from_bytes(header[72:80], "big") & 4:
                            raise OSError
        except OSError:
            raise RuntimeFailure(reason) from None
    if len({executable, boot, cloud}) != 3:
        raise RuntimeFailure("invalid_disk")
    return executable, boot, cloud


def _available_memory_mib():
    """Available physical RAM, not swap or virtual address space."""
    try:
        if os.name == "nt":
            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_ulong), ("load", ctypes.c_ulong),
                    ("total_phys", ctypes.c_ulonglong), ("avail_phys", ctypes.c_ulonglong),
                    ("total_page", ctypes.c_ulonglong), ("avail_page", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong), ("avail_virtual", ctypes.c_ulonglong),
                    ("extended", ctypes.c_ulonglong),
                ]
            status = MemoryStatus()
            status.length = ctypes.sizeof(status)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                raise OSError
            return status.avail_phys // (1024 * 1024)
        if sys.platform.startswith("linux"):
            with open("/proc/meminfo", encoding="ascii") as stream:
                for line in stream:
                    key, _, value = line.partition(":")
                    if key == "MemAvailable":
                        return int(value.split()[0]) // 1024
        raise OSError
    except (OSError, ValueError, AttributeError):
        raise RuntimeFailure("memory_unavailable") from None


def _process_alive(pid):
    """Liveness is only for conservative recovery, NEVER proof of ownership."""
    if pid is None:
        return None
    if os.name == "nt":
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False if ctypes.get_last_error() in (87, 1168) else None
        try:
            code = wintypes.DWORD()
            if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
                return None
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel.CloseHandle(handle)
    try:
        text = Path("/proc", str(pid), "stat").read_text(encoding="utf-8")
        return text.rpartition(")")[2].split()[0] not in ("Z", "X")
    except FileNotFoundError:
        return False
    except (OSError, IndexError):
        return None


class QMPClient:
    """Small bounded QMP client; no arbitrary command surface is exported."""

    def __init__(self, port):
        self.socket = None
        self.stream = None
        self.sequence = 0
        try:
            self.socket = socket.create_connection(("127.0.0.1", port), QMP_TIMEOUT_SECONDS)
            self.socket.settimeout(QMP_TIMEOUT_SECONDS)
            self.stream = self.socket.makefile("rb")
            if not isinstance(self._read().get("QMP"), dict):
                raise QMPUnavailable
            self.execute("qmp_capabilities")
        except (OSError, ValueError, QMPUnavailable):
            self.close()
            raise QMPUnavailable from None

    def _read(self):
        line = self.stream.readline(65537)
        if not line or len(line) > 65536:
            raise QMPUnavailable
        value = json.loads(line)
        if not isinstance(value, dict):
            raise QMPUnavailable
        return value

    def execute(self, command):
        if command not in ("qmp_capabilities", "query-name", "query-status", "system_powerdown"):
            raise QMPUnavailable
        self.sequence += 1
        request = {"execute": command, "id": self.sequence}
        try:
            self.socket.sendall(json.dumps(request).encode("ascii") + b"\r\n")
            deadline = time.monotonic() + QMP_TIMEOUT_SECONDS
            for _ in range(64):
                if time.monotonic() >= deadline:
                    break
                response = self._read()
                if response.get("id") == self.sequence:
                    if "error" in response or "return" not in response:
                        raise QMPUnavailable
                    return response["return"]
            raise QMPUnavailable
        except (OSError, ValueError, QMPUnavailable):
            raise QMPUnavailable from None

    def close(self):
        if self.stream is not None:
            self.stream.close()
            self.stream = None
        if self.socket is not None:
            self.socket.close()
            self.socket = None


@contextlib.contextmanager
def _owned(record, expected_name):
    client = QMPClient(record["qmp_port"])
    try:
        identity = client.execute("query-name")
        if not isinstance(identity, dict) or identity.get("name") != expected_name:
            raise OwnershipMismatch
        yield client
    finally:
        client.close()


def _qmp_state(client):
    status = client.execute("query-status")
    if not isinstance(status, dict) or type(status.get("running")) is not bool:
        raise QMPUnavailable
    return ("running", "qmp_running") if status["running"] else ("starting", "qmp_not_running")


def _urls(record):
    record["console_websocket_url"] = "ws://127.0.0.1:" + str(record["console_websocket_port"])
    record["lab_url"] = "http://127.0.0.1:" + str(record["lab_port"])
    record["arkime_url"] = "http://127.0.0.1:" + str(record["arkime_port"])
    record["kibana_url"] = "http://127.0.0.1:" + str(record["kibana_port"]) if "kibana_port" in record else None


@contextlib.contextmanager
def _reserved_ports():
    sockets = []
    try:
        ports = {}
        for key in PORT_KEYS:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(listener)
            if os.name == "nt":
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            if port < 5900:
                raise RuntimeFailure("ports_unavailable")
            ports[key] = port
        yield ports
    except OSError:
        raise RuntimeFailure("ports_unavailable") from None
    finally:
        for listener in sockets:
            listener.close()


def build_argv(executable, disk, seed, record, serial_log):
    """Construct only the fixed guest devices; file names use JSON block nodes."""
    def block(**values):
        return json.dumps(values, separators=(",", ":"), ensure_ascii=True)

    return [
        str(executable), "-no-user-config", "-nodefaults", "-name", record["vm_name"],
        "-machine", "q35", "-accel", record["accel"],
        "-m", str(record["memory_mib"]), "-smp", str(record["cpus"]),
        "-blockdev", block(driver="file", filename=str(disk), **{"node-name": "boot-file"}),
        "-blockdev", block(driver="qcow2", file="boot-file", backing=None, **{"node-name": "boot"}),
        "-device", "virtio-blk-pci,drive=boot,bootindex=1",
        "-blockdev", block(driver="file", filename=str(seed), **{"node-name": "seed-file", "read-only": True}),
        "-blockdev", block(driver="raw", file="seed-file", **{"node-name": "seed", "read-only": True}),
        "-device", "virtio-scsi-pci,id=scsi0", "-device", "scsi-cd,drive=seed,bus=scsi0.0",
        "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:{lab}-:8765,hostfwd=tcp:127.0.0.1:{arkime}-:8005,"
                   "hostfwd=tcp:127.0.0.1:{kibana}-:5601".format(
            lab=record["lab_port"], arkime=record["arkime_port"], kibana=record["kibana_port"]),
        "-device", "virtio-net-pci,netdev=net0", "-device", "virtio-vga",
        "-device", "qemu-xhci,id=xhci", "-device", "usb-tablet,bus=xhci.0",
        "-display", "none", "-vnc", "127.0.0.1:{display},websocket=127.0.0.1:{websocket}".format(
            display=record["vnc_port"] - 5900, websocket=record["console_websocket_port"]),
        "-qmp", "tcp:127.0.0.1:{port},server=on,wait=off".format(port=record["qmp_port"]),
        "-chardev", "file,id=serial0,path=" + str(serial_log).replace(",", ",,"),
        "-serial", "chardev:serial0", "-parallel", "none", "-monitor", "none",
    ]


def _status(home, name, record, *, read_only=False):
    if record is None:
        result = _base()
        result["vm_name"] = name
        return result
    try:
        with _owned(record, name) as client:
            state, reason = _qmp_state(client)
        if record["state"] == "stopping":
            state, reason = "stopping", "awaiting_powerdown"
        return _view(record, state, reason)
    except OwnershipMismatch:
        raise RuntimeFailure("ownership_mismatch") from None
    except QMPUnavailable:
        if _process_alive(record["pid"]) is False:
            record.update(state="stopped", reason="process_exited")
            if not read_only:
                _save(home, record)
            return _view(record)
        if record["state"] == "stopped" and record["pid"] is None:
            return _view(record)
        if record["state"] == "starting" and time.time() - record["launch_started"] < START_WAIT_SECONDS:
            return _view(record, "starting", "qmp_starting")
        raise RuntimeFailure("qmp_unavailable") from None


def _start(home, name, record, qemu, disk, seed, memory_mib, cpus, accel):
    if record is not None:
        try:
            with _owned(record, name):
                reason = "already_stopping" if record["state"] == "stopping" else "already_running"
                raise RuntimeFailure(reason)
        except OwnershipMismatch:
            raise RuntimeFailure("ownership_mismatch") from None
        except QMPUnavailable:
            if not (record["state"] == "stopped" and record["pid"] is None):
                if _process_alive(record["pid"]) is not False:
                    raise RuntimeFailure("existing_instance_unverified") from None
    _parameters(memory_mib, cpus, accel)
    executable, boot, cloud = _assets(qemu, disk, seed)
    if _available_memory_mib() < memory_mib + MEMORY_HEADROOM_MIB:
        raise RuntimeFailure("insufficient_memory")
    serial_log = home / "serial.log"
    _safe_file(serial_log)
    with _reserved_ports() as ports:
        new = dict(version=STATE_VERSION, profile=PROFILE, vm_name=name, pid=None,
                   state="starting", reason="qmp_starting", memory_mib=memory_mib,
                   cpus=cpus, accel=accel, launch_started=time.time(), **ports)
        _urls(new)
        # Persist intent before launch: an interrupted launch is never blindly duplicated.
        _save(home, new)
        argv = build_argv(executable, boot, cloud, new, serial_log)
    try:
        options = dict(cwd=str(home), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, shell=False, close_fds=True)
        if os.name == "nt":
            options["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            options["start_new_session"] = True
        process = subprocess.Popen(argv, **options)
    except (OSError, ValueError):
        new.update(state="stopped", reason="launch_failed")
        _save(home, new)
        return _view(new, "error", "launch_failed")
    new["pid"] = process.pid
    try:
        _save(home, new)
    except RuntimeFailure as error:
        return _view(new, "error", error.args[0])
    deadline = time.monotonic() + START_WAIT_SECONDS
    while True:
        try:
            with _owned(new, name) as client:
                state, reason = _qmp_state(client)
            new.update(state=state, reason=reason)
            _save(home, new)
            return _view(new)
        except RuntimeFailure as error:
            return _view(new, "error", error.args[0])
        except OwnershipMismatch:
            return _view(new, "error", "ownership_mismatch")
        except QMPUnavailable:
            if process.poll() is not None:
                new.update(state="stopped", reason="qemu_exited")
                _save(home, new)
                return _view(new, "error", "qemu_exited")
            if time.monotonic() >= deadline:
                return _view(new, "error", "qmp_start_timeout")
            time.sleep(POLL_SECONDS)


def _stop(home, name, record):
    if record is None:
        return _status(home, name, record)
    try:
        with _owned(record, name) as client:
            if record["state"] != "stopping":
                client.execute("system_powerdown")
        record.update(state="stopping", reason="awaiting_powerdown")
        _save(home, record)
    except OwnershipMismatch:
        raise RuntimeFailure("ownership_mismatch") from None
    except QMPUnavailable:
        if _process_alive(record["pid"]) is False or (record["state"] == "stopped" and record["pid"] is None):
            record.update(state="stopped", reason="process_exited")
            _save(home, record)
            return _view(record)
        raise RuntimeFailure("qmp_unavailable") from None
    deadline = time.monotonic() + STOP_WAIT_SECONDS
    while True:
        try:
            with _owned(record, name):
                pass
        except OwnershipMismatch:
            raise RuntimeFailure("ownership_mismatch") from None
        except QMPUnavailable:
            if _process_alive(record["pid"]) is False:
                record.update(state="stopped", reason="powered_down")
                _save(home, record)
                return _view(record)
        if time.monotonic() >= deadline:
            return _view(record, "stopping", "awaiting_powerdown")
        time.sleep(POLL_SECONDS)


def invoke(action, *, state_dir, profile=PROFILE, qemu=None, disk=None, seed=None,
           memory_mib=4096, cpus=2, accel="tcg"):
    """Return the complete JSON-safe metadata contract; never expose exception text.

    Only ``start`` accepts launch assets.  All control actions verify the exact
    deterministic QMP guest name.  A nonresponsive live/unknown process blocks a
    second launch; its PID is never used to terminate or signal it.
    """
    result = _base(profile)
    record = None
    try:
        if action not in ("status", "start", "stop"):
            raise RuntimeFailure("invalid_action")
        home, name = _state_location(state_dir, profile, create=action != "status")
        result["vm_name"] = name
        if action == "status":
            return _status(home, name, _load(home, name), read_only=True)
        with _locked(home):
            record = _load(home, name)
            if record is not None:
                result = _view(record)
            if action == "status":
                return _status(home, name, record)
            if action == "stop":
                return _stop(home, name, record)
            return _start(home, name, record, qemu, disk, seed, memory_mib, cpus, accel)
    except RuntimeFailure as error:
        result.update(state="error", reason=error.args[0])
        return result
    except (OSError, ValueError, TypeError, OverflowError):
        # OS and parser diagnostics may contain user paths; do not echo them.
        result.update(state="error", reason="runtime_io_error")
        return result


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise RuntimeFailure("invalid_arguments")


def main(argv=None):
    parser = _Parser(description=__doc__)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--profile", required=True)
    commands = parser.add_subparsers(dest="action", required=True, parser_class=_Parser)
    commands.add_parser("status")
    start = commands.add_parser("start")
    start.add_argument("--qemu", required=True)
    start.add_argument("--disk", required=True)
    start.add_argument("--seed", required=True)
    start.add_argument("--memory-mib", type=int, default=4096)
    start.add_argument("--cpus", type=int, default=2)
    start.add_argument("--accel", default="tcg", help="tcg, whpx, or kvm; never automatically substituted")
    commands.add_parser("stop")
    try:
        options = vars(parser.parse_args(argv))
        action = options.pop("action")
        result = invoke(action, **options)
    except RuntimeFailure:
        result = _base()
        result.update(state="error", reason="invalid_arguments")
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
    return 1 if result["state"] == "error" else 0


if __name__ == "__main__":
    raise SystemExit(main())
