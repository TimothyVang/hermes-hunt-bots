#!/usr/bin/env python3
"""Prepare native lab media without booting a VM or reading a Hermes profile.

The managed backend supplies verified private runtime assets and a pinned
pycdlib wheel. Offline operators may supply a public Docker image export;
managed preparation instead pulls the exact locked image digests in the guest.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile


PROFILE = "framework-network-analyst"
SOURCE_ROOT = Path(__file__).resolve().parent
WORKSPACE_ROOT = (
    SOURCE_ROOT.parents[1] if SOURCE_ROOT.parent.name == "framework" else SOURCE_ROOT
)
LAB_SOURCE = SOURCE_ROOT / "guest"
UBUNTU_SHA256 = "58be26aa7452f3005a4f7370a43928bfb33a7f35a77a8f3b264bf00266a17ca0"
DISK_BYTES = 32 * 1024**3
HEADROOM_BYTES = 1024**3
PAYLOAD_FILES = (
    "compose.yaml", "arkime.ini", "bootstrap_guest.sh", "lab_server.py",
    "ingest.py", "image-lock.json", "kibana.yml", "kibana_setup.py",
)
EVIDENCE_FILES = ("events.jsonl", "traffic.pcap", "case.json")
# Optional per-case evidence; never truth/answer-key material.
OPTIONAL_EVIDENCE_FILES = ("intel.jsonl",)
# case.json "network_capture": "none" declares a case without traffic.pcap; no other value is accepted.
CAPTURE_FILE = "traffic.pcap"
NO_CAPTURE = "none"
INSTANCE_ID = "hermes-framework-network-analyst-native-v1"
CASE_ID_PATTERN = re.compile(r"[a-z0-9-]{3,64}")
DEPLOYMENT_KEYS = frozenset({"qemu", "disk", "seed", "memory_mib", "cpus", "accel"})


class PreparationError(Exception):
    """An actionable preparation refusal, never an invitation to overwrite."""


def local_path(value: str | Path) -> Path:
    text = os.fspath(value)
    if not text or any(ord(char) < 32 for char in text):
        raise PreparationError("Paths must be nonempty local filesystem paths")
    if text.startswith(("\\\\", "//")):
        raise PreparationError("Network shares and device paths are not supported")
    path = Path(os.path.abspath(os.path.expanduser(text)))
    # Refuse redirected sources/destinations, including Windows junctions.
    for component in (path, *path.parents):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or (
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise PreparationError(f"Symlinks and reparse points are not supported: {component}")
    return path.resolve()


def source_file(value: str | Path) -> Path:
    path = local_path(value)
    if not stat.S_ISREG(path.stat().st_mode):
        raise PreparationError(f"Source must be a regular file: {path}")
    if path.stat().st_size == 0:
        raise PreparationError(f"Source must not be empty: {path}")
    return path


def state_location(value: str) -> Path:
    root = local_path(value)
    if root == root.parent:
        raise PreparationError("State directory must not be a filesystem root")
    if root == WORKSPACE_ROOT or WORKSPACE_ROOT in root.parents:
        raise PreparationError("State directory must be outside the source workspace")
    if any((parent / ".git").exists() for parent in (root, *root.parents)):
        raise PreparationError("State directory must be outside Git worktrees")
    return root


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def qemu_img(executable: Path, *arguments: str) -> str:
    result = subprocess.run(
        [str(executable), *arguments], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
        text=True, encoding="utf-8", errors="replace", check=False, timeout=600,
    )
    if result.returncode:
        detail = result.stderr.strip()[:4096]
        raise PreparationError(f"qemu-img {arguments[0]} failed: {detail}")
    return result.stdout


def user_data() -> bytes:
    # JSON is YAML-compatible: no host YAML package or interpolation is needed.
    config = {
        "hostname": "hermes-hunt-lab",
        "manage_etc_hosts": True,
        "users": [],
        "disable_root": True,
        "ssh_pwauth": False,
        "allow_public_ssh_keys": False,
        "ssh_deletekeys": True,
        "ssh_genkeytypes": [],
        "ssh_quiet_keygen": True,
        "ssh_publish_hostkeys": {"enabled": False},
        "ssh": {"emit_keys_to_console": False},
        "no_ssh_fingerprints": True,
        "growpart": {"mode": "auto", "devices": ["/"], "ignore_growroot_disabled": False},
        "resize_rootfs": True,
        "output": {"all": "| tee -a /var/log/cloud-init-output.log /dev/ttyS0"},
        "bootcmd": [
            ["systemctl", "mask", "--now", "ssh.service", "ssh.socket"],
        ],
        "write_files": [{
            "path": "/etc/ssh/sshd_config.d/99-hermes-hunt-lab.conf",
            "owner": "root:root",
            "permissions": "0644",
            "content": (
                "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
                "PubkeyAuthentication no\nPermitRootLogin no\n"
            ),
        }],
        "mounts": [[
            "/dev/sr0", "/media/lab-setup", "iso9660",
            "ro,nosuid,nodev,noexec", "0", "0",
        ]],
        "runcmd": [["bash", "-c", (
            "set -euo pipefail; "
            "mkdir -p /media/lab-setup /opt/hermes-hunt-lab; "
            "mountpoint -q /media/lab-setup || "
            "mount -t iso9660 -o ro,nosuid,nodev,noexec /dev/sr0 /media/lab-setup; "
            # A reseeded instance must not keep a previous case's optional files.
            "rm -rf /opt/hermes-hunt-lab/evidence; "
            "tar --extract --file /media/lab-setup/lab-payload.tar "
            "--directory /opt/hermes-hunt-lab --no-same-owner --no-same-permissions; "
            "cd /opt/hermes-hunt-lab; exec bash bootstrap_guest.sh"
        )]],
        "final_message": (
            "Cloud-init finished. Lab readiness is reported only by the lab health API."
        ),
    }
    return ("#cloud-config\n" + json.dumps(config, indent=2) + "\n").encode("utf-8")


def write_payload(destination, sources: list[tuple[str, Path]]) -> int:
    # Never recurse: the archive consists exclusively of this reviewed allowlist.
    with tarfile.open(fileobj=destination, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, path in sources:
            with path.open("rb") as source:
                info = tarfile.TarInfo(name)
                info.size = os.fstat(source.fileno()).st_size
                info.mode = 0o755 if name == "bootstrap_guest.sh" else 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = 0
                archive.addfile(info, source)
    length = destination.tell()
    destination.seek(0)
    return length


def write_seed(pycdlib, seed: Path, images: Path | None, payload, payload_length: int,
               instance_id: str = INSTANCE_ID) -> None:
    cloud_config = user_data()
    metadata = (json.dumps({
        "instance-id": instance_id,
        "local-hostname": "hermes-hunt-lab",
    }) + "\n").encode("utf-8")
    iso = pycdlib.PyCdlib()
    try:
        # Level 3 permits multi-extent files (>4 GiB); RR/Joliet preserve the
        # exact NoCloud and tar names instead of exposing ISO9660 aliases.
        iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="cidata")
        with ExitStack() as stack:
            entries = [
                ("user-data", "/USERDATA.;1", stack.enter_context(io.BytesIO(cloud_config)), len(cloud_config)),
                ("meta-data", "/METADATA.;1", stack.enter_context(io.BytesIO(metadata)), len(metadata)),
                ("lab-payload.tar", "/LABPAYLD.TAR;1", payload, payload_length),
            ]
            if images is not None:
                entries.append((
                    "lab-images.tar", "/LABIMAGE.TAR;1",
                    stack.enter_context(images.open("rb")), images.stat().st_size,
                ))
            for name, alias, stream, length in entries:
                iso.add_fp(
                    stream, length, iso_path=alias, rr_name=name,
                    joliet_path="/" + name, file_mode=stat.S_IFREG | 0o444,
                )
            # Exclusive creation makes a pre-existing ISO an unconditional refusal.
            with seed.open("xb") as output:
                iso.write_fp(output)
                output.flush()
                os.fsync(output.fileno())
    finally:
        iso.close()


def prepare(args: argparse.Namespace) -> dict:
    try:
        import pycdlib
    except ImportError:
        raise PreparationError("Install the host prerequisite: python -m pip install pycdlib") from None

    root = state_location(args.state_dir)
    qemu_dir = local_path(args.qemu_dir)
    suffix = ".exe" if os.name == "nt" else ""
    executable = source_file(qemu_dir / ("qemu-system-x86_64" + suffix))
    image_tool = source_file(qemu_dir / ("qemu-img" + suffix))
    if os.name != "nt" and not all(os.access(path, os.X_OK) for path in (executable, image_tool)):
        raise PreparationError("QEMU binaries must be executable")
    if args.accel == "whpx" and os.name != "nt":
        raise PreparationError("WHPX acceleration requires Windows")
    if args.accel == "kvm" and not sys.platform.startswith("linux"):
        raise PreparationError("KVM acceleration requires Linux")
    if not 512 <= args.memory_mib <= 131072:
        raise PreparationError("--memory-mib must be between 512 and 131072")
    if not 1 <= args.cpus <= 64:
        raise PreparationError("--cpus must be between 1 and 64")

    cloud_image = source_file(args.cloud_image)
    # Verify the public Ubuntu image before invoking qemu-img or making media.
    if digest_file(cloud_image) != UBUNTU_SHA256:
        raise PreparationError("Ubuntu cloud image SHA256 does not match the pinned public image")
    guest_pull = getattr(args, "guest_pull", False)
    if guest_pull == bool(args.images_tar):
        raise PreparationError("Choose exactly one of --guest-pull or --images-tar")
    images = None if guest_pull else source_file(args.images_tar)
    evidence = local_path(args.evidence_dir)
    case_metadata(source_file(evidence / "case.json"))
    sources = payload_sources(evidence)

    try:
        image_info = json.loads(qemu_img(image_tool, "info", "--output=json", "-f", "qcow2", str(cloud_image)))
        virtual_size = image_info["virtual-size"]
    except (ValueError, KeyError, TypeError):
        raise PreparationError("qemu-img did not return valid cloud image metadata") from None
    if type(virtual_size) is not int or not 0 < virtual_size <= DISK_BYTES:
        raise PreparationError("Cloud image virtual size must not exceed 32 GiB")
    if image_info.get("backing-filename") or image_info.get("data-file"):
        raise PreparationError("Cloud image must not depend on external backing or data files")

    media = root / "media"
    disk = media / "lab.qcow2"
    seed = media / "cidata.iso"
    deployment = root / "deployment.json"
    # Check even dangling symlinks; no existing media/configuration is replaced.
    for path in (deployment, disk, seed, root / ".prepare.lock"):
        if os.path.lexists(path):
            raise PreparationError(f"Refusing existing artifact (no overwrite mode): {path}")
    local_path(media)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    media.mkdir(mode=0o700, exist_ok=True)
    if not root.is_dir() or not media.is_dir():
        raise PreparationError("State and media paths must be directories")
    payload_size = sum(path.stat().st_size for _, path in sources)
    required = DISK_BYTES + (images.stat().st_size if images else 0) + 2 * payload_size + HEADROOM_BYTES
    if shutil.disk_usage(media).free < required:
        raise PreparationError(
            f"Insufficient disk headroom: need {required} free bytes for a 32 GiB guest, setup ISO, and staging"
        )

    lock = root / ".prepare.lock"
    # Exclusively reserve the operation and every output. On failure partial
    # media remain for explicit operator review; subsequent runs refuse them.
    with lock.open("x", encoding="utf-8") as lockfile:
        try:
            lockfile.write(str(os.getpid()) + "\n")
            lockfile.flush()
            for path in (deployment, disk, seed):
                if os.path.lexists(path):
                    raise PreparationError(f"Refusing existing artifact (no overwrite mode): {path}")
            with disk.open("xb"):
                pass
            qemu_img(
                image_tool, "convert", "-f", "qcow2", "-O", "qcow2",
                "-o", "compat=1.1", str(cloud_image), str(disk),
            )
            qemu_img(image_tool, "resize", "-f", "qcow2", str(disk), "32G")
            with tempfile.TemporaryFile(mode="w+b", dir=media) as payload:
                length = write_payload(payload, sources)
                write_seed(pycdlib, seed, images, payload, length)
            config = {
                "qemu": str(executable), "disk": str(disk), "seed": str(seed),
                "memory_mib": args.memory_mib, "cpus": args.cpus, "accel": args.accel,
            }
            with deployment.open("x", encoding="utf-8", newline="\n") as output:
                json.dump(config, output, indent=2)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
        finally:
            # Close first: Windows does not permit unlinking an open lock file.
            lockfile.close()
            lock.unlink()
    return {
        "status": "prepared", "profile": args.profile, "state_dir": str(root),
        "deployment": str(deployment), **config,
        "ubuntu_sha256": UBUNTU_SHA256,
    }


def payload_sources(evidence: Path) -> list[tuple[str, Path]]:
    """The reviewed guest payload: fixed guest files and allowlisted evidence names only."""
    captured = case_metadata(source_file(evidence / "case.json")).get("network_capture") != NO_CAPTURE
    if not captured and os.path.lexists(evidence / CAPTURE_FILE):
        raise PreparationError(f'case.json says network_capture "{NO_CAPTURE}" but {CAPTURE_FILE} is present')
    sources = [(name, source_file(LAB_SOURCE / name)) for name in PAYLOAD_FILES]
    sources.extend(
        ("evidence/" + name, source_file(evidence / name))
        for name in EVIDENCE_FILES if captured or name != CAPTURE_FILE
    )
    sources.extend(
        ("evidence/" + name, source_file(evidence / name))
        for name in OPTIONAL_EVIDENCE_FILES if os.path.lexists(evidence / name)
    )
    return sources


def case_metadata(path: Path) -> dict:
    try:
        case = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise PreparationError("case.json must be readable UTF-8 JSON") from None
    case_id = case.get("case_id") if isinstance(case, dict) else None
    if not isinstance(case_id, str) or not CASE_ID_PATTERN.fullmatch(case_id):
        raise PreparationError("case.json case_id must match [a-z0-9-]{3,64}")
    try:
        window = case["time_range_utc"]
        start, end = (
            datetime.fromisoformat(window[key].replace("Z", "+00:00"))
            for key in ("start_inclusive", "end_exclusive")
        )
        ordered = start < end
    except (TypeError, KeyError, AttributeError, ValueError):
        ordered = False
    if not ordered:
        raise PreparationError("case.json time_range_utc needs ISO start_inclusive < end_exclusive")
    if "network_capture" in case and case["network_capture"] != NO_CAPTURE:
        raise PreparationError(f'case.json network_capture may only be "{NO_CAPTURE}"')
    return case


class _HashWriter:
    def __init__(self):
        self.digest = hashlib.sha256()

    def write(self, data):
        self.digest.update(data)
        return len(data)


def validate_seed(pycdlib, seed: Path, instance_id: str, payload_sha256: str) -> None:
    """Read the written ISO back: NoCloud volume, exact instance-id, exact payload bytes."""
    with seed.open("rb") as stream:
        stream.seek(32769)
        if stream.read(5) != b"CD001":
            raise PreparationError(f"Written seed is not an ISO9660 image: {seed}")
    iso = pycdlib.PyCdlib()
    iso.open(str(seed))
    try:
        metadata = io.BytesIO()
        iso.get_file_from_iso_fp(metadata, rr_path="/meta-data")
        payload = _HashWriter()
        iso.get_file_from_iso_fp(payload, rr_path="/lab-payload.tar")
    finally:
        iso.close()
    if json.loads(metadata.getvalue()).get("instance-id") != instance_id:
        raise PreparationError(f"Written seed has an unexpected instance-id: {seed}")
    if payload.digest.hexdigest() != payload_sha256:
        raise PreparationError(f"Written seed payload does not match the staged payload: {seed}")


def _runtime():
    if __package__:
        from . import runtime
    else:
        import runtime
    return runtime


def _switchable_deployment(root: Path):
    """Read deployment.json and require a stopped VM; read-only, never locks or controls the VM."""
    deployment = root / "deployment.json"
    source_file(deployment)
    if os.path.lexists(root / ".prepare.lock"):
        raise PreparationError("Preparation is in progress; deployment.json was not changed")
    original = deployment.read_text(encoding="utf-8")
    try:
        config = json.loads(original)
    except ValueError:
        raise PreparationError("deployment.json is not valid JSON; it was not changed") from None
    if not isinstance(config, dict) or set(config) != DEPLOYMENT_KEYS:
        raise PreparationError("deployment.json has unexpected keys; it was not changed")
    runtime = _runtime()
    status = runtime.invoke("status", state_dir=root, profile=PROFILE)
    if status.get("state") != "stopped":
        raise PreparationError(
            f"Lab VM state is {status.get('state')} ({status.get('reason')}); "
            "stop the VM before switching its seed. deployment.json was not changed"
        )
    return original, config, runtime


def update_deployment(root: Path, seed: Path) -> dict:
    """Point deployment.json at a validated seed while the lab VM is stopped."""
    deployment = root / "deployment.json"
    original, config, runtime = _switchable_deployment(root)
    try:
        runtime._assets(config["qemu"], config["disk"], seed)
    except runtime.RuntimeFailure as error:
        raise PreparationError(f"Deployment would not validate ({error.args[0]}); it was not changed") from None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = root / f"deployment.json.{stamp}.bak"
    with backup.open("x", encoding="utf-8", newline="") as output:
        output.write(original)
        output.flush()
        os.fsync(output.fileno())
    temporary = root / f".deployment-{stamp}.tmp"
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(dict(config, seed=str(seed)), output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, deployment)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()
    return {
        "deployment": str(deployment), "deployment_updated": True,
        "previous_seed": config["seed"], "deployment_backup": str(backup),
    }


def reseed(args: argparse.Namespace) -> dict:
    """Write a NEW seed ISO (new cloud-init instance ID) for a case; never overwrite.

    cloud-init runs setup once per instance ID, so switching back to a previously loaded
    case needs a fresh ID too: later loads of the same evidence get `-load<N>` suffixes.
    The disk, images and earlier seeds are untouched.
    """
    try:
        import pycdlib
    except ImportError:
        raise PreparationError("Install the host prerequisite: python -m pip install pycdlib") from None
    root = state_location(args.state_dir)
    media = root / "media"
    local_path(media)
    if not media.is_dir():
        raise PreparationError(f"Prepared media directory not found (run prepare first): {media}")
    evidence = local_path(args.evidence_dir)
    case_id = case_metadata(source_file(evidence / "case.json"))["case_id"]
    sources = payload_sources(evidence)
    if args.update_deployment:
        # Refuse before building media when the switch could not happen anyway.
        _switchable_deployment(root)
    digest = hashlib.sha256()
    for name, path in sources:
        digest.update(name.encode("utf-8") + b"\0" + digest_file(path).encode("ascii") + b"\n")
    sha8 = digest.hexdigest()[:8]
    base_id = f"hermes-framework-network-analyst-case-{case_id}-{sha8}"
    load = 1
    while os.path.lexists(media / (f"cidata-{case_id}-{sha8}" + (f"-load{load}" if load > 1 else "") + ".iso")):
        load += 1
    suffix = f"-load{load}" if load > 1 else ""
    instance_id = base_id + suffix
    seed = media / f"cidata-{case_id}-{sha8}{suffix}.iso"
    payload_size = sum(path.stat().st_size for _, path in sources)
    if shutil.disk_usage(media).free < 2 * payload_size + HEADROOM_BYTES:
        raise PreparationError("Insufficient disk headroom for the setup ISO and staging")
    with tempfile.TemporaryFile(mode="w+b", dir=media) as payload:
        length = write_payload(payload, sources)
        staged = hashlib.sha256()
        while block := payload.read(1024 * 1024):
            staged.update(block)
        payload.seek(0)
        write_seed(pycdlib, seed, None, payload, length, instance_id)
    validate_seed(pycdlib, seed, instance_id, staged.hexdigest())
    result = {
        "status": "reseeded", "profile": args.profile, "state_dir": str(root), "load": load,
        "case_id": case_id, "instance_id": instance_id, "seed": str(seed),
        "payload": [name for name, _ in sources], "deployment_updated": False,
    }
    if args.update_deployment:
        result.update(update_deployment(root, seed))
    return result


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        description="Prepare standalone 32 GiB QEMU media and a credential-free NoCloud setup ISO; never boots a VM.",
        epilog=(
            "Requires pycdlib and public qemu-system-x86_64/qemu-img binaries. Existing artifacts are refused. "
            "Use `prepare_guest.py reseed --help` to build a new case seed for prepared media."
        ),
    )
    cli.add_argument("--qemu-dir", required=True, help="Directory containing public QEMU binaries")
    cli.add_argument("--cloud-image", required=True, help="Pinned jammy-server-cloudimg-amd64.img")
    mode = cli.add_mutually_exclusive_group(required=True)
    mode.add_argument("--images-tar", help="Offline public Docker export for the locked lab images")
    mode.add_argument("--guest-pull", action="store_true", help="Pull only locked public image digests inside the guest")
    cli.add_argument("--evidence-dir", required=True, help="Directory containing events.jsonl, traffic.pcap (absent when case.json network_capture is none), case.json and optional intel.jsonl")
    cli.add_argument("--state-dir", required=True, help="Native profile home/hunt-lab-vm, outside workspace/Git")
    cli.add_argument("--profile", required=True, choices=(PROFILE,))
    cli.add_argument("--accel", choices=("whpx", "kvm", "tcg"), default="whpx")
    cli.add_argument("--memory-mib", type=int, default=4096)
    cli.add_argument("--cpus", type=int, default=2)
    return cli


def reseed_parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        prog="prepare_guest.py reseed",
        description=(
            "Write a NEW cloud-init seed ISO (new instance-id) carrying the current guest payload and one case's "
            "evidence. On the next boot the guest re-runs setup and serves that case. Never overwrites media."
        ),
    )
    cli.add_argument("--evidence-dir", required=True, help="Directory containing events.jsonl, traffic.pcap (absent when case.json network_capture is none), case.json and optional intel.jsonl")
    cli.add_argument("--state-dir", required=True, help="Prepared native profile home/hunt-lab-vm")
    cli.add_argument("--profile", required=True, choices=(PROFILE,))
    cli.add_argument(
        "--update-deployment", action="store_true",
        help="Point deployment.json at the new seed (only while the VM is stopped; the old file is backed up)",
    )
    return cli


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        if argv[:1] == ["reseed"]:
            result = reseed(reseed_parser().parse_args(argv[1:]))
        else:
            result = prepare(parser().parse_args(argv))
    except (PreparationError, OSError, ValueError, tarfile.TarError) as error:
        print(json.dumps({
            "status": "refused", "error": str(error),
            "note": "No existing artifacts are overwritten; review any partial media before explicitly removing them.",
        }), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
