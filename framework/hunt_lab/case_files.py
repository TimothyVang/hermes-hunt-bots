"""A case folder's evidence files and case.json, checked before the container lab loads them.

Only allowlisted evidence names are loaded, never truth or answer-key material, and no path that is a link,
a reparse point, a network share or a device.
"""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import re
import stat

SOURCE_ROOT = Path(__file__).resolve().parent
WORKSPACE_ROOT = SOURCE_ROOT.parents[1] if SOURCE_ROOT.parent.name == "framework" else SOURCE_ROOT
EVIDENCE_FILES = ("events.jsonl", "traffic.pcap", "case.json")
# Optional per-case evidence; never truth/answer-key material.
OPTIONAL_EVIDENCE_FILES = ("intel.jsonl",)
# case.json "network_capture": "none" declares a case without traffic.pcap; no other value is accepted.
CAPTURE_FILE = "traffic.pcap"
NO_CAPTURE = "none"
# case.json "data_origin" marks an approved real-data case (HUNT-BOTS.md rule 1): a public research
# dataset, the operator's unclassified work export, or a window of the operator's work Elastic served live
# (work-connected); absent means synthetic. No other value is accepted. Equal to
# hermes_temporal.contracts.DATA_ORIGINS. A work-connected case is never loaded into the container lab: only
# the host-side connected service serves it (ADR 0005).
DATA_ORIGINS = ("public-dataset", "work-export", "work-connected")
CONNECTED_ORIGIN = "work-connected"
CASE_ID_PATTERN = re.compile(r"[a-z0-9-]{3,64}")


class CaseError(Exception):
    """An actionable refusal of a case folder or state location."""


def local_path(value: str | Path) -> Path:
    text = os.fspath(value)
    if not text or any(ord(char) < 32 for char in text):
        raise CaseError("Paths must be nonempty local filesystem paths")
    if text.startswith(("\\\\", "//")):
        raise CaseError("Network shares and device paths are not supported")
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
            raise CaseError(f"Symlinks and reparse points are not supported: {component}")
    return path.resolve()


def source_file(value: str | Path) -> Path:
    path = local_path(value)
    if not stat.S_ISREG(path.stat().st_mode):
        raise CaseError(f"Source must be a regular file: {path}")
    if path.stat().st_size == 0:
        raise CaseError(f"Source must not be empty: {path}")
    return path


def state_location(value: str) -> Path:
    root = local_path(value)
    if root == root.parent:
        raise CaseError("State directory must not be a filesystem root")
    if root == WORKSPACE_ROOT or WORKSPACE_ROOT in root.parents:
        raise CaseError("State directory must be outside the source workspace")
    if any((parent / ".git").exists() for parent in (root, *root.parents)):
        raise CaseError("State directory must be outside Git worktrees")
    return root


def evidence_files(evidence: Path) -> list[tuple[str, Path]]:
    """The (name, path) evidence files the container lab loads: allowlisted names only."""
    captured = case_metadata(source_file(evidence / "case.json")).get("network_capture") != NO_CAPTURE
    if not captured and os.path.lexists(evidence / CAPTURE_FILE):
        raise CaseError(f'case.json says network_capture "{NO_CAPTURE}" but {CAPTURE_FILE} is present')
    files = [(name, source_file(evidence / name)) for name in EVIDENCE_FILES if captured or name != CAPTURE_FILE]
    files.extend((name, source_file(evidence / name))
                 for name in OPTIONAL_EVIDENCE_FILES if os.path.lexists(evidence / name))
    return files


def case_metadata(path: Path) -> dict:
    try:
        case = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise CaseError("case.json must be readable UTF-8 JSON") from None
    case_id = case.get("case_id") if isinstance(case, dict) else None
    if not isinstance(case_id, str) or not CASE_ID_PATTERN.fullmatch(case_id):
        raise CaseError("case.json case_id must match [a-z0-9-]{3,64}")
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
        raise CaseError("case.json time_range_utc needs ISO start_inclusive < end_exclusive")
    if "network_capture" in case and case["network_capture"] != NO_CAPTURE:
        raise CaseError(f'case.json network_capture may only be "{NO_CAPTURE}"')
    if "data_origin" in case and case["data_origin"] not in DATA_ORIGINS:
        raise CaseError("case.json data_origin may only be " + " or ".join(
            f'"{origin}"' for origin in DATA_ORIGINS if origin != CONNECTED_ORIGIN))
    if case.get("data_origin") == CONNECTED_ORIGIN:
        raise CaseError(f'a "{CONNECTED_ORIGIN}" case is never loaded into the container lab; '
                        "serve it on this PC with python -m hunt_lab.connected serve")
    return case
