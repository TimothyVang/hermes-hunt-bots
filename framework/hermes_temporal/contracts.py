"""JSON-serializable public contracts for the native Hermes Temporal path."""
from __future__ import annotations

from dataclasses import dataclass, field
import re


MAX_STEPS = 16
MAX_STEP_TIMEOUT_SECONDS = 3600
MAX_APPROVAL_TIMEOUT_SECONDS = 86400
MAX_PROMPT_BYTES = 65536
SAFE_STEP_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
PROFILES = frozenset({
    "framework-coordinator",
    "framework-researcher",
    "framework-builder",
    "framework-reviewer",
    "framework-librarian",
    "framework-network-analyst",
})


def validate_loopback_address(address: str) -> str:
    host, separator, port = address.rpartition(":")
    if not (separator and host in ("localhost", "127.0.0.1", "[::1]")
            and port.isascii() and port.isdigit() and 1 <= int(port) <= 65535):
        raise ValueError("only a loopback Temporal server host:port is supported")
    return address


@dataclass(frozen=True)
class HermesStep:
    step_id: str
    prompt: str
    profile: str = "framework-coordinator"
    timeout_seconds: int = 300
    depends_on: tuple[str, ...] = ()
    hunt_context: dict | None = None
    def __post_init__(self) -> None:
        if not isinstance(self.step_id, str) or SAFE_STEP_ID.fullmatch(self.step_id) is None:
            raise ValueError("step_id must be a safe 1-64 character identifier")
        if not isinstance(self.prompt, str) or not self.prompt.strip():
            raise ValueError("prompt must be nonempty")
        try:
            prompt_bytes = self.prompt.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("prompt must be valid UTF-8 text") from exc
        if len(prompt_bytes) > MAX_PROMPT_BYTES:
            raise ValueError("prompt exceeds 65536 UTF-8 bytes")
        if not isinstance(self.profile, str) or self.profile not in PROFILES:
            raise ValueError("profile is not one of the six native framework profiles")
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= MAX_STEP_TIMEOUT_SECONDS:
            raise ValueError("timeout_seconds must be an integer from 1 through 3600")
        if (not isinstance(self.depends_on, tuple)
                or any(not isinstance(item, str) or SAFE_STEP_ID.fullmatch(item) is None for item in self.depends_on)
                or len(self.depends_on) != len(set(self.depends_on))):
            raise ValueError("depends_on must be a tuple of unique safe step identifiers")
        if self.hunt_context is not None:
            if not isinstance(self.hunt_context, dict) or set(self.hunt_context) != {"snapshot", "evidence_ids"}:
                raise ValueError("hunt_context must contain exactly snapshot and evidence_ids")
            evidence_ids = self.hunt_context["evidence_ids"]
            if (not isinstance(evidence_ids, list) or not evidence_ids
                    or any(not isinstance(item, str) or not item.strip() for item in evidence_ids)
                    or len(evidence_ids) != len(set(evidence_ids))):
                raise ValueError("hunt_context evidence_ids must be a nonempty list of unique strings")
            try:
                if any(len(item.encode("utf-8")) > 64 for item in evidence_ids):
                    raise ValueError("hunt_context evidence IDs exceed 64 UTF-8 bytes")
            except UnicodeEncodeError as exc:
                raise ValueError("hunt_context evidence IDs must be valid UTF-8 text") from exc
            from .ontology import validate_snapshot
            validate_snapshot(self.hunt_context["snapshot"], set(evidence_ids))


@dataclass(frozen=True)
class WorkflowRequest:
    steps: list[HermesStep]
    approval_timeout_seconds: int = 3600
    synthetic_only: bool = True
    # Stages drive their own lab tools; their reports run longer, so the workflow states
    # a lower output target. Defaults off so earlier histories deserialize unchanged.
    tool_driven: bool = False

    def __post_init__(self) -> None:
        if self.synthetic_only is not True:
            raise ValueError("this integration accepts synthetic-only workflows")
        if not isinstance(self.steps, list) or not 1 <= len(self.steps) <= MAX_STEPS:
            raise ValueError("steps must contain 1 through 16 Hermes steps")
        if any(not isinstance(step, HermesStep) for step in self.steps):
            raise ValueError("every step must be a HermesStep")
        ids = [step.step_id for step in self.steps]
        if len(ids) != len(set(ids)):
            raise ValueError("step_id values must be unique")
        seen: set[str] = set()
        for step in self.steps:
            if any(dependency not in seen for dependency in step.depends_on):
                raise ValueError("step dependencies must refer only to preceding steps")
            seen.add(step.step_id)
        if type(self.approval_timeout_seconds) is not int or not 1 <= self.approval_timeout_seconds <= MAX_APPROVAL_TIMEOUT_SECONDS:
            raise ValueError("approval_timeout_seconds must be an integer from 1 through 86400")
        if type(self.tool_driven) is not bool:
            raise ValueError("tool_driven must be a boolean")


def _validate_execution_id(value: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError("execution_id must be nonempty text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError("execution_id must be valid UTF-8 text") from exc
    if size > 512:
        raise ValueError("execution_id exceeds 512 UTF-8 bytes")


@dataclass(frozen=True)
class ExecutionRequest:
    execution_id: str
    step: HermesStep

    def __post_init__(self) -> None:
        _validate_execution_id(self.execution_id)
        if not isinstance(self.step, HermesStep):
            raise ValueError("step must be a HermesStep")


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    execution_id: str
    output: str
    reason_code: str
    session_id: str | None = None

    def __post_init__(self) -> None:
        _validate_execution_id(self.execution_id)
        if not isinstance(self.status, str) or self.status not in {"completed", "failed", "unknown"}:
            raise ValueError("invalid execution status")
        if not isinstance(self.output, str):
            raise ValueError("output must be text")
        try:
            output_bytes = self.output.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("output must be valid UTF-8 text") from exc
        if len(output_bytes) > MAX_PROMPT_BYTES:
            raise ValueError("output exceeds 65536 UTF-8 bytes")
        if not isinstance(self.reason_code, str) or self.reason_code not in {
            "completed", "native_failed", "not_dispatched", "timeout", "worker_lost",
            "cancelled", "receipt_unknown", "invalid_request", "execution_error",
            "fingerprint_conflict", "previous_dispatch_unknown", "launch_failed",
            "subprocess_timeout", "output_limit", "output_unavailable", "native_nonzero",
            "execution_disabled", "invalid_configuration", "receipt_unavailable",
            "receipt_write_failed",
        }:
            raise ValueError("invalid execution reason_code")


@dataclass(frozen=True)
class WorkflowDecision:
    step_id: str
    phase: str
    decision: str
    decision_id: str
    evidence_note: str = ""


@dataclass(frozen=True)
class HandoffRejection:
    """One handoff validation rejection of a completed execution and what the workflow did next.

    ``outcome`` is ``retried`` (the same step was offered once more behind a new execute gate),
    ``retry_exhausted`` (the step had already used its one retry), ``retry_prompt_too_large``
    (the correction notice did not fit the prompt budget), or ``retry_unavailable`` (a history
    that started before retries existed). Every outcome except ``retried`` ends the workflow at
    ``handoff_validation_rejected``. ``result`` is the rejected execution; a retried one is not
    in ``WorkflowStatus.results``, which holds the latest execution of each reached step.
    """
    step_id: str
    reason: str
    outcome: str
    result: ExecutionResult


@dataclass(frozen=True)
class WorkflowStatus:
    stage: str
    step_id: str | None
    execution_id: str | None
    results: list[ExecutionResult]
    handoff_rejections: list[HandoffRejection] = field(default_factory=list)
