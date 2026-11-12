"""JSON-serializable public contracts for the native Hermes Temporal path."""
from __future__ import annotations

from dataclasses import dataclass, field
import re


MAX_STEPS = 16
# A parallel hunt adds hunter and follow-up steps around the fixed stages.
MAX_TEAM_STEPS = 32
MAX_STEP_TIMEOUT_SECONDS = 3600
MAX_APPROVAL_TIMEOUT_SECONDS = 86400
MAX_PROMPT_BYTES = 65536
MAX_DIAGNOSTIC_CHARS = 640
# A handoff holds at most 16 claims (ontology.validate_handoff).
MAX_FOCUS_CLAIMS = 16
SAFE_STEP_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
# In a parallel workflow one decision opens or reviews a whole wave; its gate is addressed by this ID.
WAVE_GATE_ID = re.compile(r"wave-[1-9][0-9]?\Z")
USAGE_KEYS = frozenset({"input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens",
                        "total_tokens", "duration_ms"})
STEP_STATES = frozenset({"not_reached", "awaiting_approval", "working", "awaiting_review", "done",
                         "dropped", "stopped"})
PROFILES = frozenset({
    "framework-coordinator",
    "framework-researcher",
    "framework-builder",
    "framework-reviewer",
    "framework-librarian",
    "framework-network-analyst",
})
# A case is synthetic unless its case.json names one of DATA_ORIGINS (HUNT-BOTS.md rule 1): a public
# research dataset or the operator's unclassified work export. Each maps to the (name, detail) every
# bot-visible text uses for that origin, "<name> (<detail>)", instead of calling the data synthetic.
# The guest console mirrors this table (test_lab_server keeps them equal).
SYNTHETIC = "synthetic"
PUBLIC_DATASET = "public-dataset"
WORK_EXPORT = "work-export"
DATA_ORIGINS = {
    PUBLIC_DATASET: ("public research dataset", "real lab telemetry, no customer data"),
    WORK_EXPORT: ("work log export", "real telemetry from the operator's environment; unclassified work data"),
}


def origin_text(origin: str) -> str:
    name, detail = DATA_ORIGINS[origin]
    return f"{name} ({detail})"


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
    # A parallel workflow drops an optional step that does not produce a reviewed result instead
    # of ending the hunt. Defaults off so earlier histories deserialize unchanged.
    optional: bool = False
    # Parallel workflows only: (predecessor step_id, claim index). The step receives that one claim of
    # the predecessor's reviewed handoff instead of the predecessor's whole output, and is dropped
    # when the predecessor has no such claim. The predecessor must be in depends_on and carry a hunt_context.
    focus: tuple[str, int] | None = None
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
        if type(self.optional) is not bool:
            raise ValueError("optional must be a boolean")
        if self.focus is not None and (
                not isinstance(self.focus, tuple) or len(self.focus) != 2
                or not isinstance(self.focus[0], str) or SAFE_STEP_ID.fullmatch(self.focus[0]) is None
                or type(self.focus[1]) is not int or not 0 <= self.focus[1] < MAX_FOCUS_CLAIMS
                or self.focus[0] not in self.depends_on or self.hunt_context is None):
            raise ValueError("focus must be (a typed step's depends_on entry, a claim index from 0 through 15)")


@dataclass(frozen=True)
class WorkflowRequest:
    steps: list[HermesStep]
    approval_timeout_seconds: int = 3600
    synthetic_only: bool = True
    # Stages drive their own lab tools; their reports run longer, so the workflow states
    # a lower output target. Defaults off so earlier histories deserialize unchanged.
    tool_driven: bool = False
    # Steps whose dependencies are reviewed run together as one wave behind one execute and one
    # review decision. Defaults off so earlier histories deserialize and replay unchanged.
    parallel: bool = False
    # Only an explicitly authorized tool-driven hunt over a DATA_ORIGINS case sets this;
    # synthetic_only must then be False. Defaults to synthetic so earlier histories deserialize unchanged.
    data_origin: str = SYNTHETIC

    def __post_init__(self) -> None:
        if self.data_origin not in (SYNTHETIC, *DATA_ORIGINS):
            raise ValueError("data_origin must be synthetic or one of " + ", ".join(DATA_ORIGINS))
        if self.data_origin == SYNTHETIC and self.synthetic_only is not True:
            raise ValueError("this integration accepts synthetic-only workflows")
        if self.data_origin != SYNTHETIC and (self.synthetic_only is not False or self.tool_driven is not True):
            raise ValueError(f"a {self.data_origin} workflow must be tool_driven and not synthetic_only")
        limit = MAX_TEAM_STEPS if self.parallel is True else MAX_STEPS
        if not isinstance(self.steps, list) or not 1 <= len(self.steps) <= limit:
            raise ValueError(f"steps must contain 1 through {limit} Hermes steps")
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
        if type(self.parallel) is not bool:
            raise ValueError("parallel must be a boolean")
        if not self.parallel and any(step.optional for step in self.steps):
            raise ValueError("optional steps require a parallel workflow")
        if self.parallel and any(WAVE_GATE_ID.fullmatch(step.step_id) for step in self.steps):
            raise ValueError("wave-<n> step IDs are reserved for wave gates in a parallel workflow")
        if not self.parallel and any(step.focus is not None for step in self.steps):
            raise ValueError("focus steps require a parallel workflow")
        typed = {step.step_id for step in self.steps if step.hunt_context is not None}
        if any(step.focus is not None and step.focus[0] not in typed for step in self.steps):
            raise ValueError("focus must name a predecessor with a hunt_context")


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
    # Token counts and wall time of the native run, when the worker records them.
    usage: dict | None = None
    # Exit code and a redacted stderr cause of a failed native run; never model output.
    diagnostic: str | None = None

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
        if self.usage is not None and (
                not isinstance(self.usage, dict) or set(self.usage) != USAGE_KEYS
                or any(type(value) is not int or value < 0 for value in self.usage.values())):
            raise ValueError("usage must map exactly the usage keys to non-negative integers")
        if self.diagnostic is not None and (
                not isinstance(self.diagnostic, str) or len(self.diagnostic) > MAX_DIAGNOSTIC_CHARS
                or not self.diagnostic.isascii() or not self.diagnostic.isprintable()):
            raise ValueError("diagnostic must be at most 640 printable ASCII characters")


# Who sent a gate decision and through which channel. All three empty is an unidentified decision
# (any client from before identity existed); otherwise a name and a channel are required, and a
# Slack user ID exactly when the channel is slack.
DECIDER_CHANNELS = frozenset({"cli", "slack", "automated"})
MAX_DECIDER_CHARS = 200
SLACK_USER_ID = re.compile(r"[UW][A-Z0-9]{2,20}\Z")


def valid_decider(decided_by: object, via: object, slack_user: object) -> bool:
    if not (isinstance(decided_by, str) and isinstance(via, str) and isinstance(slack_user, str)):
        return False
    if not (decided_by or via or slack_user):
        return True
    return (0 < len(decided_by) <= MAX_DECIDER_CHARS and decided_by.isprintable()
            and " ".join(decided_by.split()) == decided_by and via in DECIDER_CHANNELS
            and (SLACK_USER_ID.match(slack_user) is not None if via == "slack" else not slack_user))


@dataclass(frozen=True)
class WorkflowDecision:
    step_id: str
    phase: str
    decision: str
    decision_id: str
    evidence_note: str = ""
    decided_by: str = ""
    via: str = ""
    slack_user: str = ""


@dataclass(frozen=True)
class GateDecision:
    """One decision a gate took, as the status query reports it: the gate (a step ID, or ``wave-<n>``),
    phase and choice, the decision ID, and who sent it through which channel (empty when unidentified)."""
    gate: str
    phase: str
    decision: str
    decision_id: str
    decided_by: str = ""
    via: str = ""
    slack_user: str = ""


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
class StepState:
    """One step of a parallel workflow as its status query reports it.

    ``execution_id`` names the step's latest result in ``WorkflowStatus.results``. ``reason``
    is the reason code or rejection outcome of a ``dropped`` or ``stopped`` step, else empty.
    """
    step_id: str
    state: str
    wave: int
    execution_id: str | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        if self.state not in STEP_STATES:
            raise ValueError("invalid step state")



@dataclass(frozen=True)
class WorkflowStatus:
    stage: str
    step_id: str | None
    execution_id: str | None
    results: list[ExecutionResult]
    handoff_rejections: list[HandoffRejection] = field(default_factory=list)
    # Parallel workflows only: every step's state. ``step_id`` then holds the open wave's gate
    # ID (``wave-<n>``), or the step awaiting reconciliation.
    steps: list[StepState] = field(default_factory=list)
    # Every decision a gate took, oldest first; a run whose first gate decision predates the record lists none.
    decisions: list[GateDecision] = field(default_factory=list)
