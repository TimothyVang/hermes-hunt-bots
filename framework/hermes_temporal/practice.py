"""Finite, human-gated repetition of the existing Hermes workflow."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from temporalio import workflow
from temporalio.common import RetryPolicy, WorkflowIDReusePolicy
from temporalio.exceptions import is_cancelled_exception

from .contracts import WorkflowDecision, WorkflowRequest, WorkflowStatus
from .workflows import HermesWorkflow


@dataclass(frozen=True)
class PracticeRoundResult:
    terminal_status: str
    execution_statuses: list[str]


@workflow.defn
class PracticeRoundWorkflow(HermesWorkflow):
    @workflow.query(name="status")
    def status(self) -> WorkflowStatus:
        return super().status()

    @workflow.signal(name="decision")
    def decision(self, item: WorkflowDecision) -> None:
        super().decision(item)

    @workflow.run
    async def run(self, request: WorkflowRequest) -> PracticeRoundResult:
        terminal_status = await super().run(request)
        results = self._results
        if request.parallel:
            # A dropped hunter must not halt the round, so only required steps are reported.
            required = {state.execution_id for state, step in zip(self._step_states, request.steps)
                        if not step.optional}
            results = [result for result in results if result.execution_id in required]
        return PracticeRoundResult(terminal_status, [result.status for result in results])


@dataclass(frozen=True)
class PracticeRequest:
    hunt: WorkflowRequest
    rounds: int = 3

    def __post_init__(self) -> None:
        if not isinstance(self.hunt, WorkflowRequest):
            raise ValueError("hunt must be a validated WorkflowRequest")
        if type(self.rounds) is not int or not 1 <= self.rounds <= 10:
            raise ValueError("rounds must be an integer from 1 through 10")


@dataclass(frozen=True)
class PracticeStatus:
    stage: str
    round_index: int
    rounds: int
    child_workflow_id: str | None
    completed_rounds: int
    last_result: str | None


@workflow.defn
class PracticeWorkflow:
    def __init__(self) -> None:
        self._stage = "initializing"
        self._round_index = 0
        self._rounds = 0
        self._child_workflow_id: str | None = None
        self._completed_rounds = 0
        self._last_result: str | None = None
        self._stop_requested = False
        self._child = None

    @workflow.query(name="status")
    def status(self) -> PracticeStatus:
        return PracticeStatus(
            self._stage,
            self._round_index,
            self._rounds,
            self._child_workflow_id,
            self._completed_rounds,
            self._last_result,
        )

    @workflow.signal(name="stop")
    def stop(self) -> None:
        """Request a best-effort Temporal child cancellation; never approve child gates."""
        if self._stage not in {"completed", "halted", "stopped"}:
            self._stop_requested = True
            self._stage = "stopping" if self._child is not None else "stopped"

    @workflow.run
    async def run(self, request: PracticeRequest) -> str:
        if not isinstance(request, PracticeRequest):
            raise ValueError("workflow input must be PracticeRequest")
        # Re-validate at the workflow boundary; dataclass construction is not a trust boundary.
        if not isinstance(request.hunt, WorkflowRequest):
            self._stage = "halted"
            self._last_result = "invalid_request"
            return self._stage
        if type(request.rounds) is not int or not 1 <= request.rounds <= 10:
            self._stage = "halted"
            self._last_result = "invalid_rounds"
            return self._stage
        self._rounds = request.rounds
        if self._stop_requested:
            self._stage = "stopped"
            return self._stage

        for index in range(1, self._rounds + 1):
            if self._stop_requested:
                self._stage = "stopped"
                return self._stage
            self._round_index = index
            child_id = f"{workflow.info().workflow_id}:round:{index:03d}"
            self._child_workflow_id = child_id
            self._stage = "starting_round"
            try:
                child = await workflow.start_child_workflow(
                    PracticeRoundWorkflow.run,
                    request.hunt,
                    id=child_id,
                    id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
                    cancellation_type=workflow.ChildWorkflowCancellationType.WAIT_CANCELLATION_REQUESTED,
                    parent_close_policy=workflow.ParentClosePolicy.TERMINATE,
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )
            except asyncio.CancelledError:
                self._stage = "stopped" if self._stop_requested else "halted"
                if self._last_result is None:
                    self._last_result = "child_start_uncertain"
                raise
            except Exception as exc:
                # Duplicate, rejected, or otherwise unstartable child: never guess it is safe to replay.
                self._last_result = (
                    "child_start_rejected"
                    if "already" in str(exc).lower() or "duplicate" in str(exc).lower()
                    else "child_start_uncertain"
                )
                self._stage = "halted"
                return self._stage

            self._child = child
            if self._stop_requested:
                self._stage = "stopping"
                child.cancel()
            else:
                self._stage = "running_round"

            try:
                # A stop signal races the child result without interrupting its original human gates.
                await workflow.wait_condition(lambda: self._stop_requested or child.done())
                if self._stop_requested and not child.done():
                    self._stage = "stopping"
                    child.cancel()
                try:
                    result = await child
                except asyncio.CancelledError:
                    self._last_result = "child_cancelled_unknown"
                    self._stage = "stopped" if self._stop_requested else "halted"
                    return self._stage
                except Exception as exc:
                    self._last_result = (
                        "child_cancelled_unknown"
                        if is_cancelled_exception(exc)
                        else "child_failed_unknown"
                    )
                    self._stage = "stopped" if self._stop_requested else "halted"
                    return self._stage
            except asyncio.CancelledError:
                # Parent cancellation must request cancellation of its active child before exiting.
                if not child.done():
                    child.cancel()
                raise
            finally:
                self._child = None

            if not isinstance(result, PracticeRoundResult):
                self._last_result = "child_result_unknown"
                self._stage = "halted"
                return self._stage
            statuses_completed = (
                len(result.execution_statuses) == sum(not step.optional for step in request.hunt.steps)
                and all(status == "completed" for status in result.execution_statuses)
            )
            self._last_result = (
                result.terminal_status
                if result.terminal_status != "completed" or statuses_completed
                else f"{result.terminal_status}:{','.join(result.execution_statuses)}"
            )
            if result.terminal_status != "completed" or not statuses_completed:
                self._stage = "stopped" if self._stop_requested else "halted"
                return self._stage
            self._completed_rounds += 1
            if self._stop_requested:
                self._stage = "stopped"
                return self._stage

        self._stage = "completed"
        return self._stage
