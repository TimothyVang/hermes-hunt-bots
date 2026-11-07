"""Synthetic Temporal tests for finite human-gated practice rounds."""
from __future__ import annotations

import asyncio
import importlib.util
import unittest

if importlib.util.find_spec("temporalio") is None:
    raise unittest.SkipTest("Install hermes_temporal/requirements.txt to run Temporal integration tests.")

from temporalio import activity
from temporalio.common import WorkflowIDReusePolicy
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from .contracts import ExecutionRequest, ExecutionResult, HermesStep, WorkflowDecision, WorkflowRequest
from .practice import PracticeRequest, PracticeRoundResult, PracticeRoundWorkflow, PracticeWorkflow


class PracticeWorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.executions: list[str] = []
        self.outcome = "completed"

        @activity.defn(name="execute_hermes_step")
        async def execute(request: ExecutionRequest) -> ExecutionResult:
            self.executions.append(request.execution_id)
            reason = {
                "completed": "completed",
                "failed": "native_failed",
                "unknown": "execution_error",
            }[self.outcome]
            return ExecutionResult(self.outcome, request.execution_id, "Synthetic result.", reason)

        self.execute = execute
        self.env = await WorkflowEnvironment.start_time_skipping()
        self.worker_context = Worker(
            self.env.client,
            task_queue="test-hermes-practice",
            workflows=[PracticeRoundWorkflow, PracticeWorkflow],
            activities=[execute],
        )
        await self.worker_context.__aenter__()

    async def asyncTearDown(self) -> None:
        await self.worker_context.__aexit__(None, None, None)
        await self.env.__aexit__(None, None, None)

    @staticmethod
    async def wait_for(predicate, *, timeout: float = 10):
        async def poll():
            while True:
                value = await predicate()
                if value:
                    return value
                await asyncio.sleep(0.01)
        return await asyncio.wait_for(poll(), timeout)

    async def start_practice(self, workflow_id: str, *, rounds: int = 3, start_signal: str | None = None):
        return await self.env.client.start_workflow(
            PracticeWorkflow.run,
            PracticeRequest(WorkflowRequest([HermesStep("triage", "Synthetic triage.")]), rounds),
            id=workflow_id,
            task_queue="test-hermes-practice",
            id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            start_signal=start_signal,
        )

    async def open_child_gate(self, parent, stage: str, round_number: int | None = None):
        async def at_gate():
            state = await parent.query(PracticeWorkflow.status)
            if state.stage != stage or (round_number is not None and state.round_index != round_number):
                return None
            child = self.env.client.get_workflow_handle_for(PracticeRoundWorkflow.run, state.child_workflow_id)
            child_state = await child.query(PracticeRoundWorkflow.status)
            return (state, child) if child_state.stage == "awaiting_execution_approval" else None
        return await self.wait_for(at_gate)

    async def _state_at(self, parent, stage: str):
        state = await parent.query(PracticeWorkflow.status)
        return state if state.stage == stage else None

    async def approve_round(self, parent, round_number: int) -> None:
        state, child = await self.open_child_gate(parent, "running_round", round_number)
        self.assertEqual(state.child_workflow_id, f"{parent.id}:round:{round_number:03d}")
        await child.signal(PracticeRoundWorkflow.decision, WorkflowDecision("triage", "execute", "approve", f"execute-{round_number}"))
        await self.wait_for(lambda: self._child_stage(child, "awaiting_review"))
        await child.signal(PracticeRoundWorkflow.decision, WorkflowDecision("triage", "review", "approve", f"review-{round_number}"))

    async def _child_stage(self, child, stage: str):
        state = await child.query(PracticeRoundWorkflow.status)
        return state if state.stage == stage else None

    async def test_completed_child_rounds_advance_sequentially_with_unique_ids(self) -> None:
        parent = await self.start_practice("practice-sequential", rounds=2)
        await self.approve_round(parent, 1)
        state = await self.wait_for(lambda: self._round_state(parent, 2, "running_round"))
        self.assertEqual(state.completed_rounds, 1)
        await self.approve_round(parent, 2)
        self.assertEqual(await parent.result(), "completed")
        state = await parent.query(PracticeWorkflow.status)
        self.assertEqual((state.stage, state.completed_rounds, state.last_result), ("completed", 2, "completed"))
        self.assertEqual(self.executions, [
            "practice-sequential:round:001:0",
            "practice-sequential:round:002:0",
        ])

    async def _round_state(self, parent, round_number: int, stage: str):
        state = await parent.query(PracticeWorkflow.status)
        return state if state.round_index == round_number and state.stage == stage else None

    async def test_child_execution_and_review_gates_are_not_bypassed(self) -> None:
        parent = await self.start_practice("practice-gates", rounds=1)
        state, child = await self.open_child_gate(parent, "running_round")
        child_state = await child.query(PracticeRoundWorkflow.status)
        self.assertEqual(child_state.stage, "awaiting_execution_approval")
        self.assertEqual(self.executions, [])
        await child.signal(PracticeRoundWorkflow.decision, WorkflowDecision("triage", "execute", "approve", "gate-execute"))
        child_state = await self.wait_for(lambda: self._child_stage(child, "awaiting_review"))
        self.assertEqual(child_state.results[0].output, "Synthetic result.")
        self.assertEqual(self.executions, [f"{state.child_workflow_id}:0"])
        await child.signal(PracticeRoundWorkflow.decision, WorkflowDecision("triage", "review", "approve", "gate-review"))
        self.assertEqual(await child.result(), PracticeRoundResult("completed", ["completed"]))
        self.assertEqual(await parent.result(), "completed")

    async def test_stop_before_first_round_prevents_child_dispatch(self) -> None:
        parent = await self.start_practice("practice-early-stop", start_signal="stop")
        self.assertEqual(await parent.result(), "stopped")
        state = await parent.query(PracticeWorkflow.status)
        self.assertEqual((state.stage, state.child_workflow_id, state.completed_rounds), ("stopped", None, 0))
        self.assertEqual(self.executions, [])

    async def test_stop_during_child_requests_cancel_and_prevents_next_round(self) -> None:
        parent = await self.start_practice("practice-mid-stop", rounds=2)
        state, child = await self.open_child_gate(parent, "running_round")
        await parent.signal(PracticeWorkflow.stop)
        self.assertEqual(await parent.result(), "stopped")
        observed = await parent.query(PracticeWorkflow.status)
        self.assertEqual(observed.stage, "stopped")
        self.assertEqual(observed.child_workflow_id, state.child_workflow_id)
        self.assertEqual(observed.last_result, "child_cancelled_unknown")
        self.assertEqual(self.executions, [])
        await self.wait_for(lambda: self._child_cancelled(child))
        self.assertEqual(self.executions, [])
        self.assertEqual((await parent.query(PracticeWorkflow.status)).round_index, 1)

    async def _child_cancelled(self, child) -> bool:
        description = await child.describe()
        return description.status.name in {"CANCELED", "TERMINATED"}

    async def test_noncompleted_child_result_stops_without_replay(self) -> None:
        # Denying the original execute gate makes the child terminally rejected.
        parent = await self.start_practice("practice-rejected", rounds=3)
        _, child = await self.open_child_gate(parent, "running_round")
        await child.signal(PracticeRoundWorkflow.decision, WorkflowDecision("triage", "execute", "deny", "deny-execute"))
        self.assertEqual(await parent.result(), "halted")
        state = await parent.query(PracticeWorkflow.status)
        self.assertEqual((state.round_index, state.completed_rounds, state.last_result), (1, 0, "rejected"))
        self.assertEqual(self.executions, [])

    async def test_failed_child_result_stops_without_replay(self) -> None:
        self.outcome = "failed"
        parent = await self.start_practice("practice-failed", rounds=2)
        _, child = await self.open_child_gate(parent, "running_round")
        await child.signal(PracticeRoundWorkflow.decision, WorkflowDecision("triage", "execute", "approve", "failed-execute"))
        self.assertEqual(await parent.result(), "halted")
        state = await parent.query(PracticeWorkflow.status)
        self.assertEqual((state.round_index, state.completed_rounds, state.last_result), (1, 0, "rejected"))
        self.assertEqual(self.executions, ["practice-failed:round:001:0"])

    async def test_uncertain_child_requires_reconciliation_and_halts(self) -> None:
        self.outcome = "unknown"
        parent = await self.start_practice("practice-uncertain", rounds=2)
        _, child = await self.open_child_gate(parent, "running_round")
        await child.signal(PracticeRoundWorkflow.decision, WorkflowDecision("triage", "execute", "approve", "uncertain-execute"))
        await self.wait_for(lambda: self._child_stage(child, "needs_reconciliation"))
        await child.signal(
            PracticeRoundWorkflow.decision,
            WorkflowDecision("triage", "reconcile", "abort", "uncertain-abort", "synthetic uncertainty"),
        )
        self.assertEqual(await parent.result(), "halted")
        state = await parent.query(PracticeWorkflow.status)
        self.assertEqual((state.round_index, state.completed_rounds, state.last_result), (1, 0, "aborted"))
        self.assertEqual(self.executions, ["practice-uncertain:round:001:0"])

    async def test_reconciled_unknown_last_step_halts_without_starting_next_round(self) -> None:
        self.outcome = "unknown"
        parent = await self.start_practice("practice-unknown-reviewed", rounds=2)
        _, child = await self.open_child_gate(parent, "running_round")
        await child.signal(
            PracticeRoundWorkflow.decision,
            WorkflowDecision("triage", "execute", "approve", "unknown-execute"),
        )
        await self.wait_for(lambda: self._child_stage(child, "needs_reconciliation"))
        await child.signal(
            PracticeRoundWorkflow.decision,
            WorkflowDecision("triage", "reconcile", "accept", "unknown-accept", "synthetic uncertainty reviewed"),
        )
        await self.wait_for(lambda: self._child_stage(child, "awaiting_review"))
        await child.signal(
            PracticeRoundWorkflow.decision,
            WorkflowDecision("triage", "review", "approve", "unknown-review"),
        )

        self.assertEqual(await parent.result(), "halted")
        self.assertEqual(await child.result(), PracticeRoundResult("completed", ["unknown"]))
        state = await parent.query(PracticeWorkflow.status)
        self.assertEqual((state.round_index, state.completed_rounds, state.last_result), (1, 0, "completed:unknown"))
        self.assertEqual(self.executions, ["practice-unknown-reviewed:round:001:0"])

    async def test_invalid_round_counts_rejected(self) -> None:
        request = WorkflowRequest([HermesStep("triage", "Synthetic triage.")])
        for value in (True, 0, -1, 11, 1.0, "2"):
            with self.subTest(rounds=value):
                with self.assertRaises(ValueError):
                    PracticeRequest(request, value)
        self.assertEqual(PracticeRequest(request).rounds, 3)
