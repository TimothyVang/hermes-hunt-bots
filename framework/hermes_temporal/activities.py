"""Temporal activity boundary for the explicitly enabled native transport."""
from temporalio import activity

from .contracts import ExecutionRequest, ExecutionResult
from .execution import ExecutionConfig, execute


class HermesActivities:
    def __init__(self, config: ExecutionConfig):
        self.config = config

    @activity.defn(name='execute_hermes_step')
    def execute_hermes_step(self, request: ExecutionRequest) -> ExecutionResult:
        return execute(self.config, request)
