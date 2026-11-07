"""Run a loopback Temporal worker; native execution is disabled by default."""
from __future__ import annotations

import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor
import sys

from temporalio.client import Client
from temporalio.worker import Worker

from .activities import HermesActivities
from .contracts import validate_loopback_address
from .execution import ExecutionConfig, _valid_config
from .practice import PracticeRoundWorkflow, PracticeWorkflow
from .workflows import HermesWorkflow


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', default='127.0.0.1:7233', type=validate_loopback_address,
                        help='loopback Temporal server host:port')
    parser.add_argument('--task-queue', default='hermes-temporal')
    parser.add_argument('--enable-hermes', action='store_true',
                        help='explicitly allow native Hermes dispatch using the supplied isolated home')
    parser.add_argument('--hermes-executable', help='absolute path to the native Hermes executable')
    parser.add_argument('--hermes-home', help='absolute path to the separately provisioned Hermes home')
    parser.add_argument('--working-directory', help='absolute approved task working directory')
    parser.add_argument('--receipt-db', help='absolute durable SQLite receipt path, shared by workers on this host')
    parser.add_argument('--allow-operator-home', action='store_true',
                        help="explicitly permit --hermes-home to be the operator's own signed-in Hermes home")
    parser.add_argument('--visible-sessions', action='store_true',
                        help='show dispatched native chats in Hermes session lists (default: hidden tool sessions)')
    return parser


async def _run(args: argparse.Namespace, config: ExecutionConfig) -> None:
    client = await Client.connect(args.address)
    activities = HermesActivities(config)
    with ThreadPoolExecutor(max_workers=4) as executor:
        worker = Worker(client, task_queue=args.task_queue,
                        workflows=[HermesWorkflow, PracticeRoundWorkflow, PracticeWorkflow],
                        activities=[activities.execute_hermes_step], activity_executor=executor)
        print('Temporal worker ready.', flush=True)
        await worker.run()


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.task_queue.strip():
        parser.error('task queue must not be empty')
    config = ExecutionConfig(enabled=args.enable_hermes, executable=args.hermes_executable,
                             hermes_home=args.hermes_home, working_directory=args.working_directory,
                             receipt_db=args.receipt_db, allow_operator_home=args.allow_operator_home,
                             visible_sessions=args.visible_sessions)
    if config.enabled and not _valid_config(config):
        parser.error('execution requires an explicit executable, separately provisioned home, working directory, and receipt database')
    try:
        asyncio.run(_run(args, config))
    except KeyboardInterrupt:
        return 0
    except Exception:
        print('Temporal worker failed; check local server availability and worker configuration.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
