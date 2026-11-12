"""Where the parked benchmark finds the framework it drives.

In the repository the benchmark lives in `research/benchmark/` and imports `bot`,
`workflows` and `langchain_adapter` from `framework/`. A `snapshot-source` copy holds
both in one folder. Importing this module puts the framework on `sys.path`.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FRAMEWORK = HERE if (HERE / 'bot.py').is_file() else HERE.parents[1] / 'framework'
# The whole checkout (or snapshot) that state roots must stay outside of.
SOURCE_TREE = FRAMEWORK.parent
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))


def source_root(name):
    """The folder holding the relative path `name`: beside the benchmark first, else the framework."""
    return HERE if (HERE / name).exists() else FRAMEWORK
