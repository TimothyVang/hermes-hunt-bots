"""Locations and settings shared by the operator tools.

Everything derives from this clone's root and its git-ignored runtime/ folder. The
environment variables named here override the defaults; operator/README.md lists them.
"""
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Next to the clone, never inside it: the lab runtime refuses VM state inside any Git work tree
# (state_inside_git), even a git-ignored folder, so lab disks and logs cannot be committed.
RUNTIME = Path(os.environ.get('HUNT_BOTS_RUNTIME') or ROOT.parent / 'runtime')
FRAMEWORK = ROOT / 'framework'
LAB_HOME = Path(os.environ.get('HUNT_BOTS_LAB_HOME') or RUNTIME / 'lab-home')
LAB_STATE = LAB_HOME / 'profiles' / 'framework-network-analyst' / 'hunt-lab-vm'
# lab_browser keeps each bot's session.json and audit.jsonl in <profile>/ here, next to the operator's demo.json.
LAB_BROWSER = LAB_STATE.parent / 'hunt-lab-browser'
PYTHON = os.environ.get('HUNT_BOTS_PYTHON') or sys.executable
TEMPORAL_ADDRESS = os.environ.get('HUNT_BOTS_TEMPORAL_ADDRESS')
TEMPORAL_TASK_QUEUE = os.environ.get('HUNT_BOTS_TASK_QUEUE')
PRACTICE = RUNTIME / 'practice'
CASES = RUNTIME / 'cases'
OPERATOR_ONLY = RUNTIME / 'operator-only'
TOOL_LOOPS = PRACTICE / 'tool-loops'
FILM_LOOPS = PRACTICE / 'film-loops'
GATE_RUNS = PRACTICE / 'gate-runs'
FFMPEG = os.environ.get('FFMPEG') or 'ffmpeg'
FFPROBE = os.environ.get('FFPROBE') or str(Path(FFMPEG).with_name(Path(FFMPEG).name.replace('ffmpeg', 'ffprobe')))
TOOLCAM_BROWSER = os.environ.get('TOOLCAM_BROWSER') or (
    r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' if os.name == 'nt' else 'chromium')
TOOLCAM_FONT = os.environ.get('TOOLCAM_FONT') or (
    str(Path(os.environ.get('WINDIR', '')) / 'Fonts' / 'segoeuib.ttf') if os.name == 'nt' else '')


def hermes_exe():
    """The Hermes executable that serves LAB_HOME. Installs differ per machine, so it is never guessed."""
    exe = os.environ.get('LAB_HERMES_EXE')
    if not exe:
        raise SystemExit(f'LAB_HERMES_EXE is not set. Point it at the hermes executable for the lab home {LAB_HOME}.')
    found = shutil.which(exe)
    if not found:
        raise SystemExit(f'LAB_HERMES_EXE={exe} is not an executable file.')
    return found


def hermes_env():
    return dict(os.environ, HERMES_HOME=str(LAB_HOME))


def temporal_cli():
    """Command prefix for hermes_temporal.cli; an unset address or queue keeps the CLI's own default."""
    cmd = [PYTHON, '-B', '-m', 'hermes_temporal.cli']
    if TEMPORAL_ADDRESS:
        cmd += ['--address', TEMPORAL_ADDRESS]
    if TEMPORAL_TASK_QUEUE:
        cmd += ['--task-queue', TEMPORAL_TASK_QUEUE]
    return cmd
