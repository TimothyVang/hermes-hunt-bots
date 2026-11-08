"""Locations and settings shared by the operator tools.

Everything derives from this clone's root and its git-ignored runtime/ folder. The
environment variables named here override the defaults; operator/README.md lists them.
"""
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Next to the clone, never inside it: the lab runtime refuses VM state inside any Git work tree
# (state_inside_git), even a git-ignored folder, so lab disks and logs cannot be committed.
RUNTIME = Path(os.environ.get('HUNT_BOTS_RUNTIME') or ROOT.parent / 'runtime')
FRAMEWORK = ROOT / 'framework'
LAB_HOME = Path(os.environ.get('HUNT_BOTS_LAB_HOME') or RUNTIME / 'lab-home')
PYTHON = os.environ.get('HUNT_BOTS_PYTHON') or sys.executable
# Every Python child these tools start (the Temporal CLI, scorers, the gate driver) writes its piped
# output as UTF-8, which is how the tools read it. Without this a Windows child uses the locale code
# page, and one arrow in a stage output crashed the gate driver and halted a filmed round.
os.environ.setdefault('PYTHONIOENCODING', 'utf-8')
TEMPORAL_ADDRESS = os.environ.get('HUNT_BOTS_TEMPORAL_ADDRESS')
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


@dataclass(frozen=True)
class Lane:
    """One complete lab: a Hermes home (its six profiles, lab VM and lab_browser state), the Temporal task
    queue its worker polls, the Hermes executable serving it, and the 1920x1080 desktop region its consoles
    are filmed in. Every tool that touches a lab takes its Lane, so two lanes can run side by side."""
    name: str = ''
    home: Path = LAB_HOME
    task_queue: str | None = os.environ.get('HUNT_BOTS_TASK_QUEUE')
    exe: str | None = None
    region: tuple = (0, 0, 1920, 1080)

    @property
    def state_dir(self):
        return self.home / 'profiles' / 'framework-network-analyst' / 'hunt-lab-vm'

    @property
    def browser_root(self):
        # lab_browser keeps each bot's session.json and audit.jsonl in <profile>/ here, next to the operator's demo.json.
        return self.state_dir.parent / 'hunt-lab-browser'

    def hermes_exe(self):
        """The Hermes executable that serves this home. Installs differ per machine, so it is never guessed."""
        exe = self.exe or os.environ.get('LAB_HERMES_EXE')
        if not exe:
            raise SystemExit(f'LAB_HERMES_EXE is not set. Point it at the hermes executable for the lab home {self.home}.')
        found = shutil.which(exe)
        if not found:
            raise SystemExit(f'{exe} (hermes for {self.home}) is not an executable file.')
        return found

    def env(self):
        """Environment for a child that works on this lane, including operator tools such as drive_gates.py."""
        env = dict(os.environ, HERMES_HOME=str(self.home), HUNT_BOTS_LAB_HOME=str(self.home))
        env.pop('HUNT_BOTS_TASK_QUEUE', None)
        return (env | ({'HUNT_BOTS_TASK_QUEUE': self.task_queue} if self.task_queue else {})
                | ({'LAB_HERMES_EXE': self.exe} if self.exe else {}))

    def temporal_cli(self):
        """Command prefix for hermes_temporal.cli; an unset address or queue keeps the CLI's own default."""
        cmd = [PYTHON, '-B', '-m', 'hermes_temporal.cli']
        if TEMPORAL_ADDRESS:
            cmd += ['--address', TEMPORAL_ADDRESS]
        if self.task_queue:
            cmd += ['--task-queue', self.task_queue]
        return cmd


# The lab named by HUNT_BOTS_LAB_HOME / HUNT_BOTS_TASK_QUEUE / LAB_HERMES_EXE, read once when a tool starts.
DEFAULT_LANE = Lane()
