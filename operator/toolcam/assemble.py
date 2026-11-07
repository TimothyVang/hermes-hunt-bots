"""Assemble tool-cam frames into a 1080p video with an honest, fixed speed rule.

Each tool call stays on screen at real speed for HOLD seconds after it appears; time
when the bots are only thinking plays IDLE_SPEED x faster and carries a visible badge.
Frames keep their capture order; nothing is reordered or invented.

ffmpeg comes from FFMPEG (default: ffmpeg on PATH); the badge font from TOOLCAM_FONT.

Usage: python operator/toolcam/assemble.py <cam_dir> <out.mp4> [--until-ms EPOCH_MS] [--end-card PNG] [--end-seconds 8]
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab_paths import FFMPEG, TOOLCAM_FONT  # noqa: E402

HOLD, IDLE_SPEED, MIN_FRAME = 2.5, 20.0, 1 / 30


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('cam_dir')
    ap.add_argument('out')
    ap.add_argument('--until-ms', type=int)
    ap.add_argument('--end-card')
    ap.add_argument('--end-seconds', type=float, default=8.0)
    a = ap.parse_args()
    cam = Path(a.cam_dir).resolve()  # the concat list lives in a temp dir, so its frame paths must be absolute
    if not (cam / 'frames.txt').is_file():
        raise SystemExit(f'{cam} has no frames.txt; pass a toolcam.mjs output directory')
    frames = [(int(n), int(t)) for n, t in (l.split() for l in (cam / 'frames.txt').read_text().splitlines() if l.strip())]
    events = [json.loads(l) for l in (cam / 'events.jsonl').read_text(encoding='utf-8').splitlines() if l.strip()]
    shows = sorted(e['t'] for e in events if e['kind'] in ('call', 'card'))
    if a.until_ms:
        frames = [f for f in frames if f[1] <= a.until_ms]
    lines, idle_ranges = [], []
    real = out_total = idle_out = 0.0
    pending_idle = 0.0  # sped-up time not yet long enough to fill one output video frame
    for (n, t), nxt in zip(frames, frames[1:] + [None]):
        d = ((nxt[1] - t) / 1000) if nxt else 0.5
        recent = max((s for s in shows if s <= t), default=None)
        live = recent is not None and (t - recent) / 1000 < HOLD
        real += d
        if live:
            out, pending_idle = d, 0.0
        else:
            pending_idle += d / IDLE_SPEED
            if pending_idle < MIN_FRAME:
                continue  # carried into the next idle frame, so compressed time is never silently cut
            out, pending_idle = pending_idle, 0.0
        lines.append(f"file '{(cam / 'frames' / f'f{n:06d}.jpg').as_posix()}'\nduration {out:.4f}")
        if not live:
            if idle_ranges and abs(idle_ranges[-1][1] - out_total) < 1e-6:
                idle_ranges[-1][1] = out_total + out
            else:
                idle_ranges.append([out_total, out_total + out])
            idle_out += out
        out_total += out
    if a.end_card:
        out_total += a.end_seconds
    with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False, encoding='utf-8') as f:
        f.write('ffconcat version 1.0\n' + '\n'.join(lines) + '\n')
        listing = f.name
    # Every sped-up stretch carries a visible badge, so compressed time is never passed off as live.
    enable = '+'.join(f'between(t,{s:.3f},{e:.3f})' for s, e in idle_ranges if e - s >= 0.2) or '0'
    font = "fontfile='%s':" % Path(TOOLCAM_FONT).as_posix().replace(':', '\\:') if TOOLCAM_FONT else ''
    cam_chain = ("[0:v]scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2,fps=30,"
                 "drawtext=%stext='%dx speed - bots thinking':"
                 "x=w-tw-36:y=h-118:fontsize=34:fontcolor=white:box=1:boxcolor=0x1e293b@0.92:boxborderw=14:"
                 "enable='%s',format=yuv420p,setsar=1") % (font, int(IDLE_SPEED), enable)
    inputs = ['-f', 'concat', '-safe', '0', '-i', listing]
    if a.end_card:
        # A looped still of exactly end_seconds, joined by the concat filter (the concat demuxer
        # mistimes a lone image among the frames).
        inputs += ['-loop', '1', '-framerate', '30', '-t', f'{a.end_seconds:.3f}', '-i', a.end_card]
        graph = cam_chain + "[cam];[1:v]scale=1920:1080,fps=30,format=yuv420p,setsar=1[card];[cam][card]concat=n=2:v=1:a=0[out]"
    else:
        graph = cam_chain + "[out]"
    with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False, encoding='utf-8') as f:
        f.write(graph)
        script = f.name
    cmd = [FFMPEG, '-y', *inputs, '-filter_complex_script', script, '-map', '[out]',
           '-c:v', 'libx264', '-preset', 'medium', '-crf', '20', '-movflags', '+faststart', a.out]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        raise SystemExit(f'ffmpeg not found at {FFMPEG!r}; install it or set FFMPEG') from None
    finally:
        Path(listing).unlink()
        Path(script).unlink()
    if r.returncode:
        raise SystemExit(r.stderr[-1500:])
    print(json.dumps({'out': a.out, 'frames_used': len(lines), 'real_minutes': round(real / 60, 1),
                      'video_seconds': round(out_total, 1), 'idle_seconds_in_video': round(idle_out, 1),
                      'idle_ranges': len(idle_ranges)}))


if __name__ == '__main__':
    main()
