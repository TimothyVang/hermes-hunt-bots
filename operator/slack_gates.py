"""The operator's Slack bridge for the two human decisions per hunt (ADR 0004). Opt-in; operator-side only.

drive_gates.py --two-decisions writes pending/<child>__<gate>__<digest>__review.json under the decision folder while a
hunt waits at the scope or final-report review. This long-running service posts one Slack card per record
and turns an allowlisted operator's answer into the existing hermes_temporal.cli decision on loopback:

  1. A button press (block_actions) from an allowlisted Slack user, for a record that still exists with the
     card's nonce, opens a modal that asks "What did you check?".
  2. The modal's submission (view_submission) is checked again, then the record is claimed by renaming it to
     claimed/, so each gate is decided once. The bridge confirms through `status` that the gate is still open
     and sends one decision with the ID <child>:<gate>:review:<nonce> and a note naming the operator, their
     Slack user ID, the time and the card. A sent decision is appended to decisions.jsonl and the card is
     updated; a failed one puts the record back and shows only an error code.

It uses Socket Mode, so it opens no inbound port; Temporal and the board stay on loopback. Tokens come only
from SLACK_BOT_TOKEN and SLACK_APP_TOKEN in the environment. Needs slack-sdk==3.45.0. The bots get no part
of it. Cards carry only IDs and status unless --content summary is chosen, which is for synthetic lab cases
only.

Usage: python operator/slack_gates.py --operator-name "<name>" --operator-user U0123ABCD [--channel D0123ABCD]
       [--decision-dir DIR] [--content minimal|summary]
"""
import argparse
import hmac
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from drive_gates import (DECISION_DIR, NOTE_LIMIT_BYTES, append_decision, clean_text, record_name, retry_busy,
                         sha256_text, utc_now, write_json_atomic)
from lab_paths import FRAMEWORK, PYTHON

POLL_SECONDS = 3
CLI_TIMEOUT_SECONDS = 120
NOTE_INPUT_LIMIT = 1000
CARD_TEXT_LIMIT = 2900  # a section's text may be at most 3,000 characters
MODAL_ID = 'hunt_gate_note'
ACTIONS = {'hunt_gate_approve': 'approve', 'hunt_gate_deny': 'deny'}
BUTTONS = {'scope': ('Approve', 'Reject'), 'report': ('Accept report', 'Reject report')}
VERBS = {('scope', 'approve'): 'Approve scope', ('scope', 'deny'): 'Reject scope',
         ('report', 'approve'): 'Accept report', ('report', 'deny'): 'Reject report'}
DONE = {('scope', 'approve'): 'Scope approved', ('scope', 'deny'): 'Scope rejected',
        ('report', 'approve'): 'Report accepted', ('report', 'deny'): 'Report rejected'}
RECORD_NAME = re.compile(r'[A-Za-z0-9._-]{1,120}__[A-Za-z0-9_-]{1,64}__[0-9a-f]{16}__review\.json\Z')
NONCE = re.compile(r'[0-9a-f]{32}\Z')
USER_ID = re.compile(r'[UW][A-Z0-9]{2,20}\Z')
CHANNEL_ID = re.compile(r'[CDG][A-Z0-9]{2,20}\Z')
GATE_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z')
LOOPBACK = re.compile(r'(localhost|127\.0\.0\.1|\[::1\]):[0-9]{1,5}\Z')
TASK_QUEUE = re.compile(r'[A-Za-z0-9._-]{1,128}\Z')
TOKENS = (('SLACK_BOT_TOKEN', 'xoxb-', 'bot token'), ('SLACK_APP_TOKEN', 'xapp-', 'app-level token'))
EXPIRED = 'Expired: this decision is no longer open, or a newer card replaced this one.'


class Refused(Exception):
    """A request the bridge turns down; its text is safe to show and log."""


def tokens_from_env(environ=None):
    """(bot token, app token). The refusal names a variable, never a value."""
    environ = os.environ if environ is None else environ
    values = []
    for name, prefix, what in TOKENS:
        value = (environ.get(name) or '').strip()
        if not value:
            raise Refused(f'{name} is not set; export the Slack {what} in the shell that starts the bridge')
        if not value.startswith(prefix):
            raise Refused(f'{name} is not a Slack {what} (it should start with {prefix})')
        values.append(value)
    return values


def run_cli(argv):
    """(exit code, stdout) of one hermes_temporal.cli call, or None when it timed out. The child gets no Slack variable."""
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith('SLACK_')}
    try:
        result = subprocess.run(argv, cwd=FRAMEWORK, env=env, capture_output=True, text=True, encoding='utf-8',
                                errors='replace', timeout=CLI_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return None
    return result.returncode, result.stdout


def cli_prefix(record):
    """The hermes_temporal.cli command prefix for this record, checked so a record can only ask for a decision.

    The executable is always this bridge's own Python; the record may add only a loopback --address and a
    --task-queue, and must name the record's own child and gate."""
    argv = record.get('decision_cli')
    tail = ['decision', record['child'], '--step-id', record['gate'], '--phase', 'review']
    if (not isinstance(argv, list) or not all(isinstance(item, str) for item in argv) or len(argv) < 10
            or argv[1:4] != ['-B', '-m', 'hermes_temporal.cli'] or argv[-6:] != tail):
        raise ValueError('decision_cli is not a hermes_temporal.cli decision for this gate')
    options = argv[4:-6]
    pairs = dict(zip(options[::2], options[1::2]))
    if (len(options) % 2 or len(pairs) * 2 != len(options) or not set(pairs) <= {'--address', '--task-queue'}
            or ('--address' in pairs and not LOOPBACK.match(pairs['--address']))
            or ('--task-queue' in pairs and not TASK_QUEUE.match(pairs['--task-queue']))):
        raise ValueError('decision_cli carries options other than a loopback address and a task queue')
    return [PYTHON, '-B', '-m', 'hermes_temporal.cli', *options]


def check_record(name, record):
    """The record when it is one the driver writes for one of the operator's two decisions; else ValueError."""
    if not RECORD_NAME.match(name) or not isinstance(record, dict):
        raise ValueError('not a pending record')
    for key in ('child', 'workflow', 'gate', 'kind', 'phase', 'nonce', 'opened_at', 'outputs_dir'):
        if not isinstance(record.get(key), str):
            raise ValueError(f'{key} missing')
    if record['kind'] not in BUTTONS or record['phase'] != 'review' or not NONCE.match(record['nonce']):
        raise ValueError('kind, phase or nonce invalid')
    if not GATE_ID.match(record['gate']) or record_name(record['child'], record['gate']) != name:
        raise ValueError('gate or file name does not match the record')
    decision_id = f'{record["child"]}:{record["gate"]}:review:{record["nonce"]}'
    if not decision_id.isascii() or len(decision_id) > 128:
        raise ValueError('decision ID would exceed the workflow limit')
    if 'summary' in record and not isinstance(record['summary'], str):
        raise ValueError('summary is not text')
    cli_prefix(record)
    return record


def identity_note(operator, user, at, nonce, checked):
    """The decision's evidence note, within the workflow's byte limit."""
    head = f'Decided by {operator} (Slack user {user}) via Slack at {at}; card {nonce}. Checked: '
    room = NOTE_LIMIT_BYTES - len(head.encode('utf-8'))
    return head + checked.encode('utf-8')[:room].decode('utf-8', 'ignore')


def escape(text):
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def plain(text):
    return {'type': 'plain_text', 'text': text, 'emoji': False}


def error_code(exc):
    response = getattr(exc, 'response', None)
    try:
        code = response.get('error') if response is not None else None
    except Exception:
        code = None
    return re.sub(r'[^A-Za-z0-9_]', '_', str(code or type(exc).__name__))[:64]


class Bridge:
    def __init__(self, args, web, run=run_cli, log=None):
        self.args, self.web, self.run = args, web, run
        self.folder = Path(args.decision_dir)
        self.pending, self.claimed, self.posted = (self.folder / name for name in ('pending', 'claimed', 'posted'))
        self.allowed = frozenset(args.operator_user)
        self.channel = args.channel
        self.write_log = log or self._log_to_file
        self.lock = threading.Lock()
        self.rejected = {}

    def _log_to_file(self, line):
        print(line, flush=True)
        with (self.folder / 'slack-bridge.log').open('a', encoding='utf-8') as stream:
            stream.write(line + '\n')

    def log(self, outcome, record=None, user=None):
        # Only the workflow, gate, Slack user ID and outcome: never a token, note or card text.
        parts = [time.strftime('%H:%M:%S'), outcome]
        if record:
            parts += [f'workflow={record["workflow"]}', f'gate={record["gate"]}']
        if user:
            parts.append(f'user={user}')
        self.write_log(' '.join(parts))

    def start(self):
        for folder in (self.pending, self.claimed, self.posted):
            folder.mkdir(parents=True, exist_ok=True)
        if not self.channel:
            self.channel = self.web.conversations_open(users=self.args.operator_user[0])['channel']['id']
        # A claim left by an earlier run means it stopped mid-decision, so whether its signal went out is unknown:
        # put the record back. The status check refuses it if the gate has moved on; the driver then removes it.
        for path in sorted(self.claimed.glob('*.json')):
            if (self.pending / path.name).exists():
                retry_busy(lambda: path.unlink(missing_ok=True))
            else:
                os.rename(path, self.pending / path.name)
            self.log('claim released after restart', self.read_record(self.pending / path.name))
        self.log('bridge started')

    # Records and posted cards

    def read_record(self, path):
        try:
            return check_record(path.name, json.loads(path.read_text(encoding='utf-8')))
        except (OSError, ValueError) as exc:
            if not isinstance(exc, FileNotFoundError):
                stamp = path.stat().st_mtime_ns if path.exists() else None
                if self.rejected.get(path.name) != stamp:
                    self.rejected[path.name] = stamp
                    self.log(f'record ignored ({path.name}): {exc if isinstance(exc, ValueError) else "unreadable"}')
            return None

    def read_posted(self, name):
        try:
            return json.loads((self.posted / name).read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return None

    def current(self, name, nonce):
        """The pending record when it still exists with this card's nonce."""
        if not isinstance(name, str) or not RECORD_NAME.match(name) or not isinstance(nonce, str):
            return None
        record = self.read_record(self.pending / name)
        if record is None or not hmac.compare_digest(record['nonce'], nonce):
            return None
        return record

    def poll(self):
        """Post a card for each new pending record; close cards whose record is gone."""
        with self.lock:
            live = set()
            for path in sorted(self.pending.glob('*__review.json')):
                record = self.read_record(path)
                if record is None:
                    continue
                live.add(path.name)
                posted = self.read_posted(path.name)
                if posted and posted.get('nonce') == record['nonce']:
                    continue
                if posted:
                    self.close_card(posted, 'Replaced by a newer card for the same gate.')
                self.post_card(path.name, record)
            for path in sorted(self.posted.glob('*.json')):
                if path.name in live or (self.claimed / path.name).exists():
                    continue
                posted = self.read_posted(path.name)
                if posted:
                    self.close_card(posted, 'No longer open: decided elsewhere, or the gate closed.')
                retry_busy(lambda: path.unlink(missing_ok=True))

    def card_blocks(self, name, record, closing=None):
        kind = record['kind']
        title = 'Hunt decision: approve the scope' if kind == 'scope' else 'Hunt decision: accept or reject the report'
        fields = (('Workflow', record['workflow']), ('Hunt run', record['child']),
                  ('Decision', f'{record["gate"]} review ({kind})'), ('Opened', record['opened_at']),
                  ('Outputs', record['outputs_dir']))
        blocks = [{'type': 'header', 'text': plain(title)},
                  {'type': 'section', 'fields': [{'type': 'mrkdwn', 'text': f'*{label}*\n{escape(value)[:1900]}'}
                                                 for label, value in fields]}]
        if closing:
            return blocks + [{'type': 'section', 'text': {'type': 'mrkdwn', 'text': escape(closing)}}]
        if self.args.content == 'summary' and record.get('summary'):
            head = '*Bot-written, unverified* (from the hunt output; check the outputs before deciding)\n'
            quoted = '\n'.join('>' + line for line in escape(clean_text(record['summary'])).split('\n'))
            text = head + quoted
            blocks.append({'type': 'section', 'text': {'type': 'mrkdwn', 'text': text[:CARD_TEXT_LIMIT]}})
        approve, deny = BUTTONS[kind]
        value = f'{name}|{record["nonce"]}'
        blocks.append({'type': 'actions', 'block_id': 'hunt_gate', 'elements': [
            {'type': 'button', 'action_id': 'hunt_gate_approve', 'style': 'primary', 'text': plain(approve),
             'value': value},
            {'type': 'button', 'action_id': 'hunt_gate_deny', 'style': 'danger', 'text': plain(deny), 'value': value}]})
        return blocks

    def post_card(self, name, record):
        text = f'Hunt {record["workflow"]}: {record["kind"]} decision waiting ({record["gate"]})'
        try:
            response = self.web.chat_postMessage(channel=self.channel, text=text, blocks=self.card_blocks(name, record),
                                                 unfurl_links=False, unfurl_media=False)
        except Exception as exc:
            self.log(f'card not posted: {error_code(exc)}', record)
            return
        write_json_atomic(self.posted / name, {
            'channel': response['channel'], 'ts': response['ts'], 'nonce': record['nonce'],
            'record': {key: record[key] for key in ('child', 'workflow', 'gate', 'kind', 'opened_at', 'outputs_dir')}})
        self.log('card posted', record)

    def close_card(self, posted, closing):
        record = posted.get('record') or {}
        try:
            self.web.chat_update(channel=posted['channel'], ts=posted['ts'], text=closing,
                                 blocks=self.card_blocks('', record, closing))
        except Exception as exc:
            self.log(f'card not updated: {error_code(exc)}', record if {'workflow', 'gate'} <= set(record) else None)

    def tell(self, channel, user, text):
        try:
            self.web.chat_postEphemeral(channel=channel or self.channel, user=user, text=text)
        except Exception as exc:
            self.log(f'notice not shown: {error_code(exc)}', user=user)

    # Slack interactions

    def listener(self, client, request):
        """Socket Mode listener: acknowledge first (Slack needs it within 3 seconds), then handle."""
        client.send_socket_mode_response({'envelope_id': request.envelope_id})
        if request.type != 'interactive':
            return
        payload = request.payload if isinstance(request.payload, dict) else {}
        try:
            if payload.get('type') == 'block_actions':
                self.on_block_actions(payload)
            elif payload.get('type') == 'view_submission':
                self.on_view_submission(payload)
        except Exception as exc:
            self.log(f'handler error: {type(exc).__name__}')

    def on_block_actions(self, payload):
        user = str((payload.get('user') or {}).get('id') or '')
        channel = (payload.get('channel') or {}).get('id') or (payload.get('container') or {}).get('channel_id')
        actions = payload.get('actions') or [{}]
        choice = ACTIONS.get(actions[0].get('action_id'))
        if choice is None:
            return
        if user not in self.allowed:
            self.log('refused: not allowlisted', user=user)
            self.tell(channel, user, 'Only the operator this bridge was started for can decide hunt gates.')
            return
        name, _, nonce = str(actions[0].get('value') or '').partition('|')
        with self.lock:
            record = self.current(name, nonce)
        if record is None:
            self.log('refused: expired', user=user)
            self.tell(channel, user, EXPIRED)
            return
        verb = VERBS[record['kind'], choice]
        view = {
            'type': 'modal', 'callback_id': MODAL_ID, 'title': plain(verb), 'submit': plain('Send decision'),
            'close': plain('Cancel'),
            'private_metadata': json.dumps({'record': name, 'nonce': nonce, 'choice': choice, 'channel': channel}),
            'blocks': [
                {'type': 'section', 'text': {'type': 'mrkdwn', 'text': escape(
                    f'{verb} for {record["workflow"]} ({record["child"]}, gate {record["gate"]}). '
                    'Your note is recorded with your name and Slack user ID.')}},
                {'type': 'input', 'block_id': 'note', 'label': plain('What did you check?'),
                 'element': {'type': 'plain_text_input', 'action_id': 'note', 'multiline': True,
                             'max_length': NOTE_INPUT_LIMIT}}]}
        try:
            self.web.views_open(trigger_id=payload['trigger_id'], view=view)
        except Exception as exc:
            self.log(f'note form not opened: {error_code(exc)}', record, user)
            return
        self.log(f'note requested ({choice})', record, user)

    def on_view_submission(self, payload):
        view = payload.get('view') or {}
        if view.get('callback_id') != MODAL_ID:
            return
        user = str((payload.get('user') or {}).get('id') or '')
        try:
            meta = json.loads(view.get('private_metadata') or '{}')
        except ValueError:
            meta = {}
        meta = meta if isinstance(meta, dict) else {}
        name, nonce, choice, channel = meta.get('record'), meta.get('nonce'), meta.get('choice'), meta.get('channel')
        if user not in self.allowed:
            self.log('refused: not allowlisted', user=user)
            self.tell(channel, user, 'Only the operator this bridge was started for can decide hunt gates.')
            return
        if choice not in ('approve', 'deny'):
            return
        try:
            checked = view['state']['values']['note']['note']['value']
        except (KeyError, TypeError):
            checked = None
        checked = clean_text(checked).strip() if isinstance(checked, str) else ''
        if not checked or len(checked) > NOTE_INPUT_LIMIT:
            self.log('refused: no note', user=user)
            self.tell(channel, user, f'A note of 1 to {NOTE_INPUT_LIMIT:,} characters on what you checked is required.')
            return
        with self.lock:
            record = self.current(name, nonce)
            if record is None:
                self.log('refused: expired', user=user)
                self.tell(channel, user, EXPIRED)
                return
            claimed = self.claimed / name
            try:
                os.rename(self.pending / name, claimed)
            except OSError:
                self.log('refused: already claimed', record, user)
                self.tell(channel, user, 'Already being decided: this gate was claimed by another answer.')
                return
            record = self.read_record(claimed)
            if record is None or not hmac.compare_digest(record['nonce'], nonce):
                self.release(name)
                self.log('refused: expired', user=user)
                self.tell(channel, user, EXPIRED)
                return
        self.decide(name, record, choice, user, channel, checked)

    def release(self, name):
        """Put a claimed record back, unless the driver has meanwhile written a newer one for the gate."""
        claimed = self.claimed / name
        if (self.pending / name).exists():
            retry_busy(lambda: claimed.unlink(missing_ok=True))
        else:
            retry_busy(lambda: os.rename(claimed, self.pending / name))

    def decide(self, name, record, choice, user, channel, checked):
        child, gate, nonce = record['child'], record['gate'], record['nonce']
        prefix = cli_prefix(record)
        decision_id = f'{child}:{gate}:review:{nonce}'
        at = utc_now()
        note = identity_note(self.args.operator_name, user, at, nonce, checked)
        error = None
        status = self.run([*prefix, 'status', child])
        if status is None:
            error = 'status_timeout'
        elif status[0]:
            error = f'status_exit_{status[0]}'
        else:
            try:
                state = json.loads(status[1])
            except ValueError:
                state = None
            if not isinstance(state, dict) or (state.get('stage'), state.get('step_id')) != ('awaiting_review', gate):
                error = 'expired'
        if error is None:
            sent = self.run([PYTHON, *record['decision_cli'][1:], '--choice', choice, '--decision-id', decision_id,
                             '--evidence-note', note])
            if sent is None:
                error = 'decision_timeout'
            elif sent[0]:
                error = f'decision_exit_{sent[0]}'
            else:
                try:
                    confirmed = json.loads(sent[1]).get('signal_sent') is True
                except (ValueError, AttributeError):
                    confirmed = False
                error = None if confirmed else 'decision_unconfirmed'
        if error:
            with self.lock:
                self.release(name)
            self.log(f'decision not sent: {error}', record, user)
            self.tell(channel, user, EXPIRED if error == 'expired' else f'Decision not sent (error {error}). '
                                                                         'The card stays open.')
            return
        append_decision(self.folder, workflow=record['workflow'], child=child, gate=gate, phase='review', choice=choice,
                        decided_by=f'human: {self.args.operator_name}', channel='slack', slack_user=user,
                        decision_id=decision_id, note_sha256=sha256_text(note))
        self.log(f'decided: {choice}', record, user)
        with self.lock:
            posted = self.read_posted(name)
            if posted:
                self.close_card(posted, f'{DONE[record["kind"], choice]} by {self.args.operator_name} '
                                        f'(Slack user {user}) at {at}.')
            retry_busy(lambda: (self.posted / name).unlink(missing_ok=True))
            retry_busy(lambda: (self.claimed / name).unlink(missing_ok=True))


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--operator-name', required=True, help='the operator named in every decision note and log line')
    ap.add_argument('--operator-user', required=True, nargs='+', action='extend',
                    help='Slack user ID(s) allowed to decide, for example U0123ABCD')
    ap.add_argument('--channel', help='DM or channel ID for the cards (default: a DM with the first --operator-user)')
    ap.add_argument('--decision-dir', type=Path, default=DECISION_DIR,
                    help='the folder drive_gates.py writes (default: %(default)s)')
    ap.add_argument('--content', choices=('minimal', 'summary'), default='minimal',
                    help='minimal: IDs, gate, time and outputs path; summary adds the bot-written summary '
                         '(synthetic lab cases only)')
    args = ap.parse_args(argv)
    args.operator_name = ' '.join(args.operator_name.split())
    if not args.operator_name or len(args.operator_name) > 200:
        ap.error('--operator-name must be 1 to 200 characters')
    bad = [user for user in args.operator_user if not USER_ID.match(user)]
    if bad:
        ap.error(f'not a Slack user ID: {", ".join(bad)}')
    if args.channel is not None and not CHANNEL_ID.match(args.channel):
        ap.error('--channel must be a Slack channel or DM ID such as D0123ABCD')
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        bot_token, app_token = tokens_from_env()
    except Refused as exc:
        print(f'slack_gates: {exc}', file=sys.stderr)
        return 2
    try:
        from slack_sdk.socket_mode import SocketModeClient
        from slack_sdk.web import WebClient
    except ImportError:
        print('slack_gates: slack_sdk is not installed; install slack-sdk==3.45.0 for this Python', file=sys.stderr)
        return 2
    web = WebClient(token=bot_token)
    bridge = Bridge(args, web)
    try:
        bridge.start()
    except Exception as exc:
        print(f'slack_gates: could not start: {error_code(exc)}', file=sys.stderr)
        return 1
    socket = SocketModeClient(app_token=app_token, web_client=web)
    socket.socket_mode_request_listeners.append(bridge.listener)
    socket.connect()
    try:
        while True:
            try:
                bridge.poll()
            except Exception as exc:
                bridge.log(f'poll error: {type(exc).__name__}')
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        return 0
    finally:
        socket.close()


if __name__ == '__main__':
    sys.exit(main())
