#!/usr/bin/env python3
"""One-shot benchmark child: canonical public inputs, durable calls, no retries.

The ledger's stdin is discarded, never interpreted as a path or model prompt.
Only validated narrative text is emitted, after all configured calls are durable.
"""
import contextlib
import datetime as dt
from decimal import Decimal
import logging
import os
from pathlib import Path
import sys
import time
import warnings

from benchmark_contracts import (
    BenchmarkError, call_cost_bound, canonical_bytes, confined_file, decode_json,
    digest_bytes, stage_output_schema, validate_stage_output,
)
from benchmark_store import BenchmarkStore, FAILURES, REJECTED_RESPONSE_FAILURES
import benchmark_runner as runner
from langchain_adapter import (AdapterProblem, PrerequisiteMissing, SafeParser,
                               UnsupportedParameter, check_prerequisites,
                               validate_parameters)

MAX_INPUT_BYTES = 1024 * 1024
TOKEN_FIELDS = ('input_tokens', 'output_tokens', 'cached_input_tokens', 'reasoning_tokens')
FINISH_REASONS = frozenset(('stop', 'length', 'end_turn', 'max_tokens', 'stop_sequence',
                           'content_filter', 'tool_calls', 'tool_use', 'function_call',
                           'pause_turn', 'refusal', 'eos_token'))
_THINK_OPEN = '<think>'
_THINK_CLOSE = '</think>'


def _fail(code, field='model'):
    raise BenchmarkError(code, field) from None


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='microseconds')


def _empty_usage():
    return dict.fromkeys(TOKEN_FIELDS)


@contextlib.contextmanager
def _isolated(model):
    """A process-local boundary; this child never runs concurrent transports."""
    previous = dict(os.environ)
    disabled = logging.root.manager.disable
    try:
        allowed = runner._environment(model)
        name = model['credential_env']
        secret = previous.get(name) if name is not None else None
        if name is not None and (not secret or any(ord(c) < 33 or ord(c) > 126 for c in secret)):
            _fail('credential_unavailable', 'model.credential_env')
        if model['adapter'] == 'langchain':
            target = 'OPENAI_API_KEY' if model['provider'] == 'openai' else 'ANTHROPIC_API_KEY'
            if secret is not None:
                allowed[target] = secret
            elif model['provider'] == 'openai' and model['base_url'] is not None:
                # Some unauthenticated local APIs still require a nonempty SDK key.
                # This fixed non-secret is not an inherited provider credential.
                from urllib.parse import urlsplit
                import ipaddress
                parts = urlsplit(model['base_url'])
                if parts.scheme == 'http' and (parts.hostname == 'localhost' or ipaddress.ip_address(parts.hostname).is_loopback):
                    allowed[target] = 'benchmark-local-no-credential'
        os.environ.clear()
        os.environ.update(allowed)
        for name in ('LANGSMITH_TRACING', 'LANGCHAIN_TRACING', 'LANGCHAIN_TRACING_V2'):
            os.environ[name] = 'false'
        logging.disable(logging.CRITICAL)
        with open(os.devnull, 'w', encoding='utf-8') as quiet, contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet), warnings.catch_warnings():
            warnings.simplefilter('ignore')
            yield
    finally:
        os.environ.clear()
        os.environ.update(previous)
        logging.disable(disabled)


def _metadata(response, model):
    """Only actual model/finish and usage metadata; never response IDs or reasoning."""
    metadata = getattr(response, 'response_metadata', None)
    if metadata is None:
        metadata = {}
    if type(metadata) is not dict:
        _fail('unsupported_metadata')
    returned = metadata.get('model_name') if model['provider'] == 'openai' else metadata.get('model')
    if returned is None:
        returned = metadata.get('model') if model['provider'] == 'openai' else metadata.get('model_name')
    if returned is not None and (type(returned) is not str or not returned.strip()):
        _fail('unsupported_metadata')
    finish = metadata.get('finish_reason') if model['provider'] == 'openai' else metadata.get('stop_reason')
    if finish is not None and (type(finish) is not str or finish not in FINISH_REASONS):
        _fail('unsupported_metadata')
    usage = _empty_usage()
    actual = getattr(response, 'usage_metadata', None)
    if actual is not None:
        if type(actual) is not dict:
            _fail('unsupported_metadata')
        usage['input_tokens'] = actual.get('input_tokens')
        usage['output_tokens'] = actual.get('output_tokens')
        for details, source, target in (('input_token_details', 'cache_read', 'cached_input_tokens'),
                                        ('output_token_details', 'reasoning', 'reasoning_tokens')):
            nested = actual.get(details)
            if nested is not None:
                if type(nested) is not dict:
                    _fail('unsupported_metadata')
                usage[target] = nested.get(source)
        for value in usage.values():
            if value is not None and (type(value) is not int or value < 0):
                _fail('unsupported_metadata')
        for subset, total in (('cached_input_tokens', 'input_tokens'), ('reasoning_tokens', 'output_tokens')):
            if usage[subset] is not None and usage[total] is not None and usage[subset] > usage[total]:
                _fail('unsupported_metadata')
    identity = 'unreported' if returned is None else ('reported_match' if returned in model['expected_model_ids'] else 'reported_mismatch')
    return dict(model_returned=returned, identity_status=identity, finish_reason=finish, usage=usage)


# Operator/configuration failures are never charged to the model as format errors.
_MAPPED = {'upstream_unreachable': 'dispatch_interrupted',
           'upstream_http_error': 'transport_failed',
           'response_too_large': 'output_limit',
           'model_mismatch': 'model_identity_mismatch',
           'missing_or_invalid_credential': 'credential_unavailable',
           'permission_denied': 'authentication_failed',
           'invalid_origin': 'configuration_invalid',
           'invalid_limit': 'configuration_invalid',
           'invalid_response_limit': 'configuration_invalid'}


def _failure(exc):
    if isinstance(exc, BenchmarkError):
        if exc.code in _MAPPED:
            return _MAPPED[exc.code]
        return exc.code if exc.code in FAILURES else 'invalid_response'
    if isinstance(exc, UnsupportedParameter):
        return 'unsupported_parameter'
    if isinstance(exc, PrerequisiteMissing):
        return 'prerequisite_missing'
    if isinstance(exc, AdapterProblem):
        return 'configuration_invalid'
    # Inspect types, never provider exception strings, response bodies or headers.
    names = {cls.__name__ for cls in type(exc).__mro__}
    # 'timeout' is socket.timeout, a separate class from TimeoutError before Python 3.10.
    if isinstance(exc, TimeoutError) or names & {'timeout', 'APITimeoutError', 'ReadTimeout', 'ConnectTimeout', 'TimeoutException'}:
        return 'timeout'
    if names & {'AuthenticationError', 'PermissionDeniedError'}:
        return 'authentication_failed'
    if (isinstance(exc, (KeyboardInterrupt, SystemExit))
            or names & {'APIConnectionError', 'NetworkError', 'RemoteProtocolError'}):
        return 'dispatch_interrupted'
    return 'transport_failed'


def _receipt(call_id, spec, frozen, team, start):
    return dict(schema_version=1, call_id=call_id, fingerprint=digest_bytes(canonical_bytes(spec)),
                status='failed', model_requested=spec['model']['model_requested'], model_returned=None,
                identity_status='unreported', provider=spec['model']['provider'], deployment=team['deployment'],
                role=spec['role'], stage_key=spec['stage_key'], prompt_sha256=spec['input_sha256'],
                response_sha256=None, start_utc=start, end_utc=start, elapsed_ms=0,
                timeout_seconds=spec['model']['timeout_seconds'],
                max_calls=frozen['experiment']['budgets']['max_calls_per_trial'],
                max_output_bytes=frozen['experiment']['budgets']['max_response_bytes'], finish_reason=None,
                usage=_empty_usage(), estimated_usage=_empty_usage(),
                cost=dict(api_cost_usd=None, pricing_snapshot_sha256=digest_bytes(canonical_bytes(frozen['experiment']['pricing_snapshot'])),
                          cost_basis='unknown', local_compute_cost_usd=None, local_energy_cost_usd=None,
                          bound_exceeded=False),
                failure_reason='execution_failed', response_artifact=None)


def _finish(store, receipt, spec, frozen, started):
    receipt['end_utc'] = _now()
    receipt['elapsed_ms'] = max(0, (time.monotonic_ns() - started) / 1000000)
    usage = receipt['usage']
    rates = [rate for rate in frozen['experiment']['pricing_snapshot']['rates']
             if rate['provider'] == spec['model']['provider'] and rate['model_requested'] == spec['model']['model_requested']]
    if len(rates) == 1 and usage['input_tokens'] is not None and usage['output_tokens'] is not None:
        rate = rates[0]
        cost = (Decimal(str(rate['input_per_million'])) * usage['input_tokens']
                + Decimal(str(rate['output_per_million'])) * usage['output_tokens']) / 1000000
        receipt['cost'].update(api_cost_usd=float(cost), cost_basis='computed')
    # A computed cost above the reserved worst case is flagged, never hidden.
    bound = call_cost_bound(frozen['experiment']['budgets'], spec['model'],
                            frozen['experiment']['pricing_snapshot']['rates'])
    api_cost = receipt['cost']['api_cost_usd']
    receipt['cost']['bound_exceeded'] = bool(api_cost is not None and bound is not None and api_cost > bound)
    # Never turn an artifact/commit failure into a fabricated terminal receipt.
    # The reserved record remains the authority for an uncertain dispatch.
    store.finish_call(receipt['call_id'], receipt)
    return receipt


def _answer(text):
    """The answer after a leading inline reasoning block, and whether it was cut off.

    Local reasoning models (for example DeepSeek-R1 distills served through an
    OpenAI-compatible endpoint) put their deliberation inline before the answer.
    It is discarded, never stored or scored; an unclosed block means the answer
    was cut off and there is none.
    """
    stripped = text.lstrip()
    if not stripped.startswith(_THINK_OPEN):
        return text, False
    end = stripped.find(_THINK_CLOSE)
    if end < 0:
        return '', True
    return stripped[end + len(_THINK_CLOSE):].strip(), False


def _response_bytes(response, receipt, maximum, stage, evidence, rejected):
    """Validated answer bytes and output. Once a text answer was received, its
    think-stripped bytes are put in `rejected['answer']` for failure diagnostics."""
    if getattr(response, 'tool_calls', None) or getattr(response, 'invalid_tool_calls', None):
        _fail('tool_response', 'response.tool_calls')
    if receipt['finish_reason'] in ('tool_calls', 'tool_use', 'function_call'):
        _fail('tool_response', 'response.finish_reason')
    # LangChain's text property selects text blocks, not hidden reasoning blocks.
    text = response.text
    answer, unclosed = _answer(text) if isinstance(text, str) else ('', False)
    rejected['answer'] = answer.encode('utf-8', 'replace')
    if receipt['finish_reason'] in ('length', 'max_tokens'):
        _fail('output_limit', 'response.finish_reason')
    if receipt['finish_reason'] in ('content_filter', 'pause_turn', 'refusal'):
        _fail('invalid_response', 'response.finish_reason')
    if not isinstance(text, str) or not text.strip():
        _fail('empty_response', 'response.text')
    if unclosed:
        _fail('output_limit', 'response.reasoning_block')
    if not answer:
        _fail('empty_response', 'response.text')
    try:
        raw = answer.encode('utf-8')
    except UnicodeError:
        _fail('invalid_response', 'response.encoding')
    if len(raw) > maximum:
        _fail('output_limit', 'response.bytes')
    output = decode_json(raw)
    validate_stage_output(output, stage, evidence)
    return raw, output


def _rejected_response(store, trial, receipt, exc, rejected):
    """Evaluator-only diagnostics for a received answer that failed the format.

    The think-stripped answer (first `max_output_bytes` bytes, marked truncated
    when longer) is a separate artifact that no prompt, checker or score reads.
    """
    if (receipt['failure_reason'] not in REJECTED_RESPONSE_FAILURES or 'answer' not in rejected
            or not isinstance(exc, BenchmarkError)):
        return
    answer, maximum = rejected['answer'], receipt['max_output_bytes']
    receipt['rejected_response'] = dict(
        error_code=exc.code, error_field=exc.field, byte_count=len(answer), truncated=len(answer) > maximum,
        artifact=store.write_artifact(trial['trial_id'], 'rejected-responses', answer[:maximum]) if answer else None)


def _context(call_spec, prompt):
    if type(call_spec) is not dict or set(call_spec) != {'state_root', 'call_id', 'spec'}:
        _fail('invalid_fields', 'call')
    store = BenchmarkStore(call_spec['state_root'])
    spec = call_spec['spec']
    fingerprint = digest_bytes(canonical_bytes(spec))
    with store.connection() as db:
        trial, frozen, team = store._call_spec(db, spec, fingerprint)
    if spec['component'] != 'narrative':
        _fail('scope_mismatch', 'call.component')
    identity, _, _ = runner._source_identity()
    if any(spec[key] != value for key, value in identity.items()):
        _fail('fingerprint_conflict', 'call.source_identity')
    canonical = runner.build_prompt(store, trial, spec['stage_key'])
    if type(prompt) is str:
        prompt = prompt.encode('utf-8')
    if type(prompt) is not bytes or prompt != canonical or store.read_artifact(trial['trial_id'], spec['prompt_artifact']) != canonical:
        _fail('fingerprint_conflict', 'call.prompt')
    if runner.release_required(runner._case(frozen, trial)['scenario'], spec['model']):
        _current_authorization(store, trial, spec['model'], human_only=True)
    return store, spec, trial, frozen, team, canonical


def _current_authorization(store, trial, model, human_only=False):
    model_sha = digest_bytes(canonical_bytes(model))
    authorizations = store.trial_authorizations(trial['trial_id'])
    with store.connection() as db:
        for item in reversed(authorizations):
            if (item['kind'] == 'authorization' and item['trial_id'] == trial['trial_id']
                    and item['experiment_id'] == trial['experiment_id']
                    and item['evidence_sha256'] == trial['case_evidence_sha256']
                    and model_sha in item['model_sha256s']
                    and (not human_only or item['by'] != 'operator-cli')):
                try:
                    store._authorization(db, item['authorization_sha256'])
                except BenchmarkError as exc:
                    if exc.code == 'authorization_expired':
                        continue
                    raise
                return item['authorization_sha256']
    _fail('release_required' if human_only else 'authorization_required', 'call.authorization')


def _checker(store, spec, trial, frozen, team, output, narrative_receipt, reused):
    if spec['stage_key'] != 'analysis' or 'evidence_checker' not in team:
        return None
    from benchmark_typesafe import build_checker_request, invoke_checker, assemble_checker
    from envision_protocol import encode_json
    model = team['evidence_checker']
    evidence = runner._case(frozen, trial)['evidence']
    request, invalid = build_checker_request(output, evidence, model)
    if request is None:
        from benchmark_decisions import checker_validator_output
        return checker_validator_output(output, evidence, narrative_receipt['response_sha256'])
    matches = [call for call in store.calls(trial_id=trial['trial_id'])
               if call['spec']['component'] == 'evidence_checker' and call['spec']['stage_key'] == 'analysis'
               and call['spec']['attempt_index'] == spec['attempt_index']]
    if reused:
        if len(matches) != 1:
            _fail('checker_incomplete', 'checker')
        existing = matches[0]
        if store.read_artifact(trial['trial_id'], existing['spec']['prompt_artifact']) != encode_json(request):
            _fail('fingerprint_conflict', 'checker.prompt')
        receipt = store.reserve_call(existing['call_id'], existing['fingerprint'], existing['spec'])
        if receipt['status'] != 'completed':
            _fail(receipt['failure_reason'], 'checker')
        appendix = decode_json(store.read_artifact(trial['trial_id'], receipt['response_artifact']))
        if appendix.get('narrative_sha256') != narrative_receipt['response_sha256']:
            _fail('fingerprint_conflict', 'checker')
        return appendix
    identity, _, _ = runner._source_identity()
    if any(spec[key] != value for key, value in identity.items()):
        _fail('fingerprint_conflict', 'call.source_identity')
    if runner._case(frozen, trial)['scenario']['provenance'] != 'synthetic':
        _current_authorization(store, trial, model, human_only=True)
    raw_request = encode_json(request)
    ref = store.write_artifact(trial['trial_id'], 'prompts', raw_request)
    checker_spec = dict(spec, component='evidence_checker', model=model, prompt_artifact=ref,
                        input_sha256=digest_bytes(raw_request),
                        authorization_sha256=_current_authorization(store, trial, model))
    # Derive an opaque stable ID without extending a maximum-length caller ID.
    call_id = digest_bytes(canonical_bytes({'narrative': narrative_receipt['call_id'], 'component': 'evidence_checker'}))
    old = store.reserve_call(call_id, digest_bytes(canonical_bytes(checker_spec)), checker_spec)
    if old is not None:
        _fail('state_conflict', 'checker')
    started = time.monotonic_ns()
    receipt = _receipt(call_id, checker_spec, frozen, team, _now())
    appendix = None
    raw = None
    try:
        with _isolated(model):
            response = invoke_checker(model, request, receipt['max_output_bytes'])
        receipt.update({key: response[key] for key in ('model_returned', 'identity_status', 'usage', 'finish_reason')})
        if receipt['identity_status'] == 'reported_mismatch':
            _fail('model_identity_mismatch')
        elapsed = max(0, (time.monotonic_ns() - started) // 1000000)
        appendix = assemble_checker(output, evidence, narrative_receipt['response_sha256'], model, response, invalid, elapsed)
        raw = canonical_bytes(appendix)
        if len(raw) > receipt['max_output_bytes']:
            _fail('output_limit')
        receipt.update(status='completed', failure_reason=None)
    except BaseException as exc:
        reason = _failure(exc)
        receipt.update(status='unknown' if reason in ('timeout', 'dispatch_interrupted') else 'failed', failure_reason=reason)
    if receipt['status'] == 'completed':
        receipt['response_artifact'] = store.write_artifact(trial['trial_id'], 'checker', raw)
        receipt['response_sha256'] = digest_bytes(raw)
    _finish(store, receipt, checker_spec, frozen, started)
    if receipt['status'] != 'completed':
        _fail(receipt['failure_reason'], 'checker')
    return appendix


def execute_call(call_spec, prompt):
    """Execute an explicitly frozen call, returning receipt/output/checker objects.

    A repeated terminal call reuses only immutable stored responses. Reserved or
    unknown calls never redispatch; persistence errors leave reservations intact.
    """
    store, spec, trial, frozen, team, canonical = _context(call_spec, prompt)
    call_id = call_spec['call_id']
    model = spec['model']
    structured = model['parameters'].get('structured_output', False)
    # Refuse non-model prerequisites before reservation consumes an attempt.
    try:
        validate_parameters(model['provider'], model['max_output_tokens'], model['parameters']['temperature'],
                            model['parameters']['seed'], structured)
        check_prerequisites(model['provider'])
    except AdapterProblem as exc:
        _fail(_failure(exc), 'model')
    evidence = runner._case(frozen, trial)['evidence']
    options = dict(max_output_tokens=model['max_output_tokens'], temperature=model['parameters']['temperature'],
                   seed=model['parameters']['seed'])
    if structured:
        # Guides decoding only; validate_stage_output below stays authoritative.
        options['response_schema'] = stage_output_schema(spec['stage_key'], evidence)
    old = store.reserve_call(call_id, digest_bytes(canonical_bytes(spec)), spec)
    if old is not None:
        if old['status'] != 'completed':
            _fail(old['failure_reason'], 'call')
        output = decode_json(store.read_artifact(trial['trial_id'], old['response_artifact']))
        validate_stage_output(output, spec['stage_key'], evidence)
        checker = _checker(store, spec, trial, frozen, team, output, old, True)
        return dict(receipt=old, output=output, checker=checker)
    started = time.monotonic_ns()
    receipt = _receipt(call_id, spec, frozen, team, _now())
    raw = output = failure = None
    rejected = {}
    try:
        with _isolated(model):
            from langchain_adapter import invoke_response
            response = invoke_response(canonical.decode('utf-8'), model['provider'], model['model_requested'],
                                       model['base_url'], model['timeout_seconds'], **options)
            receipt.update(_metadata(response, model))
            # Identity first: a wrong model's output is never validated or retained.
            if receipt['identity_status'] == 'reported_mismatch':
                _fail('model_identity_mismatch')
            raw, output = _response_bytes(response, receipt, receipt['max_output_bytes'], spec['stage_key'],
                                          evidence, rejected)
        receipt.update(status='completed', failure_reason=None)
    except BaseException as exc:
        failure = exc
        reason = _failure(exc)
        receipt.update(status='unknown' if reason in ('timeout', 'dispatch_interrupted') else 'failed', failure_reason=reason)
    # Only structurally validated public text may be retained as a response,
    # never provider exceptions, arbitrary SDK objects or hidden reasoning.
    if raw is not None and output is not None:
        receipt['response_artifact'] = store.write_artifact(trial['trial_id'], 'responses', raw)
        receipt['response_sha256'] = digest_bytes(raw)
    else:
        _rejected_response(store, trial, receipt, failure, rejected)
    _finish(store, receipt, spec, frozen, started)
    if receipt['status'] != 'completed':
        _fail(receipt['failure_reason'], 'call')
    checker = _checker(store, spec, trial, frozen, team, output, receipt, False)
    return dict(receipt=receipt, output=output, checker=checker)


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument('--state-root', required=True)
    parser.add_argument('--call-id', required=True)
    parser.add_argument('--call-spec', required=True)
    args = parser.parse_args(argv)
    dispatched = False
    try:
        store = BenchmarkStore(args.state_root)
        path = Path(args.call_spec)
        if not path.is_absolute():
            _fail('invalid_path', 'call.spec')
        try:
            relative = path.relative_to(store.root).as_posix()
        except ValueError:
            _fail('path_escape', 'call.spec')
        path = confined_file(store.root, relative)
        if path.stat().st_size > MAX_INPUT_BYTES:
            _fail('budget_exceeded', 'call.spec')
        raw_spec = path.read_bytes()
        spec = decode_json(raw_spec)
        if type(spec) is not dict or type(spec.get('trial_id')) is not str:
            _fail('invalid_fields', 'call.spec')
        expected = 'trials/' + spec['trial_id'] + '/artifacts/specs/' + digest_bytes(raw_spec)
        if relative != expected or canonical_bytes(spec) != raw_spec:
            _fail('fingerprint_conflict', 'call.spec')
        ledger_input = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(ledger_input) > MAX_INPUT_BYTES:
            _fail('budget_exceeded', 'ledger.stdin')
        del ledger_input
        trial = store.get_trial(spec['trial_id'])
        prompt = runner.build_prompt(store, trial, spec.get('stage_key'))
        envelope = dict(state_root=str(store.root), call_id=args.call_id, spec=spec)
        _context(envelope, prompt)
        dispatched = True
        result = execute_call(envelope, prompt)
        raw = store.read_artifact(trial['trial_id'], result['receipt']['response_artifact'])
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        return 0
    except BenchmarkError:
        # A fixed boundary message, not arbitrary values or exception bodies.
        print('Error: benchmark model execution failed; inspect the durable call status; no automatic retry.', file=sys.stderr)
        if dispatched:
            try:
                dispatched = any(call['call_id'] == args.call_id for call in store.calls())
            except Exception:
                return 1
        return 1 if dispatched else 2
    except BaseException:
        print('Error: benchmark model child failed; inspect the durable call status; no automatic retry.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
