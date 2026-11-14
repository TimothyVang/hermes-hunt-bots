"""Atomic model validation on local session creation and legacy ``model: None`` healing.

Regression coverage for two coupled local-session authority invariants:
1. ``session.create`` / ``stage_local_session`` / ``create_local_session`` resolves the effective
   model (explicit request model or ``default_local_model()``) and refuses missing/blank models
   with ``invalid_params`` (``field='model'``) before writing to ``sessions``, ``gateway_routing``,
   or ``state_meta``.
2. Pre-fix ``model: None`` local receipts persisted across ``sessions``, ``gateway_routing``, and
   ``state_meta`` are normalized (when a model is available) or quarantined (when none is) before
   ``restore_policy`` at both ``gateway/session_local.py`` (idempotent ``request_id`` retry) and
   ``gateway/session_local_recovery.py`` (``restore_local_session`` / ``recover_local_sessions``).
"""
from __future__ import annotations

from dataclasses import asdict, replace
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest
from websockets.asyncio.client import connect


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Redirect ``Path.home()``, ``HERMES_HOME``, and ``gateway.run._hermes_home`` to ``tmp_path``."""
    from gateway import run

    home = tmp_path / ".hermes"
    home.mkdir(parents=True, exist_ok=True)
    (home / "models_dev_cache.json").write_text(
        json.dumps({"hermes-test-offline": {"id": "hermes-test-offline", "env": [], "models": {}}}),
        encoding="utf-8",
    )
    (home / ".env").write_text("", encoding="utf-8")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(run, "_hermes_home", home)
    # Isolate from any ambient welcome-trial claim on the developer host.
    monkeypatch.setattr("hermes_cli.anon_auth.trial_model", lambda: "")
    return home


def _write_config(home: Path, payload: dict) -> None:
    (home / "config.yaml").write_text(json.dumps(payload), encoding="utf-8")


def _owner(home: Path):
    from gateway.config import GatewayConfig
    from gateway.session import SessionStore
    from gateway.session_authorities import SessionAuthorities
    from gateway.session_authority import SessionAuthority
    from gateway.session_controls import AuthorityConnection
    import hermes_state_runtime as rt

    profile_id = str(home.resolve())
    store = SessionStore(home / "sessions", GatewayConfig())
    db = store._db
    runner = SimpleNamespace(
        session_store=store,
        _session_db=db,
        adapters={},
        _draining=False,
        _evict_cached_agent=lambda route: None,
        _cached_agent_for=lambda route: None,
        _peek_session_state=lambda route: None,
        _handle_message=None,
    )
    runner._adapter_for_source = lambda source: runner.adapters.get(source.platform)
    authority = SessionAuthority(
        runner,
        profile_id=profile_id,
        instance_id="owner",
        db=db,
        epoch=rt.begin_runtime_epoch(db, instance_id="owner"),
    )
    authorities = SessionAuthorities(home)
    authorities.add(home, authority)
    runner.session_authority = authority
    runner.session_authorities = authorities
    conn = AuthorityConnection(authority, object(), {"user_id": "human"})
    return store, runner, authority, conn


def _table_counts(db_path: Path) -> dict[str, int]:
    from hermes_state_local import POLICY_PREFIX

    with sqlite3.connect(db_path) as conn:
        sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        routing = conn.execute("SELECT COUNT(*) FROM gateway_routing WHERE scope = ''").fetchone()[0]
        policies = conn.execute(
            "SELECT COUNT(*) FROM state_meta WHERE key LIKE ?",
            (POLICY_PREFIX + "%",),
        ).fetchone()[0]
    return {"sessions": sessions, "gateway_routing": routing, "state_meta": policies}


def _seed_legacy_null_model_receipt(authority, actor, *, request_id: str, source: str = "gui", cwd: str) -> tuple[str, str]:
    """Persist the 3-table ``model: None`` receipt shape pre-fix ``commit_local_session`` wrote."""
    from gateway.config import Platform
    from gateway.session import SessionEntry
    from gateway.session_lifecycle import _now
    from gateway.session_local import load_profile_config
    from gateway.session_local_recovery import local_identity, local_source
    from gateway.session_policy import build_policy
    from hermes_state_local import commit_local_session

    params = {"request_id": request_id, "source": source, "cwd": cwd, "toolsets": []}
    config = load_profile_config(Path(authority.profile_id))
    policy = replace(build_policy(params, config, private_secrets={}, workspace_posture=True), model=None)
    sid = local_identity(authority.profile_id, actor.subject, request_id)
    origin = local_source(authority, sid, actor.subject)
    route = authority.runner.session_store._generate_session_key(origin)
    now = _now()
    entry = SessionEntry(route, sid, now, now, origin=origin, platform=Platform.LOCAL)
    receipt = {
        "profile_id": authority.profile_id,
        "principal_id": actor.subject,
        "request_id": request_id,
        "session_id": sid,
        "route": route,
        "entry": entry.to_dict(),
        "policy": asdict(policy),
    }
    commit_local_session(authority.db, epoch=authority.epoch, receipt=receipt)
    return sid, route


@pytest.mark.asyncio
async def test_create_session_without_model_rejects_atomically_and_leaves_no_sqlite_rows(isolated_home):
    from gateway.session_local import create_local_session
    from hermes_state_runtime import RuntimeStoreError

    _write_config(isolated_home, {})
    store, _runner, authority, owner = _owner(isolated_home)
    try:
        refused = await owner.dispatch({
            "id": "skip-1",
            "method": "session.create",
            "params": {"request_id": "skipped-onboarding", "source": "gui", "cwd": str(isolated_home), "toolsets": []},
        })
        assert "error" in refused, refused
        assert refused["error"]["message"] == "invalid_params", refused
        assert refused["error"]["data"]["reason"] == "invalid_params"
        assert refused["error"]["data"]["field"] == "model"
        assert _table_counts(authority.db.db_path) == {"sessions": 0, "gateway_routing": 0, "state_meta": 0}

        _write_config(isolated_home, {"model": {"default": "   "}})
        with pytest.raises(RuntimeStoreError) as exc_info:
            create_local_session(
                authority,
                owner.actor,
                {"request_id": "sync-blank", "source": "cli", "cwd": str(isolated_home), "toolsets": []},
            )
        assert exc_info.value.reason == "invalid_params"
        assert exc_info.value.field == "model"
        assert _table_counts(authority.db.db_path) == {"sessions": 0, "gateway_routing": 0, "state_meta": 0}

        _write_config(isolated_home, {
            "model": {
                "provider": "custom",
                "base_url": "http://127.0.0.1:8111/v1",
                "default": "configured-model",
                "api_key": "sk-test",
            }
        })
        created = await owner.dispatch({
            "id": "skip-2",
            "method": "session.create",
            "params": {"request_id": "skipped-onboarding", "source": "gui", "cwd": str(isolated_home), "toolsets": []},
        })
        assert "result" in created, created
        sid = created["result"]["session_id"]
        assert created["result"]["info"]["model"] == "configured-model"

        # Exact retry must run before pre-validation so a frozen model survives profile clearing.
        _write_config(isolated_home, {})
        retried = await owner.dispatch({
            "id": "skip-3",
            "method": "session.create",
            "params": {"request_id": "skipped-onboarding", "source": "gui", "cwd": str(isolated_home), "toolsets": []},
        })
        assert "result" in retried, retried
        assert retried["result"]["session_id"] == sid
        assert retried["result"]["info"]["model"] == "configured-model"
    finally:
        await owner.close()
        store.close_all_db_handles()


@pytest.mark.asyncio
async def test_legacy_null_model_heals_on_recovery_and_on_idempotent_create_retry(isolated_home):
    from gateway.session_local_recovery import recover_local_sessions, restore_local_session
    from hermes_state_local import local_receipt

    _write_config(isolated_home, {})
    store, _runner, authority, owner = _owner(isolated_home)
    try:
        sid_recover, _ = _seed_legacy_null_model_receipt(
            authority, owner.actor, request_id="legacy-recover", cwd=str(isolated_home)
        )
        sid_retry, _ = _seed_legacy_null_model_receipt(
            authority, owner.actor, request_id="legacy-retry", cwd=str(isolated_home)
        )
        sid_ended, _ = _seed_legacy_null_model_receipt(
            authority, owner.actor, request_id="legacy-ended", cwd=str(isolated_home)
        )
        sid_ws_ended, _ = _seed_legacy_null_model_receipt(
            authority, owner.actor, request_id="legacy-ws-ended", cwd=str(isolated_home)
        )
        with sqlite3.connect(authority.db.db_path) as conn:
            from hermes_state_local import POLICY_PREFIX

            ws_receipt = json.loads(
                conn.execute("SELECT value FROM state_meta WHERE key = ?", (POLICY_PREFIX + sid_ws_ended,)).fetchone()[0]
            )
            ws_receipt["policy"]["model"] = "\t\n"
            conn.execute(
                "UPDATE state_meta SET value = ? WHERE key = ?",
                (json.dumps(ws_receipt), POLICY_PREFIX + sid_ws_ended),
            )
            conn.execute("UPDATE sessions SET model = ? WHERE id = ?", ("\t\n", sid_ws_ended))
        authority.db.end_session(sid_ended, end_reason="user_exit")
        authority.db.end_session(sid_ws_ended, end_reason="user_exit")

        _write_config(isolated_home, {"model": "healed-from-profile"})

        retried = await owner.dispatch({
            "id": "retry-heal",
            "method": "session.create",
            "params": {"request_id": "legacy-retry", "source": "gui", "cwd": str(isolated_home), "toolsets": []},
        })
        assert "result" in retried, retried
        assert retried["result"]["session_id"] == sid_retry
        assert retried["result"]["info"]["model"] == "healed-from-profile"
        assert local_receipt(authority.db, sid_retry)["policy"]["model"] == "healed-from-profile"
        assert authority.db.get_session(sid_retry)["model"] == "healed-from-profile"

        recover_local_sessions(authority)
        assert sid_ended not in authority.sessions
        assert sid_ws_ended not in authority.sessions
        assert local_receipt(authority.db, sid_ended)["policy"]["model"] == "healed-from-profile"
        assert authority.db.get_session(sid_ended)["model"] == "healed-from-profile"
        assert local_receipt(authority.db, sid_ws_ended)["policy"]["model"] == "healed-from-profile"
        assert authority.db.get_session(sid_ws_ended)["model"] == "healed-from-profile"

        ref = restore_local_session(authority, sid_recover)
        assert ref.session_id == sid_recover
        assert local_receipt(authority.db, sid_recover)["policy"]["model"] == "healed-from-profile"
        assert authority.db.get_session(sid_recover)["model"] == "healed-from-profile"

        resumed = await owner.dispatch({
            "id": "resume-healed",
            "method": "session.resume",
            "params": {"session_id": sid_recover},
        })
        assert "result" in resumed, resumed
        assert resumed["result"]["info"]["model"] == "healed-from-profile"
    finally:
        await owner.close()
        store.close_all_db_handles()


@pytest.mark.asyncio
async def test_legacy_null_model_quarantines_when_unconfigured_and_preserves_nonempty_transcript(isolated_home):
    from gateway.session_listing import stored_picker_sessions
    from gateway.session_local_recovery import recover_local_sessions
    from hermes_state_local import POLICY_PREFIX

    _write_config(isolated_home, {})
    store, _runner, authority, owner = _owner(isolated_home)
    authority._native_legacy_transports = {owner.actor.transport_id: owner.actor}
    routing_home = isolated_home / "launch-routing"
    routing_home.mkdir()
    store._routing_home = routing_home
    routing_db = store._routing_db
    assert routing_db is not None and routing_db.db_path != authority.db.db_path
    try:
        sid_unused, route_unused = _seed_legacy_null_model_receipt(
            authority, owner.actor, request_id="legacy-unused", cwd=str(isolated_home)
        )
        sid_history, route_history = _seed_legacy_null_model_receipt(
            authority, owner.actor, request_id="legacy-history", cwd=str(isolated_home)
        )
        sid_deletable, _ = _seed_legacy_null_model_receipt(
            authority, owner.actor, request_id="legacy-deletable", cwd=str(isolated_home)
        )
        with sqlite3.connect(routing_db.db_path) as rconn:
            rconn.execute(
                "INSERT INTO gateway_routing(scope, session_key, entry_json, updated_at) VALUES ('', ?, ?, 1.0)",
                (route_unused, json.dumps({"session_id": sid_unused})),
            )
        authority.db.append_message(sid_history, role="user", content="keep my transcript")
        authority.db.append_message(sid_deletable, role="user", content="delete retires policy")

        recover_local_sessions(authority)
        assert sid_unused not in authority.sessions
        assert sid_history not in authority.sessions
        assert authority.db.get_session(sid_unused) is None
        with sqlite3.connect(routing_db.db_path) as rconn:
            assert rconn.execute(
                "SELECT 1 FROM gateway_routing WHERE session_key = ?", (route_unused,)
            ).fetchone() is None

        with sqlite3.connect(authority.db.db_path) as conn:
            assert conn.execute(
                "SELECT 1 FROM gateway_routing WHERE scope = '' AND session_key = ?", (route_unused,)
            ).fetchone() is None
            assert conn.execute(
                "SELECT 1 FROM state_meta WHERE key = ?", (POLICY_PREFIX + sid_unused,)
            ).fetchone() is None

            # Retaining POLICY_PREFIX keeps picker visibility and delete_session() secret retirement intact.
            assert conn.execute(
                "SELECT 1 FROM gateway_routing WHERE scope = '' AND session_key = ?", (route_history,)
            ).fetchone() is None
            assert conn.execute(
                "SELECT 1 FROM state_meta WHERE key = ?", (POLICY_PREFIX + sid_history,)
            ).fetchone() is not None
        assert len(authority.db.get_messages_as_conversation(sid_history)) == 1

        picker_ids = {row["id"] for row in stored_picker_sessions(authority, owner.actor, limit=50)["sessions"]}
        assert sid_history in picker_ids
        assert sid_deletable in picker_ids

        assert authority.db.delete_session(sid_deletable) is True
        with sqlite3.connect(authority.db.db_path) as conn:
            assert conn.execute(
                "SELECT 1 FROM state_meta WHERE key = ?", (POLICY_PREFIX + sid_deletable,)
            ).fetchone() is None

        minted = await owner.dispatch({
            "id": "mint-explicit",
            "method": "session.create",
            "params": {
                "request_id": "legacy-unused",
                "source": "gui",
                "cwd": str(isolated_home),
                "toolsets": [],
                "model": "explicit-recovery-model",
            },
        })
        assert "result" in minted, minted
        assert minted["result"]["session_id"] == sid_unused
        assert minted["result"]["info"]["model"] == "explicit-recovery-model"

        refused_resume = await owner.dispatch({
            "id": "resume-quarantined",
            "method": "session.resume",
            "params": {"session_id": sid_history},
        })
        assert refused_resume["error"]["message"] == "invalid_params", refused_resume
        assert refused_resume["error"]["data"]["field"] == "model"

        _write_config(isolated_home, {"model": {"default": "unquarantined-model"}})
        healed_resume = await owner.dispatch({
            "id": "resume-unquarantined",
            "method": "session.resume",
            "params": {"session_id": sid_history},
        })
        assert "result" in healed_resume, healed_resume
        assert healed_resume["result"]["info"]["model"] == "unquarantined-model"
        assert any(m.get("content") == "keep my transcript" for m in healed_resume["result"]["messages"])
    finally:
        await owner.close()
        store.close_all_db_handles()


@pytest.mark.asyncio
async def test_malformed_entry_receipt_is_untouched_and_concurrent_preheal_is_noop(isolated_home):
    from gateway.session_local import create_local_session
    from gateway.session_local_recovery import (
        _quarantine_null_model_receipt,
        heal_legacy_null_model_session,
        recover_local_sessions,
        restore_local_session,
    )
    from hermes_state_local import POLICY_PREFIX, local_receipt
    from hermes_state_runtime import RuntimeStoreError

    _write_config(isolated_home, {})
    store, _runner, authority, owner = _owner(isolated_home)
    try:
        sid_tampered, _ = _seed_legacy_null_model_receipt(
            authority, owner.actor, request_id="tampered-route", cwd=str(isolated_home)
        )
        sid_foreign_lineage, _ = _seed_legacy_null_model_receipt(
            authority, owner.actor, request_id="tampered-foreign-lineage", cwd=str(isolated_home)
        )
        sid_unhashable_lineage, _ = _seed_legacy_null_model_receipt(
            authority, owner.actor, request_id="tampered-unhashable-lineage", cwd=str(isolated_home)
        )
        ref_unrelated_empty = create_local_session(
            authority,
            owner.actor,
            {
                "request_id": "unrelated-empty-victim",
                "source": "gui",
                "cwd": str(isolated_home),
                "toolsets": [],
                "model": "victim-model",
            },
        )
        sid_b_unrelated_empty = ref_unrelated_empty.session_id
        with sqlite3.connect(authority.db.db_path) as conn:
            tampered = json.loads(
                conn.execute("SELECT value FROM state_meta WHERE key = ?", (POLICY_PREFIX + sid_tampered,)).fetchone()[0]
            )
            tampered["route"] = "agent:main:local:foreign-route"
            conn.execute(
                "UPDATE state_meta SET value = ? WHERE key = ?",
                (json.dumps(tampered), POLICY_PREFIX + sid_tampered),
            )

            foreign_lineage = json.loads(
                conn.execute(
                    "SELECT value FROM state_meta WHERE key = ?", (POLICY_PREFIX + sid_foreign_lineage,)
                ).fetchone()[0]
            )
            foreign_lineage["lineage"] = [sid_foreign_lineage, sid_b_unrelated_empty]
            conn.execute(
                "UPDATE state_meta SET value = ? WHERE key = ?",
                (json.dumps(foreign_lineage), POLICY_PREFIX + sid_foreign_lineage),
            )

            unhashable_lineage = json.loads(
                conn.execute(
                    "SELECT value FROM state_meta WHERE key = ?", (POLICY_PREFIX + sid_unhashable_lineage,)
                ).fetchone()[0]
            )
            unhashable_lineage["lineage"] = [{}]
            conn.execute(
                "UPDATE state_meta SET value = ? WHERE key = ?",
                (json.dumps(unhashable_lineage), POLICY_PREFIX + sid_unhashable_lineage),
            )

        assert heal_legacy_null_model_session(authority, sid_tampered, raise_on_quarantine=True) is True
        assert authority.db.get_session(sid_tampered) is not None
        with pytest.raises(RuntimeStoreError, match="storage_unavailable"):
            restore_local_session(authority, sid_tampered)

        recover_local_sessions(authority)
        assert authority.db.get_session(sid_b_unrelated_empty) is not None
        assert local_receipt(authority.db, sid_b_unrelated_empty)["policy"]["model"] == "victim-model"
        assert authority.db.get_session(sid_foreign_lineage) is not None
        assert authority.db.get_session(sid_unhashable_lineage) is not None
        with pytest.raises(RuntimeStoreError, match="storage_unavailable"):
            restore_local_session(authority, sid_foreign_lineage)
        with pytest.raises(RuntimeStoreError, match="storage_unavailable"):
            restore_local_session(authority, sid_unhashable_lineage)

        ref_healthy = create_local_session(
            authority,
            owner.actor,
            {
                "request_id": "concurrent-winner",
                "source": "gui",
                "cwd": str(isolated_home),
                "toolsets": [],
                "model": "already-normalized",
            },
        )
        assert _quarantine_null_model_receipt(authority, ref_healthy.session_id) == "already_healed"
        assert authority.db.get_session(ref_healthy.session_id) is not None
        assert local_receipt(authority.db, ref_healthy.session_id)["policy"]["model"] == "already-normalized"
    finally:
        await owner.close()
        store.close_all_db_handles()


@pytest.mark.asyncio
async def test_loopback_ws_gateway_server_rejects_empty_model_and_heals_legacy_null_model(isolated_home):
    """End-to-end loopback ``hermes-gateway-v1`` WebSocket probe over ``start_gateway_api``."""
    from gateway.run_api import start_gateway_api, stop_gateway_api
    from gateway.runtime_bootstrap import TicketStore
    from gateway.session_contract import CANONICAL_GATEWAY_PROTOCOL

    _write_config(isolated_home, {})
    store, runner, authority, owner = _owner(isolated_home)
    profile_id = authority.profile_id
    tickets = TicketStore("owner", [profile_id])
    runner.session_runtime_descriptor = {"state": "ready"}
    runner.session_ticket_store = tickets
    handle = await start_gateway_api(runner)
    try:
        url = handle.api_origin.replace("http:", "ws:") + "/api/ws"
        ticket = tickets.mint(profile_id=profile_id, subject=owner.actor.subject, purpose="interactive")
        subprotocols = [CANONICAL_GATEWAY_PROTOCOL, f"hermes-gateway-ticket.{ticket}"]

        async with connect(url, subprotocols=subprotocols) as ws:
            async def rpc(req_id: str, method: str, **params):
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}))
                while True:
                    frame = json.loads(await ws.recv())
                    if frame.get("id") == req_id:
                        return frame

            refused = await rpc("ws-1", "session.create", request_id="ws-empty", source="gui",
                                cwd=str(isolated_home), toolsets=[])
            assert "error" in refused, refused
            assert refused["error"]["message"] == "invalid_params", refused
            assert refused["error"]["data"]["field"] == "model"
            assert _table_counts(authority.db.db_path) == {"sessions": 0, "gateway_routing": 0, "state_meta": 0}

            sid_legacy, _ = _seed_legacy_null_model_receipt(
                authority, owner.actor, request_id="ws-legacy-null", cwd=str(isolated_home)
            )
            _write_config(isolated_home, {"model": {"default": "ws-healed-model"}})

            healed_create = await rpc("ws-2", "session.create", request_id="ws-legacy-null", source="gui",
                                      cwd=str(isolated_home), toolsets=[])
            assert "result" in healed_create, healed_create
            assert healed_create["result"]["session_id"] == sid_legacy
            assert healed_create["result"]["info"]["model"] == "ws-healed-model"

            resumed = await rpc("ws-3", "session.resume", session_id=sid_legacy)
            assert "result" in resumed, resumed
            assert resumed["result"]["info"]["model"] == "ws-healed-model"
    finally:
        await stop_gateway_api(handle)
        await owner.close()
        store.close_all_db_handles()
