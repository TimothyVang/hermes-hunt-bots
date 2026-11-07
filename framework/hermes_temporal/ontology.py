"""Pure, bounded validation for shared synthetic hunt snapshots and handoffs."""
from __future__ import annotations

import json
import re
from typing import Iterable


ENTITY_KINDS = frozenset({"host", "account", "address", "domain", "key", "process", "session", "service", "resource"})
PREDICATES = frozenset({"associated_with", "observed_on", "communicates_with", "resolves_to", "spawned"})
CLAIM_KINDS = frozenset({"observed", "inference", "hypothesis", "finding"})
REVIEW_DISPOSITIONS = frozenset({"needs_revision", "needs_validation", "review_ready"})
HANDOFF_DISPOSITIONS = frozenset({"needs_revision", "needs_validation", "review_ready"})
PROFILES = frozenset({
    "framework-coordinator", "framework-researcher", "framework-builder",
    "framework-reviewer", "framework-librarian", "framework-network-analyst",
})
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_STEP_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_SNAPSHOT_FIELDS = {"schema_version", "case_id", "entities", "relations"}
_ENTITY_FIELDS = {"entity_id", "kind", "label", "evidence_ids"}
_RELATION_FIELDS = {"relation_id", "subject_id", "predicate", "object_id", "evidence_ids"}
_HANDOFF_FIELDS = {"schema_version", "case_id", "step_id", "profile", "claims", "reviews", "disposition", "limitations", "requested_decisions"}
_CLAIM_FIELDS = {"claim_id", "kind", "statement", "evidence_ids", "entity_ids", "contradicts"}
_REVIEW_FIELDS = {"review_id", "claim_ids", "disposition", "rationale", "evidence_ids"}
_MAX_SNAPSHOT_BYTES = 32768
MAX_HANDOFF_BYTES = 16384


def _obj(value: object, fields: set[str], name: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise ValueError(f"{name} must contain exactly the specified fields")
    return value


def _text(value: object, name: str, limit: int, *, ident: bool = False) -> str:
    if type(value) is not str or not value or not value.strip():
        raise ValueError(f"{name} must be nonempty text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be valid UTF-8") from exc
    if size > limit or (ident and not _SAFE_ID.fullmatch(value)):
        raise ValueError(f"invalid or oversized {name}")
    return value


def _ids(value: object, name: str, allowed: set[str], *, maximum: int = 64) -> list[str]:
    if type(value) is not list or not 1 <= len(value) <= maximum:
        raise ValueError(f"{name} must be a nonempty bounded list")
    result = []
    seen = set()
    for raw in value:
        item = _text(raw, name, 128, ident=True)
        if item in seen:
            raise ValueError(f"{name} contains duplicate references")
        if item not in allowed:
            raise ValueError(f"unknown {name} reference: {item}")
        seen.add(item)
        result.append(item)
    return result


def _encoded_size(value: object, limit: int, name: str) -> None:
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        size = len(encoded.encode("utf-8"))
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"{name} must be finite JSON with valid Unicode") from exc
    if size > limit:
        raise ValueError(f"{name} exceeds its UTF-8 byte limit")


def validate_snapshot(raw: object, evidence_ids: Iterable[str]) -> dict:
    """Validate and return an owned canonical-ID-preserving snapshot copy."""
    supplied = _evidence_set(evidence_ids)
    _obj(raw, _SNAPSHOT_FIELDS, "snapshot")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ValueError("schema_version must be integer 1")
    case_id = _text(raw["case_id"], "case_id", 128, ident=True)
    if type(raw["entities"]) is not list or len(raw["entities"]) > 64:
        raise ValueError("entities must be a list of at most 64 entities")
    if type(raw["relations"]) is not list or len(raw["relations"]) > 128:
        raise ValueError("relations must be a list of at most 128 relations")
    entities = []
    entity_ids = set()
    for item in raw["entities"]:
        _obj(item, _ENTITY_FIELDS, "entity")
        entity_id = _text(item["entity_id"], "entity_id", 128, ident=True)
        if entity_id in entity_ids:
            raise ValueError("duplicate entity ID")
        entity_ids.add(entity_id)
        kind = item["kind"]
        if type(kind) is not str or kind not in ENTITY_KINDS:
            raise ValueError("unknown entity kind")
        label = _text(item["label"], "entity label", 1024)
        refs = _ids(item["evidence_ids"], "evidence ID", supplied)
        entities.append({"entity_id": entity_id, "kind": kind, "label": label, "evidence_ids": refs})
    relations = []
    relation_ids = set()
    for item in raw["relations"]:
        _obj(item, _RELATION_FIELDS, "relation")
        relation_id = _text(item["relation_id"], "relation_id", 128, ident=True)
        if relation_id in relation_ids:
            raise ValueError("duplicate relation ID")
        relation_ids.add(relation_id)
        subject = _text(item["subject_id"], "subject_id", 128, ident=True)
        object_id = _text(item["object_id"], "object_id", 128, ident=True)
        if subject not in entity_ids or object_id not in entity_ids:
            raise ValueError("relation endpoint does not resolve")
        predicate = item["predicate"]
        if type(predicate) is not str or predicate not in PREDICATES:
            raise ValueError("unknown relation predicate")
        refs = _ids(item["evidence_ids"], "evidence ID", supplied)
        relations.append({"relation_id": relation_id, "subject_id": subject, "predicate": predicate,
                          "object_id": object_id, "evidence_ids": refs})
    result = {"schema_version": 1, "case_id": case_id, "entities": entities, "relations": relations}
    _encoded_size(result, _MAX_SNAPSHOT_BYTES, "snapshot")
    return result


def _evidence_set(evidence_ids: Iterable[str]) -> set[str]:
    if isinstance(evidence_ids, (str, bytes, dict)):
        raise ValueError("evidence_ids must be an iterable of unique IDs")
    try:
        values = list(evidence_ids)
    except (TypeError, ValueError) as exc:
        raise ValueError("evidence_ids must be an iterable of unique IDs") from exc
    if len(values) > 128:
        raise ValueError("too many supplied evidence IDs")
    result = set()
    for value in values:
        ident = _text(value, "evidence ID", 128, ident=True)
        if ident in result:
            raise ValueError("supplied evidence IDs must be unique")
        result.add(ident)
    return result


def select_snapshot(snapshot: object, evidence_ids: Iterable[str]) -> dict:
    """Return a copy containing only fully supported entities and relations."""
    available = _evidence_set(evidence_ids)
    # Validate structure and its self-contained references; evidence outside this selection is valid input.
    all_refs = []
    if type(snapshot) is dict and type(snapshot.get("entities")) is list and type(snapshot.get("relations")) is list:
        for item in snapshot["entities"] + snapshot["relations"]:
            if type(item) is dict and type(item.get("evidence_ids")) is list:
                for ref in item["evidence_ids"]:
                    all_refs.append(_text(ref, "evidence ID", 128, ident=True))
    full = validate_snapshot(snapshot, set(all_refs))
    entities = [entity for entity in full["entities"] if set(entity["evidence_ids"]) <= available]
    included = {entity["entity_id"] for entity in entities}
    relations = [relation for relation in full["relations"]
                 if set(relation["evidence_ids"]) <= available
                 and relation["subject_id"] in included and relation["object_id"] in included]
    return {"schema_version": 1, "case_id": full["case_id"], "entities": entities, "relations": relations}


def validate_handoff(raw: object, *, snapshot: object, evidence_ids: Iterable[str], step_id: str,
                     profile: str, predecessors: Iterable[dict] = (), note_limit: int = 512,
                     handoff_limit: int = MAX_HANDOFF_BYTES) -> dict:
    """Validate a handoff; caller supplies predecessors only after its human-review gate.

    ``note_limit`` bounds each limitation/requested-decision string in UTF-8 bytes and
    ``handoff_limit`` bounds the whole normalized handoff. Predecessors are always held to
    MAX_HANDOFF_BYTES, because only a final step (never forwarded) may use a larger limit."""
    supplied = _evidence_set(evidence_ids)
    if type(step_id) is not str or not _STEP_ID.fullmatch(step_id):
        raise ValueError("invalid step_id")
    if type(profile) is not str or profile not in PROFILES:
        raise ValueError("invalid profile")
    snap = validate_snapshot(snapshot, supplied)
    _obj(raw, _HANDOFF_FIELDS, "handoff")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ValueError("schema_version must be integer 1")
    case_id = _text(raw["case_id"], "case_id", 128, ident=True)
    if case_id != snap["case_id"]:
        raise ValueError("handoff case_id does not match snapshot")
    if raw["step_id"] != step_id or raw["profile"] != profile:
        raise ValueError("handoff identity does not match execution context")
    entities = {item["entity_id"] for item in snap["entities"]}
    prior_claims: set[str] = set()
    prior_claim_profiles: dict[str, str] = {}
    prior_steps: set[str] = set()
    prior_reviews: set[str] = set()
    try:
        prior_values = list(predecessors)
    except (TypeError, ValueError) as exc:
        raise ValueError("predecessors must be reviewed handoff objects") from exc
    if len(prior_values) > 16:
        raise ValueError("too many predecessors")
    for predecessor in prior_values:
        p = _validate_predecessor(predecessor, snap["case_id"], note_limit)
        if p["step_id"] == step_id or p["step_id"] in prior_steps:
            raise ValueError("duplicate or self predecessor step")
        prior_steps.add(p["step_id"])
        for claim in p["claims"]:
            if claim["claim_id"] in prior_claims:
                raise ValueError("duplicate predecessor claim ID")
            prior_claims.add(claim["claim_id"])
            prior_claim_profiles[claim["claim_id"]] = p["profile"]
        for review in p["reviews"]:
            if review["review_id"] in prior_reviews:
                raise ValueError("duplicate predecessor review ID")
            prior_reviews.add(review["review_id"])
    claims_raw = raw["claims"]
    reviews_raw = raw["reviews"]
    if type(claims_raw) is not list or len(claims_raw) > 16:
        raise ValueError("claims must be a list of at most 16")
    if type(reviews_raw) is not list or len(reviews_raw) > 16:
        raise ValueError("reviews must be a list of at most 16")
    claim_ids = set(prior_claims)
    claims = []
    current_claim_ids = set()
    for item in claims_raw:
        _obj(item, _CLAIM_FIELDS, "claim")
        claim_id = _text(item["claim_id"], "claim_id", 192, ident=True)
        if not claim_id.startswith(step_id + ":") or claim_id in claim_ids:
            raise ValueError("claim ID must be uniquely namespaced by step_id")
        claim_ids.add(claim_id)
        current_claim_ids.add(claim_id)
        kind = item["kind"]
        if type(kind) is not str or kind not in CLAIM_KINDS:
            raise ValueError("unknown claim kind")
        statement = _text(item["statement"], "claim statement", 2048)
        refs = _ids(item["evidence_ids"], "evidence ID", supplied, maximum=32)
        refs_entities = _optional_ids(item["entity_ids"], "entity ID", entities, maximum=64)
        contradicts = _optional_text_ids(item["contradicts"], "claim ID", 32)
        if claim_id in contradicts:
            raise ValueError("claim cannot contradict itself")
        claims.append({"claim_id": claim_id, "kind": kind, "statement": statement,
                       "evidence_ids": refs, "entity_ids": refs_entities, "contradicts": contradicts})
    # Re-check contradictions after all claims exist (forward references are allowed, self is not).
    for claim in claims:
        for target in claim["contradicts"]:
            if target not in current_claim_ids and target not in prior_claims:
                raise ValueError("contradiction target is not a current or predecessor claim")
    disposition = raw["disposition"]
    if type(disposition) is not str or disposition not in HANDOFF_DISPOSITIONS:
        raise ValueError("invalid handoff disposition")
    limitations = _text_list(raw["limitations"], "limitations", 16, note_limit)
    decisions = _text_list(raw["requested_decisions"], "requested_decisions", 16, note_limit)
    reviews = []
    if profile != "framework-reviewer" and reviews_raw:
        raise ValueError("only framework-reviewer may supply reviews")
    review_ids = set(prior_reviews)
    for item in reviews_raw:
        _obj(item, _REVIEW_FIELDS, "review")
        review_id = _text(item["review_id"], "review_id", 192, ident=True)
        if not review_id.startswith(step_id + ":") or review_id in review_ids:
            raise ValueError("review ID must be uniquely namespaced by step_id")
        review_ids.add(review_id)
        reviewed_claims = _ids(
            item["claim_ids"], "claim ID",
            {claim_id for claim_id, owner in prior_claim_profiles.items() if owner != "framework-reviewer"},
            maximum=32,
        )
        review_disposition = item["disposition"]
        if type(review_disposition) is not str or review_disposition not in REVIEW_DISPOSITIONS:
            raise ValueError("invalid review disposition")
        rationale = _text(item["rationale"], "review rationale", 2048)
        refs = _optional_ids(item["evidence_ids"], "evidence ID", supplied, maximum=32)
        reviews.append({"review_id": review_id, "claim_ids": reviewed_claims,
                        "disposition": review_disposition, "rationale": rationale, "evidence_ids": refs})
    result = {"schema_version": 1, "case_id": case_id, "step_id": step_id, "profile": profile,
              "claims": claims, "reviews": reviews, "disposition": disposition,
              "limitations": limitations, "requested_decisions": decisions}
    _encoded_size(result, handoff_limit, "handoff")
    return result



def _optional_text_ids(value: object, name: str, maximum: int) -> list[str]:
    if type(value) is not list or len(value) > maximum:
        raise ValueError(f"{name} must be a bounded list")
    result = []
    seen = set()
    for item in value:
        ident = _text(item, name, 192, ident=True)
        if ident in seen:
            raise ValueError(f"{name} contains duplicate references")
        seen.add(ident)
        result.append(ident)
    return result
def _optional_ids(value: object, name: str, allowed: set[str], *, maximum: int) -> list[str]:
    if type(value) is not list or len(value) > maximum:
        raise ValueError(f"{name} must be a bounded list")
    if not value:
        return []
    return _ids(value, name, allowed, maximum=maximum)


def _text_list(value: object, name: str, maximum: int, text_limit: int) -> list[str]:
    if type(value) is not list or len(value) > maximum:
        raise ValueError(f"{name} must be a bounded list")
    return [_text(item, name, text_limit) for item in value]


def _validate_predecessor(raw: object, case_id: str, note_limit: int = 512) -> dict:
    """Validate predecessor shape only; prior review and context are caller-owned facts."""
    _obj(raw, _HANDOFF_FIELDS, "predecessor")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ValueError("invalid predecessor version")
    if _text(raw["case_id"], "predecessor case_id", 128, ident=True) != case_id:
        raise ValueError("predecessor case mismatch")
    sid = raw["step_id"]
    prof = raw["profile"]
    if type(sid) is not str or not _STEP_ID.fullmatch(sid) or type(prof) is not str or prof not in PROFILES:
        raise ValueError("invalid predecessor identity")
    claims = raw["claims"]
    reviews = raw["reviews"]
    if type(claims) is not list or len(claims) > 16 or type(reviews) is not list or len(reviews) > 16:
        raise ValueError("predecessor must contain bounded claims and reviews")
    if reviews and prof != "framework-reviewer":
        raise ValueError("only framework-reviewer may supply predecessor reviews")
    claim_ids = set()
    for item in claims:
        _obj(item, _CLAIM_FIELDS, "predecessor claim")
        cid = _text(item["claim_id"], "predecessor claim_id", 192, ident=True)
        if not cid.startswith(sid + ":") or cid in claim_ids:
            raise ValueError("invalid predecessor claim ID")
        claim_ids.add(cid)
        if type(item["kind"]) is not str or item["kind"] not in CLAIM_KINDS:
            raise ValueError("invalid predecessor claim kind")
        _text(item["statement"], "predecessor statement", 2048)
        _historical_ids(item["evidence_ids"], "predecessor evidence ID", 32, required=True, text_limit=128)
        _historical_ids(item["entity_ids"], "predecessor entity ID", 64, required=False, text_limit=128)
        contradictions = _historical_ids(item["contradicts"], "predecessor claim ID", 32, required=False)
        if cid in contradictions:
            raise ValueError("predecessor claim contradicts itself")
    if type(raw["disposition"]) is not str or raw["disposition"] not in HANDOFF_DISPOSITIONS:
        raise ValueError("invalid predecessor disposition")
    _text_list(raw["limitations"], "predecessor limitations", 16, note_limit)
    _text_list(raw["requested_decisions"], "predecessor requested_decisions", 16, note_limit)
    review_ids = set()
    for review in reviews:
        _obj(review, _REVIEW_FIELDS, "predecessor review")
        rid = _text(review["review_id"], "predecessor review_id", 192, ident=True)
        if not rid.startswith(sid + ":") or rid in review_ids:
            raise ValueError("invalid predecessor review ID")
        review_ids.add(rid)
        _historical_ids(review["claim_ids"], "predecessor review claim ID", 32, required=True)
        if type(review["disposition"]) is not str or review["disposition"] not in REVIEW_DISPOSITIONS:
            raise ValueError("invalid predecessor review disposition")
        _text(review["rationale"], "predecessor review rationale", 2048)
        _historical_ids(review["evidence_ids"], "predecessor evidence ID", 32, required=False, text_limit=128)
    _encoded_size(raw, MAX_HANDOFF_BYTES, "predecessor handoff")
    return raw


def _historical_ids(value: object, name: str, maximum: int, *, required: bool,
                    text_limit: int = 192) -> list[str]:
    if type(value) is not list or len(value) > maximum or (required and not value):
        raise ValueError(f"{name} must be a bounded {'nonempty ' if required else ''}list")
    result = []
    seen = set()
    for item in value:
        ident = _text(item, name, text_limit, ident=True)
        if ident in seen:
            raise ValueError(f"{name} contains duplicate references")
        seen.add(ident)
        result.append(ident)
    return result


def handoff_instructions() -> str:
    """Return concise native-child JSON guidance; inclusion is not enforcement."""
    # Keep every enum, prefix and list-shape rule in sync with validate_handoff:
    # native models cannot satisfy constraints the prompt does not state.
    return (
        "Return one strict JSON object, no fences, exactly: schema_version=1, case_id, step_id, profile, claims, reviews, "
        "disposition (review_ready|needs_validation|needs_revision), limitations, requested_decisions (string lists; max 16, each under 300 chars). "
        "Claims (max 16), exactly: claim_id (step_id + \":\" + suffix, e.g. \"scope:c1\"), kind (observed|inference|hypothesis|finding), "
        "statement (under 1600 chars), evidence_ids (nonempty; supplied source_id values, never event.id), entity_ids (snapshot entity_id values only, else []), "
        "contradicts (own/direct-predecessor claim IDs or []). Coverage gaps go in limitations, not claims. "
        "Reviews (framework-reviewer only): review_id (same prefix), "
        "claim_ids (predecessor claims only), disposition (same 3 values), rationale, evidence_ids; never approvals. "
        "Never invent evidence, IDs, approvals, execution or facts; keep uncertainty."
    )
