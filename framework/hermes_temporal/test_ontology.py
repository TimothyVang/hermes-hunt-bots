"""Consumer-visible behavior for pure ontology contracts."""
from __future__ import annotations

import copy
import unittest

from . import ontology
from .ontology import select_snapshot, validate_handoff, validate_snapshot


EVIDENCE = ["dns:1", "hunt:2"]
SNAPSHOT = {
    "schema_version": 1,
    "case_id": "case-7",
    "entities": [
        {"entity_id": "host:alpha", "kind": "host", "label": "Synthetic host alpha", "evidence_ids": ["dns:1"]},
        {"entity_id": "domain:beta", "kind": "domain", "label": "example.invalid", "evidence_ids": ["hunt:2"]},
        {"entity_id": "account:gamma", "kind": "account", "label": "Synthetic account", "evidence_ids": ["dns:1", "hunt:2"]},
    ],
    "relations": [
        {"relation_id": "r:1", "subject_id": "host:alpha", "predicate": "resolves_to",
         "object_id": "domain:beta", "evidence_ids": ["dns:1"]},
        {"relation_id": "r:2", "subject_id": "account:gamma", "predicate": "associated_with",
         "object_id": "host:alpha", "evidence_ids": ["hunt:2"]},
    ],
}


def handoff(step, profile, *, claims=(), reviews=(), disposition="review_ready"):
    return {
        "schema_version": 1, "case_id": "case-7", "step_id": step, "profile": profile,
        "claims": list(claims), "reviews": list(reviews), "disposition": disposition,
        "limitations": ["Synthetic summaries only"], "requested_decisions": [],
    }


def claim(cid, *, evidence="dns:1", entities=("host:alpha",), kind="observed", contradicts=()):
    return {"claim_id": cid, "kind": kind, "statement": "Host alpha was named in the supplied summary.",
            "evidence_ids": [evidence], "entity_ids": list(entities), "contradicts": list(contradicts)}


class OntologyTests(unittest.TestCase):
    def test_ancestor_claims_are_contradiction_targets_only(self):
        analysis = validate_handoff(handoff("analysis", "framework-coordinator", claims=[claim("analysis:c1")]),
                                    snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="analysis",
                                    profile="framework-coordinator")
        follow = handoff("follow-2", "framework-researcher",
                         claims=[claim("follow-2:c1", contradicts=("evidence:c8",))])
        common = dict(snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="follow-2",
                      profile="framework-researcher", predecessors=[analysis])
        # Live (team-k6-131024 follow-2): a grandparent target was rejected, which spent the one retry.
        with self.assertRaisesRegex(ValueError, r"^contradiction target is not a claim of this step or of a "
                                                r"human-reviewed earlier step: evidence:c8 in follow-2:c1$"):
            validate_handoff(follow, **common)
        accepted = validate_handoff(follow, **common, ancestor_claims=["evidence:c8", "hypotheses:c1"])
        self.assertEqual(accepted["claims"][0]["contradicts"], ["evidence:c8"])
        with self.assertRaisesRegex(ValueError, "evidence:c8 in follow-2:c1$"):
            validate_handoff(follow, **common, ancestor_claims=["evidence:c9", "hypotheses:c1"])
        with self.assertRaisesRegex(ValueError, "cannot contradict itself"):
            validate_handoff(handoff("follow-2", "framework-researcher",
                                     claims=[claim("follow-2:c1", contradicts=("follow-2:c1",))]),
                             **common, ancestor_claims=["follow-2:c1"])
        review = {"review_id": "purple:r1", "claim_ids": ["evidence:c8"], "disposition": "review_ready",
                  "rationale": "Reviewed.", "evidence_ids": []}
        with self.assertRaisesRegex(ValueError, "unknown claim ID reference: evidence:c8"):
            validate_handoff(handoff("purple", "framework-reviewer", reviews=[review]), snapshot=SNAPSHOT,
                             evidence_ids=EVIDENCE, step_id="purple", profile="framework-reviewer",
                             predecessors=[analysis], ancestor_claims=["evidence:c8"])

    def test_rejections_name_the_claim_and_what_is_expected(self):
        common = dict(snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="evidence", profile="framework-researcher")
        # Live: 13 follow-ups put the verdict "unresolved" into kind; a retry told nothing repeated it.
        with self.assertRaisesRegex(ValueError, r"^unknown claim kind in evidence:c2 \(allowed: finding, "
                                                r"hypothesis, inference, observed\)$"):
            validate_handoff(handoff("evidence", "framework-researcher",
                                     claims=[claim("evidence:c1"), claim("evidence:c2", kind="unresolved")]), **common)
        # Live (team-k3-234711): the retry repeated step_id "hunt" because the error named no expectation.
        with self.assertRaisesRegex(ValueError, r"\(expected step_id evidence, profile framework-researcher\)$"):
            validate_handoff(handoff("hunt", "framework-researcher", claims=[claim("hunt:c1")]), **common)
        with self.assertRaisesRegex(ValueError, r"^claim ID hunt:c1 must start with evidence:$"):
            validate_handoff(handoff("evidence", "framework-researcher", claims=[claim("hunt:c1")]), **common)
        with self.assertRaisesRegex(ValueError, r"^duplicate claim ID evidence:c1$"):
            validate_handoff(handoff("evidence", "framework-researcher",
                                     claims=[claim("evidence:c1"), claim("evidence:c1")]), **common)
        prior = validate_handoff(handoff("scope", "framework-coordinator", claims=[claim("scope:c1")]),
                                 **dict(common, step_id="scope", profile="framework-coordinator"))
        review = {"review_id": "evidence:r1", "claim_ids": ["scope:c1"], "disposition": "review_ready",
                  "rationale": "Reviewed.", "evidence_ids": []}
        with self.assertRaisesRegex(ValueError, r"^duplicate review ID evidence:r1$"):
            validate_handoff(handoff("evidence", "framework-reviewer", reviews=[review, review]),
                             **dict(common, profile="framework-reviewer", predecessors=[prior]))

    def test_unexplained_rejections_keep_the_text_older_workflow_histories_recorded(self):
        common = dict(snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="evidence",
                      profile="framework-researcher", explained=False)
        for raw, message in (
            (handoff("hunt", "framework-researcher"), "handoff identity does not match execution context"),
            (handoff("evidence", "framework-researcher", claims=[claim("hunt:c1")]),
             "claim ID must be uniquely namespaced by step_id"),
            (handoff("evidence", "framework-researcher", claims=[claim("evidence:c1", kind="unresolved")]),
             "unknown claim kind"),
            (handoff("evidence", "framework-researcher", claims=[claim("evidence:c1", contradicts=("x:c1",))]),
             "contradiction target is not a current or predecessor claim"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, f"^{message}$"):
                validate_handoff(raw, **common)

    def test_instructions_state_every_enforced_enum_and_prefix_rule(self):
        # Live native runs failed validation on rules the prompt never stated
        # (claim_id separator, disposition values, text sizes). Keep them stated,
        # and keep every stated size inside the enforced limit.
        text = ontology.handoff_instructions()
        for value in (*ontology.HANDOFF_DISPOSITIONS, *ontology.CLAIM_KINDS):
            self.assertIn(value, text)
        self.assertIn('step_id + ":"', text)
        self.assertIn("max 16, each under 300 chars", text)
        self.assertIn("statement (under 1600 chars)", text)
        # Live reviewers invented their own verdicts and reviewed their own claims.
        self.assertEqual(ontology.REVIEW_DISPOSITIONS, ontology.HANDOFF_DISPOSITIONS)
        review_rules = text.split("Reviews (framework-reviewer only)")[1]
        self.assertIn("disposition (same 3 values)", review_rules)
        self.assertIn("claim_ids (predecessor claims only)", review_rules)
        self.assertIn("contradicts (own/direct-predecessor claim IDs or [])", text)
        # Tool-driven steps contradicted grandparent claims they saw quoted (now allowed by the workflow),
        # Purple reviews carried a stray claim_id key, and a trailing note broke JSON parsing.
        tool_text = ontology.handoff_instructions(tool_driven=True)
        self.assertIn("contradicts (claim IDs of this or any human-reviewed earlier step, or [])", tool_text)
        self.assertIn("no claim_id key", tool_text.split("Reviews (framework-reviewer only)")[1])
        self.assertIn("no text after it", tool_text)
        # Live evidence steps put event IDs ("evt-0001") into evidence_ids, which accepts
        # only supplied source IDs; the prompt names the distinction and validation rejects it.
        self.assertIn("evidence_ids (nonempty; supplied source_id values, never event.id)", text)
        with self.assertRaises(ValueError):
            validate_handoff(handoff("scope", "framework-coordinator", claims=[claim("scope:c1", evidence="evt-0001")]),
                             snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="scope", profile="framework-coordinator")
        # Live evidence steps put hostnames from evidence text ("pos-term-10", "process-1")
        # into entity_ids, which accepts only snapshot entity IDs.
        self.assertIn("entity_ids (snapshot entity_id values only, else [])", text)
        with self.assertRaises(ValueError):
            validate_handoff(handoff("scope", "framework-coordinator", claims=[claim("scope:c1", entities=("pos-term-10",))]),
                             snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="scope", profile="framework-coordinator")
        # Models overshoot stated lengths (live: 518 bytes vs a stated 500, 530 chars vs a
        # stated 400); a ~66% overshoot of a stated note size must still pass the enforced limit.
        stated = handoff("scope", "framework-coordinator", claims=[claim("scope:c1")] * 1)
        stated["claims"][0]["statement"] = "y" * 1999
        stated["limitations"] = ["x" * 499] * 4
        stated["requested_decisions"] = ["z" * 499] * 4
        validate_handoff(stated, snapshot=SNAPSHOT, evidence_ids=EVIDENCE,
                         step_id="scope", profile="framework-coordinator")

    def test_note_limit_parameter_bounds_each_note_and_predecessor_notes(self):
        long_note = "n" * 600
        prior = handoff("first", "framework-coordinator", claims=[claim("first:c1")])
        prior["limitations"] = [long_note]
        with self.assertRaises(ValueError):
            validate_handoff(prior, snapshot=SNAPSHOT, evidence_ids=EVIDENCE,
                             step_id="first", profile="framework-coordinator")
        accepted = validate_handoff(prior, snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="first",
                                    profile="framework-coordinator", note_limit=1024)
        downstream = handoff("second", "framework-coordinator", claims=[claim("second:c1")])
        validate_handoff(downstream, snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="second",
                         profile="framework-coordinator", predecessors=[accepted], note_limit=1024)
        with self.assertRaises(ValueError):
            validate_handoff(downstream, snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="second",
                             profile="framework-coordinator", predecessors=[accepted])
        prior["limitations"] = ["n" * 1025]
        with self.assertRaises(ValueError):
            validate_handoff(prior, snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="first",
                             profile="framework-coordinator", note_limit=1024)

    def test_handoff_limit_bounds_whole_handoff(self):
        big = handoff("final", "framework-coordinator", claims=[claim("final:c1")])
        big["limitations"] = ["n" * 1000] * 16
        big["requested_decisions"] = ["d" * 1000] * 4
        with self.assertRaises(ValueError):
            validate_handoff(big, snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="final",
                             profile="framework-coordinator", note_limit=1024)
        validate_handoff(big, snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="final",
                         profile="framework-coordinator", note_limit=1024, handoff_limit=32768)

    def test_snapshot_returns_owned_copy_and_selection_preserves_references(self):
        source = copy.deepcopy(SNAPSHOT)
        normalized = validate_snapshot(source, EVIDENCE)
        normalized["entities"][0]["label"] = "changed copy"
        self.assertEqual(source["entities"][0]["label"], "Synthetic host alpha")
        selected = select_snapshot(source, ["dns:1"])
        self.assertEqual([item["entity_id"] for item in selected["entities"]], ["host:alpha"])
        self.assertEqual([item["relation_id"] for item in selected["relations"]], [])
        self.assertEqual(selected["case_id"], "case-7")
        both = select_snapshot(source, EVIDENCE)
        self.assertEqual([item["relation_id"] for item in both["relations"]], ["r:1", "r:2"])
        self.assertEqual(both["entities"][0]["entity_id"], "host:alpha")

    def test_snapshot_rejects_unknown_evidence_collisions_and_boolean_version(self):
        bad = copy.deepcopy(SNAPSHOT)
        bad["schema_version"] = True
        with self.assertRaises(ValueError):
            validate_snapshot(bad, EVIDENCE)
        bad = copy.deepcopy(SNAPSHOT)
        bad["entities"][0]["evidence_ids"] = ["missing"]
        with self.assertRaises(ValueError):
            validate_snapshot(bad, EVIDENCE)
        bad = copy.deepcopy(SNAPSHOT)
        bad["entities"].append(copy.deepcopy(bad["entities"][0]))
        with self.assertRaises(ValueError):
            validate_snapshot(bad, EVIDENCE)
        bad = copy.deepcopy(SNAPSHOT)
        bad["relations"][0]["object_id"] = "not-present"
        with self.assertRaises(ValueError):
            validate_snapshot(bad, EVIDENCE)

    def test_unknown_fields_unicode_and_encoded_size_fail_closed(self):
        bad = copy.deepcopy(SNAPSHOT)
        bad["extra"] = "not part of the contract"
        with self.assertRaises(ValueError):
            validate_snapshot(bad, EVIDENCE)
        bad = copy.deepcopy(SNAPSHOT)
        bad["entities"][0]["label"] = "\ud800"
        with self.assertRaises(ValueError):
            validate_snapshot(bad, EVIDENCE)

        oversized_snapshot = {
            "schema_version": 1, "case_id": "large", "entities": [
                {"entity_id": f"host:{index}", "kind": "host", "label": "x" * 1000,
                 "evidence_ids": ["dns:1"]} for index in range(40)
            ], "relations": [],
        }
        with self.assertRaises(ValueError):
            validate_snapshot(oversized_snapshot, EVIDENCE)

        oversized_claims = [
            claim(f"large:{index}", entities=(), kind="finding") | {"statement": "x" * 2048}
            for index in range(9)
        ]
        with self.assertRaises(ValueError):
            validate_handoff(handoff("large", "framework-builder", claims=oversized_claims),
                             snapshot=SNAPSHOT, evidence_ids=EVIDENCE,
                             step_id="large", profile="framework-builder")

    def test_a_wrong_field_set_names_the_missing_and_unexpected_fields(self):
        bad = copy.deepcopy(SNAPSHOT)
        del bad["relations"]
        bad["notes"] = "x"
        bad["weird key!"] = "y"
        with self.assertRaisesRegex(ValueError, r"\(missing relations; unexpected notes, 1 more\)"):
            validate_snapshot(bad, EVIDENCE)
        with self.assertRaisesRegex(ValueError, r"a JSON object with case_id, entities, relations, schema_version"):
            validate_snapshot([], EVIDENCE)

    def test_historical_citations_survive_compact_context_and_transitive_handoff(self):
        broad = validate_handoff(
            handoff("network", "framework-network-analyst", claims=[
                claim("network:observation", evidence="hunt:2", entities=("domain:beta",))
            ]),
            snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="network",
            profile="framework-network-analyst",
        )
        analysis = validate_handoff(
            handoff("analysis", "framework-coordinator", claims=[
                claim("analysis:summary", evidence="hunt:2", entities=("domain:beta",),
                      contradicts=("network:observation",))
            ]),
            snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="analysis",
            profile="framework-coordinator", predecessors=[broad],
        )
        compact = select_snapshot(SNAPSHOT, ["dns:1"])
        detection = validate_handoff(
            handoff("detection", "framework-builder", claims=[
                claim("detection:proposal", contradicts=("analysis:summary",))
            ]),
            snapshot=compact, evidence_ids=["dns:1"], step_id="detection",
            profile="framework-builder", predecessors=[analysis],
        )
        self.assertEqual(detection["claims"][0]["contradicts"], ["analysis:summary"])

    def test_reviewer_cannot_review_current_or_prior_reviewer_claims(self):
        prior_review = validate_handoff(
            handoff("review-a", "framework-reviewer", claims=[
                claim("review-a:claim", kind="finding")
            ]),
            snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="review-a",
            profile="framework-reviewer",
        )
        review = {
            "review_id": "review-b:review", "claim_ids": ["review-a:claim"],
            "disposition": "review_ready", "rationale": "Attempted self-review.",
            "evidence_ids": ["dns:1"],
        }
        with self.assertRaises(ValueError):
            validate_handoff(
                handoff("review-b", "framework-reviewer", reviews=[review]),
                snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="review-b",
                profile="framework-reviewer", predecessors=[prior_review],
            )
        own_claim_review = dict(review, claim_ids=["review-b:claim"])
        with self.assertRaises(ValueError):
            validate_handoff(
                handoff("review-b", "framework-reviewer",
                        claims=[claim("review-b:claim", kind="finding")], reviews=[own_claim_review]),
                snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="review-b",
                profile="framework-reviewer",
            )
    def test_network_review_chain_keeps_ids_and_requires_independent_reviewer(self):
        network = validate_handoff(
            handoff("network", "framework-network-analyst", claims=[claim("network:observation")]),
            snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="network", profile="framework-network-analyst",
        )
        review = {
            "review_id": "review:check-1", "claim_ids": ["network:observation"],
            "disposition": "review_ready", "rationale": "Citation resolves to supplied DNS evidence.",
            "evidence_ids": ["dns:1"],
        }
        reviewer_claim = claim("review:check-1", evidence="dns:1", kind="finding")
        reviewed = validate_handoff(
            handoff("review", "framework-reviewer", claims=[reviewer_claim], reviews=[review]),
            snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="review", profile="framework-reviewer",
            predecessors=[network],
        )
        final = validate_handoff(
            handoff("synthesis", "framework-coordinator", claims=[claim(
                "synthesis:summary", kind="inference", contradicts=["network:observation"]
            )]),
            snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="synthesis", profile="framework-coordinator",
            predecessors=[network, reviewed],
        )
        self.assertEqual(final["claims"][0]["claim_id"], "synthesis:summary")
        self.assertEqual(final["claims"][0]["contradicts"], ["network:observation"])
        self.assertEqual(reviewed["reviews"][0]["review_id"], "review:check-1")
        with self.assertRaises(ValueError):
            validate_handoff(
                handoff("rogue", "framework-coordinator", claims=[claim("rogue:c", evidence="other")]),
                snapshot=SNAPSHOT, evidence_ids=EVIDENCE, step_id="rogue", profile="framework-coordinator",
                predecessors=[reviewed],
            )

    def test_rejects_stale_identity_unknown_claim_and_self_contradiction(self):
        base = handoff("analysis", "framework-coordinator", claims=[claim("analysis:c")])
        with self.assertRaises(ValueError):
            validate_handoff(base, snapshot=SNAPSHOT, evidence_ids=EVIDENCE,
                             step_id="other", profile="framework-coordinator")
        bad = copy.deepcopy(base)
        bad["claims"][0]["contradicts"] = ["unknown:c"]
        with self.assertRaises(ValueError):
            validate_handoff(bad, snapshot=SNAPSHOT, evidence_ids=EVIDENCE,
                             step_id="analysis", profile="framework-coordinator")
        bad = copy.deepcopy(base)
        bad["claims"][0]["contradicts"] = ["analysis:c"]
        with self.assertRaises(ValueError):
            validate_handoff(bad, snapshot=SNAPSHOT, evidence_ids=EVIDENCE,
                             step_id="analysis", profile="framework-coordinator")
        with self.assertRaises(ValueError):
            validate_handoff(base, snapshot=SNAPSHOT, evidence_ids=EVIDENCE,
                             step_id="analysis", profile="unknown-role")

    def test_rejects_malformed_predecessors_and_nonreviewer_review_objects(self):
        prior = handoff("prior", "framework-network-analyst", claims=[claim("prior:c")])
        malformed = copy.deepcopy(prior)
        malformed["claims"][0]["claim_id"] = "wrong-prefix"
        with self.assertRaises(ValueError):
            validate_handoff(handoff("next", "framework-coordinator"), snapshot=SNAPSHOT,
                             evidence_ids=EVIDENCE, step_id="next", profile="framework-coordinator",
                             predecessors=[malformed])
        review = {"review_id": "next:r", "claim_ids": ["prior:c"], "disposition": "review_ready",
                  "rationale": "Reviewed", "evidence_ids": ["dns:1"]}
        with self.assertRaises(ValueError):
            validate_handoff(handoff("next", "framework-builder", reviews=[review]), snapshot=SNAPSHOT,
                             evidence_ids=EVIDENCE, step_id="next", profile="framework-builder",
                             predecessors=[prior])
        nonreviewer_with_review = dict(prior, reviews=[dict(review, review_id="prior:r")])
        with self.assertRaises(ValueError):
            validate_handoff(handoff("next", "framework-coordinator"), snapshot=SNAPSHOT,
                             evidence_ids=EVIDENCE, step_id="next", profile="framework-coordinator",
                             predecessors=[nonreviewer_with_review])
        with self.assertRaises(ValueError):
            validate_handoff(handoff("next", "framework-coordinator"), snapshot=SNAPSHOT,
                             evidence_ids=EVIDENCE, step_id="next", profile="framework-coordinator",
                             predecessors=[dict(prior, case_id="different")])


if __name__ == "__main__":
    unittest.main()
