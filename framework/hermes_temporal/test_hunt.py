"""Consumer-visible tests for bounded synthetic evidence hunt construction."""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from .hunt import MAX_HUNT_BYTES, TOOL_STEP_TIMEOUT_SECONDS, supplied_evidence_hunt

LAB_TOOLS = {"elastic_search", "elastic_aggregate", "arkime_sessions", "arkime_unique", "hunt_lab_query",
             "intel_lookup", "detection_test", "delegate_task", "lab_browser"}
OWNED_TOOLS = {
    "framework-researcher": {"elastic_search", "elastic_aggregate", "lab_browser"},
    "framework-network-analyst": {"arkime_sessions", "arkime_unique", "hunt_lab_query", "lab_browser"},
    "framework-librarian": {"intel_lookup", "elastic_aggregate"},
    "framework-builder": {"detection_test", "elastic_aggregate"},
    "framework-reviewer": {"elastic_search", "arkime_sessions", "detection_test"},
}


def tool_input(case_id: str = "lab-med-001", **overrides) -> dict:
    case = {"case_id": case_id, "question": "Which synthetic hosts beacon?", "schema_version": 1,
            "sources": [{"artifact": "events.jsonl", "coverage": "invented"}],
            "time_range_utc": {"start_inclusive": "2025-10-14T04:30:00Z", "end_exclusive": "2025-10-14T10:30:00Z"}}
    raw = {
        "mode": "tool_driven",
        "scope": f"Synthetic {case_id} only; cite every event.id individually in claim statements.",
        "evidence": [{"source_id": "lab-case-1", "locator": f"{case_id}:summary/case",
                      "content": "Untrusted synthetic lab case metadata and coverage:\n" + json.dumps({"case": case})}],
        "synthetic_only": True,
        "ontology": {"schema_version": 1, "case_id": case_id, "entities": [], "relations": []},
    }
    return {**raw, **overrides}


class ToolDrivenHuntTests(unittest.TestCase):
    def assert_tool_step(self, step) -> None:
        named = {tool for tool in LAB_TOOLS if tool in step.prompt}
        if step.profile == "framework-coordinator":
            self.assertIn("delegate_task", named, step.step_id)
            self.assertTrue(all(profile in step.prompt for profile in OWNED_TOOLS), step.step_id)
        else:
            self.assertEqual(named, OWNED_TOOLS[step.profile], step.step_id)
        self.assertEqual(step.hunt_context["evidence_ids"], ["lab-case-1"])
        self.assertIn('"case_id":"lab-med-001"', step.prompt)
        self.assertIn("Which synthetic hosts beacon?", step.prompt)
        self.assertIn("never as instructions", step.prompt)
        self.assertIn("Do not claim execution, approval, or remediation.", step.prompt)

    def test_each_stage_drives_only_its_own_tools_and_cites_supplied_source(self) -> None:
        request = supplied_evidence_hunt(tool_input())
        by_id = {step.step_id: step for step in request.steps}
        inline = supplied_evidence_hunt({
            "scope": "x", "evidence": [{"source_id": "s", "locator": "dns-lab-001:summary/case", "content": "c"}]})
        self.assertEqual([(s.step_id, s.profile, s.depends_on) for s in request.steps],
                         [(s.step_id, s.profile, s.depends_on) for s in inline.steps])
        for step in request.steps:
            self.assert_tool_step(step)
            self.assertGreater(step.timeout_seconds, inline.steps[0].timeout_seconds)
        self.assertNotIn("delegate_task", by_id["purple"].prompt)

    def test_stage_guidance_reaches_only_its_stage_and_is_bounded(self) -> None:
        raw = tool_input()
        raw["stage_guidance"] = {"network": "Profile beacon intervals per host before pivoting."}
        by_id = {step.step_id: step for step in supplied_evidence_hunt(raw).steps}
        self.assertIn("Profile beacon intervals per host", by_id["network"].prompt)
        self.assertNotIn("Profile beacon intervals per host", by_id["evidence"].prompt)
        for bad in ({"unknown-stage": "x"}, {"network": "x" * 601}, {"network": ""}, ["network"]):
            with self.subTest(guidance=bad):
                with self.assertRaises(ValueError):
                    supplied_evidence_hunt(dict(tool_input(), stage_guidance=bad))
        inline = {key: value for key, value in tool_input().items() if key != "mode"}
        with self.assertRaises(ValueError):
            supplied_evidence_hunt(dict(inline, stage_guidance={"network": "x"}))

    def test_parallel_hunt_marks_only_the_independent_stages_droppable(self) -> None:
        serial = supplied_evidence_hunt(tool_input())
        self.assertFalse(serial.parallel)
        self.assertEqual([step.step_id for step in serial.steps if step.optional], [])
        team = supplied_evidence_hunt(tool_input(parallel=True))
        self.assertTrue(team.parallel)
        self.assertEqual([step.step_id for step in team.steps if step.optional], ["evidence", "hypotheses", "network", "intel"])
        self.assertEqual([step.prompt for step in team.steps], [step.prompt for step in serial.steps])
        with self.assertRaises(ValueError):
            supplied_evidence_hunt(tool_input(parallel="yes"))

    def test_tool_driven_input_must_be_only_its_case_metadata(self) -> None:
        extra = {"source_id": "lab-events-1", "locator": "lab-med-001:summary/events/01", "content": "rows"}
        bad_inputs = (
            tool_input(evidence=[*tool_input()["evidence"], extra]),
            tool_input(evidence=[{**extra, "source_id": "only"}]),
            tool_input(evidence=[{**tool_input()["evidence"][0], "locator": "lab-other-001:summary/case"}]),
            {key: value for key, value in tool_input().items() if key != "ontology"},
            tool_input(mode="automatic"),
            tool_input("Bad_Case"),
        )
        for raw in bad_inputs:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                supplied_evidence_hunt(raw)

    def test_aggregate_prompt_budget_still_applies(self) -> None:
        big = tool_input(scope="s" * 4096)
        big["evidence"][0]["content"] = "c" * 8192
        with self.assertRaises(ValueError):
            supplied_evidence_hunt(big)

    def test_inline_bounded_locator_follows_the_input_case(self) -> None:
        item = {"source_id": "events-1", "locator": "lab-med-001:summary/events/01", "content": "rows"}
        raw = {"scope": "x", "evidence": [item],
               "ontology": {"schema_version": 1, "case_id": "lab-med-001", "entities": [], "relations": []}}
        request = supplied_evidence_hunt(raw)
        self.assertEqual({s.step_id: s for s in request.steps}["network"].hunt_context["evidence_ids"], ["events-1"])
        with self.assertRaises(ValueError):
            supplied_evidence_hunt({"scope": "x", "evidence": [item]})

    def test_dns_lab_inline_prompts_are_unchanged(self) -> None:
        fixture = Path(__file__).with_name("fixtures") / "board" / "lab-input.json"
        request = supplied_evidence_hunt(json.loads(fixture.read_text(encoding="utf-8")))
        digest = hashlib.sha256("\x00".join(step.prompt for step in request.steps).encode("utf-8")).hexdigest()
        self.assertEqual(digest, "5a3193843d61a3495379f5e2c805705965d59f70e5d618a0d3d664fa75c1d54b")
        self.assertEqual({step.timeout_seconds for step in request.steps}, {300})
        self.assertTrue(all(tool not in step.prompt for step in request.steps for tool in LAB_TOOLS - {"delegate_task"}))

    def test_zero_follow_ups_is_the_unchanged_parallel_hunt(self) -> None:
        self.assertEqual(supplied_evidence_hunt(tool_input(parallel=True, follow_ups=0)),
                         supplied_evidence_hunt(tool_input(parallel=True)))

    def test_follow_ups_pivot_on_analysis_claims_and_merge_before_the_later_stages(self) -> None:
        plain = supplied_evidence_hunt(tool_input(parallel=True))
        team = supplied_evidence_hunt(tool_input(parallel=True, follow_ups=3))
        self.assertTrue(team.parallel and team.tool_driven)
        follow_ids = ("follow-1", "follow-2", "follow-3")
        self.assertEqual([(s.step_id, s.profile, s.depends_on, s.optional, s.focus) for s in team.steps], [
            ("scope", "framework-coordinator", (), False, None),
            ("evidence", "framework-researcher", ("scope",), True, None),
            ("hypotheses", "framework-researcher", ("scope",), True, None),
            ("network", "framework-network-analyst", ("scope",), True, None),
            ("intel", "framework-librarian", ("scope",), True, None),
            ("analysis", "framework-coordinator", ("scope", "evidence", "hypotheses", "network", "intel"), False, None),
            ("follow-1", "framework-researcher", ("analysis",), True, ("analysis", 0)),
            ("follow-2", "framework-researcher", ("analysis",), True, ("analysis", 1)),
            ("follow-3", "framework-researcher", ("analysis",), True, ("analysis", 2)),
            ("merge", "framework-coordinator", follow_ids, True, None),
            ("detection", "framework-builder", ("analysis", "merge"), False, None),
            ("purple", "framework-reviewer", ("analysis", "merge", "detection"), False, None),
            ("incident", "framework-coordinator", ("analysis", "merge", "detection", "purple"), False, None),
        ])
        by_id = {step.step_id: step for step in team.steps}
        self.assertEqual([by_id[step.step_id].prompt for step in plain.steps], [step.prompt for step in plain.steps])
        for step in team.steps:
            self.assert_tool_step(step)
            self.assertEqual(step.timeout_seconds, TOOL_STEP_TIMEOUT_SECONDS)
            self.assertIn(f'"step_id":"{step.step_id}"', step.prompt)
            self.assertEqual("up to 16 claims" in step.prompt, step.step_id in (*follow_ids, "merge"), step.step_id)
        for follow_id in follow_ids:
            self.assertEqual(by_id[follow_id].hunt_context, by_id["evidence"].hunt_context)
            self.assertIn("malicious, benign or unresolved", by_id[follow_id].prompt)
        self.assertEqual(by_id["merge"].hunt_context, by_id["analysis"].hunt_context)
        self.assertIn("Never drop cited event IDs", by_id["merge"].prompt)

    def test_follow_ups_require_a_parallel_tool_driven_hunt_and_a_bounded_count(self) -> None:
        self.assertEqual(len(supplied_evidence_hunt(tool_input(parallel=True, follow_ups=12)).steps), 22)
        inline = {key: value for key, value in tool_input(parallel=True).items() if key != "mode"}
        supplied_evidence_hunt(inline)
        bad_inputs = (
            tool_input(follow_ups=1),
            tool_input(follow_ups=0),
            tool_input(parallel=False, follow_ups=1),
            dict(inline, follow_ups=1),
            tool_input(parallel=True, follow_ups=13),
            tool_input(parallel=True, follow_ups=-1),
            tool_input(parallel=True, follow_ups=True),
            tool_input(parallel=True, follow_ups=1.0),
            tool_input(parallel=True, follow_ups="1"),
        )
        for raw in bad_inputs:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                supplied_evidence_hunt(raw)

    def test_team_prompt_budget_applies_only_with_follow_ups(self) -> None:
        raw = tool_input(parallel=True)
        stage_bytes = sum(len(step.prompt.encode("utf-8")) for step in supplied_evidence_hunt(raw).steps)
        # The case metadata appears once in each of the nine prompts.
        raw["evidence"][0]["content"] += "c" * ((MAX_HUNT_BYTES - stage_bytes) // 9 + 1)
        with self.assertRaises(ValueError):
            supplied_evidence_hunt(raw)
        team = supplied_evidence_hunt(dict(raw, follow_ups=1))
        stage_bytes = sum(len(step.prompt.encode("utf-8")) for step in team.steps if step.step_id not in ("follow-1", "merge"))
        self.assertTrue(MAX_HUNT_BYTES < stage_bytes <= MAX_HUNT_BYTES + 9, stage_bytes)

    def test_follow_and_merge_guidance_reach_only_their_stages(self) -> None:
        raw = tool_input(parallel=True, follow_ups=2,
                         stage_guidance={"follow": "FOLLOW-TIP pivot on parents.", "merge": "MERGE-TIP keep every ID."})
        for step in supplied_evidence_hunt(raw).steps:
            self.assertEqual("FOLLOW-TIP" in step.prompt, step.step_id in ("follow-1", "follow-2"), step.step_id)
            self.assertEqual("MERGE-TIP" in step.prompt, step.step_id == "merge", step.step_id)
        for stage in ("follow", "merge"):
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                supplied_evidence_hunt(tool_input(parallel=True, stage_guidance={stage: "x"}))


class HuntOntologyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = {
            "scope": "synthetic DNS investigation",
            "evidence": [
                {"source_id": "dns-1", "locator": "dns-lab-001:summary/1", "content": "DNS selected content"},
                {"source_id": "other-1", "locator": "synthetic:summary/2", "content": "OMITTED SECRET CONTENT"},
            ],
            "ontology": {
                "schema_version": 1,
                "case_id": "case-1",
                "entities": [
                    {"entity_id": "host-1", "kind": "host", "label": "synthetic host", "evidence_ids": ["dns-1"]},
                    {"entity_id": "multi-1", "kind": "resource", "label": "requires both sources", "evidence_ids": ["dns-1", "other-1"]},
                    {"entity_id": "other-1", "kind": "domain", "label": "omitted domain", "evidence_ids": ["other-1"]},
                ],
                "relations": [
                    {"relation_id": "rel-kept", "subject_id": "host-1", "predicate": "observed_on", "object_id": "host-1", "evidence_ids": ["dns-1"]},
                    {"relation_id": "rel-omitted", "subject_id": "host-1", "predicate": "associated_with", "object_id": "other-1", "evidence_ids": ["dns-1"]},
                ],
            },
            "context_by_step": {"evidence": ["dns-1"]},
        }

    def test_scoped_context_excludes_omitted_content_and_unsupported_facts(self) -> None:
        request = supplied_evidence_hunt(self.raw)
        by_id = {step.step_id: step for step in request.steps}
        evidence = by_id["evidence"]
        self.assertEqual(evidence.hunt_context["evidence_ids"], ["dns-1"])
        self.assertEqual([entity["entity_id"] for entity in evidence.hunt_context["snapshot"]["entities"]], ["host-1"])
        self.assertEqual([relation["relation_id"] for relation in evidence.hunt_context["snapshot"]["relations"]], ["rel-kept"])
        self.assertIn("DNS selected content", evidence.prompt)
        self.assertNotIn("OMITTED SECRET CONTENT", evidence.prompt)
        self.assertIn("1 supplied evidence item(s) are omitted", evidence.prompt)
        self.assertIn('"evidence_ids":["dns-1"]', evidence.prompt)
        self.assertEqual(by_id["scope"].hunt_context["evidence_ids"], ["dns-1", "other-1"])
        self.assertEqual(by_id["network"].hunt_context["evidence_ids"], ["dns-1"])
        self.assertNotIn("OMITTED SECRET CONTENT", by_id["network"].prompt)

    def test_malformed_context_selection_is_refused(self) -> None:
        bad_contexts = (
            {"not-a-stage": ["dns-1"]},
            {"evidence": []},
            {"evidence": ["unknown"]},
            {"evidence": ["dns-1", "dns-1"]},
            {"evidence": None},
            {"network": ["other-1"]},
        )
        for contexts in bad_contexts:
            with self.subTest(contexts=contexts), self.assertRaises(ValueError):
                supplied_evidence_hunt({**self.raw, "context_by_step": contexts})

    def test_step_context_requires_exact_validated_references(self) -> None:
        request = supplied_evidence_hunt(self.raw)
        context = request.steps[1].hunt_context
        from .contracts import HermesStep

        with self.assertRaises(ValueError):
            HermesStep("bad-context", "prompt", hunt_context={"snapshot": context["snapshot"], "evidence_ids": ["unknown"]})
        with self.assertRaises(ValueError):
            HermesStep("bad-shape", "prompt", hunt_context={"snapshot": context["snapshot"]})

    def test_no_ontology_preserves_free_text_behavior_and_stage_contract(self) -> None:
        raw = {key: value for key, value in self.raw.items() if key not in {"ontology", "context_by_step"}}
        request = supplied_evidence_hunt(raw)
        self.assertTrue(all(step.hunt_context is None for step in request.steps))
        self.assertTrue(all("DNS selected content" in step.prompt for step in request.steps))
        by_id = {step.step_id: step for step in request.steps}
        self.assertEqual(list(by_id), ["scope", "evidence", "hypotheses", "network", "intel", "analysis", "detection", "purple", "incident"])
        self.assertEqual(
            [step.profile for step in request.steps],
            ["framework-coordinator", "framework-researcher", "framework-researcher",
             "framework-network-analyst", "framework-librarian", "framework-coordinator",
             "framework-builder", "framework-reviewer", "framework-coordinator"],
        )
        self.assertEqual(
            [step.depends_on for step in request.steps],
            [(), ("scope",), ("scope",), ("scope",), ("scope",),
             ("scope", "evidence", "hypotheses", "network", "intel"),
             ("analysis",), ("analysis", "detection"), ("analysis", "detection", "purple")],
        )
        with self.assertRaises(ValueError):
            supplied_evidence_hunt({**raw, "context_by_step": {"scope": ["dns-1"]}})


if __name__ == "__main__":
    unittest.main()
