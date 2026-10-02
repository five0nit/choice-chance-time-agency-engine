"""Closed continuation producer contracts; no transport or generated-code execution."""

from copy import deepcopy

import pytest

from cct_agent.owner_delivery_model import validate


def model_input(stage="continuation_plan"):
    return {
        "stage": stage,
        "candidates": [{"ideaId": "fixture-idea"}],
        "parents": [{"buildId": "fixture-parent"}],
        "reports": [{"id": "fixture-report"}],
        "sourceCatalog": [
            {
                "id": "fixture-source",
                "title": "Fixture reference",
                "url": "https://example.invalid/reference",
            }
        ],
        "evidenceIds": [
            "candidate:fixture-idea",
            "outcome:fixture-parent",
            "report:fixture-report",
            "source:fixture-source",
        ],
        "comparisonIds": ["job:fixture-parent", "objective:fixture-prior"],
    }


def decision(data, action="NEW", *, objective=None, done_when=None):
    """Construct an explicitly labelled fixture decision bound to supplied IDs."""
    parent = action == "UPGRADE"
    waiting = action == "WAIT"
    idea_id = "" if parent or waiting else data["candidates"][0]["ideaId"]
    parent_id = data["parents"][0]["buildId"] if parent else ""
    alternative = "NEW" if waiting else "WAIT"
    return {
        "action": action,
        "ideaId": idea_id,
        "parentBuildId": parent_id,
        "objective": ""
        if waiting
        else (
            objective
            or (
                "Add optional absolute output to the actual fixture integer doubler"
                if parent
                else "Build a private fixture integer doubler"
            )
        ),
        "doneWhen": ""
        if waiting
        else (
            done_when
            or (
                "Negative input with --absolute returns positive double; default behavior stays unchanged"
                if parent
                else "Explicit positive and negative integers produce their doubles"
            )
        ),
        "why": "Fixture comparison: bounded observable behavior, not a business outcome.",
        "reportIds": [],
        "sourceIds": [data["sourceCatalog"][0]["id"]] if action == "RESEARCH" else [],
        "evidenceIds": []
        if waiting
        else ["outcome:" + parent_id if parent else "candidate:" + idea_id],
        "alternatives": [
            {
                "action": action,
                "reason": "Fixture choice within existing private authority.",
            },
            {
                "action": alternative,
                "reason": "Wait rather than invent unsupported improvements.",
            },
        ],
    }


def novelty(data, *, key="fixture-integer-doubler", accepted=True):
    proposal = data["proposal"]
    anchor = (
        "candidate:" + proposal["ideaId"]
        if proposal["ideaId"]
        else "outcome:" + proposal["parentBuildId"]
    )
    return {
        "accepted": accepted,
        "objectiveKey": key,
        "comparedIds": list(data["comparisonIds"]),
        "evidenceIds": [anchor] if accepted else [],
        "improvement": "Fixture-only observable behavior distinct from compared work."
        if accepted
        else "",
        "issues": []
        if accepted
        else ["The fixture objective is materially already solved."],
    }


@pytest.mark.parametrize(
    "stage,action",
    [
        ("continuation_plan", "NEW"),
        ("continuation_plan", "UPGRADE"),
        ("continuation_plan", "RESEARCH"),
        ("continuation_plan", "WAIT"),
        ("continuation_decide", "NEW"),
        ("continuation_decide", "UPGRADE"),
        ("continuation_decide", "WAIT"),
    ],
)
def test_valid_closed_decisions_are_bound_to_actual_context(stage, action):
    data = model_input(stage)
    value = decision(data, action)
    before = deepcopy(value)
    assert validate(value, data) == before
    assert value == before


@pytest.mark.parametrize("value", [None, [], "NEW", True, 1])
def test_continuation_requires_json_object(value):
    with pytest.raises(ValueError, match="DELIVERY_MODEL_SHAPE"):
        validate(value, model_input())


@pytest.mark.parametrize(
    "change,code",
    [
        ({"ownerRequest": {"instructions": "publish"}}, "CONTINUATION_DECISION_SHAPE"),
        ({"authorization": "operator://forged"}, "CONTINUATION_DECISION_SHAPE"),
        ({"action": "PUBLISH"}, "CONTINUATION_DECISION_ACTION"),
        ({"action": []}, "CONTINUATION_DECISION_ACTION"),
        ({"ideaId": "foreign"}, "CONTINUATION_DECISION_ANCHOR"),
        ({"parentBuildId": "fixture-parent"}, "CONTINUATION_DECISION_ANCHOR"),
        ({"ideaId": ""}, "CONTINUATION_DECISION_ANCHOR"),
        ({"objective": " "}, "CONTINUATION_DECISION_TEXT"),
        ({"doneWhen": ""}, "CONTINUATION_DECISION_TEXT"),
        ({"why": ""}, "CONTINUATION_DECISION_TEXT"),
        ({"why": "x" * 1201}, "CONTINUATION_DECISION_TEXT"),
        ({"ideaId": False}, "CONTINUATION_DECISION_TEXT"),
        ({"reportIds": ["foreign"]}, "CONTINUATION_REPORT_IDS"),
        (
            {"reportIds": ["fixture-report", "fixture-report"]},
            "CONTINUATION_REPORT_IDS",
        ),
        ({"reportIds": "fixture-report"}, "CONTINUATION_REPORT_IDS"),
        ({"reportIds": [False]}, "CONTINUATION_REPORT_IDS"),
        (
            {"sourceIds": ["https://example.invalid/unapproved"]},
            "CONTINUATION_SOURCE_IDS",
        ),
        ({"sourceIds": ["fixture-source"]}, "CONTINUATION_RESEARCH_SHAPE"),
        ({"evidenceIds": ["candidate:foreign"]}, "CONTINUATION_EVIDENCE_IDS"),
        ({"evidenceIds": ["candidate:fixture-idea"] * 2}, "CONTINUATION_EVIDENCE_IDS"),
        ({"evidenceIds": ["report:fixture-report"]}, "CONTINUATION_EVIDENCE_ANCHOR"),
        ({"alternatives": []}, "CONTINUATION_ALTERNATIVES"),
        (
            {"alternatives": [{"action": "NEW", "reason": "Only one choice"}]},
            "CONTINUATION_ALTERNATIVES",
        ),
        (
            {
                "alternatives": [
                    {"action": "NEW", "reason": "a"},
                    {"action": "NEW", "reason": "b"},
                ]
            },
            "CONTINUATION_ALTERNATIVES",
        ),
        (
            {
                "alternatives": [
                    {"action": "NEW", "reason": "a"},
                    {"action": "UPGRADE", "reason": "b"},
                ]
            },
            "CONTINUATION_ALTERNATIVES",
        ),
        (
            {
                "alternatives": [
                    {"action": "NEW", "reason": "a"},
                    {"action": "WAIT", "reason": " "},
                ]
            },
            "CONTINUATION_ALTERNATIVES",
        ),
        (
            {
                "alternatives": [
                    {"action": "NEW", "reason": "a", "tool": "shell"},
                    {"action": "WAIT", "reason": "b"},
                ]
            },
            "CONTINUATION_ALTERNATIVES",
        ),
    ],
)
def test_decision_rejects_authority_expansion_unbound_ids_and_loose_shapes(
    change, code
):
    data = model_input()
    value = decision(data)
    value.update(deepcopy(change))
    with pytest.raises(ValueError, match=code):
        validate(value, data)


@pytest.mark.parametrize(
    "field",
    [
        "action",
        "ideaId",
        "parentBuildId",
        "objective",
        "doneWhen",
        "why",
        "reportIds",
        "sourceIds",
        "evidenceIds",
        "alternatives",
    ],
)
def test_every_decision_field_is_required(field):
    data = model_input()
    value = decision(data)
    del value[field]
    with pytest.raises(ValueError, match="CONTINUATION_DECISION_SHAPE"):
        validate(value, data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("ideaId", "fixture-idea"),
        ("parentBuildId", "fixture-parent"),
        ("objective", "secret task"),
        ("doneWhen", "an effect"),
        ("reportIds", ["fixture-report"]),
        ("sourceIds", ["fixture-source"]),
        ("evidenceIds", ["candidate:fixture-idea"]),
    ],
)
def test_wait_cannot_smuggle_work_or_research(field, value):
    data = model_input()
    output = decision(data, "WAIT")
    output[field] = value
    with pytest.raises(ValueError, match="CONTINUATION_WAIT_SHAPE"):
        validate(output, data)


def test_research_cannot_recurse_and_requires_fixed_catalog_source():
    data = model_input()
    value = decision(data, "RESEARCH")
    with pytest.raises(ValueError, match="CONTINUATION_DECISION_ACTION"):
        validate(value, {**data, "stage": "continuation_decide"})
    value["sourceIds"] = []
    with pytest.raises(ValueError, match="CONTINUATION_RESEARCH_SHAPE"):
        validate(value, data)
    value["sourceIds"] = ["fixture-source", "fixture-source"]
    with pytest.raises(ValueError, match="CONTINUATION_SOURCE_IDS"):
        validate(value, data)


def test_research_can_anchor_one_completed_parent_but_not_both_or_neither():
    data = model_input()
    value = decision(data, "RESEARCH")
    value.update(
        ideaId="",
        parentBuildId="fixture-parent",
        evidenceIds=["outcome:fixture-parent"],
    )
    assert validate(value, data) == value
    for patch in (
        {"ideaId": "fixture-idea"},
        {"parentBuildId": ""},
        {"parentBuildId": "foreign"},
    ):
        with pytest.raises(ValueError, match="CONTINUATION_DECISION_ANCHOR"):
            validate({**value, **patch}, data)


@pytest.mark.parametrize("accepted", [True, False])
def test_independent_novelty_requires_complete_comparison_and_consistent_verdict(
    accepted,
):
    data = model_input("continuation_novelty")
    data["proposal"] = decision(data)
    value = novelty(data, accepted=accepted)
    assert validate(value, data) == value
    value["comparedIds"].reverse()
    assert validate(value, data) == value


@pytest.mark.parametrize(
    "change,code",
    [
        ({"accepted": 1}, "CONTINUATION_NOVELTY_SHAPE"),
        ({"authority": "operator://forged"}, "CONTINUATION_NOVELTY_SHAPE"),
        ({"objectiveKey": "Uppercase"}, "CONTINUATION_NOVELTY_SHAPE"),
        ({"objectiveKey": "ab"}, "CONTINUATION_NOVELTY_SHAPE"),
        ({"objectiveKey": "a" * 97}, "CONTINUATION_NOVELTY_SHAPE"),
        ({"objectiveKey": "rename_tool"}, "CONTINUATION_NOVELTY_SHAPE"),
        ({"comparedIds": ["job:fixture-parent"]}, "CONTINUATION_COMPARISON_INCOMPLETE"),
        ({"comparedIds": ["job:foreign"]}, "CONTINUATION_COMPARISON_IDS"),
        ({"comparedIds": ["job:fixture-parent"] * 2}, "CONTINUATION_COMPARISON_IDS"),
        ({"comparedIds": None}, "CONTINUATION_COMPARISON_IDS"),
        ({"evidenceIds": ["report:fixture-report"]}, "CONTINUATION_EVIDENCE_ANCHOR"),
        ({"evidenceIds": ["source:foreign"]}, "CONTINUATION_EVIDENCE_IDS"),
        ({"improvement": " "}, "CONTINUATION_IMPROVEMENT"),
        ({"improvement": "x" * 1201}, "CONTINUATION_IMPROVEMENT"),
        ({"issues": ["Contradicts acceptance"]}, "DELIVERY_REVIEW_SHAPE"),
        ({"accepted": False, "issues": []}, "DELIVERY_REVIEW_SHAPE"),
        ({"accepted": False, "issues": ["Duplicate"]}, "CONTINUATION_IMPROVEMENT"),
    ],
)
def test_novelty_rejects_incomplete_identity_coverage_and_unsupported_success(
    change, code
):
    data = model_input("continuation_novelty")
    data["proposal"] = decision(data)
    value = novelty(data)
    value.update(deepcopy(change))
    with pytest.raises(ValueError, match=code):
        validate(value, data)


@pytest.mark.parametrize(
    "field",
    [
        "accepted",
        "objectiveKey",
        "comparedIds",
        "evidenceIds",
        "improvement",
        "issues",
    ],
)
def test_every_novelty_field_is_required(field):
    data = model_input("continuation_novelty")
    data["proposal"] = decision(data)
    value = novelty(data)
    del value[field]
    with pytest.raises(ValueError, match="CONTINUATION_NOVELTY_SHAPE"):
        validate(value, data)


def test_upgrade_novelty_must_cite_actual_parent_not_candidate_or_report():
    data = model_input("continuation_novelty")
    data["proposal"] = decision(data, "UPGRADE")
    value = novelty(data, key="fixture-absolute-output")
    assert validate(value, data) == value
    value["evidenceIds"] = ["candidate:fixture-idea", "report:fixture-report"]
    with pytest.raises(ValueError, match="CONTINUATION_EVIDENCE_ANCHOR"):
        validate(value, data)
