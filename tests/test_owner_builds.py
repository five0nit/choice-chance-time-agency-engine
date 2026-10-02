"""Real orchestration/storage; inert owner/provider fixtures and bwrap E2E."""

import copy
from datetime import datetime, timezone
import pytest
from tests.test_owner_delivery import (
    environment as environment,
    OwnerDelivery,
)
from cct_agent.owner_builds import digest
from cct_agent.owner_delivery_local import LocalDeliveryDriver


def controls(w, g, revision=1, **changes):
    value = dict(
        schemaVersion="cct.owner_build_controls.v1",
        ownerUid=w.config["ownerUid"],
        revision=revision,
        maxDailyJobs=4,
        maxDailyProviderCalls=20,
        maxDailyToolCalls=12,
        updatedAt=datetime.fromtimestamp(w.clock(), timezone.utc),
        **{},
    )
    value.update(changes)
    g.documents["cct_owner_build_controls", "current"] = value
    w.gate()
    return value


def request(w, g, action="upgrade", name="req-0001", **changes):
    parent = next(j for j in w.jobs() if j["phase"] == "COMPLETE")
    w.builds.backfill()
    value = dict(
        schemaVersion="cct.owner_build_request.v1",
        ownerUid=w.config["ownerUid"],
        requestId=name,
        parentBuildId=parent["id"],
        parentDigest=w.builds.library(parent["id"])["bundleDigest"],
        action=action,
        instructions="Add a documented boundary case.",
        maxProviderCalls=6,
        maxToolCalls=2,
        createdAt=datetime.fromtimestamp(w.clock(), timezone.utc),
        expiresAt=datetime.fromtimestamp(w.clock() + 3600, timezone.utc),
        controlRevision=(w.meta("buildControls") or {}).get("revision", 0),
    )
    value.update(changes)
    g.documents["cct_owner_build_requests", name] = value
    return value


def seed(w):
    assert w.tick()["phase"] == "COMPLETE"
    return copy.deepcopy(w.jobs()[0])


def row(w, name="req-0001"):
    return dict(
        w.db.execute("SELECT * FROM build_requests WHERE id=?", (name,)).fetchone()
    )


def test_backfill_exact_private_files_without_more_calls(environment):
    w, g, e, d, s, m, clock = environment
    original = seed(w)
    before = len(m.calls)
    w.builds.backfill()
    w.builds.backfill()
    value = g.documents["cct_owner_builds", original["id"]]
    assert value["bundleDigest"] == digest(original["bundle"])
    assert [{k: f[k] for k in ("path", "content")} for f in value["files"]] == original[
        "bundle"
    ]["files"]
    assert len(m.calls) == before and value["status"] == "COMPLETE"
    assert value["usage"] == {"providerCalls": 3, "toolCalls": 1}
    assert value["ownerUid"] == w.config["ownerUid"]


@pytest.mark.parametrize("action", ["upgrade", "steer"])
def test_followup_consumes_actual_parent_and_preserves_original(environment, action):
    w, g, e, d, s, m, clock = environment
    original = seed(w)
    controls(w, g)
    request(w, g, action)
    assert w.tick()["phase"] == "COMPLETE"
    assert row(w)["state"] == "COMPLETE"
    child = w.jobs()[-1]
    assert child["parentBuildId"] == original["id"] and child["id"] != original["id"]
    assert w.jobs()[0]["bundle"] == original["bundle"]
    calls = [p for p in m.calls if p.get("ownerRequest")]
    assert [p["stage"] for p in calls] == ["build", "acceptance", "review"]
    assert all(p["parentBuild"]["bundle"] == original["bundle"] for p in calls)
    assert len(d.calls) == 2
    before = len(m.calls)
    w.builds.ingest()
    w.builds.activate()
    assert len(m.calls) == before and len(w.jobs()) == 2


def test_discovery_real_durable_brief_no_fake_sandbox(environment):
    w, g, e, d, s, m, clock = environment
    seed(w)
    controls(w, g)
    request(w, g, "discover")
    old = w.model_override

    def model(p):
        if p["stage"] == "discover":
            return dict(
                title="Boundary gaps",
                summary="saved-evidence exploration; no fresh web research",
                gaps=["Saved interface has no bad-input example."],
                alternatives=["Keep original."],
                proposedUpgrades=["Add boundary documentation."],
                researchQuestions=["What inputs matter?"],
            )
        return old(p)

    w.model_override = model
    assert w.tick()["phase"] == "COMPLETE"
    child = w.jobs()[-1]
    assert child["action"] == "discover"
    assert len(d.calls) == 1 and child["bundle"]["files"][0]["path"] == "DISCOVERY.md"
    assert child["verification"]["freshWebResearch"] is False
    assert child["verification"]["sandbox"] == "not-applicable"
    assert "sandbox tests" not in child["reason"].replace(
        "no fresh web research or executable sandbox tests", ""
    )
    assert w.meta("lastOutcome")["status"] == "REVIEWED_SAVED_EVIDENCE_BRIEF"
    # Discovery itself can be the parent of a later true executable upgrade.
    clock[0] += 1
    request(
        w,
        g,
        name="req-0002",
        parentBuildId=child["id"],
        parentDigest=digest(child["bundle"]),
    )
    assert w.tick()["phase"] == "COMPLETE"
    assert (
        w.jobs()[-1]["parentBuild"]["bundle"] == child["bundle"] and len(d.calls) == 2
    )


def test_archive_restore_works_at_job_cap_without_provider_calls(environment):
    w, g, e, d, s, m, clock = environment
    original = seed(w)
    controls(w, g, maxDailyJobs=1)
    before = len(m.calls)
    request(w, g, "archive")
    assert w.tick()["phase"] == "DAILY_CAP"
    assert w.builds.library(original["id"])["archived"] is True
    assert row(w)["state"] == "COMPLETE" and len(m.calls) == before
    request(w, g, "restore", name="req-0002")
    w.tick()
    assert (
        w.builds.library(original["id"])["archived"] is False and len(m.calls) == before
    )


def test_budget_raise_applies_and_reduction_preserves_rolling_usage(environment):
    w, g, e, d, s, m, clock = environment
    seed(w)
    controls(w, g, maxDailyJobs=1)
    request(w, g)
    assert w.tick()["phase"] == "DAILY_CAP" and row(w)["state"] == "WAITING_BUDGET"
    before = w.builds.usage()
    controls(w, g, revision=2, maxDailyJobs=2)
    assert w.tick()["phase"] == "COMPLETE"
    controls(w, g, revision=3, maxDailyProviderCalls=1)
    assert w.builds.usage()["providerCalls"] > before["providerCalls"]
    with pytest.raises(RuntimeError, match="DELIVERY_MODEL_DAILY_CAP"):
        w.model("review", {}, "probe")
    clock[0] += 86401
    assert w.builds.usage()["providerCalls"] == 0


@pytest.mark.parametrize(
    "field,bad",
    [
        ("maxDailyJobs", 5),
        ("maxDailyProviderCalls", True),
        ("maxDailyToolCalls", 13),
        ("ownerUid", "foreign"),
    ],
)
def test_bad_controls_fail_closed_and_do_not_reset_budget(environment, field, bad):
    w, g, e, d, s, m, clock = environment
    seed(w)
    old = w.builds.usage()
    with pytest.raises(ValueError):
        controls(w, g, **{field: bad})
    before = len(m.calls)
    assert w.tick()["phase"] == "ERROR" and len(m.calls) == before
    assert w.builds.usage() == old


@pytest.mark.parametrize(
    "changes",
    [
        {"parentDigest": "0" * 64},
        {"controlRevision": 99},
        {"maxProviderCalls": True},
        {"action": "publish"},
        {"action": "steer", "instructions": "  "},
        {"requestId": "mismatch"},
    ],
)
def test_invalid_requests_no_child_or_provider(environment, changes):
    w, g, e, d, s, m, clock = environment
    seed(w)
    controls(w, g, maxDailyJobs=1)
    request(w, g, **changes)
    before = len(m.calls)
    w.tick()
    assert (
        row(w)["state"] == "REJECTED" and len(w.jobs()) == 1 and len(m.calls) == before
    )


def test_request_lifetime_cap_persists_across_windows(environment):
    w, g, e, d, s, m, clock = environment
    seed(w)
    controls(w, g)
    request(w, g, maxProviderCalls=1)
    assert w.tick()["phase"] == "BLOCKED" and row(w)["state"] == "FAILED"
    child = w.jobs()[-1]
    assert child["reason"] == "BUILDS_REQUEST_PROVIDER_CAP"
    assert w.builds.usage(child["id"])["providerCalls"] == 1
    clock[0] += 86401
    with pytest.raises(RuntimeError, match="BUILDS_REQUEST_PROVIDER_CAP"):
        w.builds.charge("provider", child["id"], "review")


def test_tool_cap_holds_saved_bundle_and_resumes_without_rebuild(environment):
    w, g, e, d, s, m, clock = environment
    seed(w)
    controls(w, g, maxDailyToolCalls=1)
    request(w, g)
    assert w.tick()["phase"] == "DAILY_CAP" and row(w)["state"] == "WAITING_BUDGET"
    child = w.jobs()[-1]
    assert child["bundle"] and child["acceptance"]
    assert len(d.calls) == 1
    controls(w, g, revision=2, maxDailyToolCalls=2)
    assert w.tick()["phase"] == "COMPLETE" and len(d.calls) == 2
    assert sum(p["stage"] == "build" for p in m.calls) == 2


def test_pause_during_control_readback_blocks_next_provider(environment, monkeypatch):
    w, g, e, d, s, m, clock = environment
    seed(w)
    controls(w, g)
    request(w, g)
    old = g.read

    def read(collection, document="current"):
        value = old(collection, document)
        if collection == "cct_owner_build_controls_status":
            g.workspace["learningEnabled"] = False
        return value

    monkeypatch.setattr(g, "read", read)
    before = len(m.calls)
    assert w.tick()["phase"] == "PAUSED" and len(m.calls) == before


def test_readback_failure_holds_budget_effects(environment, monkeypatch):
    w, g, e, d, s, m, clock = environment
    seed(w)
    original = g.publish

    def publish(collection, document, value):
        if collection == "cct_owner_build_controls_status":
            return
        original(collection, document, value)

    monkeypatch.setattr(g, "publish", publish)
    clock[0] += 1
    before = len(m.calls)
    assert w.tick()["phase"] == "ERROR" and len(m.calls) == before


def test_request_cursor_walks_more_than_one_page_and_low_id_arrivals(environment):
    w, g, e, d, s, m, clock = environment
    seed(w)
    controls(w, g, maxDailyJobs=1)
    for i in range(105):
        request(w, g, "archive", name=f"req-{i:04d}")
    w.builds.ingest()
    assert w.db.execute("SELECT count(*) FROM build_requests").fetchone()[0] == 100
    w.builds.ingest()
    assert w.db.execute("SELECT count(*) FROM build_requests").fetchone()[0] == 105
    request(w, g, "restore", name="aaa-late")
    w.builds.ingest()
    w.builds.ingest()
    assert row(w, "aaa-late")["state"] == "QUEUED"


def test_restart_preserves_controls_requests_and_originals(environment):
    w, g, e, d, s, m, clock = environment
    original = seed(w)
    controls(w, g, maxDailyJobs=1)
    request(w, g)
    w.tick()
    second = OwnerDelivery(
        w.home, gateway=g, evidence=e, driver=d, services=s, model=m, clock=w.clock
    )
    try:
        assert second.builds.effective() == w.builds.effective()
        assert second.tick()["phase"] == "DAILY_CAP" and len(second.jobs()) == 1
        controls(second, g, revision=2, maxDailyJobs=2)
        assert second.tick()["phase"] == "COMPLETE"
        assert second.jobs()[0]["bundle"] == original["bundle"]
    finally:
        second.close()


def test_real_bubblewrap_upgrade_end_to_end(environment):
    w, g, e, d, s, m, clock = environment
    w.driver = LocalDeliveryDriver(w.directory / "real-sandbox")
    original = seed(w)
    controls(w, g)
    request(w, g, "steer")
    result = w.tick()
    assert result["phase"] == "COMPLETE", result
    child = w.jobs()[-1]
    assert child["execution"]["verification"]["independentBehavior"] is True
    assert len(child["execution"]["verification"]["acceptanceEvidence"]) == 2
    assert row(w)["state"] == "COMPLETE"
    assert w.jobs()[0]["bundle"] == original["bundle"]
