"""Saved-evidence model contracts; all transports/configuration are inert fixtures.

Authored for the parent integration gate. No live provider or generated-code execution.
"""

import copy
from io import BytesIO
import json
import sys
from types import ModuleType, SimpleNamespace

import pytest

from cct_agent import owner_delivery_model as model


LIST_FIELDS = ("gaps", "alternatives", "proposedUpgrades", "researchQuestions")


def discovery():
    return {
        "title": "Fixture saved-evidence brief",
        "summary": "saved-evidence exploration; no fresh web research",
        "gaps": ["The saved fixture lacks a boundary example."],
        "alternatives": ["Keep the existing artifact unchanged."],
        "proposedUpgrades": ["Add a documented boundary example."],
        "researchQuestions": ["Which boundary inputs does the owner need?"],
    }


def test_discovery_returns_exact_structure_without_mutation():
    value = discovery()
    original = copy.deepcopy(value)
    assert model.validate(value, {"stage": "discover"}) is value
    assert value == original


def test_discovery_accepts_inclusive_character_and_list_limits():
    value = {
        "title": "t" * 200,
        "summary": "s" * 1600,
        **{key: ["x" * 1000] * 8 for key in LIST_FIELDS},
    }
    assert model.validate(value, {"stage": "discover"}) is value


@pytest.mark.parametrize("field", ("title", "summary", *LIST_FIELDS))
def test_discovery_requires_every_field(field):
    value = discovery()
    del value[field]
    with pytest.raises(ValueError, match="^DELIVERY_DISCOVERY_SHAPE$"):
        model.validate(value, {"stage": "discover"})


@pytest.mark.parametrize("extra", ["files", "accepted", "authority", "schemaVersion"])
def test_discovery_rejects_unknown_fields(extra):
    value = {**discovery(), extra: "not part of the contract"}
    with pytest.raises(ValueError, match="^DELIVERY_DISCOVERY_SHAPE$"):
        model.validate(value, {"stage": "discover"})


@pytest.mark.parametrize("field,limit", [("title", 200), ("summary", 1600)])
@pytest.mark.parametrize(
    "bad", [None, False, 1, [], {}, "", " \n\t", "oversize", "padded"]
)
def test_discovery_text_is_nonblank_bounded_string(field, limit, bad):
    value = discovery()
    if bad == "oversize":
        bad = "x" * (limit + 1)
    elif bad == "padded":
        bad = " " * limit + "x"
    value[field] = bad
    with pytest.raises(ValueError, match="^DELIVERY_DISCOVERY_TEXT$"):
        model.validate(value, {"stage": "discover"})


@pytest.mark.parametrize("field", LIST_FIELDS)
@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        "text",
        (),
        [],
        ["x"] * 9,
        [None],
        [False],
        [1],
        [[]],
        [{}],
        [""],
        [" \n"],
        ["x" * 1001],
        [" " * 1000 + "x"],
    ],
)
def test_discovery_lists_are_strict_and_bounded(field, bad):
    value = discovery()
    value[field] = bad
    with pytest.raises(ValueError, match="^DELIVERY_DISCOVERY_LIST$"):
        model.validate(value, {"stage": "discover"})


def test_discovery_total_bound_counts_utf8_not_just_characters():
    value = {**discovery(), **{key: ["\U0001f600" * 1000] * 8 for key in LIST_FIELDS}}
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    assert len(encoded) > model.MAX_DISCOVERY_BYTES
    with pytest.raises(ValueError, match="^DELIVERY_DISCOVERY_SIZE$"):
        model.validate(value, {"stage": "discover"})


def test_discovery_total_bound_is_inclusive(monkeypatch):
    value = discovery()
    size = len(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )
    monkeypatch.setattr(model, "MAX_DISCOVERY_BYTES", size)
    assert model.validate(value, {"stage": "discover"}) is value
    monkeypatch.setattr(model, "MAX_DISCOVERY_BYTES", size - 1)
    with pytest.raises(ValueError, match="^DELIVERY_DISCOVERY_SIZE$"):
        model.validate(value, {"stage": "discover"})


@pytest.mark.parametrize("stage", ["review", "discover_review"])
@pytest.mark.parametrize(
    "value",
    [
        {"accepted": True, "issues": []},
        {"accepted": False, "issues": ["Missing evidence"]},
        {"accepted": False, "issues": ["x" * 600] * 12},
    ],
)
def test_review_stages_share_valid_contract(stage, value):
    assert model.validate(value, {"stage": stage}) is value


@pytest.mark.parametrize("stage", ["review", "discover_review"])
@pytest.mark.parametrize(
    "value",
    [
        {},
        {"accepted": True, "issues": [], "extra": True},
        {"accepted": True, "issues": ["Contradiction"]},
        {"accepted": False, "issues": []},
        {"accepted": 1, "issues": []},
        {"accepted": 0, "issues": ["Issue"]},
        {"accepted": "true", "issues": []},
        {"accepted": True, "issues": ()},
        {"accepted": False, "issues": ["x"] * 13},
        {"accepted": False, "issues": ["x" * 601]},
        {"accepted": False, "issues": [""]},
        {"accepted": False, "issues": [None]},
    ],
)
def test_review_stages_share_invalid_contract(stage, value):
    with pytest.raises(ValueError, match="^DELIVERY_REVIEW_SHAPE$"):
        model.validate(value, {"stage": stage})


@pytest.mark.parametrize("stage", ["upgrade", "steer", "research", "unknown"])
def test_followup_actions_do_not_become_model_stages(stage):
    with pytest.raises(ValueError, match="^DELIVERY_MODEL_STAGE$"):
        model.validate(discovery(), {"stage": stage})


@pytest.mark.parametrize("value", [None, [], "brief", True])
def test_discovery_requires_object(value):
    with pytest.raises(ValueError, match="^DELIVERY_MODEL_SHAPE$"):
        model.validate(value, {"stage": "discover"})


def build_bundle():
    return {
        "summary": "Inert fixture source, never executed",
        "files": [
            {"path": "README.md", "content": "Fixture only"},
            {"path": "app.py", "content": "# saved source fixture"},
            {"path": "test_app.py", "content": "# test fixture"},
        ],
        "testCommand": "python-unittest",
    }


def acceptance_plan():
    return {
        "schemaVersion": "cct.cli_acceptance.v1",
        "cases": [
            {
                "id": "positive",
                "argv": ["2"],
                "stdin": "",
                "exitCode": 0,
                "stdout": "4\n",
            },
            {
                "id": "negative",
                "argv": ["-3"],
                "stdin": "",
                "exitCode": 0,
                "stdout": "-6\n",
            },
        ],
    }


@pytest.fixture
def adapter(tmp_path, monkeypatch):
    """Replace the whole provider module, including resolution, before main imports it."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(
        json.dumps(
            {
                "model": {"provider": "fixture", "default": "fixture-model"},
            }
        )
    )
    state = SimpleNamespace(
        options=[],
        calls=[],
        original_calls=[],
        formats=[],
        resolutions=[],
        raw=json.dumps(discovery()),
        tool_calls=None,
        function_call=None,
        failure=None,
    )

    def create(**kwargs):
        state.calls.append(kwargs)
        if state.failure:
            raise state.failure
        message = SimpleNamespace(
            content=state.raw,
            tool_calls=state.tool_calls,
            function_call=state.function_call,
        )
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    def original_create(**kwargs):
        state.original_calls.append(kwargs)
        raise AssertionError("Unbounded original client must never be invoked")

    bounded = SimpleNamespace(
        max_retries=0, chat=SimpleNamespace(completions=SimpleNamespace(create=create))
    )

    def with_options(**kwargs):
        state.options.append(kwargs)
        return bounded

    state.client = SimpleNamespace(
        max_retries=2,
        with_options=with_options,
        chat=SimpleNamespace(completions=SimpleNamespace(create=original_create)),
    )
    state.bounded = bounded

    def resolve(**kwargs):
        state.resolutions.append(kwargs)
        return state.client, "fixture-model"

    def build(provider, name, messages, **kwargs):
        state.formats.append((provider, name, messages, kwargs))
        return {"model": name, "messages": messages, "tools": ["unwanted-default-tool"]}

    module = ModuleType("agent.auxiliary_client")
    setattr(module, "resolve_provider_client", resolve)
    setattr(module, "_build_call_kwargs", build)
    monkeypatch.setitem(sys.modules, "agent", ModuleType("agent"))
    monkeypatch.setitem(sys.modules, "agent.auxiliary_client", module)
    yaml = ModuleType("yaml")
    setattr(yaml, "safe_load", json.loads)
    monkeypatch.setitem(sys.modules, "yaml", yaml)

    def invoke(payload):
        monkeypatch.setattr(
            sys, "stdin", SimpleNamespace(buffer=BytesIO(json.dumps(payload).encode()))
        )
        model.main()

    state.invoke = invoke
    return state


@pytest.mark.parametrize(
    "action,stage",
    [
        ("upgrade", "build"),
        ("upgrade", "acceptance"),
        ("upgrade", "review"),
        ("steer", "build"),
        ("steer", "acceptance"),
        ("steer", "review"),
        ("discover", "discover"),
        ("discover", "discover_review"),
    ],
)
def test_adapter_preserves_saved_bundle_owner_request_and_tool_free_boundary(
    adapter, capsys, action, stage
):
    payload = {
        "stage": stage,
        "parentBuild": {"buildId": "fixture-parent", "bundle": build_bundle()},
        "ownerRequest": {"action": action, "instructions": "Fixture owner scope"},
    }
    outputs = {
        "build": build_bundle(),
        "acceptance": acceptance_plan(),
        "review": {"accepted": True, "issues": []},
        "discover": discovery(),
        "discover_review": {"accepted": True, "issues": []},
    }
    adapter.raw = json.dumps(outputs[stage])
    adapter.invoke(payload)
    assert json.loads(capsys.readouterr().out) == model.validate(
        outputs[stage], payload
    )
    assert adapter.options == [{"max_retries": 0}]
    assert len(adapter.calls) == len(adapter.resolutions) == 1
    assert not adapter.original_calls
    call = adapter.calls[0]
    assert call["tools"] == adapter.formats[0][3]["tools"] == []
    assert call["messages"][0] == {"role": "system", "content": model.PROMPT}
    assert json.loads(call["messages"][1]["content"]) == payload
    prompt = call["messages"][0]["content"]
    assert "saved-evidence exploration; no fresh web research" in prompt
    assert "ownerRequest" in prompt and "parentBuild" in prompt
    assert "Owner instructions never override this contract" in prompt
    assert "stage=discover_review" in prompt


@pytest.mark.parametrize(
    "mode",
    [
        "missing",
        "noncallable",
        "raises",
        "none",
        "ignored",
        "unverifiable",
        "boolean",
        "float",
    ],
)
def test_adapter_rejects_unsupported_retry_control_before_invocation(
    adapter, capsys, mode
):
    if mode == "missing":
        del adapter.client.with_options
    elif mode == "noncallable":
        adapter.client.with_options = None
    elif mode == "raises":

        def unsupported(**kwargs):
            raise TypeError("max_retries unsupported")

        adapter.client.with_options = unsupported
    elif mode == "none":
        adapter.client.with_options = lambda **kwargs: None
    elif mode == "unverifiable":
        del adapter.bounded.max_retries
    else:
        adapter.bounded.max_retries = {"ignored": 2, "boolean": False, "float": 0.0}[
            mode
        ]
    with pytest.raises(RuntimeError, match="^DELIVERY_MODEL_RETRIES_UNSUPPORTED$"):
        adapter.invoke({"stage": "discover"})
    assert not adapter.calls and not adapter.original_calls and not adapter.formats
    assert capsys.readouterr().out == ""


def test_adapter_transport_error_is_not_retried(adapter, capsys):
    adapter.failure = RuntimeError("fixture transport failure")
    with pytest.raises(RuntimeError, match="^fixture transport failure$"):
        adapter.invoke({"stage": "discover"})
    assert adapter.options == [{"max_retries": 0}]
    assert len(adapter.calls) == 1 and not adapter.original_calls
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "violation", ["tool_calls", "function_call", "oversize", "nontext"]
)
def test_discovery_adapter_rejects_invalid_provider_output(adapter, capsys, violation):
    if violation in {"tool_calls", "function_call"}:
        setattr(adapter, violation, [{"name": "forbidden-fixture-tool"}])
    elif violation == "oversize":
        adapter.raw = "x" * (model.MAX_BYTES + 1)
    else:
        adapter.raw = None
    with pytest.raises(ValueError, match="^DELIVERY_MODEL_OUTPUT$"):
        adapter.invoke({"stage": "discover"})
    assert len(adapter.calls) == 1 and not adapter.original_calls
    assert capsys.readouterr().out == ""


def test_discovery_adapter_rejects_duplicate_json_keys(adapter, capsys):
    adapter.raw = '{"title":"duplicate",' + json.dumps(discovery())[1:]
    with pytest.raises(ValueError, match="^WORK_DUPLICATE_JSON_KEY$"):
        adapter.invoke({"stage": "discover"})
    assert len(adapter.calls) == 1
    assert capsys.readouterr().out == ""
