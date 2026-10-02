"""Exact Hermes Codex adapter with a real SDK and inert HTTP transport."""

import pytest


def test_codex_keeps_responses_route_and_sends_only_one_failed_http_request(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    auxiliary = pytest.importorskip(
        "agent.auxiliary_client", reason="requires the optional Hermes host integration"
    )
    CodexAuxiliaryClient = auxiliary.CodexAuxiliaryClient
    httpx = pytest.importorskip("httpx", reason="requires the optional HTTP SDK")
    OpenAI = pytest.importorskip(
        "openai", reason="requires the optional OpenAI SDK"
    ).OpenAI
    from cct_agent.owner_delivery_model import _without_transport_retries

    requests = []

    def fail(request):
        requests.append(request)
        raise httpx.ConnectError("inert fixture connection failure", request=request)

    client = OpenAI(
        api_key="fixture-not-a-secret",
        base_url="https://example.invalid/backend-api/codex",
        max_retries=2,
        http_client=httpx.Client(transport=httpx.MockTransport(fail)),
    )
    wrapper = _without_transport_retries(CodexAuxiliaryClient(client, "fixture-model"))
    assert type(wrapper) is CodexAuxiliaryClient
    assert wrapper._real_client.max_retries == 0
    with pytest.raises(Exception):
        wrapper.chat.completions.create(
            model="fixture-model",
            messages=[{"role": "user", "content": "inert fixture"}],
            tools=[],
            timeout=2,
        )
    assert len(requests) == 1
    assert requests[0].url.path.endswith("/responses")
    wrapper.close()
