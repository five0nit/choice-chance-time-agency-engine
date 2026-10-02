# Live owner discovery interview

If the owner changes workspace revision while a question is unanswered, the old turn remains in the journal and a new turn uses current preferences. This does not re-send the old message or count an unanswered question as an answer. Ambiguous delivery on the current revision still stops; it is never silently treated as delivered.

`cct-owner-dialogue` is a tool-free adaptive producer for the existing owner connection. It does not run project audits, test suites, CCT executor tasks, or another profile's proposal worker.

## Flow

1. Read fresh, owner-validated `cct_workspace/current` preferences.
2. Check the profile's dialogue enablement, owner-messaging gate, dashboard `learningEnabled`, and `externalMessages` permission.
3. Invoke that profile's configured Hermes provider/model with an empty tool list. Ask one useful question, or offer ranked concrete proposal drafts.
4. Persist the exact generated text and deterministic outbox ID before enqueueing. The existing connection sends Telegram and publishes the authenticated dashboard question.
5. Wait for the actual owner reply recorded by the connection. A stable predecessor ID prevents consuming the same reply twice.
6. Repeat adaptively. After six answers, require proposals with explicit assumptions rather than continuing a questionnaire.
7. Delivered proposals enter `AWAITING_APPROVAL`. Nothing executes. Choosing/approving work is a separate operator handoff, not an automatic grant from free-text answers or seed-card decisions.

## Focused verification

The model adapter runs under the owning Hermes environment, which supplies PyYAML. A separate QA environment needs that dependency for the adapter tests:

```sh
uv pip install --python /path/to/qa/bin/python PyYAML==6.0.3
/path/to/qa/bin/python -m pytest -o addopts= -q tests/test_owner_dialogue.py tests/test_owner_messaging.py
```

Fixtures use temporary profiles and mocked model/Firebase/Telegram boundaries. They never submit an answer to the live interview; passing tests do not establish a genuine owner-answer round trip.

## Profile installation

Install the current CCT wheel with its `firebase` extra into an isolated release environment. The existing owner connection can stay on its unchanged release; both processes use the same profile-local outbox. Do not run a second delivery daemon.

Create `$HERMES_HOME/config/cct-owner-dialogue.json`:

```json
{
  "enabled": true,
  "conversationId": "owner-discovery-v1",
  "modelPython": "/absolute/path/to/hermes-agent/venv/bin/python"
}
```

The model subprocess uses installed Hermes `agent.auxiliary_client.call_llm`, the same profile's `config.yaml` and configured authentication. The CCT release need not install Hermes or duplicate its dependencies. Ensure Hermes source is importable by that interpreter (for source installs, set `PYTHONPATH` to the Hermes source root). Do not put secrets in this JSON, prompts, command arguments or logs.

Run `cct-owner-dialogue run` under a profile-owned systemd service. This producer holds `owner-connection/dialogue.lock`; it never takes ownership of the separate transport daemon. `once` performs one real production turn; it is not a synthetic-answer test. `status` reads the latest persisted state without calling the model.

## Controls and limits

- Dashboard learning toggle pauses/resumes generation. Owner-message permission independently gates delivery. The separate diagnostic executor controls are NOT conversation controls; leave them OFF for this workflow.
- Poll every 15 seconds, but call the model only when starting or after an unanswered predecessor becomes `ANSWERED`.
- One outstanding interview question. Existing outbox limits remain ten daily attempted messages, five total open questions, and 24-hour question expiry.
- Three model attempts per predecessor; ten per rolling day. Failure backs off five minutes. No repeated calls while waiting for Mike.
- Fresh workspace check after generation discards stale output. Ambiguous or denied delivery stops the interview visibly in local status; no blind resend.
- `owner-connection/dialogue.sqlite` stores turns, attempts and status; `messages.sqlite` remains authoritative for sent messages and authenticated answers.
- Change conversation ID and restart only the dialogue producer for an explicitly requested new interview. Do not reset state or invent owner replies just to show a green run.

## Verification boundary

A live first question plus Telegram acknowledgement and exact Firestore readback proves generation/delivery only. Full adaptive answer-to-follow-up and proposal completion remain unverified until Mike provides actual answers. Do not claim an end-to-end conversation from emulator fixtures, admin-written answers, or a model-generated fake owner.
