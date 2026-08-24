"""One-shot proactive cognition runner suitable for a silent scheduler."""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from .initiative import InitiativeBridge, ProactiveFeedback
from .opportunity_initiative import OpportunityInitiative
from .proactive import InitiationSignals, ProactiveEngine, ThoughtPacket
from .pursuit_dialogue import PursuitDialogue
from .store import EventStore, canonical_json
from .topics import Topic, TopicStore


_TRUSTED_PROACTIVE_TOPIC_SOURCE_PREFIXES = (
    "auto:workspace:",
    "host_adapter:",
    "self:",
)


def _topic_proactive_eligible(topic: Topic) -> bool:
    return topic.source.startswith(_TRUSTED_PROACTIVE_TOPIC_SOURCE_PREFIXES)


class ProactiveRunner:
    """Turns changed topics into at most one emission attempt per wake."""

    def __init__(self, store: EventStore) -> None:
        self.store = store
        self.topics = TopicStore(store)
        self.engine = ProactiveEngine(store)
        self.pursuits = PursuitDialogue(store)
        self.opportunities = OpportunityInitiative(store, proactive=self.engine)
        self.bridge = InitiativeBridge(store)

    def _processed_revisions(self) -> dict[str, int]:
        revisions: dict[str, int] = {}
        for event in self.store.events("proactive.runner.completed"):
            revisions[str(event.payload["topic_id"])] = int(
                event.payload["topic_revision"]
            )
        return revisions

    def _next_topic(self) -> Topic | None:
        processed = self._processed_revisions()
        candidates = [
            topic
            for topic in self.topics.all(status="open")
            if processed.get(topic.id, 0) < topic.revision
        ]
        if not candidates:
            return None
        return max(
            candidates,
            key=lambda topic: (
                topic.urgency
                + topic.novelty
                + topic.goal_relevance
                + topic.unresolved_conflict,
                topic.logical_tick,
                topic.id,
            ),
        )

    @staticmethod
    def _deterministic_packet(topic: Topic) -> ThoughtPacket:
        semantic = {
            "topic_id": topic.id,
            "revision": topic.revision,
            "summary": topic.summary,
            "questions": list(topic.questions),
            "hypotheses": list(topic.hypotheses),
        }
        identifier = "packet_topic_" + sha256(
            canonical_json(semantic).encode("utf-8")
        ).hexdigest()[:20]
        hypothesis = topic.hypotheses[:1] or (
            "Progress requires one bounded falsifiable next step.",
        )
        question = topic.questions[:1] or (
            "Which observation would most change the current conclusion?",
        )
        return ThoughtPacket(
            id=identifier,
            topic_id=topic.id,
            observation=topic.summary,
            hypotheses=hypothesis,
            open_questions=question,
            evidence=(f"topic:{topic.id}:revision:{topic.revision}",),
            uncertainty=max(0.05, min(0.95, 1.0 - topic.goal_relevance * 0.7)),
            recommended_action="SHARE",
            rationale_summary=(
                "The topic changed and exceeds the bounded initiation relevance gate."
            ),
            source="self:deterministic-proactive-runner",
            created_tick=topic.logical_tick,
        )

    def run_once(
        self,
        *,
        time_bucket: str,
    ) -> dict[str, Any]:
        promotion = self.bridge.promote()
        wake_index = self.store.allocate_counter("proactive_wake")
        pursuit = self.pursuits.run_once(
            wake_index=wake_index,
            time_bucket=time_bucket,
        )
        if pursuit.get("candidate_found"):
            return {
                **pursuit,
                "initiative_kind": "pursuit_dialogue",
                "llm_calls": 0,
                "promotion": promotion,
            }
        opportunity = self.opportunities.run_once(
            wake_index=wake_index,
            time_bucket=time_bucket,
        )
        if opportunity.get("candidate_found"):
            return {
                **opportunity,
                "initiative_kind": "opportunity",
                "llm_calls": 0,
                "promotion": promotion,
            }
        open_topics = self.topics.all(status="open")
        if not open_topics:
            return {
                "message": "",
                "reason": (
                    str(opportunity["reason"])
                    if opportunity.get("reason") == "OPPORTUNITY_SNOOZED"
                    else "NO_OPEN_TOPIC"
                ),
                "wake_index": wake_index,
                "llm_calls": 0,
                "initiative_kind": (
                    "opportunity"
                    if opportunity.get("reason") == "OPPORTUNITY_SNOOZED"
                    else "topic"
                ),
                "scout": opportunity.get("scout"),
                "promotion": promotion,
            }
        topic = self._next_topic()
        if topic is None:
            return {
                "message": "",
                "reason": "NO_NEW_STATE",
                "wake_index": wake_index,
                "llm_calls": 0,
                "scout": opportunity.get("scout"),
                "promotion": promotion,
            }

        if not _topic_proactive_eligible(topic):
            self.store.append_once_result_guarded(
                "proactive.runner.completed",
                f"{topic.id}:{topic.revision}",
                {
                    "topic_id": topic.id,
                    "topic_revision": topic.revision,
                    "packet_id": None,
                    "decision": "WAIT",
                    "reason_codes": ["UNTRUSTED_TOPIC_QUARANTINED"],
                    "emitted": False,
                    "wake_index": wake_index,
                    "time_bucket": time_bucket,
                    "llm_calls": 0,
                    "external_effects": 0,
                    "semantic_taint": True,
                    "producer_text_propagated": False,
                    "raw_chain_of_thought_stored": False,
                },
                strict_existing_payload=False,
            )
            return {
                "message": "",
                "reason": "UNTRUSTED_TOPIC_QUARANTINED",
                "reason_codes": ["UNTRUSTED_TOPIC_QUARANTINED"],
                "wake_index": wake_index,
                "llm_calls": 0,
                "topic_id": topic.id,
                "topic_revision": topic.revision,
                "state_consumed": True,
                "external_effects": 0,
                "promotion": promotion,
            }

        temporary = self.engine.temporary_suppression(
            wake_index=wake_index, time_bucket=time_bucket
        )
        if temporary:
            return {
                "message": "",
                "reason": temporary[0],
                "reason_codes": temporary,
                "wake_index": wake_index,
                "llm_calls": 0,
                "topic_id": topic.id,
                "topic_revision": topic.revision,
                "state_consumed": False,
                "promotion": promotion,
            }

        llm_calls = 0
        packet = self._deterministic_packet(topic)

        signals = InitiationSignals(
            urgency=topic.urgency,
            novelty=topic.novelty,
            goal_relevance=topic.goal_relevance,
            unresolved_conflict=topic.unresolved_conflict,
            interruption_cost=0.1,
        )
        decision = self.engine.submit(
            packet,
            signals=signals,
            wake_index=wake_index,
            time_bucket=time_bucket,
        )
        message = ""
        emitted = False
        emission_reason = ""
        if decision["decision"] == "SEND":
            emission = self.engine.emit(
                str(decision["proposal_event_id"]),
                wake_index=wake_index,
                time_bucket=time_bucket,
            )
            message = str(emission["message"])
            emitted = bool(emission["emitted"])
            emission_reason = str(emission["reason"])
            if bool(emission.get("retryable")):
                return {
                    "message": "",
                    "reason": emission_reason,
                    "reason_codes": [emission_reason],
                    "wake_index": wake_index,
                    "llm_calls": llm_calls,
                    "topic_id": topic.id,
                    "topic_revision": topic.revision,
                    "state_consumed": False,
                    "promotion": promotion,
                }

        completion_reasons = list(decision["reason_codes"])
        if not emitted and emission_reason:
            completion_reasons.append(emission_reason)

        self.store.append_once_result_guarded(
            "proactive.runner.completed",
            f"{topic.id}:{topic.revision}",
            {
                "topic_id": topic.id,
                "topic_revision": topic.revision,
                "packet_id": packet.id,
                "decision": decision["decision"],
                "reason_codes": completion_reasons,
                "emitted": emitted,
                "wake_index": wake_index,
                "time_bucket": time_bucket,
                "llm_calls": llm_calls,
                "external_effects": 0,
                "raw_chain_of_thought_stored": False,
            },
            strict_existing_payload=False,
        )
        return {
            "message": message,
            "reason": "EMITTED" if emitted else emission_reason or str(decision["decision"]),
            "decision": decision,
            "packet": packet.as_payload(),
            "wake_index": wake_index,
            "llm_calls": llm_calls,
            "promotion": promotion,
        }

    def status(self) -> dict[str, Any]:
        def topic_projection(topic: Topic) -> dict[str, Any]:
            return {
                "id_sha256": sha256(topic.id.encode("utf-8")).hexdigest(),
                "title_sha256": sha256(topic.title.encode("utf-8")).hexdigest(),
                "summary_sha256": sha256(topic.summary.encode("utf-8")).hexdigest(),
                "source_sha256": sha256(topic.source.encode("utf-8")).hexdigest(),
                "questions_sha256": sha256(
                    canonical_json(list(topic.questions)).encode("utf-8")
                ).hexdigest(),
                "hypotheses_sha256": sha256(
                    canonical_json(list(topic.hypotheses)).encode("utf-8")
                ).hexdigest(),
                "commitments_sha256": sha256(
                    canonical_json(list(topic.commitments)).encode("utf-8")
                ).hexdigest(),
                "question_count": len(topic.questions),
                "hypothesis_count": len(topic.hypotheses),
                "commitment_count": len(topic.commitments),
                "urgency": topic.urgency,
                "novelty": topic.novelty,
                "goal_relevance": topic.goal_relevance,
                "unresolved_conflict": topic.unresolved_conflict,
                "logical_tick": topic.logical_tick,
                "revision": topic.revision,
                "status": topic.status,
                "proactive_eligible": _topic_proactive_eligible(topic),
                "content_in_status": False,
                "identifier_cleartext_in_status": False,
            }

        return {
            "open_topics": [
                topic_projection(topic) for topic in self.topics.all(status="open")
            ],
            "closed_topics": [
                topic_projection(topic) for topic in self.topics.all(status="closed")
            ],
            "runner_completions": len(
                self.store.events("proactive.runner.completed")
            ),
            "engine": self.engine.status(),
            "pursuit_dialogue": self.pursuits.status(),
            "opportunity_initiative": self.opportunities.status(),
            "initiative_bridge": self.bridge.status(),
            "feedback": ProactiveFeedback(self.store).status(),
            "raw_chain_of_thought_stored": False,
        }

    def context(self, *, max_chars: int = 3000) -> str:
        topics = [
            topic
            for topic in self.topics.all(status="open")
            if _topic_proactive_eligible(topic)
        ][-3:]
        if not topics:
            return ""
        lines = ["Proactive conversation continuity (structured; no hidden reasoning):"]
        for topic in topics:
            lines.append(
                f"- [{topic.id}] {topic.summary} "
                f"(revision={topic.revision}, source={topic.source})"
            )
            if topic.questions:
                lines.append(f"  open question: {topic.questions[0]}")
        rendered = "\n".join(lines)
        return rendered[:max_chars]
