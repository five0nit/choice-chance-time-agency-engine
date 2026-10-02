"""Deterministic repeated-stall detection and proposal-only exploration requests."""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Iterable, Mapping

from .kernel import NO_OP_ID
from .models import Option
from .store import EventStore, canonical_json
from .workspace import WorkspaceItem


class StallDetector:
    """Detect repeated blocked/no-op states without creating action authority."""

    def __init__(self, store: EventStore, *, repeat_threshold: int = 2) -> None:
        if not 2 <= repeat_threshold <= 20:
            raise ValueError("stall repeat_threshold must be between 2 and 20")
        self.store = store
        self.repeat_threshold = repeat_threshold

    @staticmethod
    def _digest(value: object) -> str:
        return sha256(canonical_json(value).encode("utf-8")).hexdigest()

    def observe(
        self,
        *,
        goal_id: str | None,
        decision: Mapping[str, Any] | None,
        options: Iterable[Option],
        candidates: Iterable[WorkspaceItem],
        logical_tick: int,
    ) -> dict[str, Any]:
        if goal_id is None or decision is None:
            return {
                "observed": False,
                "detected": False,
                "exploration_requested": False,
                "external_effects": 0,
            }
        option_rows = list(options)
        candidate_rows = list(candidates)
        non_noop = [option for option in option_rows if option.id != NO_OP_ID]
        blocked = [option for option in non_noop if not option.allowed]
        conflicts = [
            item for item in candidate_rows if item.unresolved_conflict >= 0.5
        ]
        signals: list[str] = []
        if decision.get("chosen_option_id") == NO_OP_ID:
            signals.append("NO_OP")
        if non_noop and len(blocked) == len(non_noop):
            signals.append("BLOCKED_FRONTIER")
        if conflicts:
            signals.append("UNRESOLVED_CONFLICT")
        if not signals:
            return {
                "observed": False,
                "detected": False,
                "exploration_requested": False,
                "external_effects": 0,
            }

        option_state = [
            {
                "option_id_sha256": self._digest(option.id),
                "allowed": option.allowed,
                "blocked_reasons_sha256": self._digest(
                    sorted(str(reason) for reason in option.blocked_reasons)
                ),
            }
            for option in sorted(non_noop, key=lambda row: row.id)
        ]
        evidence_digests = sorted(
            item.content_digest for item in candidate_rows if item.content_digest
        )
        conflict_digests = sorted(
            item.content_digest for item in conflicts if item.content_digest
        )
        material = {
            "goal_id_sha256": self._digest(goal_id),
            "chosen_option_id_sha256": self._digest(
                str(decision.get("chosen_option_id", ""))
            ),
            "signals": signals,
            "option_state": option_state,
            "evidence_digests": evidence_digests,
            "conflict_digests": conflict_digests,
        }
        fingerprint = self._digest(material)
        sample_payload = {
            "schema_version": "cct.stall-sample.v1",
            "logical_tick": int(logical_tick),
            "fingerprint": fingerprint,
            "goal_id_sha256": material["goal_id_sha256"],
            "signals": signals,
            "option_count": len(non_noop),
            "blocked_option_count": len(blocked),
            "conflict_count": len(conflicts),
            "evidence_digest_count": len(evidence_digests),
            "producer_text_persisted": False,
            "raw_chain_of_thought_stored": False,
            "external_effects": 0,
        }
        sample = self.store.append_once(
            "cognition.stall.sampled",
            f"{fingerprint}:{logical_tick}",
            sample_payload,
        )
        samples = [
            event
            for event in self.store.events("cognition.stall.sampled")
            if event.payload.get("fingerprint") == fingerprint
        ]
        repeat_count = len(samples)
        detected = None
        request = None
        if repeat_count >= self.repeat_threshold:
            detected = self.store.append_once(
                "cognition.stall.detected",
                fingerprint,
                {
                    "schema_version": "cct.stall-detected.v1",
                    "fingerprint": fingerprint,
                    "goal_id_sha256": material["goal_id_sha256"],
                    "signals": signals,
                    "repeat_threshold": self.repeat_threshold,
                    "first_sample_event_id": samples[0].event_id,
                    "threshold_sample_event_id": samples[
                        self.repeat_threshold - 1
                    ].event_id,
                    "producer_text_persisted": False,
                    "external_effects": 0,
                },
            )
            request = self.store.append_once(
                "cognition.exploration.requested",
                fingerprint,
                {
                    "schema_version": "cct.exploration-request.v1",
                    "fingerprint": fingerprint,
                    "goal_id_sha256": material["goal_id_sha256"],
                    "stall_event_id": detected.event_id,
                    "proposal_only": True,
                    "required_fields": [
                        "provenance",
                        "assumptions",
                        "uncertainty",
                        "falsifiable_discriminator",
                    ],
                    "effect_authority_granted": False,
                    "permission_changed": False,
                    "producer_text_persisted": False,
                    "raw_chain_of_thought_stored": False,
                    "external_effects": 0,
                },
            )
        return {
            "observed": True,
            "fingerprint": fingerprint,
            "repeat_count": repeat_count,
            "repeat_threshold": self.repeat_threshold,
            "sample_event_id": sample.event_id,
            "detected": detected is not None,
            "stall_event_id": detected.event_id if detected else None,
            "exploration_requested": request is not None,
            "exploration_request_event_id": request.event_id if request else None,
            "effect_authority_granted": False,
            "external_effects": 0,
        }

    def status(self) -> dict[str, Any]:
        samples = self.store.events("cognition.stall.sampled")
        detected = self.store.events("cognition.stall.detected")
        requests = self.store.events("cognition.exploration.requested")
        return {
            "samples": len(samples),
            "unique_fingerprints": len(
                {str(event.payload["fingerprint"]) for event in samples}
            ),
            "detected": len(detected),
            "exploration_requests": len(requests),
            "proposal_only": all(
                event.payload.get("proposal_only") is True for event in requests
            ),
            "effect_authority_granted": False,
            "external_effects": 0,
        }
