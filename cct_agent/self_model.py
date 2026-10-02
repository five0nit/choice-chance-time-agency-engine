"""Persistent capability and commitment self-model with calibration receipts."""

from __future__ import annotations

from hashlib import sha256
from math import isfinite
from typing import Any, Iterable

from .store import EventStore, canonical_json


class SelfModel:
    COMPETENCE_ONLY_PERMISSION = "competence_estimate_only_no_effect_authority"

    def __init__(self, store: EventStore, *, identity: str) -> None:
        if not identity.strip():
            raise ValueError("self-model identity must not be empty")
        self.store = store
        self.identity = identity

    def _receipt_capabilities(self) -> dict[str, dict[str, Any]]:
        grouped: dict[str, list[Any]] = {}
        for event in self.store.events("autonomy.run.completed"):
            capability = event.payload.get("capability")
            if isinstance(capability, str) and capability.strip():
                grouped.setdefault(capability, []).append(event)
        capabilities: dict[str, dict[str, Any]] = {}
        for name, events in grouped.items():
            verified_successes = 0
            failures = 0
            counted: list[Any] = []
            for event in events:
                payload = event.payload
                if (
                    payload.get("success") is True
                    and payload.get("verified") is True
                    and int(payload.get("receipt_count", 0)) > 0
                ):
                    verified_successes += 1
                    counted.append(event)
                elif payload.get("success") is False:
                    failures += 1
                    counted.append(event)
            samples = verified_successes + failures
            if not samples:
                continue
            success_rate = round(verified_successes / samples, 12)
            confidence = round((verified_successes + 1) / (samples + 2), 12)
            capabilities[name] = {
                "name": name,
                "available": verified_successes > 0 and confidence >= 0.5,
                "confidence": confidence,
                "permission": self.COMPETENCE_ONLY_PERMISSION,
                "evidence": [f"event:{event.event_id}" for event in counted[-32:]],
                "last_test_tick": counted[-1].seq,
                "source": "verified_autonomy_receipt_projection",
                "receipt_projection": {
                    "samples": samples,
                    "verified_successes": verified_successes,
                    "failures": failures,
                    "success_rate": success_rate,
                },
            }
        return capabilities

    def _capabilities(self) -> dict[str, dict[str, Any]]:
        capabilities = self._receipt_capabilities()
        for event in self.store.events():
            if event.kind == "self.capability.updated":
                row = dict(event.payload["capability"])
                name = str(row["name"])
                receipt_projection = capabilities.get(name, {}).get(
                    "receipt_projection"
                )
                derived_evidence = list(
                    capabilities.get(name, {}).get("evidence", [])
                )
                explicit_evidence = list(row.get("evidence", []))
                row["evidence"] = list(
                    dict.fromkeys([*derived_evidence, *explicit_evidence])
                )[-32:]
                row["source"] = "explicit_or_bridged_self_model"
                if receipt_projection is not None:
                    row["receipt_projection"] = receipt_projection
                capabilities[name] = row
            elif event.kind == "self.prediction.resolved":
                payload = event.payload
                name = str(payload["capability"])
                row = dict(
                    capabilities.get(
                        name,
                        {
                            "name": name,
                            "permission": self.COMPETENCE_ONLY_PERMISSION,
                            "evidence": [],
                        },
                    )
                )
                row["available"] = bool(payload["succeeded"])
                row["confidence"] = float(payload["corrected_confidence"])
                row["last_test_tick"] = int(payload["logical_tick"])
                row["evidence"] = list(
                    dict.fromkeys(
                        [
                            *list(row.get("evidence", [])),
                            *[str(item) for item in payload.get("evidence", [])],
                        ]
                    )
                )[-32:]
                row["source"] = "self_prediction_resolution"
                capabilities[name] = row
        return capabilities

    def declare_capability(
        self,
        *,
        name: str,
        available: bool,
        confidence: float,
        permission: str,
        evidence: Iterable[str],
        logical_tick: int,
    ) -> dict[str, Any]:
        if not name.strip() or not permission.strip():
            raise ValueError("capability name and permission must not be empty")
        if not isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError("capability confidence must be between 0 and 1")
        evidence_rows = tuple(str(item) for item in evidence)
        if not evidence_rows:
            raise ValueError("capability requires evidence")
        capability = {
            "name": name,
            "available": bool(available),
            "confidence": round(float(confidence), 12),
            "permission": permission,
            "evidence": list(evidence_rows),
            "last_test_tick": logical_tick,
        }
        event = self.store.append(
            "self.capability.updated",
            {"logical_tick": logical_tick, "capability": capability},
        )
        return {**capability, "event_id": event.event_id}

    def predict(
        self,
        *,
        capability: str,
        predicted_success: float,
        logical_tick: int,
    ) -> dict[str, Any]:
        if capability not in self._capabilities():
            raise KeyError(f"unknown capability: {capability}")
        if not isfinite(predicted_success) or not 0.0 <= predicted_success <= 1.0:
            raise ValueError("predicted_success must be between 0 and 1")
        material = {
            "identity": self.identity,
            "capability": capability,
            "predicted_success": predicted_success,
            "logical_tick": logical_tick,
            "ordinal": len(self.store.events("self.prediction.made")) + 1,
        }
        prediction_id = "pred_" + sha256(
            canonical_json(material).encode("utf-8")
        ).hexdigest()[:20]
        event = self.store.append(
            "self.prediction.made",
            {"prediction_id": prediction_id, **material},
        )
        return {"prediction_id": prediction_id, **material, "event_id": event.event_id}

    def prediction(self, prediction_id: str) -> dict[str, Any] | None:
        event = next(
            (
                row
                for row in self.store.events("self.prediction.made")
                if row.payload.get("prediction_id") == prediction_id
            ),
            None,
        )
        return ({**dict(event.payload), "event_id": event.event_id} if event else None)

    def predict_once(
        self,
        *,
        prediction_id: str,
        capability: str,
        predicted_success: float,
        logical_tick: int,
        evidence: Iterable[str],
        source_run_id: str,
    ) -> dict[str, Any]:
        if not prediction_id.strip() or len(prediction_id) > 160:
            raise ValueError("prediction_id must contain 1..160 characters")
        capabilities = self._capabilities()
        if capability not in capabilities:
            raise KeyError(f"unknown capability: {capability}")
        if not isfinite(predicted_success) or not 0.0 <= predicted_success <= 1.0:
            raise ValueError("predicted_success must be between 0 and 1")
        evidence_rows = tuple(str(item) for item in evidence)
        if not evidence_rows:
            raise ValueError("self prediction requires evidence")
        payload = {
            "prediction_id": prediction_id,
            "identity": self.identity,
            "capability": capability,
            "predicted_success": round(float(predicted_success), 12),
            "prior_confidence": round(
                float(capabilities[capability]["confidence"]), 12
            ),
            "logical_tick": int(logical_tick),
            "evidence": list(evidence_rows),
            "source_run_id": source_run_id,
            "effect_authority_granted": False,
        }
        event, created = self.store.append_once_result(
            "self.prediction.made", prediction_id, payload
        )
        return {**payload, "event_id": event.event_id, "created": created}

    def record_result_once(
        self,
        *,
        prediction_id: str,
        succeeded: bool,
        evidence: Iterable[str],
        logical_tick: int,
        source_run_id: str,
    ) -> dict[str, Any]:
        evidence_rows = tuple(str(item) for item in evidence)
        if not evidence_rows:
            raise ValueError("self prediction result requires evidence")
        existing = next(
            (
                row
                for row in self.store.events("self.prediction.resolved")
                if row.payload.get("prediction_id") == prediction_id
            ),
            None,
        )
        if existing is not None:
            if (
                existing.payload.get("succeeded") is not bool(succeeded)
                or existing.payload.get("source_run_id") != source_run_id
                or existing.payload.get("logical_tick") != int(logical_tick)
                or existing.payload.get("evidence") != list(evidence_rows)
            ):
                raise ValueError(
                    "self prediction resolution conflicts with existing receipt"
                )
            return {
                **dict(existing.payload),
                "event_id": existing.event_id,
                "created": False,
            }
        prediction = self.prediction(prediction_id)
        if prediction is None:
            raise KeyError(f"unknown self prediction: {prediction_id}")
        capability_name = str(prediction["capability"])
        predicted = float(prediction["predicted_success"])
        actual = 1.0 if succeeded else 0.0
        brier_error = round((predicted - actual) ** 2, 12)
        prior_confidence = float(
            prediction.get(
                "prior_confidence",
                self._capabilities()[capability_name]["confidence"],
            )
        )
        corrected_confidence = (
            prior_confidence + 0.25 * (1.0 - prior_confidence)
            if succeeded
            else prior_confidence * 0.5
        )
        payload = {
            "logical_tick": int(logical_tick),
            "prediction_id": prediction_id,
            "capability": capability_name,
            "predicted_success": predicted,
            "succeeded": bool(succeeded),
            "brier_error": brier_error,
            "previous_confidence": prior_confidence,
            "corrected_confidence": round(corrected_confidence, 12),
            "evidence": list(evidence_rows),
            "source_run_id": source_run_id,
            "permission_changed": False,
            "effect_authority_granted": False,
        }
        event, created = self.store.append_once_result(
            "self.prediction.resolved", prediction_id, payload
        )
        return {**payload, "event_id": event.event_id, "created": created}

    def record_result(
        self,
        *,
        prediction_id: str,
        succeeded: bool,
        evidence: Iterable[str],
        logical_tick: int,
    ) -> dict[str, Any]:
        prediction = next(
            (
                event
                for event in self.store.events("self.prediction.made")
                if event.payload.get("prediction_id") == prediction_id
            ),
            None,
        )
        if prediction is None:
            raise KeyError(f"unknown self prediction: {prediction_id}")
        capability_name = str(prediction.payload["capability"])
        capability = self._capabilities()[capability_name]
        predicted = float(prediction.payload["predicted_success"])
        actual = 1.0 if succeeded else 0.0
        brier_error = round((predicted - actual) ** 2, 12)
        prior_confidence = float(capability["confidence"])
        corrected_confidence = (
            prior_confidence + 0.25 * (1.0 - prior_confidence)
            if succeeded
            else prior_confidence * 0.5
        )
        evidence_rows = tuple(str(item) for item in evidence)
        updated = self.declare_capability(
            name=capability_name,
            available=bool(capability["available"]) if succeeded else False,
            confidence=corrected_confidence,
            permission=str(capability["permission"]),
            evidence=[*capability.get("evidence", []), *evidence_rows],
            logical_tick=logical_tick,
        )
        payload = {
            "logical_tick": logical_tick,
            "prediction_id": prediction_id,
            "capability": capability_name,
            "predicted_success": predicted,
            "succeeded": bool(succeeded),
            "brier_error": brier_error,
            "previous_confidence": prior_confidence,
            "corrected_confidence": updated["confidence"],
            "evidence": list(evidence_rows),
        }
        event = self.store.append("self.prediction.resolved", payload)
        return {**payload, "event_id": event.event_id}

    def add_commitment(
        self,
        *,
        commitment_id: str,
        statement: str,
        source: str,
        logical_tick: int,
        status: str = "active",
    ) -> dict[str, Any]:
        if status not in {"active", "fulfilled", "released"}:
            raise ValueError("invalid commitment status")
        payload = {
            "logical_tick": logical_tick,
            "commitment": {
                "id": commitment_id,
                "statement": statement,
                "source": source,
                "status": status,
            },
        }
        event = self.store.append("self.commitment.updated", payload)
        return {**payload["commitment"], "event_id": event.event_id}

    def add_uncertainty(
        self,
        *,
        uncertainty_id: str,
        statement: str,
        confidence: float,
        source: str,
        logical_tick: int,
    ) -> dict[str, Any]:
        if not isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError("uncertainty confidence must be between 0 and 1")
        payload = {
            "logical_tick": logical_tick,
            "uncertainty": {
                "id": uncertainty_id,
                "statement": statement,
                "confidence": confidence,
                "source": source,
            },
        }
        event = self.store.append("self.uncertainty.updated", payload)
        return {**payload["uncertainty"], "event_id": event.event_id}

    @staticmethod
    def _latest_rows(store: EventStore, kind: str, key: str) -> list[dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        for event in store.events(kind):
            row = dict(event.payload[key])
            rows[str(row["id"])] = row
        return [rows[name] for name in sorted(rows)]

    def snapshot(self) -> dict[str, Any]:
        predictions = self.store.events("self.prediction.made")
        resolved = self.store.events("self.prediction.resolved")
        errors = [float(event.payload["brier_error"]) for event in resolved]
        interoception = self.store.latest("interoception.sampled")
        return {
            "identity": self.identity,
            "capabilities": self._capabilities(),
            "commitments": self._latest_rows(
                self.store, "self.commitment.updated", "commitment"
            ),
            "uncertainties": self._latest_rows(
                self.store, "self.uncertainty.updated", "uncertainty"
            ),
            "resource_state": (
                dict(interoception.payload["signals"]) if interoception else {}
            ),
            "regulatory_state": (
                dict(interoception.payload["regulatory"]) if interoception else {}
            ),
            "prediction_count": len(predictions),
            "resolved_prediction_count": len(resolved),
            "mean_brier_error": round(sum(errors) / len(errors), 12) if errors else None,
        }
