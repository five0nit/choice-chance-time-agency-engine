"""Immutable domain models for the Choice-Chance-Time kernel."""

from __future__ import annotations

from dataclasses import dataclass, field
from math import isfinite
from typing import Any, Mapping, Sequence


def _unit_interval(name: str, value: float) -> None:
    if not isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")


def _finite_non_negative(name: str, value: float, *, positive: bool = False) -> None:
    invalid = not isfinite(value) or (value <= 0.0 if positive else value < 0.0)
    if invalid:
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(f"{name} must be finite and {qualifier}")


@dataclass(frozen=True, slots=True)
class Value:
    """A durable evaluative commitment used to score choices."""

    name: str
    weight: float
    description: str

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("value name must not be empty")
        _finite_non_negative("value weight", self.weight)
        if not self.description.strip():
            raise ValueError("value description must not be empty")


@dataclass(frozen=True, slots=True)
class Constitution:
    """Slow-changing identity commitments and bounded exploration policy."""

    identity: str
    values: tuple[Value, ...]
    constraints: tuple[str, ...]
    risk_aversion: float = 0.6
    time_discount: float = 0.08
    exploration_rate: float = 0.2
    temperature: float = 0.35
    epistemic_bonus: float = 0.35
    irreversibility_penalty: float = 0.3

    def __post_init__(self) -> None:
        if not self.identity.strip():
            raise ValueError("constitution identity must not be empty")
        if not self.values:
            raise ValueError("constitution requires at least one value")
        names = [value.name for value in self.values]
        if len(names) != len(set(names)):
            raise ValueError("constitution value names must be unique")
        if not self.constraints:
            raise ValueError("constitution requires at least one constraint")
        if any(not constraint.strip() for constraint in self.constraints):
            raise ValueError("constitution constraints must not be empty")
        _unit_interval("risk_aversion", self.risk_aversion)
        _unit_interval("exploration_rate", self.exploration_rate)
        _finite_non_negative("time_discount", self.time_discount)
        _finite_non_negative("temperature", self.temperature, positive=True)
        _finite_non_negative("epistemic_bonus", self.epistemic_bonus)
        _finite_non_negative(
            "irreversibility_penalty", self.irreversibility_penalty
        )

    @property
    def weights(self) -> dict[str, float]:
        return {value.name: value.weight for value in self.values}


@dataclass(frozen=True, slots=True)
class Goal:
    """A persistent objective, including whether the agent formed it itself."""

    id: str
    statement: str
    rationale: str
    source: str
    horizon: str
    alignment: Mapping[str, float]
    evidence: tuple[str, ...] = field(default_factory=tuple)
    status: str = "active"
    created_at: str | None = None

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("goal id must not be empty")
        if not self.statement.strip():
            raise ValueError("goal statement must not be empty")
        if not self.rationale.strip():
            raise ValueError("goal rationale must not be empty")
        if self.source not in {"self", "external", "joint"}:
            raise ValueError("goal source must be self, external, or joint")
        if self.status not in {"active", "paused", "completed", "abandoned"}:
            raise ValueError("invalid goal status")
        if not self.horizon.strip():
            raise ValueError("goal horizon must not be empty")
        if not self.alignment:
            raise ValueError("goal requires declared value alignment")
        for name, impact in self.alignment.items():
            if not name.strip():
                raise ValueError("goal alignment name must not be empty")
            numeric = float(impact)
            if not isfinite(numeric) or not -1.0 <= numeric <= 1.0:
                raise ValueError(f"goal alignment for {name} must be between -1 and 1")


@dataclass(frozen=True, slots=True)
class Option:
    """One counterfactual action branch considered for a goal."""

    id: str
    description: str
    value_impacts: Mapping[str, float]
    information_gain: float = 0.0
    uncertainty: float = 0.0
    time_cost: float = 0.0
    irreversible: bool = False
    blocked_reasons: tuple[str, ...] = field(default_factory=tuple)
    assumptions: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("option id must not be empty")
        if not self.description.strip():
            raise ValueError("option description must not be empty")
        _unit_interval("information_gain", self.information_gain)
        _unit_interval("uncertainty", self.uncertainty)
        _finite_non_negative("time_cost", self.time_cost)
        for name, impact in self.value_impacts.items():
            if not name.strip():
                raise ValueError("value impact name must not be empty")
            numeric = float(impact)
            if not isfinite(numeric) or not -1.0 <= numeric <= 1.0:
                raise ValueError(f"impact for {name} must be between -1 and 1")

    @property
    def allowed(self) -> bool:
        return not self.blocked_reasons


def options_from_dicts(rows: Sequence[Mapping[str, Any]]) -> list[Option]:
    """Parse JSON-compatible option objects with strict defaults."""

    options: list[Option] = []
    for row in rows:
        options.append(
            Option(
                id=str(row["id"]),
                description=str(row["description"]),
                value_impacts={
                    str(key): float(value)
                    for key, value in dict(row.get("value_impacts", {})).items()
                },
                information_gain=float(row.get("information_gain", 0.0)),
                uncertainty=float(row.get("uncertainty", 0.0)),
                time_cost=float(row.get("time_cost", 0.0)),
                irreversible=bool(row.get("irreversible", False)),
                blocked_reasons=tuple(str(x) for x in row.get("blocked_reasons", [])),
                assumptions=tuple(str(x) for x in row.get("assumptions", [])),
            )
        )
    return options
