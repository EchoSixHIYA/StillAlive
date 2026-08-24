"""Engine input and result value objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


ANSWER_VALUES: tuple[float, ...] = (-1.0, -0.5, 0.0, 0.5, 1.0)
PRIVACY_LEVELS: tuple[str, ...] = (
    "L0_PUBLIC",
    "L1_RELATION",
    "L2_PRIVATE",
    "L3_SENSITIVE",
    "L4_VERIFICATION_ONLY",
)


@dataclass(frozen=True)
class TraitValue:
    """Expected answer; ``value=None`` means the trait is undefined."""

    value: float | None
    confidence: float = 0.0

    def __post_init__(self) -> None:
        if self.value is not None and self.value not in ANSWER_VALUES:
            raise ValueError("TraitValue.value must be one of the five answer values or None")
        if not 0 <= self.confidence <= 1:
            raise ValueError("TraitValue.confidence must be between 0 and 1")


@dataclass(frozen=True)
class DiscoveryQuestion:
    id: str
    privacy_level: str
    weight: float = 1.0
    facet_tag: str | None = None
    active: bool = True

    def __post_init__(self) -> None:
        if self.privacy_level not in PRIVACY_LEVELS:
            raise ValueError(f"unknown privacy level: {self.privacy_level}")
        if self.weight <= 0:
            raise ValueError("question weight must be greater than zero")


@dataclass(frozen=True)
class PersonProfile:
    id: str
    traits: Mapping[str, TraitValue] = field(default_factory=dict)

