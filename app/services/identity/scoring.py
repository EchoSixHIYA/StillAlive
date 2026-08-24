"""Deterministic scoring and probability functions."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping

from app.services.identity.models import DiscoveryQuestion, PersonProfile, TraitValue


def match_value(user_value: float, trait: TraitValue | None) -> float | None:
    """Return the SPEC-050 match value, or None for an undefined trait."""

    if trait is None or trait.value is None or trait.confidence <= 0:
        return None
    return 1.0 - abs(user_value - trait.value) / 2.0


def privacy_score_multiplier(privacy_level: str) -> float:
    """Small privacy-aware weight adjustment used by the production scorer."""

    return {
        "L0_PUBLIC": 1.0,
        "L1_RELATION": 0.98,
        "L2_PRIVATE": 0.90,
        "L3_SENSITIVE": 0.50,
        "L4_VERIFICATION_ONLY": 0.0,
    }.get(privacy_level, 0.0)


def candidate_score(
    person: PersonProfile,
    questions: Mapping[str, DiscoveryQuestion],
    answers: Mapping[str, float],
) -> float:
    """Compute a weighted average match without treating unknown traits as matches."""

    numerator = 0.0
    denominator = 0.0
    for question_id, user_value in answers.items():
        question = questions.get(question_id)
        if question is None:
            continue
        trait = person.traits.get(question_id)
        match = match_value(user_value, trait)
        if match is None:
            continue
        effective_weight = question.weight * trait.confidence * privacy_score_multiplier(question.privacy_level)
        if effective_weight <= 0:
            continue
        numerator += match * effective_weight
        denominator += effective_weight
    return numerator / denominator if denominator else 0.0


def softmax(scores: Iterable[float], temperature: float = 0.15) -> list[float]:
    values = list(scores)
    if not values:
        return []
    if temperature <= 0:
        raise ValueError("temperature must be greater than zero")
    maximum = max(values)
    exponents = [math.exp((value - maximum) / temperature) for value in values]
    total = sum(exponents)
    return [value / total for value in exponents]

