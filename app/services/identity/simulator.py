"""Deterministic EXACT and HUMAN_NOISE simulations using IdentityEngine."""

from __future__ import annotations

import random
from dataclasses import dataclass
from enum import StrEnum

from app.services.identity.engine import IdentityEngine, IdentityEngineConfig
from app.services.identity.models import ANSWER_VALUES, DiscoveryQuestion, PersonProfile, TraitValue


class NoiseProfile(StrEnum):
    EXACT = "EXACT"
    HUMAN_NOISE = "HUMAN_NOISE"


@dataclass(frozen=True)
class SimulationResult:
    target_person_id: str
    profile: NoiseProfile
    algorithm_version: str
    noise_profile_version: str
    seed: int
    status: str
    guessed_person_id: str | None
    question_count: int
    score_margin: float
    top_person_id: str | None
    answers: tuple[tuple[str, float], ...]


NOISE_PROFILE_VERSION = "human-noise-v1"


def _noisy_answer(trait: TraitValue | None, rng: random.Random, profile: NoiseProfile) -> float:
    expected = trait.value if trait and trait.value is not None else 0.0
    if profile == NoiseProfile.EXACT:
        return expected
    confidence = trait.confidence if trait else 0.0
    unknown_probability = min(0.85, 0.10 + 0.30 * (1.0 - confidence))
    neighbor_probability = min(0.30, 0.20 + 0.10 * (1.0 - confidence))
    roll = rng.random()
    if roll < unknown_probability:
        return 0.0
    if roll < unknown_probability + neighbor_probability:
        index = ANSWER_VALUES.index(expected)
        if index == 0:
            return ANSWER_VALUES[1]
        if index == len(ANSWER_VALUES) - 1:
            return ANSWER_VALUES[-2]
        return ANSWER_VALUES[index - 1] if rng.random() < 0.5 else ANSWER_VALUES[index + 1]
    return expected


def simulate(
    target_person: PersonProfile,
    people: list[PersonProfile],
    questions: list[DiscoveryQuestion],
    *,
    profile: NoiseProfile = NoiseProfile.EXACT,
    seed: int = 0,
    config: IdentityEngineConfig | None = None,
) -> SimulationResult:
    engine = IdentityEngine(people, questions, config)
    rng = random.Random(seed)
    captured_answers: list[tuple[str, float]] = []
    status = "question"
    decision = engine.decision()
    while status == "question":
        question = engine.next_question()
        if question is None:
            decision = engine.decision()
            break
        answer = _noisy_answer(target_person.traits.get(question.id), rng, profile)
        captured_answers.append((question.id, answer))
        decision = engine.answer(question.id, answer)
        status = decision.status
    ranked = decision.top_candidates
    return SimulationResult(
        target_person_id=target_person.id,
        profile=profile,
        algorithm_version=engine.config.algorithm_version,
        noise_profile_version=NOISE_PROFILE_VERSION if profile == NoiseProfile.HUMAN_NOISE else "exact-v1",
        seed=seed,
        status=decision.status,
        guessed_person_id=decision.guess_person_id,
        question_count=engine.question_count,
        score_margin=decision.margin,
        top_person_id=ranked[0].person_id if ranked else None,
        answers=tuple(captured_answers),
    )

