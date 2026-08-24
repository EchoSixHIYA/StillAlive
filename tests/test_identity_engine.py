"""SPEC-050 Identity Engine unit acceptance tests."""

from __future__ import annotations

import pytest

from app.services.identity.engine import IdentityEngine, IdentityEngineConfig
from app.services.identity.models import DiscoveryQuestion, PersonProfile, TraitValue
from app.services.identity.scoring import candidate_score, match_value
from app.services.identity.selector import information_gain, select_question
from app.services.identity.simulator import NoiseProfile, simulate


def _question(question_id: str, privacy: str = "L1_RELATION") -> DiscoveryQuestion:
    return DiscoveryQuestion(id=question_id, privacy_level=privacy, weight=1.0)


def _profiles(question_ids: list[str]) -> list[PersonProfile]:
    return [
        PersonProfile("A", {question_id: TraitValue(1.0, 1.0) for question_id in question_ids}),
        PersonProfile("B", {question_id: TraitValue(-1.0, 1.0) for question_id in question_ids}),
    ]


def test_match_formula_and_undefined_trait_never_becomes_positive_match() -> None:
    assert match_value(1.0, TraitValue(1.0, 1.0)) == 1.0
    assert match_value(1.0, TraitValue(-1.0, 1.0)) == 0.0
    assert match_value(1.0, TraitValue(None, 1.0)) is None
    assert match_value(1.0, None) is None

    question = _question("q1")
    person = PersonProfile("A", {"q1": TraitValue(None, 1.0)})
    assert candidate_score(person, {"q1": question}, {"q1": 1.0}) == 0.0


def test_selector_prefers_information_gain_and_excludes_l4_and_default_l3() -> None:
    questions = {
        "high": _question("high"),
        "same": _question("same"),
        "sensitive": _question("sensitive", "L3_SENSITIVE"),
        "verification": _question("verification", "L4_VERIFICATION_ONLY"),
    }
    people = [
        PersonProfile("A", {"high": TraitValue(1.0, 1.0), "same": TraitValue(1.0, 1.0), "sensitive": TraitValue(-1.0, 1.0)}),
        PersonProfile("B", {"high": TraitValue(-1.0, 1.0), "same": TraitValue(1.0, 1.0), "sensitive": TraitValue(1.0, 1.0)}),
    ]
    assert information_gain(questions["high"], people) > information_gain(questions["same"], people)
    assert select_question(questions, people, set()).id == "high"
    assert select_question({"verification": questions["verification"]}, people, set()) is None
    assert select_question({"sensitive": questions["sensitive"]}, people, set()) is None


def test_guess_threshold_requires_three_answers_and_margin() -> None:
    question_ids = ["q1", "q2", "q3"]
    questions = [_question(question_id) for question_id in question_ids]
    engine = IdentityEngine(_profiles(question_ids), questions)
    assert engine.decision().status == "question"
    for question_id in question_ids:
        decision = engine.answer(question_id, 1.0)
    assert decision.status == "guess"
    assert decision.guess_person_id == "A"
    assert decision.top_candidates[0].probability >= 0.88
    assert decision.margin >= 0.35


def test_unable_to_identify_is_legal_and_no_top1_is_forced() -> None:
    questions = [_question("q1"), _question("q2"), _question("q3")]
    people = [
        PersonProfile("A", {"q1": TraitValue(1.0, 1.0), "q2": TraitValue(1.0, 1.0), "q3": TraitValue(1.0, 1.0)}),
        PersonProfile("B", {"q1": TraitValue(1.0, 1.0), "q2": TraitValue(1.0, 1.0), "q3": TraitValue(1.0, 1.0)}),
    ]
    engine = IdentityEngine(people, questions, IdentityEngineConfig(max_questions=3))
    decision = engine.decision()
    for question_id in ["q1", "q2", "q3"]:
        decision = engine.answer(question_id, 1.0)
    assert decision.status == "unable_to_identify"
    assert decision.guess_person_id is None


def test_reject_set_recalculates_and_locks_after_three_rejections() -> None:
    question_ids = ["q1", "q2", "q3"]
    questions = [_question(question_id) for question_id in question_ids]
    engine = IdentityEngine(_profiles(question_ids), questions)
    for question_id in question_ids:
        decision = engine.answer(question_id, 1.0)
    assert decision.guess_person_id == "A"
    next_decision = engine.reject_guess("A")
    assert next_decision.guess_person_id == "B"
    engine.reject_guess("B")
    engine.reject_guess("A")
    locked = engine.reject_guess("B")
    assert locked.status == "locked"


def test_exact_and_human_noise_simulations_are_reproducible() -> None:
    question_ids = ["q1", "q2", "q3", "q4"]
    questions = [_question(question_id) for question_id in question_ids]
    people = _profiles(question_ids)
    exact_one = simulate(people[0], people, questions, profile=NoiseProfile.EXACT, seed=42)
    exact_two = simulate(people[0], people, questions, profile=NoiseProfile.EXACT, seed=42)
    noisy_one = simulate(people[0], people, questions, profile=NoiseProfile.HUMAN_NOISE, seed=42)
    noisy_two = simulate(people[0], people, questions, profile=NoiseProfile.HUMAN_NOISE, seed=42)
    assert exact_one == exact_two
    assert noisy_one == noisy_two
    assert exact_one.algorithm_version == "identity-engine-v1"
    assert noisy_one.noise_profile_version == "human-noise-v1"
    assert exact_one.guessed_person_id == "A"


def test_l4_is_never_answerable_by_discovery_engine() -> None:
    engine = IdentityEngine([PersonProfile("A", {"q4": TraitValue(1.0, 1.0)})], [_question("q4", "L4_VERIFICATION_ONLY")])
    assert engine.next_question() is None
    with pytest.raises(ValueError, match="not allowed"):
        engine.answer("q4", 1.0)

