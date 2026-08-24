"""Production Identity Engine state machine."""

from __future__ import annotations

from dataclasses import dataclass

from app.services.identity.models import ANSWER_VALUES, DiscoveryQuestion, PersonProfile
from app.services.identity.scoring import candidate_score, softmax
from app.services.identity.selector import select_question


@dataclass(frozen=True)
class IdentityEngineConfig:
    algorithm_version: str = "identity-engine-v1"
    max_questions: int = 15
    guess_probability: float = 0.88
    guess_margin: float = 0.35
    min_answers_for_guess: int = 3
    max_rejections: int = 3
    softmax_temperature: float = 0.15
    allow_l3: bool = False


@dataclass(frozen=True)
class CandidateProbability:
    person_id: str
    score: float
    probability: float


@dataclass(frozen=True)
class IdentityDecision:
    status: str
    guess_person_id: str | None
    top_candidates: tuple[CandidateProbability, ...]
    margin: float


class IdentityEngine:
    """Pure stateful coordinator; no web/database dependency."""

    def __init__(self, people: list[PersonProfile], questions: list[DiscoveryQuestion], config: IdentityEngineConfig | None = None) -> None:
        self.config = config or IdentityEngineConfig()
        self.people = {person.id: person for person in people}
        self.questions = {question.id: question for question in questions}
        self.answers: dict[str, float] = {}
        self.asked: set[str] = set()
        self.rejected_person_ids: set[str] = set()
        self.question_count = 0

    def _active_people(self) -> list[PersonProfile]:
        return [person for person in self.people.values() if person.id not in self.rejected_person_ids]

    def ranked_candidates(self) -> tuple[CandidateProbability, ...]:
        candidates = self._active_people()
        scores = [candidate_score(person, self.questions, self.answers) for person in candidates]
        probabilities = softmax(scores, self.config.softmax_temperature)
        ranked = [CandidateProbability(person.id, score, probability) for person, score, probability in zip(candidates, scores, probabilities, strict=True)]
        return tuple(sorted(ranked, key=lambda item: (-item.probability, item.person_id)))

    def decision(self) -> IdentityDecision:
        ranked = self.ranked_candidates()
        if not ranked:
            return IdentityDecision("locked", None, (), 0.0)
        top = ranked[0]
        second_probability = ranked[1].probability if len(ranked) > 1 else 0.0
        margin = top.probability - second_probability
        if self.question_count >= self.config.min_answers_for_guess and top.probability >= self.config.guess_probability and margin >= self.config.guess_margin:
            return IdentityDecision("guess", top.person_id, ranked, margin)
        if self.question_count >= self.config.max_questions or self.next_question() is None:
            return IdentityDecision("unable_to_identify", None, ranked, margin)
        return IdentityDecision("question", None, ranked, margin)

    def next_question(self) -> DiscoveryQuestion | None:
        return select_question(self.questions, self._active_people(), self.asked, allow_l3=self.config.allow_l3)

    def answer(self, question_id: str, value: float) -> IdentityDecision:
        if question_id not in self.questions:
            raise KeyError(f"unknown question: {question_id}")
        if value not in ANSWER_VALUES:
            raise ValueError("answer must be one of the five answer values")
        if question_id in self.asked:
            raise ValueError("question has already been answered")
        question = self.questions[question_id]
        if not question.active or question.privacy_level == "L4_VERIFICATION_ONLY" or (question.privacy_level == "L3_SENSITIVE" and not self.config.allow_l3):
            raise ValueError("question is not allowed in Discovery")
        self.answers[question_id] = value
        self.asked.add(question_id)
        self.question_count += 1
        return self.decision()

    def reject_guess(self, person_id: str) -> IdentityDecision:
        if person_id not in self.people:
            raise KeyError(f"unknown person: {person_id}")
        self.rejected_person_ids.add(person_id)
        if len(self.rejected_person_ids) > self.config.max_rejections:
            return IdentityDecision("locked", None, (), 0.0)
        return self.decision()

