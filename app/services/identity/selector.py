"""Privacy-aware information-gain question selection."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

from app.services.identity.models import ANSWER_VALUES, DiscoveryQuestion, PersonProfile


PRIVACY_PENALTY = {
    "L0_PUBLIC": 0.0,
    "L1_RELATION": 0.05,
    "L2_PRIVATE": 0.20,
    "L3_SENSITIVE": 1.0,
    "L4_VERIFICATION_ONLY": math.inf,
}


def information_gain(question: DiscoveryQuestion, candidates: Sequence[PersonProfile]) -> float:
    """Entropy of defined expected answers across current candidates."""

    counts = {value: 0 for value in ANSWER_VALUES}
    defined = 0
    for candidate in candidates:
        trait = candidate.traits.get(question.id)
        if trait is None or trait.value is None or trait.confidence <= 0:
            continue
        counts[trait.value] += 1
        defined += 1
    if defined == 0 or len(candidates) == 0:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        if count:
            probability = count / defined
            entropy -= probability * math.log2(probability)
    return entropy * (defined / len(candidates))


def question_utility(question: DiscoveryQuestion, candidates: Sequence[PersonProfile], asked: set[str], *, allow_l3: bool = False) -> float:
    if not question.active or question.id in asked:
        return -math.inf
    if question.privacy_level == "L4_VERIFICATION_ONLY":
        return -math.inf
    if question.privacy_level == "L3_SENSITIVE" and not allow_l3:
        return -math.inf
    coverage = sum(1 for candidate in candidates if candidate.traits.get(question.id) and candidate.traits[question.id].value is not None) / max(len(candidates), 1)
    low_coverage_penalty = (1.0 - coverage) * 0.50
    return information_gain(question, candidates) * question.weight - PRIVACY_PENALTY[question.privacy_level] - low_coverage_penalty


def select_question(
    questions: Mapping[str, DiscoveryQuestion],
    candidates: Sequence[PersonProfile],
    asked: set[str],
    *,
    allow_l3: bool = False,
) -> DiscoveryQuestion | None:
    scored = [(question_utility(question, candidates, asked, allow_l3=allow_l3), question) for question in questions.values()]
    valid = [item for item in scored if math.isfinite(item[0])]
    if not valid:
        return None
    valid.sort(key=lambda item: (-item[0], item[1].id))
    return valid[0][1]

