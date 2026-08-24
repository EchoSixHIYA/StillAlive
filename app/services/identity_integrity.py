"""Identity Integrity computation built on the production Identity Engine."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from itertools import combinations
from statistics import mean
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.engine import Engine

from app.config import Settings
from app.models.identity import Person, Question, TraitAnswer
from app.models.integrity import IdentityCluster, IdentityIntegritySnapshot, IdentityPairMetric
from app.services.identity.engine import IdentityEngineConfig
from app.services.identity.models import ANSWER_VALUES, DiscoveryQuestion, PersonProfile, TraitValue
from app.services.identity.scoring import privacy_score_multiplier
from app.services.identity.simulator import NOISE_PROFILE_VERSION, NoiseProfile, SimulationResult, simulate

DISCOVERY_PRIVACY_LEVELS = {"L0_PUBLIC", "L1_RELATION", "L2_PRIVATE"}


def mark_latest_stale(db: Session, *, actor_type: str = "system", actor_id: str | None = None, reason: str = "authoring_change") -> None:
    latest = db.scalar(select(IdentityIntegritySnapshot).order_by(IdentityIntegritySnapshot.created_at.desc()).limit(1))
    if latest is not None and latest.status not in {"stale", "running"}:
        latest.status = "stale"


def _engine_inputs(db: Session) -> tuple[list[PersonProfile], list[DiscoveryQuestion]]:
    people = db.scalars(select(Person).where(Person.status == "active").order_by(Person.id)).all()
    questions = db.scalars(select(Question).where(Question.active.is_(True)).order_by(Question.id)).all()
    answers = db.scalars(select(TraitAnswer).where(TraitAnswer.person_id.in_([person.id for person in people]))).all() if people else []
    answers_by_person: dict[str, dict[str, TraitValue]] = defaultdict(dict)
    for answer in answers:
        if answer.value not in ANSWER_VALUES:
            continue
        answers_by_person[answer.person_id][answer.question_id] = TraitValue(answer.value, answer.confidence)
    profiles = [PersonProfile(person.id, answers_by_person[person.id]) for person in people]
    discovery_questions = [
        DiscoveryQuestion(question.id, question.privacy_level, question.weight, question.facet_tag, question.active)
        for question in questions
        if question.privacy_level in DISCOVERY_PRIVACY_LEVELS
    ]
    return profiles, discovery_questions


def _stable_seed(target_id: str, profile: NoiseProfile) -> int:
    digest = hashlib.sha256(f"{target_id}:{profile.value}:identity-integrity-v1".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _run_target_simulations(
    target: PersonProfile,
    people: list[PersonProfile],
    questions: list[DiscoveryQuestion],
    *,
    profile: NoiseProfile,
    sessions: int,
    engine_config: IdentityEngineConfig,
) -> list[SimulationResult]:
    base_seed = _stable_seed(target.id, profile)
    return [
        simulate(target, people, questions, profile=profile, seed=base_seed + index, config=engine_config)
        for index in range(sessions)
    ]


def _static_metrics(person_a: PersonProfile, person_b: PersonProfile, questions: list[DiscoveryQuestion]) -> tuple[float, int, int, int, float]:
    common = []
    strong = []
    separation_numerator = 0.0
    separation_denominator = 0.0
    for question in questions:
        trait_a = person_a.traits.get(question.id)
        trait_b = person_b.traits.get(question.id)
        if trait_a is None or trait_b is None or trait_a.value is None or trait_b.value is None:
            continue
        common.append(1.0 - abs(trait_a.value - trait_b.value) / 2.0)
        effective_weight = question.weight * privacy_score_multiplier(question.privacy_level)
        separation_numerator += effective_weight * abs(trait_a.value - trait_b.value) / 2.0
        separation_denominator += effective_weight
        if question.privacy_level in {"L0_PUBLIC", "L1_RELATION", "L2_PRIVATE"} and question.weight > 0 and abs(trait_a.value - trait_b.value) >= 1.0 and trait_a.confidence >= 0.75 and trait_b.confidence >= 0.75:
            strong.append(question)
    similarity = mean(common) if common else 1.0
    facets = {question.facet_tag for question in strong if question.facet_tag}
    theoretical_separation = separation_numerator / separation_denominator if separation_denominator else 0.0
    return similarity, len(strong), len(facets), len(common), theoretical_separation


def _p05(values: list[float]) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    return values[max(0, int(0.05 * (len(values) - 1)))]


def _pair_risk(
    confusion: float,
    *,
    exact_a_to_b: float,
    exact_b_to_a: float,
    strong_discriminator_count: int,
    common_count: int,
    trait_similarity: float,
    blocking_threshold: float,
    warning_threshold: float,
) -> str:
    if exact_a_to_b > 0 or exact_b_to_a > 0:
        return "blocking"
    if common_count == 0 or (strong_discriminator_count == 0 and trait_similarity >= 0.999999):
        return "blocking"
    if confusion >= blocking_threshold:
        return "blocking"
    if confusion >= warning_threshold:
        return "warning"
    return "pass"


def _clusters(metrics: list[IdentityPairMetric]) -> list[tuple[list[str], str, str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    for metric in metrics:
        if metric.risk not in {"warning", "blocking"}:
            continue
        graph[metric.person_a_id].add(metric.person_b_id)
        graph[metric.person_b_id].add(metric.person_a_id)
    seen: set[str] = set()
    result = []
    for start in sorted(graph):
        if start in seen:
            continue
        stack = [start]
        members = []
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            members.append(current)
            stack.extend(graph[current] - seen)
        member_set = set(members)
        edges = [metric for metric in metrics if metric.risk in {"warning", "blocking"} and metric.person_a_id in member_set and metric.person_b_id in member_set]
        worst = max(edges, key=lambda metric: (1 if metric.risk == "blocking" else 0, max(metric.confusion_a_to_b, metric.confusion_b_to_a)))
        risk = "blocking" if any(edge.risk == "blocking" for edge in edges) else "warning"
        result.append((sorted(members), risk, f"{worst.person_a_id}:{worst.person_b_id}"))
    return result


def recompute_integrity(engine: Engine, settings: Settings, *, mode: str = "incremental") -> IdentityIntegritySnapshot:
    """Run a deterministic integrity snapshot and persist all derived metrics."""

    sessions = settings.integrity_incremental_simulations_per_person if mode == "incremental" else settings.integrity_seal_simulations_per_person
    engine_config = IdentityEngineConfig(max_questions=settings.identity_max_questions)
    with Session(engine) as db:
        profiles, questions = _engine_inputs(db)
        snapshot = IdentityIntegritySnapshot(
            mode=mode,
            algorithm_version=engine_config.algorithm_version,
            noise_profile_version=NOISE_PROFILE_VERSION,
            active_person_count=len(profiles),
            active_question_count=len(questions),
            status="running",
            created_at=datetime.now(timezone.utc),
        )
        db.add(snapshot)
        db.flush()
        metrics: list[IdentityPairMetric] = []
        exact_results = {profile.id: _run_target_simulations(profile, profiles, questions, profile=NoiseProfile.EXACT, sessions=sessions, engine_config=engine_config) for profile in profiles}
        noisy_results = {profile.id: _run_target_simulations(profile, profiles, questions, profile=NoiseProfile.HUMAN_NOISE, sessions=sessions, engine_config=engine_config) for profile in profiles}
        for person_a, person_b in combinations(profiles, 2):
            similarity, strong_count, facet_count, common_count, theoretical_separation = _static_metrics(person_a, person_b, questions)
            human_a = noisy_results[person_a.id]
            human_b = noisy_results[person_b.id]
            exact_a = exact_results[person_a.id]
            exact_b = exact_results[person_b.id]
            confusion_a_to_b = sum(result.guessed_person_id == person_b.id for result in human_a) / max(len(human_a), 1)
            confusion_b_to_a = sum(result.guessed_person_id == person_a.id for result in human_b) / max(len(human_b), 1)
            exact_a_to_b = sum(result.guessed_person_id == person_b.id for result in exact_a) / max(len(exact_a), 1)
            exact_b_to_a = sum(result.guessed_person_id == person_a.id for result in exact_b) / max(len(exact_b), 1)
            margins = [result.score_margin for result in human_a + human_b]
            confusion = max(confusion_a_to_b, confusion_b_to_a)
            risk = _pair_risk(confusion, exact_a_to_b=exact_a_to_b, exact_b_to_a=exact_b_to_a, strong_discriminator_count=strong_count, common_count=common_count, trait_similarity=similarity, blocking_threshold=settings.identity_blocking_confusion_rate, warning_threshold=settings.identity_warning_confusion_rate)
            metrics.append(IdentityPairMetric(snapshot_id=snapshot.id, person_a_id=person_a.id, person_b_id=person_b.id, trait_similarity=similarity, strong_discriminator_count=strong_count, distinct_facet_count=facet_count, common_question_count=common_count, theoretical_max_score_separation=theoretical_separation, confusion_a_to_b=confusion_a_to_b, confusion_b_to_a=confusion_b_to_a, mean_score_margin=mean(margins) if margins else 0.0, p05_score_margin=_p05(margins), risk=risk))
        db.add_all(metrics)
        db.flush()
        clusters = _clusters(metrics)
        for index, (members, risk, worst_pair) in enumerate(clusters, start=1):
            db.add(IdentityCluster(snapshot_id=snapshot.id, cluster_id=f"cluster-{index}", member_person_ids=json.dumps(members), risk=risk, worst_pair=worst_pair))
        snapshot.blocking_pair_count = sum(metric.risk == "blocking" for metric in metrics)
        snapshot.warning_pair_count = sum(metric.risk == "warning" for metric in metrics)
        snapshot.cluster_count = len(clusters)
        snapshot.worst_confusion_rate = max((max(metric.confusion_a_to_b, metric.confusion_b_to_a) for metric in metrics), default=0.0)
        snapshot.status = "blocking" if snapshot.blocking_pair_count else "warning" if snapshot.warning_pair_count else "pass"
        snapshot.finished_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(snapshot)
        return snapshot


def recompute_incremental(engine: Engine, settings: Settings) -> IdentityIntegritySnapshot:
    return recompute_integrity(engine, settings, mode="incremental")
