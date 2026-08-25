"""First-use setup progress for the administrator experience.

The application intentionally keeps delivery available while authoring is in
progress.  This module therefore reports progress and recommended next
actions instead of treating an incomplete catalog as an application error.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.identity import Person, Question, TraitAnswer
from app.models.integrity import IdentityIntegritySnapshot
from app.models.release import RecoveryKeyRecord, SealedRelease
from app.models.verification import VerificationChallenge


DISCOVERY_PRIVACY_LEVELS = {"L0_PUBLIC", "L1_RELATION", "L2_PRIVATE", "L3_SENSITIVE"}


def _item(
    key: str,
    title: str,
    detail: str,
    action_label: str,
    action_url: str,
    done: bool,
    *,
    required: bool = True,
) -> dict[str, object]:
    return {
        "key": key,
        "title": title,
        "detail": detail,
        "action_label": action_label,
        "action_url": action_url,
        "done": done,
        "required": required,
    }


def build_setup_checklist(db: Session) -> dict[str, object]:
    """Return a small, template-friendly checklist for first-time setup."""

    active_people = db.scalars(select(Person).where(Person.status == "active")).all()
    active_questions = db.scalars(
        select(Question).where(
            Question.active.is_(True),
            Question.privacy_level.in_(DISCOVERY_PRIVACY_LEVELS),
        )
    ).all()
    active_person_ids = {person.id for person in active_people}
    active_question_ids = {question.id for question in active_questions}

    answers = db.scalars(
        select(TraitAnswer).where(
            TraitAnswer.person_id.in_(active_person_ids) if active_person_ids else False,
            TraitAnswer.question_id.in_(active_question_ids) if active_question_ids else False,
        )
    ).all()
    answer_keys = {(answer.person_id, answer.question_id) for answer in answers}
    missing_traits = sum(
        (person_id, question_id) not in answer_keys
        for person_id in active_person_ids
        for question_id in active_question_ids
    )

    challenge_counts = {
        person_id: int(count)
        for person_id, count in db.execute(
            select(VerificationChallenge.person_id, func.count(VerificationChallenge.id))
            .where(VerificationChallenge.active.is_(True))
            .group_by(VerificationChallenge.person_id)
        ).all()
    }
    missing_challenges = [person for person in active_people if challenge_counts.get(person.id, 0) == 0]

    asset_counts = {
        person_id: int(count)
        for person_id, count in db.execute(
            select(Asset.person_id, func.count(Asset.id))
            .where(Asset.active.is_(True))
            .group_by(Asset.person_id)
        ).all()
    }
    missing_assets = [person for person in active_people if asset_counts.get(person.id, 0) == 0]

    latest_snapshot = db.scalar(select(IdentityIntegritySnapshot).order_by(IdentityIntegritySnapshot.created_at.desc()).limit(1))
    integrity_ready = bool(
        latest_snapshot
        and latest_snapshot.mode in {"full", "seal"}
        and latest_snapshot.status == "pass"
        and latest_snapshot.blocking_pair_count == 0
        and latest_snapshot.warning_pair_count == 0
    )
    recovery_ready = db.scalar(select(RecoveryKeyRecord).where(RecoveryKeyRecord.rotated_at.is_(None)).limit(1)) is not None
    ready_releases = int(db.scalar(select(func.count(SealedRelease.id)).where(SealedRelease.status == "ready")) or 0)

    items = [
        _item("people", "建立人物", f"已建立 {len(active_people)} 个可交付人物。", "管理人物", "/admin/people", bool(active_people)),
        _item("questions", "建立识别问题", f"已有 {len(active_questions)} 个可用于公开识别的问题。", "管理问题", "/admin/questions", bool(active_questions)),
        _item(
            "traits",
            "补齐识别特征",
            "已补齐全部人物 × 问题答案。" if active_people and active_questions and missing_traits == 0 else f"还有 {missing_traits} 项人物答案待填写。",
            "去补充答案",
            f"/admin/people/{active_people[0].id}" if active_people else "/admin/people/new",
            bool(active_people and active_questions and missing_traits == 0),
        ),
        _item(
            "challenges",
            "配置专属验证",
            "每个人物都有至少一个启用的专属验证问题。" if active_people and not missing_challenges else f"还有 {len(missing_challenges)} 个人物没有专属验证问题。",
            "去配置验证",
            f"/admin/people/{missing_challenges[0].id if missing_challenges else (active_people[0].id if active_people else '')}#verification" if active_people else "/admin/people/new",
            bool(active_people and not missing_challenges),
        ),
        _item(
            "assets",
            "上传遗产内容",
            "每个人物都有至少一份启用的遗产内容。" if active_people and not missing_assets else f"还有 {len(missing_assets)} 个人物没有可交付内容。",
            "去上传内容",
            f"/admin/people/{missing_assets[0].id if missing_assets else (active_people[0].id if active_people else '')}#assets" if active_people else "/admin/people/new",
            bool(active_people and not missing_assets),
        ),
        _item("frontend", "用朋友视角试跑", "这是人工验收步骤，不会改变线上数据。", "打开前台", "/", True, required=False),
        _item("recovery", "保存 Recovery Key", "Recovery Key 只应离线保存，不要放入代码库。", "管理 Recovery Key", "/admin/recovery-key", recovery_ready),
        _item(
            "integrity",
            "通过身份完整性检查",
            "最新检查已通过，没有阻塞或提醒人物对。" if integrity_ready else "需要重新计算，并按待办消除人物混淆风险。",
            "查看并处理待办",
            "/admin/identity-integrity",
            integrity_ready,
        ),
        _item("release", "创建离线封存包", f"已有 {ready_releases} 个可恢复的离线封存包。", "管理离线封存包", "/admin/releases", ready_releases > 0),
    ]
    required_items = [item for item in items if item["required"]]
    completed_required = sum(bool(item["done"]) for item in required_items)
    return {
        "items": items,
        "completed": completed_required,
        "total": len(required_items),
        "all_required_done": completed_required == len(required_items),
        "active_people": len(active_people),
        "active_questions": len(active_questions),
        "missing_traits": missing_traits,
        "missing_challenges": len(missing_challenges),
        "missing_assets": len(missing_assets),
        "latest_snapshot": latest_snapshot,
        "ready_releases": ready_releases,
    }
