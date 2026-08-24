"""Audit event writer with a deliberately small metadata surface."""

from __future__ import annotations

import json
from collections.abc import Mapping

from sqlalchemy.orm import Session

from app.models.audit import AuditEvent


def record_audit(
    db: Session,
    *,
    actor_type: str,
    event_type: str,
    actor_id: str | None = None,
    target_type: str = "system",
    target_id: str | None = None,
    metadata: Mapping[str, str | int | bool | None] | None = None,
) -> AuditEvent:
    """Add a whitelist-shaped event; callers must never pass secret material."""

    event = AuditEvent(
        actor_type=actor_type,
        actor_id=actor_id,
        event_type=event_type,
        target_type=target_type,
        target_id=target_id,
        metadata_json=json.dumps(dict(metadata or {}), sort_keys=True, ensure_ascii=True),
    )
    db.add(event)
    db.flush()
    return event

