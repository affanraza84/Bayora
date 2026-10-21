"""
Audit Event Helper
Provides atomic appending of SHA-256 hash-chained audit events into PostgreSQL/SQLite.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from services.control_plane.db.models import AuditEvent
from services.audit_service.hasher import (
    compute_event_hash,
    compute_payload_digest,
    format_canonical_timestamp,
)

GENESIS_PREVIOUS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


async def append_audit_event(
    db: AsyncSession,
    tenant_id: str,
    actor: str,
    action: str,
    resource: str,
    decision: str,
    policy_version: str = "v1.0",
    payload_content: str = "",
) -> AuditEvent:
    """
    Appends an immutable, SHA-256 hash-chained audit event to the database.
    Calculates previous_hash from the immediate predecessor sequence record.
    """
    # Fetch last audit event sequence in database
    stmt = select(AuditEvent).order_by(desc(AuditEvent.sequence_number)).limit(1)
    result = await db.execute(stmt)
    last_event = result.scalar_one_or_none()

    if last_event:
        prev_hash = last_event.event_hash
        next_seq = last_event.sequence_number + 1
    else:
        prev_hash = GENESIS_PREVIOUS_HASH
        next_seq = 1

    now = datetime.now(timezone.utc)
    canonical_ts = format_canonical_timestamp(now)
    digest = compute_payload_digest(payload_content) if payload_content else ""
    event_id = str(uuid.uuid4())

    event_hash = compute_event_hash(
        previous_hash=prev_hash,
        sequence_number=next_seq,
        event_id=event_id,
        actor=actor,
        action=action,
        resource=resource,
        decision=decision,
        iso_timestamp=canonical_ts,
        policy_version=policy_version,
        payload_digest=digest,
    )

    new_event = AuditEvent(
        sequence_number=next_seq,
        event_id=event_id,
        tenant_id=tenant_id,
        actor=actor,
        action=action,
        resource=resource,
        decision=decision,
        timestamp=now,
        policy_version=policy_version,
        payload_digest=digest,
        previous_hash=prev_hash,
        event_hash=event_hash,
    )

    db.add(new_event)
    await db.flush()
    return new_event
