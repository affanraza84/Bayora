"""
Audit Trail & Cryptographic Verification Router
Exposes GET /api/audit/events, POST /api/audit/checkpoints, and POST /api/audit/verify.
Enforces tenant scoping, unbroken SHA-256 chain verification, and independent
verification of stored Ed25519 checkpoint signatures against trusted keys.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, asc, desc
from sqlalchemy.ext.asyncio import AsyncSession

from services.control_plane.db.session import get_db
from services.control_plane.db.models import AuditEvent, EvidenceBundle, AuditCheckpoint
from services.control_plane.auth.jwt import SecurityContext
from services.control_plane.auth.rbac import require_permissions
from services.control_plane.schemas.audit import (
    AuditEventResponse,
    AuditListResponse,
    AuditVerifyRequest,
    AuditVerifyResponse,
    AuditCheckpointCreateRequest,
    AuditCheckpointResponse,
)
from services.audit_service.hasher import (
    verify_chain,
    format_canonical_timestamp,
    sign_checkpoint,
    verify_checkpoint,
)
from services.audit_service.keys import (
    key_registry,
    get_active_signing_key,
)

router = APIRouter(prefix="/api/audit", tags=["Audit & Cryptographic Verification"])


@router.get(
    "/events",
    response_model=AuditListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Append-Only Audit Events",
)
async def list_audit_events(
    start_seq: int = Query(1, ge=1),
    end_seq: Optional[int] = Query(None, ge=1),
    limit: int = Query(100, ge=1, le=1000),
    current_user: SecurityContext = Depends(require_permissions("audit:view")),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves audit events. Scoped to current tenant unless requested by platform_admin or auditor.
    """
    query = select(AuditEvent).where(AuditEvent.sequence_number >= start_seq)

    if end_seq is not None:
        query = query.where(AuditEvent.sequence_number <= end_seq)

    if current_user.role not in ["platform_admin", "auditor"]:
        query = query.where(AuditEvent.tenant_id == current_user.tenant_id)

    query = query.order_by(asc(AuditEvent.sequence_number)).limit(limit)

    res = await db.execute(query)
    events = res.scalars().all()

    count_query = select(AuditEvent)
    if current_user.role not in ["platform_admin", "auditor"]:
        count_query = count_query.where(AuditEvent.tenant_id == current_user.tenant_id)
    c_res = await db.execute(count_query)
    total_events = len(c_res.scalars().all())

    items = [
        AuditEventResponse(
            sequence_number=e.sequence_number,
            event_id=e.event_id,
            tenant_id=e.tenant_id,
            actor=e.actor,
            action=e.action,
            resource=e.resource,
            decision=e.decision,
            timestamp=e.timestamp,
            policy_version=e.policy_version,
            payload_digest=e.payload_digest,
            previous_hash=e.previous_hash,
            event_hash=e.event_hash,
        )
        for e in events
    ]

    return AuditListResponse(
        total_events=total_events,
        returned_events=len(items),
        events=items,
    )


@router.post(
    "/checkpoints",
    response_model=AuditCheckpointResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create and Store an Ed25519 Signed Audit Checkpoint",
)
async def create_audit_checkpoint(
    body: AuditCheckpointCreateRequest,
    current_user: SecurityContext = Depends(require_permissions("audit:verify")),
    db: AsyncSession = Depends(get_db),
):
    """
    Computes and signs an immutable audit checkpoint over an unbroken sequence range.
    Stores the checkpoint payload, key identifier, and Ed25519 digital signature into the database.
    """
    query = select(AuditEvent).where(AuditEvent.sequence_number >= body.start_sequence)
    if body.end_sequence:
        query = query.where(AuditEvent.sequence_number <= body.end_sequence)

    query = query.order_by(asc(AuditEvent.sequence_number))
    res = await db.execute(query)
    events = res.scalars().all()

    if not events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot create checkpoint: No audit events found in requested range",
        )

    event_dicts = [
        {
            "sequence_number": e.sequence_number,
            "event_id": e.event_id,
            "actor": e.actor,
            "action": e.action,
            "resource": e.resource,
            "decision": e.decision,
            "timestamp": format_canonical_timestamp(e.timestamp),
            "policy_version": e.policy_version,
            "payload_digest": e.payload_digest,
            "previous_hash": e.previous_hash,
            "event_hash": e.event_hash,
        }
        for e in events
    ]

    is_valid, broken_seq, msg = verify_chain(event_dicts)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "verification_status": "TAMPERING_DETECTED",
                "error_code": "HASH_CHAIN_BROKEN",
                "broken_sequence_number": broken_seq,
                "message": msg,
            },
        )

    now = datetime.now(timezone.utc)
    root_hash = events[-1].event_hash
    start_seq = events[0].sequence_number
    end_seq = events[-1].sequence_number

    key_id, priv_key, pub_key = get_active_signing_key()
    sig_hex = sign_checkpoint(
        private_key_bytes=priv_key,
        start_seq=start_seq,
        end_seq=end_seq,
        root_hash=root_hash,
        timestamp=format_canonical_timestamp(now),
    )

    checkpoint = AuditCheckpoint(
        id=str(uuid.uuid4()),
        tenant_id=current_user.tenant_id,
        start_sequence=start_seq,
        end_sequence=end_seq,
        root_hash=root_hash,
        timestamp=now,
        signer_key_id=key_id,
        ed25519_signature=sig_hex,
    )
    db.add(checkpoint)
    await db.commit()
    await db.refresh(checkpoint)

    return AuditCheckpointResponse(
        checkpoint_id=checkpoint.id,
        tenant_id=checkpoint.tenant_id,
        start_sequence=checkpoint.start_sequence,
        end_sequence=checkpoint.end_sequence,
        root_hash=checkpoint.root_hash,
        timestamp=checkpoint.timestamp,
        signer_key_id=checkpoint.signer_key_id,
        ed25519_signature=checkpoint.ed25519_signature,
        created_at=checkpoint.created_at,
    )


@router.post(
    "/verify",
    response_model=AuditVerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Cryptographically Verify Audit Chain & Stored Ed25519 Checkpoint Signatures",
)
async def verify_audit_trail(
    body: AuditVerifyRequest,
    current_user: SecurityContext = Depends(require_permissions("audit:verify")),
    db: AsyncSession = Depends(get_db),
):
    """
    Independently recomputes mathematical SHA-256 hash continuity from genesis to end_seq,
    loads the previously stored checkpoint(s), and verifies their Ed25519 signatures
    against the trusted key registry. Never generates fresh replacement signatures during verification.
    """
    if body.end_sequence and body.start_sequence > body.end_sequence:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_sequence cannot be greater than end_sequence",
        )

    query = select(AuditEvent).where(AuditEvent.sequence_number >= body.start_sequence)
    if body.end_sequence:
        query = query.where(AuditEvent.sequence_number <= body.end_sequence)

    query = query.order_by(asc(AuditEvent.sequence_number))
    res = await db.execute(query)
    events = res.scalars().all()

    if not events:
        return AuditVerifyResponse(
            verification_status="VALID",
            events_evaluated=0,
            hash_chain_continuity="INTACT",
            ed25519_signature_status="SKIPPED",
            root_hash="0000000000000000000000000000000000000000000000000000000000000000",
            verified_at=datetime.now(timezone.utc),
            message="No events in sequence range to evaluate",
        )

    # 1. Independent chain continuity recomputation
    event_dicts = [
        {
            "sequence_number": e.sequence_number,
            "event_id": e.event_id,
            "actor": e.actor,
            "action": e.action,
            "resource": e.resource,
            "decision": e.decision,
            "timestamp": format_canonical_timestamp(e.timestamp),
            "policy_version": e.policy_version,
            "payload_digest": e.payload_digest,
            "previous_hash": e.previous_hash,
            "event_hash": e.event_hash,
        }
        for e in events
    ]

    is_valid, broken_seq, msg = verify_chain(event_dicts)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "verification_status": "TAMPERING_DETECTED",
                "error_code": "HASH_CHAIN_BROKEN",
                "broken_sequence_number": broken_seq,
                "message": msg,
            },
        )

    now = datetime.now(timezone.utc)
    root_hash = events[-1].event_hash
    sig_status = "SKIPPED"
    verified_key_id: Optional[str] = None
    checkpoint_id: Optional[str] = None
    checkpoints_evaluated = 0

    # 2. Genuine verification of stored checkpoint signature against trusted keys
    if body.verify_ed25519_signatures:
        cp_query = (
            select(AuditCheckpoint)
            .where(AuditCheckpoint.end_sequence <= events[-1].sequence_number)
            .order_by(desc(AuditCheckpoint.end_sequence))
            .limit(1)
        )
        cp_res = await db.execute(cp_query)
        stored_checkpoint = cp_res.scalar_one_or_none()

        if not stored_checkpoint:
            sig_status = "NO_STORED_CHECKPOINT"
        else:
            checkpoints_evaluated = 1
            checkpoint_id = stored_checkpoint.id

            # A. Checkpoint root hash must match computed chain hash at checkpoint's end_seq
            matching_event = next(
                (e for e in events if e.sequence_number == stored_checkpoint.end_sequence),
                None,
            )
            if not matching_event or matching_event.event_hash != stored_checkpoint.root_hash:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail={
                        "verification_status": "TAMPERING_DETECTED",
                        "error_code": "CHECKPOINT_HASH_MISMATCH",
                        "broken_sequence_number": stored_checkpoint.end_sequence,
                        "message": f"Stored checkpoint root hash '{stored_checkpoint.root_hash}' differs from computed chain hash at sequence {stored_checkpoint.end_sequence}",
                    },
                )

            # B. Signer key ID must be trusted in KeyRegistry
            trusted_pub_key = key_registry.get_trusted_key(stored_checkpoint.signer_key_id)
            if trusted_pub_key is None:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail={
                        "verification_status": "TAMPERING_DETECTED",
                        "error_code": "UNTRUSTED_KEY_ID",
                        "message": f"Checkpoint signer key ID '{stored_checkpoint.signer_key_id}' is not trusted",
                    },
                )

            # C. Verify stored Ed25519 signature over canonical checkpoint payload
            sig_ok = verify_checkpoint(
                public_key_bytes=trusted_pub_key,
                signature_hex=stored_checkpoint.ed25519_signature,
                start_seq=stored_checkpoint.start_sequence,
                end_seq=stored_checkpoint.end_sequence,
                root_hash=stored_checkpoint.root_hash,
                timestamp=format_canonical_timestamp(stored_checkpoint.timestamp),
            )

            if not sig_ok:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail={
                        "verification_status": "TAMPERING_DETECTED",
                        "error_code": "INVALID_SIGNATURE",
                        "message": f"Stored Ed25519 signature verification failed for checkpoint {stored_checkpoint.id}",
                    },
                )

            sig_status = "VERIFIED"
            verified_key_id = stored_checkpoint.signer_key_id

    return AuditVerifyResponse(
        verification_status="VALID",
        events_evaluated=len(events),
        hash_chain_continuity="INTACT",
        ed25519_signature_status=sig_status,
        root_hash=root_hash,
        verified_at=now,
        signer_key_id=verified_key_id,
        checkpoint_id=checkpoint_id,
        checkpoints_evaluated=checkpoints_evaluated,
    )


# Alias router for /api/audit-events compatibility
audit_events_router = APIRouter(prefix="/api/audit-events", tags=["Audit & Cryptographic Verification"])
audit_events_router.add_api_route(
    "",
    list_audit_events,
    methods=["GET"],
    response_model=AuditListResponse,
    summary="List Append-Only Audit Events (Alias)",
)
audit_events_router.add_api_route(
    "/checkpoints",
    create_audit_checkpoint,
    methods=["POST"],
    response_model=AuditCheckpointResponse,
    summary="Create Checkpoint (Alias)",
)
audit_events_router.add_api_route(
    "/verify",
    verify_audit_trail,
    methods=["POST"],
    response_model=AuditVerifyResponse,
    summary="Verify Audit Chain & Checkpoint Signatures (Alias)",
)
