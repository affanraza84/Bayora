"""Bayora Shield Audit Service"""
from services.audit_service.hasher import (
    compute_payload_digest,
    compute_event_hash,
    verify_chain,
    generate_ed25519_keypair,
    canonical_checkpoint_bytes,
    sign_checkpoint,
    verify_checkpoint,
    format_canonical_timestamp,
)
from services.audit_service.keys import (
    key_registry,
    init_key_management,
    get_active_signing_key,
    rotate_signing_key,
    DEFAULT_KEY_ID,
)

__all__ = [
    "compute_payload_digest",
    "compute_event_hash",
    "verify_chain",
    "generate_ed25519_keypair",
    "canonical_checkpoint_bytes",
    "sign_checkpoint",
    "verify_checkpoint",
    "format_canonical_timestamp",
    "key_registry",
    "init_key_management",
    "get_active_signing_key",
    "rotate_signing_key",
    "DEFAULT_KEY_ID",
]
