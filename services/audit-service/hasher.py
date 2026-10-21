"""
Bayora Shield - Audit Service Cryptographic Engine
Implements canonical JSON serialization, SHA-256 hash chaining, sequential numbering,
tamper detection, and Ed25519 asymmetric checkpoint signing and verification.

SECURITY BOUNDARY NOTE:
A cryptographic hash chain alone guarantees link-to-link continuity, but does NOT prevent
an attacker with full database write access from recalculating and rewriting an entire alternate
branch of history, nor does it alone prove that events were not truncated at the head or tail.
To mitigate history-rewriting, Bayora Shield combines the SHA-256 chain with periodic Ed25519
digital signatures of checkpoints, where private signing keys are held strictly outside
ordinary application database tables and worker containers.
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Dict, Any, Tuple, List, Union
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def format_canonical_timestamp(dt: Union[datetime, str]) -> str:
    """Formats a datetime or string into a deterministic canonical UTC timestamp string."""
    if isinstance(dt, str):
        # Normalize strings
        cleaned = dt.replace("Z", "+00:00")
        try:
            dt_obj = datetime.fromisoformat(cleaned)
        except Exception:
            return dt
        return format_canonical_timestamp(dt_obj)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compute_payload_digest(raw_content: str) -> str:
    """Calculates hex SHA-256 digest of payload content."""
    return hashlib.sha256(raw_content.encode("utf-8")).hexdigest()


def compute_event_hash(
    previous_hash: str,
    sequence_number: int,
    event_id: str,
    actor: str,
    action: str,
    resource: str,
    decision: str,
    iso_timestamp: str,
    policy_version: str,
    payload_digest: str,
) -> str:
    """
    Computes deterministic SHA-256 digest of an audit event over sorted canonical JSON.
    """
    canonical_ts = format_canonical_timestamp(iso_timestamp)
    payload = {
        "action": action,
        "actor": actor,
        "decision": decision,
        "event_id": event_id,
        "payload_digest": payload_digest,
        "policy_version": policy_version,
        "previous_hash": previous_hash,
        "resource": resource,
        "sequence_number": sequence_number,
        "timestamp": canonical_ts,
    }
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def verify_chain(events: List[Dict[str, Any]]) -> Tuple[bool, int, str]:
    """
    Verifies unbroken mathematical continuity of a sequence of audit events.
    Returns: (is_valid, broken_sequence_number, detail_message)
    """
    if not events:
        return True, 0, "Empty chain is trivially valid"

    for i, event in enumerate(events):
        seq = event["sequence_number"]
        if i == 0:
            expected_prev = event.get("previous_hash")
            if not expected_prev or len(expected_prev) != 64:
                return (
                    False,
                    seq,
                    f"Genesis discontinuity at sequence {seq}: invalid previous_hash format",
                )
        else:
            prev_event = events[i - 1]
            expected_prev = prev_event["event_hash"]
            if event["previous_hash"] != expected_prev:
                return (
                    False,
                    seq,
                    f"Discontinuity at sequence {seq}: previous_hash '{event['previous_hash']}' != expected '{expected_prev}'",
                )

        # Recalculate event hash
        calculated_hash = compute_event_hash(
            previous_hash=event["previous_hash"],
            sequence_number=event["sequence_number"],
            event_id=event["event_id"],
            actor=event["actor"],
            action=event["action"],
            resource=event["resource"],
            decision=event["decision"],
            iso_timestamp=event["timestamp"],
            policy_version=event.get("policy_version", "unknown"),
            payload_digest=event.get("payload_digest", ""),
        )

        if calculated_hash != event["event_hash"]:
            return (
                False,
                seq,
                f"Tampering detected at sequence {seq}: stored hash '{event['event_hash']}' != recomputed hash '{calculated_hash}'",
            )

    return True, 0, "Chain continuity verified"


# ------------------------------------------------------------------------------
# Ed25519 Checkpoint Signing & Verification
# ------------------------------------------------------------------------------

def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """Generates a new Ed25519 private/public keypair in raw 32-byte format."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def canonical_checkpoint_bytes(
    start_seq: int,
    end_seq: int,
    root_hash: str,
    timestamp: str,
) -> bytes:
    """Serializes checkpoint payload canonically before signing/verification."""
    payload = {
        "end_seq": end_seq,
        "root_hash": root_hash,
        "start_seq": start_seq,
        "timestamp": format_canonical_timestamp(timestamp),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_checkpoint(
    private_key_bytes: bytes,
    start_seq: int,
    end_seq: int,
    root_hash: str,
    timestamp: str,
) -> str:
    """Signs an audit checkpoint using an Ed25519 private key, returning hex signature."""
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    data = canonical_checkpoint_bytes(start_seq, end_seq, root_hash, timestamp)
    signature = private_key.sign(data)
    return signature.hex()


def verify_checkpoint(
    public_key_bytes: bytes,
    signature_hex: str,
    start_seq: int,
    end_seq: int,
    root_hash: str,
    timestamp: str,
) -> bool:
    """
    Verifies an Ed25519 signature over canonical checkpoint data.
    Returns True if valid, False if signature or data has been modified.
    """
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        signature = bytes.fromhex(signature_hex)
        data = canonical_checkpoint_bytes(start_seq, end_seq, root_hash, timestamp)
        public_key.verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False
