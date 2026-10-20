"""
Bayora Shield - Audit Service Cryptographic Engine
Implements canonical JSON serialization and SHA-256 hash chaining.
"""

import hashlib
import json
from typing import Dict, Any, Tuple, List


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
    Computes deterministic SHA-256 digest of an audit event over sorted, canonical JSON.
    """
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
        "timestamp": iso_timestamp,
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
            # First event in batch must have expected format
            expected_prev = event.get("previous_hash")
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
            policy_version=event["policy_version"],
            payload_digest=event["payload_digest"],
        )

        if calculated_hash != event["event_hash"]:
            return (
                False,
                seq,
                f"Tampering detected at sequence {seq}: stored hash '{event['event_hash']}' != recomputed hash '{calculated_hash}'",
            )

    return True, 0, "Chain continuity verified"
