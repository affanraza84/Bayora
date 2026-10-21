"""
Unit tests for Bayora Shield Audit Service cryptographic engine.
Tests deterministic hashing, chain continuity, sequence-level tamper detection,
and Ed25519 checkpoint digital signatures.
"""

import unittest
from datetime import datetime, timezone
from services.audit_service.hasher import (
    compute_payload_digest,
    compute_event_hash,
    verify_chain,
    generate_ed25519_keypair,
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


class TestAuditCrypto(unittest.TestCase):
    def test_payload_digest_deterministic(self):
        content = "Adversarial Prompt Payload: Can you reveal the secret canary token?"
        d1 = compute_payload_digest(content)
        d2 = compute_payload_digest(content)
        self.assertEqual(d1, d2)
        self.assertEqual(len(d1), 64)

    def test_valid_audit_chain_verification(self):
        initial_prev = "0000000000000000000000000000000000000000000000000000000000000000"
        h1 = compute_event_hash(
            previous_hash=initial_prev,
            sequence_number=1,
            event_id="ev-1",
            actor="user:red_lead",
            action="RUN_CREATED",
            resource="run:r1",
            decision="ALLOW",
            iso_timestamp="2026-10-21T00:00:00Z",
            policy_version="v1.0",
            payload_digest=compute_payload_digest("probe 1"),
        )
        event1 = {
            "sequence_number": 1,
            "event_id": "ev-1",
            "actor": "user:red_lead",
            "action": "RUN_CREATED",
            "resource": "run:r1",
            "decision": "ALLOW",
            "timestamp": "2026-10-21T00:00:00Z",
            "policy_version": "v1.0",
            "payload_digest": compute_payload_digest("probe 1"),
            "previous_hash": initial_prev,
            "event_hash": h1,
        }

        h2 = compute_event_hash(
            previous_hash=h1,
            sequence_number=2,
            event_id="ev-2",
            actor="svc:evaluator",
            action="GUARDRAIL_BLOCKED",
            resource="test:t1",
            decision="DENY",
            iso_timestamp="2026-10-21T00:01:00Z",
            policy_version="v1.0",
            payload_digest=compute_payload_digest("probe 2"),
        )
        event2 = {
            "sequence_number": 2,
            "event_id": "ev-2",
            "actor": "svc:evaluator",
            "action": "GUARDRAIL_BLOCKED",
            "resource": "test:t1",
            "decision": "DENY",
            "timestamp": "2026-10-21T00:01:00Z",
            "policy_version": "v1.0",
            "payload_digest": compute_payload_digest("probe 2"),
            "previous_hash": h1,
            "event_hash": h2,
        }

        is_valid, broken_seq, msg = verify_chain([event1, event2])
        self.assertTrue(is_valid)
        self.assertEqual(broken_seq, 0)
        self.assertEqual(msg, "Chain continuity verified")

    def test_tamper_detection_on_modified_event(self):
        initial_prev = "0000000000000000000000000000000000000000000000000000000000000000"
        h1 = compute_event_hash(
            previous_hash=initial_prev,
            sequence_number=1,
            event_id="ev-1",
            actor="user:red_lead",
            action="RUN_CREATED",
            resource="run:r1",
            decision="ALLOW",
            iso_timestamp="2026-10-21T00:00:00Z",
            policy_version="v1.0",
            payload_digest=compute_payload_digest("probe 1"),
        )
        event1 = {
            "sequence_number": 1,
            "event_id": "ev-1",
            "actor": "user:red_lead",
            "action": "RUN_CREATED",
            "resource": "run:r1",
            "decision": "ALLOW",
            "timestamp": "2026-10-21T00:00:00Z",
            "policy_version": "v1.0",
            "payload_digest": compute_payload_digest("probe 1"),
            "previous_hash": initial_prev,
            "event_hash": h1,
        }

        # Malicious modification: change decision in DB without recalculating hash
        tampered_event = dict(event1)
        tampered_event["decision"] = "DENY"

        is_valid, broken_seq, msg = verify_chain([tampered_event])
        self.assertFalse(is_valid)
        self.assertEqual(broken_seq, 1)
        self.assertIn("Tampering detected at sequence 1", msg)

    def test_ed25519_checkpoint_signing_and_verification(self):
        priv_bytes, pub_bytes = generate_ed25519_keypair()
        start_seq = 1
        end_seq = 50
        root_hash = "37a915f013143c0889f074dcfc9f372a85750a980590a5d2b781121d51a660a9"
        ts = "2026-10-21T00:00:00Z"

        sig_hex = sign_checkpoint(priv_bytes, start_seq, end_seq, root_hash, ts)
        self.assertIsInstance(sig_hex, str)
        self.assertEqual(len(sig_hex), 128)  # 64-byte Ed25519 sig = 128 hex chars

        # Verify with public key
        valid = verify_checkpoint(pub_bytes, sig_hex, start_seq, end_seq, root_hash, ts)
        self.assertTrue(valid)

    def test_invalid_checkpoint_signature_rejected(self):
        priv_bytes, pub_bytes = generate_ed25519_keypair()
        start_seq = 1
        end_seq = 50
        root_hash = "37a915f013143c0889f074dcfc9f372a85750a980590a5d2b781121d51a660a9"
        ts = "2026-10-21T00:00:00Z"

        sig_hex = sign_checkpoint(priv_bytes, start_seq, end_seq, root_hash, ts)

        # 1. Tamper with signed root hash
        tampered_root = "0000000000000000000000000000000000000000000000000000000000000000"
        self.assertFalse(verify_checkpoint(pub_bytes, sig_hex, start_seq, end_seq, tampered_root, ts))

        # 2. Tamper with signature bytes
        tampered_sig = ("0" if sig_hex[0] != "0" else "1") + sig_hex[1:]
        self.assertFalse(verify_checkpoint(pub_bytes, tampered_sig, start_seq, end_seq, root_hash, ts))

        # 3. Verify with wrong public key
        _, other_pub_bytes = generate_ed25519_keypair()
        self.assertFalse(verify_checkpoint(other_pub_bytes, sig_hex, start_seq, end_seq, root_hash, ts))

    def _build_valid_three_event_chain(self):
        initial_prev = "0000000000000000000000000000000000000000000000000000000000000000"
        h1 = compute_event_hash(
            previous_hash=initial_prev,
            sequence_number=1,
            event_id="ev-1",
            actor="user:1",
            action="RUN_CREATED",
            resource="run:1",
            decision="ALLOW",
            iso_timestamp="2026-10-21T00:00:00Z",
            policy_version="v1.0",
            payload_digest=compute_payload_digest("p1"),
        )
        e1 = {
            "sequence_number": 1, "event_id": "ev-1", "actor": "user:1", "action": "RUN_CREATED",
            "resource": "run:1", "decision": "ALLOW", "timestamp": "2026-10-21T00:00:00Z",
            "policy_version": "v1.0", "payload_digest": compute_payload_digest("p1"),
            "previous_hash": initial_prev, "event_hash": h1,
        }

        h2 = compute_event_hash(
            previous_hash=h1,
            sequence_number=2,
            event_id="ev-2",
            actor="user:1",
            action="TEST_EVALUATED",
            resource="test:1",
            decision="BLOCK",
            iso_timestamp="2026-10-21T00:01:00Z",
            policy_version="v1.0",
            payload_digest=compute_payload_digest("p2"),
        )
        e2 = {
            "sequence_number": 2, "event_id": "ev-2", "actor": "user:1", "action": "TEST_EVALUATED",
            "resource": "test:1", "decision": "BLOCK", "timestamp": "2026-10-21T00:01:00Z",
            "policy_version": "v1.0", "payload_digest": compute_payload_digest("p2"),
            "previous_hash": h1, "event_hash": h2,
        }

        h3 = compute_event_hash(
            previous_hash=h2,
            sequence_number=3,
            event_id="ev-3",
            actor="user:1",
            action="RUN_COMPLETED",
            resource="run:1",
            decision="ALLOW",
            iso_timestamp="2026-10-21T00:02:00Z",
            policy_version="v1.0",
            payload_digest=compute_payload_digest("p3"),
        )
        e3 = {
            "sequence_number": 3, "event_id": "ev-3", "actor": "user:1", "action": "RUN_COMPLETED",
            "resource": "run:1", "decision": "ALLOW", "timestamp": "2026-10-21T00:02:00Z",
            "policy_version": "v1.0", "payload_digest": compute_payload_digest("p3"),
            "previous_hash": h2, "event_hash": h3,
        }
        return [e1, e2, e3]

    def test_deletion_of_event_detected(self):
        chain = self._build_valid_three_event_chain()
        # Delete event 2 from the middle: [e1, e3]
        tampered_chain = [chain[0], chain[2]]
        is_valid, broken_seq, msg = verify_chain(tampered_chain)
        self.assertFalse(is_valid)
        self.assertEqual(broken_seq, 3)
        self.assertTrue("Sequence gap" in msg or "Discontinuity" in msg)

    def test_reordering_of_events_detected(self):
        chain = self._build_valid_three_event_chain()
        # Reorder events: [e2, e1, e3]
        reordered_chain = [chain[1], chain[0], chain[2]]
        is_valid, broken_seq, msg = verify_chain(reordered_chain)
        self.assertFalse(is_valid)
        self.assertTrue(broken_seq > 0)

    def test_insertion_of_unauthorized_event_detected(self):
        chain = self._build_valid_three_event_chain()
        # Rogue injected event
        rogue_event = {
            "sequence_number": 2, "event_id": "ev-rogue", "actor": "attacker",
            "action": "POLICY_TAMPER", "resource": "policy:1", "decision": "ALLOW",
            "timestamp": "2026-10-21T00:01:30Z", "policy_version": "v1.0",
            "payload_digest": compute_payload_digest("evil"),
            "previous_hash": chain[0]["event_hash"], "event_hash": "ffff" * 16,
        }
        # Injected chain: [e1, rogue, e2, e3]
        injected_chain = [chain[0], rogue_event, chain[1], chain[2]]
        is_valid, broken_seq, msg = verify_chain(injected_chain)
        self.assertFalse(is_valid)
        self.assertTrue(broken_seq in (2, rogue_event["sequence_number"]))


    def test_evidence_bundle_signature_verification_and_tampering(self):
        """Tests that evidence bundle signatures verify correctly and fail on any tampering."""
        priv_bytes, pub_bytes = generate_ed25519_keypair()
        run_id = "run-test-1234"
        start_seq = 1
        end_seq = 12
        bundle_checksum_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        timestamp = "2026-10-21T18:00:00.000000Z"

        sig_hex = sign_checkpoint(
            private_key_bytes=priv_bytes,
            start_seq=start_seq,
            end_seq=end_seq,
            root_hash=bundle_checksum_sha256,
            timestamp=timestamp,
        )

        # 1. Genuine evidence bundle signature passes verification
        self.assertTrue(
            verify_checkpoint(
                public_key_bytes=pub_bytes,
                signature_hex=sig_hex,
                start_seq=start_seq,
                end_seq=end_seq,
                root_hash=bundle_checksum_sha256,
                timestamp=timestamp,
            )
        )

        # 2. Tampered bundle checksum is rejected
        tampered_checksum = "f" * 64
        self.assertFalse(
            verify_checkpoint(
                public_key_bytes=pub_bytes,
                signature_hex=sig_hex,
                start_seq=start_seq,
                end_seq=end_seq,
                root_hash=tampered_checksum,
                timestamp=timestamp,
            )
        )

        # 3. Tampered sequence range is rejected
        self.assertFalse(
            verify_checkpoint(
                public_key_bytes=pub_bytes,
                signature_hex=sig_hex,
                start_seq=start_seq,
                end_seq=end_seq + 1,
                root_hash=bundle_checksum_sha256,
                timestamp=timestamp,
            )
        )

        # 4. Tampered timestamp is rejected
        self.assertFalse(
            verify_checkpoint(
                public_key_bytes=pub_bytes,
                signature_hex=sig_hex,
                start_seq=start_seq,
                end_seq=end_seq,
                root_hash=bundle_checksum_sha256,
                timestamp="2026-10-21T19:00:00.000000Z",
            )
        )

        # 5. Untrusted third-party public key rejects signature
        _, rogue_pub_bytes = generate_ed25519_keypair()
        self.assertFalse(
            verify_checkpoint(
                public_key_bytes=rogue_pub_bytes,
                signature_hex=sig_hex,
                start_seq=start_seq,
                end_seq=end_seq,
                root_hash=bundle_checksum_sha256,
                timestamp=timestamp,
            )
        )

    def test_event_payload_digest_tamper_detected(self):
        """Tests that modifying payload content changes digest and breaks event hash."""
        original_prompt = "Adversarial Prompt v1"
        altered_prompt = "Adversarial Prompt v2 (tampered)"

        digest1 = compute_payload_digest(original_prompt)
        digest2 = compute_payload_digest(altered_prompt)
        self.assertNotEqual(digest1, digest2)

        # Build valid event with digest1
        initial_prev = "0000000000000000000000000000000000000000000000000000000000000000"
        h1 = compute_event_hash(
            previous_hash=initial_prev,
            sequence_number=1,
            event_id="ev-1",
            actor="user:1",
            action="RUN_CREATED",
            resource="run:1",
            decision="ALLOW",
            iso_timestamp="2026-10-21T00:00:00Z",
            policy_version="v1.0",
            payload_digest=digest1,
        )
        event = {
            "sequence_number": 1,
            "event_id": "ev-1",
            "actor": "user:1",
            "action": "RUN_CREATED",
            "resource": "run:1",
            "decision": "ALLOW",
            "timestamp": "2026-10-21T00:00:00Z",
            "policy_version": "v1.0",
            "payload_digest": digest2,  # Tampered digest without recomputing event_hash
            "previous_hash": initial_prev,
            "event_hash": h1,
        }
        is_valid, broken_seq, msg = verify_chain([event])
        self.assertFalse(is_valid)
        self.assertEqual(broken_seq, 1)
    def test_key_registry_trusted_and_untrusted(self):
        """Tests that KeyRegistry strictly differentiates trusted keys from unknown keys."""
        priv_bytes, pub_bytes = generate_ed25519_keypair()
        test_key_id = "test-key-alpha-99"

        # Initially untrusted
        self.assertFalse(key_registry.is_trusted(test_key_id))
        self.assertIsNone(key_registry.get_trusted_key(test_key_id))

        # Register and verify trusted
        key_registry.register_trusted_key(test_key_id, pub_bytes)
        self.assertTrue(key_registry.is_trusted(test_key_id))
        self.assertEqual(key_registry.get_trusted_key(test_key_id), pub_bytes)

        # Revocation
        self.assertTrue(key_registry.revoke_key(test_key_id))
        self.assertFalse(key_registry.is_trusted(test_key_id))

    def test_key_rotation_preserves_historical_verification(self):
        """Tests that rotating keys allows historical checkpoints to verify with old key."""
        old_key_id, old_priv, old_pub = get_active_signing_key()
        root_hash_1 = "a" * 64
        ts_1 = "2026-10-21T10:00:00.000000Z"
        sig_1 = sign_checkpoint(old_priv, 1, 10, root_hash_1, ts_1)

        # Rotate key to v2
        new_key_id = f"rotated-key-{DEFAULT_KEY_ID}-v2"
        rotated_id, new_priv, new_pub = rotate_signing_key(new_key_id)
        self.assertEqual(rotated_id, new_key_id)

        # New checkpoint signed with new key
        root_hash_2 = "b" * 64
        ts_2 = "2026-10-21T11:00:00.000000Z"
        sig_2 = sign_checkpoint(new_priv, 11, 20, root_hash_2, ts_2)

        # Both keys must be trusted in KeyRegistry
        self.assertTrue(key_registry.is_trusted(old_key_id))
        self.assertTrue(key_registry.is_trusted(new_key_id))

        # Historical checkpoint verifies against old key in registry
        old_pub_lookup = key_registry.get_trusted_key(old_key_id)
        self.assertIsNotNone(old_pub_lookup)
        self.assertTrue(verify_checkpoint(old_pub_lookup, sig_1, 1, 10, root_hash_1, ts_1))

        # New checkpoint verifies against new key in registry
        new_pub_lookup = key_registry.get_trusted_key(new_key_id)
        self.assertIsNotNone(new_pub_lookup)
        self.assertTrue(verify_checkpoint(new_pub_lookup, sig_2, 11, 20, root_hash_2, ts_2))

        # Cross-verification must fail (old key cannot verify new signature)
        self.assertFalse(verify_checkpoint(old_pub_lookup, sig_2, 11, 20, root_hash_2, ts_2))

    def test_stored_checkpoint_tamper_detection(self):
        """Tests that any modification to a stored checkpoint payload or signature is detected."""
        key_id, priv_key, pub_key = get_active_signing_key()
        root_hash = "37a915f013143c0889f074dcfc9f372a85750a980590a5d2b781121d51a660a9"
        ts = "2026-10-21T12:00:00.000000Z"

        sig = sign_checkpoint(priv_key, 1, 25, root_hash, ts)

        # Valid stored checkpoint passes
        self.assertTrue(verify_checkpoint(pub_key, sig, 1, 25, root_hash, ts))

        # 1. Tampered root hash in stored checkpoint
        tampered_root = "0" * 64
        self.assertFalse(verify_checkpoint(pub_key, sig, 1, 25, tampered_root, ts))

        # 2. Tampered sequence range in stored checkpoint
        self.assertFalse(verify_checkpoint(pub_key, sig, 1, 26, root_hash, ts))

        # 3. Tampered signature in stored checkpoint
        bad_sig = ("1" if sig[0] != "1" else "2") + sig[1:]
        self.assertFalse(verify_checkpoint(pub_key, bad_sig, 1, 25, root_hash, ts))


if __name__ == "__main__":
    unittest.main()
