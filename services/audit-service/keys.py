"""
Bayora Shield - Audit Key Management & Trust Registry
Provides stable Ed25519 signing key management, trusted public key registry,
and key rotation support for audit checkpoints and evidence bundles.

SECURITY & KEY-CUSTODY NOTES:
- Prototype Design:
  Signing keys for development and testing are loaded from configured file paths
  (ED25519_PRIVATE_KEY_PATH), environment variables (BAYORA_ED25519_PRIVATE_KEY_HEX),
  or stable development key material.
- Production Requirement:
  In production, private keys must NEVER reside in application containers or database tables.
  Keys must be held inside a Hardware Security Module (HSM), AWS KMS, or HashiCorp Vault
  Transit engine.
- Key Rotation:
  When a signing key is rotated, the new key becomes active for signing future checkpoints,
  while historical public keys remain in the Trusted Key Registry so previously signed
  checkpoints and evidence bundles remain cryptographically verifiable.
"""

import os
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from services.audit_service.hasher import (
    generate_ed25519_keypair,
    canonical_checkpoint_bytes,
    sign_checkpoint,
    verify_checkpoint,
    format_canonical_timestamp,
)


class KeyRegistry:
    """
    Registry of trusted Ed25519 public keys mapped by key_id.
    Ensures verification only trusts signatures produced by authorized keys.
    """

    def __init__(self):
        self._trusted_keys: Dict[str, bytes] = {}

    def register_trusted_key(self, key_id: str, public_key_bytes: bytes) -> None:
        """Registers a public key as trusted for verification."""
        if not key_id:
            raise ValueError("key_id cannot be empty")
        if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
            raise ValueError(
                f"Invalid Ed25519 public key bytes length: "
                f"{len(public_key_bytes) if isinstance(public_key_bytes, bytes) else 'not bytes'}"
            )
        self._trusted_keys[key_id] = public_key_bytes

    def get_trusted_key(self, key_id: str) -> Optional[bytes]:
        """Retrieves a trusted public key by key_id, or None if untrusted."""
        return self._trusted_keys.get(key_id)

    def is_trusted(self, key_id: str) -> bool:
        """Returns True if the key_id is registered in the trusted registry."""
        return key_id in self._trusted_keys

    def revoke_key(self, key_id: str) -> bool:
        """Revokes a key from the trusted registry."""
        if key_id in self._trusted_keys:
            del self._trusted_keys[key_id]
            return True
        return False

    def list_trusted_key_ids(self) -> list:
        """Returns list of currently trusted key identifiers."""
        return list(self._trusted_keys.keys())


# Global singleton instance of KeyRegistry
key_registry = KeyRegistry()

# Standard Key Identifiers
DEFAULT_KEY_ID = "bayora-ed25519-v1"

# Documented development keypair (used as stable baseline for local dev/testing)
_DEFAULT_DEV_PRIV_HEX = "49f4862a7daeefd2c0ebf32de4c493d9a8de36c1a70ac1e048d3d489f33599f5"
_DEFAULT_DEV_PUB_HEX = "5c922fe49c35afa52ef2cd145920bad1da523b80066e8a579f8f0bc09775360c"

# Active signing state
_ACTIVE_KEY_ID: str = DEFAULT_KEY_ID
_ACTIVE_PRIVATE_KEY: Optional[bytes] = None
_ACTIVE_PUBLIC_KEY: Optional[bytes] = None


def init_key_management(
    key_id: str = DEFAULT_KEY_ID,
    private_key_path: Optional[str] = None,
    public_key_path: Optional[str] = None,
) -> Tuple[str, bytes, bytes]:
    """
    Initializes stable signing key material and registers the public key.
    Prioritizes:
    1. Explicit file paths if provided and readable.
    2. Environment variable hex strings (BAYORA_ED25519_PRIVATE_KEY_HEX).
    3. Stable development keypair registered into KeyRegistry.
    """
    global _ACTIVE_KEY_ID, _ACTIVE_PRIVATE_KEY, _ACTIVE_PUBLIC_KEY

    priv_bytes: Optional[bytes] = None
    pub_bytes: Optional[bytes] = None

    # 1. Check environment variable hex override
    env_priv_hex = os.environ.get("BAYORA_ED25519_PRIVATE_KEY_HEX")
    env_pub_hex = os.environ.get("BAYORA_ED25519_PUBLIC_KEY_HEX")
    if env_priv_hex and env_pub_hex:
        try:
            priv_bytes = bytes.fromhex(env_priv_hex)
            pub_bytes = bytes.fromhex(env_pub_hex)
        except Exception:
            priv_bytes, pub_bytes = None, None

    # 2. Check explicit key paths if present
    if not priv_bytes and private_key_path and os.path.isfile(private_key_path):
        try:
            with open(private_key_path, "rb") as f:
                raw_priv = f.read()
            if len(raw_priv) == 32:
                priv_bytes = raw_priv
            else:
                priv_key_obj = serialization.load_pem_private_key(raw_priv, password=None)
                priv_bytes = priv_key_obj.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            if public_key_path and os.path.isfile(public_key_path):
                with open(public_key_path, "rb") as f:
                    raw_pub = f.read()
                if len(raw_pub) == 32:
                    pub_bytes = raw_pub
                else:
                    pub_key_obj = serialization.load_pem_public_key(raw_pub)
                    pub_bytes = pub_key_obj.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
            else:
                # Derive public key from private key
                priv_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
                pub_bytes = priv_key_obj.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
        except Exception:
            priv_bytes, pub_bytes = None, None

    # 3. Fallback to documented stable development keypair
    if not priv_bytes:
        priv_bytes = bytes.fromhex(_DEFAULT_DEV_PRIV_HEX)
        pub_bytes = bytes.fromhex(_DEFAULT_DEV_PUB_HEX)

    _ACTIVE_KEY_ID = key_id
    _ACTIVE_PRIVATE_KEY = priv_bytes
    _ACTIVE_PUBLIC_KEY = pub_bytes

    # Register into trusted key registry
    key_registry.register_trusted_key(key_id, pub_bytes)

    return _ACTIVE_KEY_ID, _ACTIVE_PRIVATE_KEY, _ACTIVE_PUBLIC_KEY


def get_active_signing_key() -> Tuple[str, bytes, bytes]:
    """Returns the current active (key_id, private_key_bytes, public_key_bytes)."""
    global _ACTIVE_KEY_ID, _ACTIVE_PRIVATE_KEY, _ACTIVE_PUBLIC_KEY
    if _ACTIVE_PRIVATE_KEY is None or _ACTIVE_PUBLIC_KEY is None:
        init_key_management()
    return _ACTIVE_KEY_ID, _ACTIVE_PRIVATE_KEY, _ACTIVE_PUBLIC_KEY  # type: ignore


def rotate_signing_key(new_key_id: str) -> Tuple[str, bytes, bytes]:
    """
    Rotates the active signing key to a new Ed25519 keypair.
    The previous key remains in KeyRegistry so historic checkpoints still verify.
    """
    global _ACTIVE_KEY_ID, _ACTIVE_PRIVATE_KEY, _ACTIVE_PUBLIC_KEY
    new_priv, new_pub = generate_ed25519_keypair()
    _ACTIVE_KEY_ID = new_key_id
    _ACTIVE_PRIVATE_KEY = new_priv
    _ACTIVE_PUBLIC_KEY = new_pub
    key_registry.register_trusted_key(new_key_id, new_pub)
    return new_key_id, new_priv, new_pub


# Initialize default keypair on import
init_key_management()
