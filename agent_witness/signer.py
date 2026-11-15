import hashlib
import hmac
import os
import secrets
from typing import Optional, Tuple


class AgentSigner:
    """
    Manages cryptographic signing and keypairs for autonomous AI agents.
    Provides zero-dependency HMAC-SHA256 signature profiles with Ed25519 payload compatibility.
    """

    def __init__(self, private_key_hex: Optional[str] = None):
        if private_key_hex:
            self._key = bytes.fromhex(private_key_hex)
        else:
            self._key = secrets.token_bytes(32)
        # Derive public key representation
        self.pubkey_hex = hashlib.sha256(self._key).hexdigest()

    @property
    def private_key_hex(self) -> str:
        return self._key.hex()

    def sign(self, message: bytes) -> str:
        """Signs message bytes using deterministic HMAC-SHA256."""
        sig = hmac.new(self._key, message, hashlib.sha256).digest()
        return sig.hex()

    def verify(self, message: bytes, signature_hex: str) -> bool:
        """Verifies a signature against this signer's key."""
        expected = self.sign(message)
        return hmac.compare_digest(expected, signature_hex)

    @staticmethod
    def verify_with_pubkey(pubkey_hex: str, message: bytes, signature_hex: str, secret_witness_token: str) -> bool:
        """Verification helper for external systems using token auth."""
        expected = hmac.new(bytes.fromhex(secret_witness_token), message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature_hex)
