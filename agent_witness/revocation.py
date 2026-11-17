from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .merkle import MerkleTree
from .models import WitnessReceipt
from .signer import AgentSigner


class RevocationReason:
    KEY_COMPROMISE = "KEY_COMPROMISE"
    ROGUE_BEHAVIOR = "ROGUE_BEHAVIOR"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    OPERATOR_KILL_SWITCH = "OPERATOR_KILL_SWITCH"
    EXPIRED_DELEGATION = "EXPIRED_DELEGATION"


@dataclass
class RevocationEntry:
    """Cryptographic record of an agent key, credential, or session revocation."""
    entry_id: str
    target_type: str  # "AGENT_PUBKEY", "CREDENTIAL_ID", "SESSION_ID"
    target_identifier: str
    reason: str
    revoked_at: float
    revoked_by_pubkey: str
    emergency_halt: bool
    signature: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def canonical_digest(self) -> str:
        data = {
            "entry_id": self.entry_id,
            "target_type": self.target_type,
            "target_identifier": self.target_identifier,
            "reason": self.reason,
            "revoked_at": f"{self.revoked_at:.4f}",
            "revoked_by_pubkey": self.revoked_by_pubkey,
            "emergency_halt": self.emergency_halt,
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RevocationEntry":
        return cls(
            entry_id=data["entry_id"],
            target_type=data["target_type"],
            target_identifier=data["target_identifier"],
            reason=data["reason"],
            revoked_at=float(data["revoked_at"]),
            revoked_by_pubkey=data["revoked_by_pubkey"],
            emergency_halt=bool(data.get("emergency_halt", False)),
            signature=data["signature"],
            metadata=data.get("metadata", {}),
        )


@dataclass
class NonRevocationAttestation:
    """Cryptographic attestation confirming an agent or credential is not in the revocation registry."""
    target_identifier: str
    revocation_merkle_root: str
    checked_at: float
    is_active: bool
    registry_size: int
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RevocationRegistry:
    """
    Decentralized, tamper-evident cryptographic revocation registry.
    Maintains revocation entries, calculates a Merkle Revocation Root, and issues
    attestations to prevent compromised agents from generating valid receipts.
    """

    def __init__(
        self,
        storage_path: Optional[str | Path] = None,
        authority_signer: Optional[AgentSigner] = None,
    ):
        self.storage_path = Path(storage_path) if storage_path else None
        self.authority_signer = authority_signer or AgentSigner()
        self._entries: Dict[str, RevocationEntry] = {}
        if self.storage_path and self.storage_path.exists():
            self._load()

    def _load(self) -> None:
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data.get("entries", []):
                    entry = RevocationEntry.from_dict(item)
                    self._entries[entry.target_identifier] = entry
        except Exception:
            pass

    def _save(self) -> None:
        if not self.storage_path:
            return
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "revocation_root": self.get_revocation_root(),
            "updated_at": time.time(),
            "entries": [e.to_dict() for e in self._entries.values()],
        }
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def revoke(
        self,
        target_identifier: str,
        target_type: str = "AGENT_PUBKEY",
        reason: str = RevocationReason.OPERATOR_KILL_SWITCH,
        emergency_halt: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RevocationEntry:
        """Publishes a signed revocation notice into the registry."""
        entry_id = f"rev_{uuid.uuid4().hex[:10]}"
        now = time.time()
        raw_preimage = f"{entry_id}:{target_type}:{target_identifier}:{reason}:{now:.4f}:{emergency_halt}"
        sig = self.authority_signer.sign(raw_preimage.encode("utf-8"))

        entry = RevocationEntry(
            entry_id=entry_id,
            target_type=target_type,
            target_identifier=target_identifier,
            reason=reason,
            revoked_at=now,
            revoked_by_pubkey=self.authority_signer.pubkey_hex,
            emergency_halt=emergency_halt,
            signature=sig,
            metadata=metadata or {},
        )
        self._entries[target_identifier] = entry
        self._save()
        return entry

    def is_revoked(self, target_identifier: str) -> Tuple[bool, Optional[RevocationEntry]]:
        """Checks if a target identifier (pubkey, credential id, session id) is revoked."""
        if target_identifier in self._entries:
            return (True, self._entries[target_identifier])
        return (False, None)

    def get_revocation_root(self) -> str:
        """Computes deterministic Merkle root across all active revocation digests."""
        if not self._entries:
            return hashlib.sha256(b"EMPTY_REVOCATION_REGISTRY").hexdigest()
        sorted_keys = sorted(self._entries.keys())
        current = [bytes.fromhex(self._entries[k].canonical_digest()) for k in sorted_keys]
        from .merkle import compute_parent_hash
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                parent = compute_parent_hash(left, right)
                next_level.append(parent)
            current = next_level
        return current[0].hex()

    def attest_non_revocation(self, target_identifier: str) -> NonRevocationAttestation:
        """Issues a signed non-revocation attestation proving the target is active."""
        is_revoked, _ = self.is_revoked(target_identifier)
        root = self.get_revocation_root()
        now = time.time()
        payload = f"{target_identifier}:{root}:{now:.4f}:{not is_revoked}"
        sig = self.authority_signer.sign(payload.encode("utf-8"))

        return NonRevocationAttestation(
            target_identifier=target_identifier,
            revocation_merkle_root=root,
            checked_at=now,
            is_active=not is_revoked,
            registry_size=len(self._entries),
            signature=sig,
        )

    def verify_witness_receipt_active(self, receipt: WitnessReceipt) -> Tuple[bool, Optional[str]]:
        """Verifies that the receipt's signer is not revoked or blacklisted."""
        is_revoked, entry = self.is_revoked(receipt.agent_pubkey)
        if is_revoked and entry:
            return (False, f"Signer pubkey {receipt.agent_pubkey} is revoked: {entry.reason}")

        # Check session_id if present in metadata
        session_id = receipt.agent_id
        is_rev_agent, entry_agent = self.is_revoked(session_id)
        if is_rev_agent and entry_agent:
            return (False, f"Agent ID {session_id} is revoked: {entry_agent.reason}")

        return (True, None)

    def list_entries(self) -> List[RevocationEntry]:
        """Returns all entries in the registry."""
        return list(self._entries.values())
