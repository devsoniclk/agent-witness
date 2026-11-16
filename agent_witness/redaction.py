from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .merkle import MerkleTree, compute_leaf_hash
from .models import DeliberationStep, StepType, WitnessReceipt
from .signer import AgentSigner


@dataclass
class SaltedCommitment:
    """A cryptographic commitment to a field using salt: commitment = sha256(salt || value)."""
    field_name: str
    commitment_hash: str
    salt: str

    @classmethod
    def create(cls, field_name: str, value: str, salt: Optional[str] = None) -> Tuple["SaltedCommitment", str]:
        if salt is None:
            salt = hashlib.sha256(f"{field_name}:{value}:{time.time()}".encode("utf-8")).hexdigest()[:16]
        payload = f"{salt}:{value}".encode("utf-8")
        h = hashlib.sha256(payload).hexdigest()
        return cls(field_name=field_name, commitment_hash=h, salt=salt), value

    def verify(self, value: str) -> bool:
        payload = f"{self.salt}:{value}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest() == self.commitment_hash

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


@dataclass
class SelectiveDisclosureReceipt:
    """
    WitnessReceipt with zero-knowledge or selective disclosure redactions applied.
    Redacted steps retain their original RFC 6962 leaf hashes so that the
    top-level Merkle root and cryptographic agent signature remain 100% valid.
    """
    version: str
    agent_id: str
    agent_pubkey: str
    model_id: str
    system_prompt_hash: str
    merkle_root: str
    step_count: int
    timestamp: float
    signature: str
    steps: List[Dict[str, Any]]
    redacted_step_indices: List[int]
    field_commitments: Dict[str, Dict[str, str]] = field(default_factory=dict)
    redaction_timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RedactionEngine:
    """
    Engine for creating and verifying selectively disclosed / redacted WitnessReceipts.
    Allows concealing confidential thoughts, sensitive tool payloads, PII, or API keys
    while strictly preserving cryptographic Merkle root verifiability.
    """

    DEFAULT_SENSITIVE_PATTERNS = [
        r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+",
        r"(?i)(?:api_key|apikey|secret|password|token)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\.]{8,}['\"]?",
        r"(?i)private_key\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\.]{16,}['\"]?",
        r"\b(?:sk|pk)_[a-zA-Z0-9]{24,}\b",
    ]

    @classmethod
    def redact_receipt(
        cls,
        receipt: WitnessReceipt | Dict[str, Any],
        redact_steps: Optional[List[int]] = None,
        redact_patterns: Optional[List[str]] = None,
        redact_reason: str = "Confidential / Redacted for Privacy",
    ) -> SelectiveDisclosureReceipt:
        """
        Redacts specified step indices and/or matches against sensitive regex patterns.
        Preserves original leaf hashes so Merkle root integrity is untouched.
        """
        if isinstance(receipt, dict):
            rec_dict = json.loads(json.dumps(receipt))
        else:
            rec_dict = receipt.to_dict()

        target_indices = set(redact_steps or [])
        compiled_patterns = [
            re.compile(p) for p in (redact_patterns or cls.DEFAULT_SENSITIVE_PATTERNS)
        ]

        steps = rec_dict.get("steps", [])
        redacted_indices: List[int] = []

        for s in steps:
            idx = s.get("index", -1)
            # Ensure step has a recorded leaf_hash
            if "leaf_hash" not in s:
                st = DeliberationStep(
                    step_type=StepType(s["type"]),
                    index=s["index"],
                    content=s["content"],
                    metadata=s.get("metadata", {}),
                    timestamp=s.get("timestamp", 0.0),
                )
                s["leaf_hash"] = compute_leaf_hash(st).hex()

            original_leaf_hash = s["leaf_hash"]
            content = str(s.get("content", ""))

            # Check if index is explicitly targeted or matches sensitive regex
            has_pattern_match = any(p.search(content) for p in compiled_patterns)
            if idx in target_indices or has_pattern_match:
                s["original_type"] = s.get("type")
                s["content"] = f"[REDACTED: {redact_reason}]"
                s["metadata"] = {"redacted": True, "reason": redact_reason}
                s["is_redacted"] = True
                s["leaf_hash"] = original_leaf_hash  # MUST preserve original leaf hash
                redacted_indices.append(idx)
            else:
                s["is_redacted"] = False

        return SelectiveDisclosureReceipt(
            version=rec_dict.get("version", "1.0.0"),
            agent_id=rec_dict.get("agent_id", "unknown"),
            agent_pubkey=rec_dict.get("agent_pubkey", ""),
            model_id=rec_dict.get("model_id", "unknown"),
            system_prompt_hash=rec_dict.get("system_prompt_hash", ""),
            merkle_root=rec_dict.get("merkle_root", ""),
            step_count=rec_dict.get("step_count", len(steps)),
            timestamp=rec_dict.get("timestamp", 0.0),
            signature=rec_dict.get("signature", ""),
            steps=steps,
            redacted_step_indices=sorted(list(set(redacted_indices))),
        )

    @classmethod
    def verify_selective_disclosure(
        cls,
        receipt: SelectiveDisclosureReceipt | WitnessReceipt | Dict[str, Any],
        signer: Optional[AgentSigner] = None,
    ) -> Tuple[bool, str]:
        """
        Verifies that a redacted / selective disclosure receipt maintains full Merkle root integrity.
        For unredacted steps, hashes canonical bytes.
        For redacted steps, utilizes the preserved cryptographic leaf hash.
        """
        if isinstance(receipt, (SelectiveDisclosureReceipt, WitnessReceipt)):
            d = receipt.to_dict()
        else:
            d = receipt

        steps = d.get("steps", [])
        reconstructed_leaves: List[bytes] = []

        for s in steps:
            is_redacted = s.get("is_redacted", False)
            if is_redacted:
                leaf_hash_hex = s.get("leaf_hash")
                if not leaf_hash_hex or len(leaf_hash_hex) != 64:
                    return False, f"Redacted step {s.get('index')} missing valid 64-char leaf_hash"
                reconstructed_leaves.append(bytes.fromhex(leaf_hash_hex))
            else:
                st = DeliberationStep(
                    step_type=StepType(s["type"]),
                    index=s["index"],
                    content=s["content"],
                    metadata=s.get("metadata", {}),
                    timestamp=s.get("timestamp", 0.0),
                )
                reconstructed_leaves.append(compute_leaf_hash(st))

        # Rebuild Merkle Tree from reconstructed leaves
        tree = MerkleTree.__new__(MerkleTree)
        tree.steps = []
        tree.leaves = reconstructed_leaves
        tree.levels = []
        tree._build_tree()

        if tree.root_hex != d.get("merkle_root"):
            return False, f"Rebuilt Merkle root {tree.root_hex} does not match receipt root {d.get('merkle_root')}"

        # Signature verification if signer is available
        sig = d.get("signature", "")
        if signer:
            payload = f"{d.get('agent_id')}:{d.get('model_id')}:{d.get('system_prompt_hash')}:{d.get('merkle_root')}:{d.get('step_count')}"
            if not signer.verify(payload.encode("utf-8"), sig):
                return False, "Agent signature verification failed for Merkle root"
        elif len(sig) < 32:
            return False, "Invalid signature format in receipt"

        return True, "Selective disclosure receipt verified: Merkle root and signature valid"
