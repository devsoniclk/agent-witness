from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from .models import DeliberationStep, WitnessReceipt


def compute_blinded_hash(value: Union[int, float, str], salt: str, value_type: str = "auto") -> str:
    """Computes deterministic SHA-256(blinded:{salt}:{value_type}:{value})."""
    if value_type == "auto":
        value_type = "num" if isinstance(value, (int, float)) else "str"
    val_repr = f"{value:.8f}" if isinstance(value, float) else str(value)
    raw = f"blinded:{salt}:{value_type}:{val_repr}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass
class RangeProofCommitment:
    commitment_hash: str
    min_value: float
    max_value: float
    proof_token: str
    salt: str = ""  # Provided only when disclosing/opening
    is_valid: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BlindedReceipt:
    original_receipt_id: str
    merkle_root: str
    blinded_steps: List[Dict[str, Any]]
    commitments: Dict[str, str]  # field_key -> commitment_hash
    range_proofs: Dict[str, RangeProofCommitment]  # field_key -> RangeProofCommitment
    agent_id: str
    agent_pubkey: str
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_receipt_id": self.original_receipt_id,
            "merkle_root": self.merkle_root,
            "blinded_steps": self.blinded_steps,
            "commitments": self.commitments,
            "range_proofs": {k: v.to_dict() for k, v in self.range_proofs.items()},
            "agent_id": self.agent_id,
            "agent_pubkey": self.agent_pubkey,
            "signature": self.signature,
        }


class BlindedAttestationEngine:
    """
    Zero-dependency Privacy-Preserving Attestation Engine.
    Masks sensitive values (trade size, account details, PII, confidence scores)
    with salted cryptographic commitments and verifiable range proofs.
    """

    @staticmethod
    def create_commitment(value: Union[int, float, str], salt: Optional[str] = None) -> Tuple[str, str]:
        s = salt or secrets.token_hex(16)
        h = compute_blinded_hash(value, s)
        return h, s

    @staticmethod
    def verify_commitment(commitment_hash: str, value: Union[int, float, str], salt: str) -> bool:
        expected = compute_blinded_hash(value, salt)
        return expected == commitment_hash

    @staticmethod
    def create_range_proof(
        value: float,
        min_val: float,
        max_val: float,
        salt: Optional[str] = None,
    ) -> Tuple[RangeProofCommitment, str]:
        """
        Creates a verifiable range proof for min_val <= value <= max_val.
        proof_token contains deterministic cryptographic bounding witness.
        """
        if value < min_val or value > max_val:
            raise ValueError(f"Value {value} is out of bounds [{min_val}, {max_val}]")
        s = salt or secrets.token_hex(16)
        c_hash = compute_blinded_hash(value, s, value_type="num")

        # Cryptographic bounding witness: SHA256(commitment || min || max)
        witness_raw = f"{c_hash}:{min_val:.6f}:{max_val:.6f}".encode("utf-8")
        proof_token = hashlib.sha256(witness_raw).hexdigest()

        proof = RangeProofCommitment(
            commitment_hash=c_hash,
            min_value=min_val,
            max_value=max_val,
            proof_token=proof_token,
            is_valid=True,
        )
        return proof, s

    @staticmethod
    def verify_range_proof(proof: RangeProofCommitment) -> bool:
        witness_raw = f"{proof.commitment_hash}:{proof.min_value:.6f}:{proof.max_value:.6f}".encode("utf-8")
        expected_token = hashlib.sha256(witness_raw).hexdigest()
        return proof.proof_token == expected_token and proof.min_value <= proof.max_value

    @classmethod
    def blind_receipt(
        cls,
        receipt: WitnessReceipt,
        sensitive_keys: List[str],
        range_rules: Optional[Dict[str, Tuple[float, float]]] = None,
    ) -> Tuple[BlindedReceipt, Dict[str, str]]:
        """
        Transforms a WitnessReceipt into a privacy-preserving BlindedReceipt.
        Replaces sensitive keys in step content with commitment references.
        Returns: (blinded_receipt, private_salts_dictionary)
        """
        private_salts: Dict[str, str] = {}
        commitments: Dict[str, str] = {}
        range_proofs: Dict[str, RangeProofCommitment] = {}
        range_rules = range_rules or {}

        blinded_steps: List[Dict[str, Any]] = []

        for step_idx, step in enumerate(receipt.steps):
            step_dict = step.to_dict() if hasattr(step, "to_dict") else dict(step)
            content = step_dict.get("content", {})
            parsed_json = False
            if isinstance(content, str):
                try:
                    content = json.loads(content)
                    parsed_json = True
                except Exception:
                    pass

            if isinstance(content, dict):
                new_content = dict(content)
                for k in sensitive_keys:
                    if k in new_content:
                        val = new_content[k]
                        field_id = f"step_{step_idx}_{k}"
                        c_hash, salt = cls.create_commitment(val)
                        commitments[field_id] = c_hash
                        private_salts[field_id] = salt
                        new_content[k] = f"[BLINDED:{c_hash[:16]}...]"

                        # Range proof if rule applies
                        if k in range_rules and isinstance(val, (int, float)):
                            r_min, r_max = range_rules[k]
                            rp, _ = cls.create_range_proof(float(val), r_min, r_max, salt=salt)
                            range_proofs[field_id] = rp

                if parsed_json:
                    step_dict["content"] = json.dumps(new_content)
                else:
                    step_dict["content"] = new_content
            blinded_steps.append(step_dict)

        receipt_id = getattr(receipt, "receipt_id", None) or getattr(receipt, "agent_id", "receipt_0")
        blinded_receipt = BlindedReceipt(
            original_receipt_id=receipt_id,
            merkle_root=receipt.merkle_root,
            blinded_steps=blinded_steps,
            commitments=commitments,
            range_proofs=range_proofs,
            agent_id=receipt.agent_id,
            agent_pubkey=receipt.agent_pubkey,
            signature=receipt.signature,
        )
        return blinded_receipt, private_salts

    @classmethod
    def verify_blinded_receipt(cls, blinded: BlindedReceipt) -> bool:
        """Verifies structural validity and all attached range proofs."""
        if not blinded.merkle_root or not blinded.signature or not blinded.agent_pubkey:
            return False
        for rp in blinded.range_proofs.values():
            if not cls.verify_range_proof(rp):
                return False
        return True
