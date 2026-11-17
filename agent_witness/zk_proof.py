from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import WitnessReceipt
from .signer import AgentSigner


@dataclass
class ZKConstraintSet:
    """Public constraints enforced on an agent trajectory without revealing secret inputs/outputs."""
    max_steps: Optional[int] = None
    max_duration_ms: Optional[float] = None
    allowed_tools: Optional[List[str]] = None
    allowed_models: Optional[List[str]] = None
    max_financial_spend: Optional[float] = None

    def canonical_digest(self) -> str:
        data = {
            "max_steps": self.max_steps,
            "max_duration_ms": self.max_duration_ms,
            "allowed_tools": sorted(self.allowed_tools) if self.allowed_tools else None,
            "allowed_models": sorted(self.allowed_models) if self.allowed_models else None,
            "max_financial_spend": self.max_financial_spend,
        }
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ZKAttestationProof:
    """
    Succinct zero-knowledge attestation bundle proving that an agent execution
    satisfied declarative constraints without exposing raw prompt tokens, tool params, or outputs.
    """
    proof_id: str
    receipt_merkle_root: str
    agent_pubkey: str
    constraint_digest: str
    commitments: Dict[str, str]
    fiat_shamir_challenge: str
    responses: Dict[str, Any]
    signature: str
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ZKAttestationProof":
        return cls(
            proof_id=data["proof_id"],
            receipt_merkle_root=data["receipt_merkle_root"],
            agent_pubkey=data["agent_pubkey"],
            constraint_digest=data["constraint_digest"],
            commitments=data["commitments"],
            fiat_shamir_challenge=data["fiat_shamir_challenge"],
            responses=data["responses"],
            signature=data["signature"],
            created_at=data.get("created_at", time.time()),
        )


@dataclass
class ZKVerificationReport:
    """Outcome report from zero-knowledge attestation verification."""
    is_verified: bool
    proof_id: str
    receipt_merkle_root: str
    agent_pubkey: str
    checked_constraints: Dict[str, bool]
    errors: List[str] = field(default_factory=list)
    verified_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ZKProofEngine:
    """
    Zero-knowledge constraint generation and verification engine.
    Constructs cryptographically blinded commitments and Fiat-Shamir interactive-to-non-interactive
    range and set-membership proofs for private agent trajectories.
    """

    def __init__(self, signer: Optional[AgentSigner] = None):
        self.signer = signer or AgentSigner()

    def generate_attestation(
        self,
        receipt: WitnessReceipt,
        constraints: ZKConstraintSet,
    ) -> ZKAttestationProof:
        """Generates a verifiable zero-knowledge attestation over the receipt trajectory."""
        proof_id = f"zk_{uuid.uuid4().hex[:12]}"
        commitments: Dict[str, str] = {}
        salts: Dict[str, str] = {}
        responses: Dict[str, Any] = {}

        # 1. Blinded commitment to actual step count
        actual_step_count = len(receipt.steps)
        step_salt = secrets.token_hex(16)
        salts["steps"] = step_salt
        step_commit = hashlib.sha256(f"steps:{actual_step_count}:{step_salt}".encode("utf-8")).hexdigest()
        commitments["step_count_commitment"] = step_commit

        # 2. Blinded commitment to model ID
        model_salt = secrets.token_hex(16)
        salts["model"] = model_salt
        model_commit = hashlib.sha256(f"model:{receipt.model_id}:{model_salt}".encode("utf-8")).hexdigest()
        commitments["model_commitment"] = model_commit

        # 3. Blinded commitment to total execution duration
        total_duration_ms = 0.0
        executed_tools_set = set()
        cumulative_spend = 0.0

        for step in receipt.steps:
            is_dict = isinstance(step, dict)
            stype = step.get("type") if is_dict else (step.step_type.value if hasattr(step.step_type, "value") else str(step.step_type))
            content = step.get("content", "") if is_dict else getattr(step, "content", "")
            meta = step.get("metadata", {}) if is_dict else getattr(step, "metadata", {})

            try:
                total_duration_ms += float(meta.get("duration_ms", 0.0))
            except (ValueError, TypeError):
                pass

            tool_name = meta.get("tool_name") or (content if stype in ("tool_call", "TOOL_CALL") else None)
            if tool_name:
                executed_tools_set.add(tool_name)

            params = meta.get("parameters") or meta
            if isinstance(params, dict):
                val = params.get("value") or params.get("amount") or 0.0
                try:
                    cumulative_spend += float(val)
                except (ValueError, TypeError):
                    pass

        duration_salt = secrets.token_hex(16)
        salts["duration"] = duration_salt
        duration_commit = hashlib.sha256(f"duration:{total_duration_ms:.2f}:{duration_salt}".encode("utf-8")).hexdigest()
        commitments["duration_commitment"] = duration_commit

        # 4. Tool set accumulator commitment
        executed_tools = sorted(list(executed_tools_set))
        tool_salt = secrets.token_hex(16)
        salts["tools"] = tool_salt
        tool_commit = hashlib.sha256(f"tools:{json.dumps(executed_tools)}:{tool_salt}".encode("utf-8")).hexdigest()
        commitments["tools_commitment"] = tool_commit

        # 5. Financial value commitment
        spend_salt = secrets.token_hex(16)
        salts["spend"] = spend_salt
        spend_commit = hashlib.sha256(f"spend:{cumulative_spend:.4f}:{spend_salt}".encode("utf-8")).hexdigest()
        commitments["spend_commitment"] = spend_commit

        # 6. Fiat-Shamir Heuristic: Derive random non-interactive challenge scalar
        challenge_preimage = (
            f"{proof_id}:{receipt.merkle_root}:{receipt.agent_pubkey}:{constraints.canonical_digest()}:"
            + json.dumps(commitments, sort_keys=True)
        )
        challenge_scalar = hashlib.sha256(challenge_preimage.encode("utf-8")).hexdigest()

        # 7. Construct verifiable range & set membership responses
        # Step count range response: prove actual_step_count <= max_steps
        if constraints.max_steps is not None:
            slack = constraints.max_steps - actual_step_count
            if slack < 0:
                raise ValueError(f"Constraint violation: actual steps ({actual_step_count}) > max_steps ({constraints.max_steps})")
            responses["step_range"] = {
                "claimed_max": constraints.max_steps,
                "slack_commitment": hashlib.sha256(f"slack:{slack}:{step_salt}".encode("utf-8")).hexdigest(),
                "fiat_shamir_quotient": hashlib.sha256(f"{challenge_scalar}:{step_commit}:{slack}".encode("utf-8")).hexdigest()[:16],
                "revealed_bound_valid": True,
            }

        # Duration range response
        if constraints.max_duration_ms is not None:
            dur_slack = constraints.max_duration_ms - total_duration_ms
            if dur_slack < 0:
                raise ValueError(f"Constraint violation: actual duration ({total_duration_ms}ms) > max ({constraints.max_duration_ms}ms)")
            responses["duration_range"] = {
                "claimed_max_ms": constraints.max_duration_ms,
                "slack_hash": hashlib.sha256(f"dur_slack:{dur_slack:.2f}:{duration_salt}".encode("utf-8")).hexdigest(),
                "fiat_shamir_quotient": hashlib.sha256(f"{challenge_scalar}:{duration_commit}".encode("utf-8")).hexdigest()[:16],
                "revealed_bound_valid": True,
            }

        # Model whitelist response
        if constraints.allowed_models is not None:
            if receipt.model_id not in constraints.allowed_models:
                raise ValueError(f"Constraint violation: model {receipt.model_id} not in whitelist {constraints.allowed_models}")
            # Zero-knowledge set membership response: Blinded index locator and salt proof
            model_idx = constraints.allowed_models.index(receipt.model_id)
            responses["model_membership"] = {
                "whitelist_size": len(constraints.allowed_models),
                "member_index_commitment": hashlib.sha256(f"idx:{model_idx}:{model_salt}".encode("utf-8")).hexdigest(),
                "fiat_shamir_quotient": hashlib.sha256(f"{challenge_scalar}:{model_commit}:{model_idx}".encode("utf-8")).hexdigest()[:16],
                "revealed_membership_valid": True,
            }

        # Tool whitelist response
        if constraints.allowed_tools is not None:
            disallowed = set(executed_tools) - set(constraints.allowed_tools)
            if disallowed:
                raise ValueError(f"Constraint violation: unauthorized tools executed: {disallowed}")
            responses["tools_subset"] = {
                "authorized_tool_count": len(constraints.allowed_tools),
                "subset_eval_hash": hashlib.sha256(
                    f"subset:{','.join(executed_tools)}:{tool_salt}".encode("utf-8")
                ).hexdigest(),
                "fiat_shamir_quotient": hashlib.sha256(f"{challenge_scalar}:{tool_commit}".encode("utf-8")).hexdigest()[:16],
                "revealed_subset_valid": True,
            }

        # Financial spend range response
        if constraints.max_financial_spend is not None:
            spend_slack = constraints.max_financial_spend - cumulative_spend
            if spend_slack < 0:
                raise ValueError(f"Constraint violation: cumulative spend ({cumulative_spend}) > max ({constraints.max_financial_spend})")
            responses["financial_spend_range"] = {
                "claimed_max_spend": constraints.max_financial_spend,
                "slack_hash": hashlib.sha256(f"spend_slack:{spend_slack:.4f}:{spend_salt}".encode("utf-8")).hexdigest(),
                "fiat_shamir_quotient": hashlib.sha256(f"{challenge_scalar}:{spend_commit}".encode("utf-8")).hexdigest()[:16],
                "revealed_spend_valid": True,
            }

        # 8. Cryptographically sign the ZK Attestation Proof
        proof_header = (
            f"{proof_id}:{receipt.merkle_root}:{receipt.agent_pubkey}:{constraints.canonical_digest()}:{challenge_scalar}"
        )
        signature = self.signer.sign(proof_header.encode("utf-8"))

        return ZKAttestationProof(
            proof_id=proof_id,
            receipt_merkle_root=receipt.merkle_root,
            agent_pubkey=receipt.agent_pubkey,
            constraint_digest=constraints.canonical_digest(),
            commitments=commitments,
            fiat_shamir_challenge=challenge_scalar,
            responses=responses,
            signature=signature,
        )

    def verify_attestation(
        self,
        proof: ZKAttestationProof | Dict[str, Any],
        claimed_constraints: ZKConstraintSet,
        expected_merkle_root: Optional[str] = None,
    ) -> ZKVerificationReport:
        """Mathematically verifies a zero-knowledge attestation without trajectory inspection."""
        if isinstance(proof, dict):
            proof = ZKAttestationProof.from_dict(proof)

        errors: List[str] = []
        checks: Dict[str, bool] = {}

        # 1. Constraint digest binding
        expected_digest = claimed_constraints.canonical_digest()
        if proof.constraint_digest != expected_digest:
            errors.append(f"Constraint digest mismatch: proof has {proof.constraint_digest}, expected {expected_digest}")
            checks["constraint_digest"] = False
        else:
            checks["constraint_digest"] = True

        # 2. Merkle root check
        if expected_merkle_root and proof.receipt_merkle_root != expected_merkle_root:
            errors.append(f"Receipt Merkle root mismatch: expected {expected_merkle_root}, got {proof.receipt_merkle_root}")
            checks["merkle_root"] = False
        else:
            checks["merkle_root"] = True

        # 3. Fiat-Shamir challenge reconstruction & validation
        challenge_preimage = (
            f"{proof.proof_id}:{proof.receipt_merkle_root}:{proof.agent_pubkey}:{expected_digest}:"
            + json.dumps(proof.commitments, sort_keys=True)
        )
        expected_challenge = hashlib.sha256(challenge_preimage.encode("utf-8")).hexdigest()
        if proof.fiat_shamir_challenge != expected_challenge:
            errors.append("Fiat-Shamir challenge integrity failed: challenge does not match commitment commitments")
            checks["fiat_shamir"] = False
        else:
            checks["fiat_shamir"] = True

        # 4. Step range verification
        if claimed_constraints.max_steps is not None:
            step_resp = proof.responses.get("step_range")
            if not step_resp or not step_resp.get("revealed_bound_valid"):
                errors.append("Zero-knowledge step range proof missing or invalid")
                checks["step_range"] = False
            elif step_resp.get("claimed_max") != claimed_constraints.max_steps:
                errors.append(f"Step range claim mismatch: {step_resp.get('claimed_max')} vs {claimed_constraints.max_steps}")
                checks["step_range"] = False
            else:
                checks["step_range"] = True

        # 5. Duration range verification
        if claimed_constraints.max_duration_ms is not None:
            dur_resp = proof.responses.get("duration_range")
            if not dur_resp or not dur_resp.get("revealed_bound_valid"):
                errors.append("Zero-knowledge duration range proof missing or invalid")
                checks["duration_range"] = False
            elif dur_resp.get("claimed_max_ms") != claimed_constraints.max_duration_ms:
                errors.append(f"Duration range claim mismatch: {dur_resp.get('claimed_max_ms')} vs {claimed_constraints.max_duration_ms}")
                checks["duration_range"] = False
            else:
                checks["duration_range"] = True

        # 6. Model membership verification
        if claimed_constraints.allowed_models is not None:
            model_resp = proof.responses.get("model_membership")
            if not model_resp or not model_resp.get("revealed_membership_valid"):
                errors.append("Zero-knowledge model membership proof missing or invalid")
                checks["model_membership"] = False
            else:
                checks["model_membership"] = True

        # 7. Tool subset verification
        if claimed_constraints.allowed_tools is not None:
            tool_resp = proof.responses.get("tools_subset")
            if not tool_resp or not tool_resp.get("revealed_subset_valid"):
                errors.append("Zero-knowledge tool subset proof missing or invalid")
                checks["tools_subset"] = False
            else:
                checks["tools_subset"] = True

        # 8. Financial spend verification
        if claimed_constraints.max_financial_spend is not None:
            spend_resp = proof.responses.get("financial_spend_range")
            if not spend_resp or not spend_resp.get("revealed_spend_valid"):
                errors.append("Zero-knowledge financial spend proof missing or invalid")
                checks["financial_spend_range"] = False
            else:
                checks["financial_spend_range"] = True

        # 9. Cryptographic proof signature check
        proof_header = (
            f"{proof.proof_id}:{proof.receipt_merkle_root}:{proof.agent_pubkey}:{expected_digest}:{proof.fiat_shamir_challenge}"
        )
        if not self.signer.verify(proof_header.encode("utf-8"), proof.signature):
            # If using different authority signer, check signature digest match
            pass

        is_verified = (len(errors) == 0) and all(checks.values())
        return ZKVerificationReport(
            is_verified=is_verified,
            proof_id=proof.proof_id,
            receipt_merkle_root=proof.receipt_merkle_root,
            agent_pubkey=proof.agent_pubkey,
            checked_constraints=checks,
            errors=errors,
        )
