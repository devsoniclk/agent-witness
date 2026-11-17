from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .delegation import DelegationCapability
from .models import StepType, WitnessReceipt
from .policy import PolicyGuard
from .receipt import WitnessEngine


class DisputeType(str, Enum):
    UNAUTHORIZED_TOOL = "unauthorized_tool"
    EXPIRED_DELEGATION = "expired_delegation"
    BUDGET_EXCEEDED = "budget_exceeded"
    UNGROUNDED_ACTION = "ungrounded_action"
    TAMPERED_RECEIPT = "tampered_receipt"
    POLICY_VIOLATION = "policy_violation"


@dataclass
class DisputeClaim:
    claim_id: str
    challenger_id: str
    target_agent_id: str
    receipt: WitnessReceipt
    dispute_type: DisputeType
    disputed_step_index: Optional[int] = None
    supporting_evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["dispute_type"] = self.dispute_type.value
        d["receipt"] = self.receipt.to_dict()
        return d


@dataclass
class SlashingPayload:
    target_agent_id: str
    slashing_bps: int
    fault_hash: str
    evm_calldata: str
    solana_instruction: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DisputeResolutionReport:
    claim_id: str
    is_fault_confirmed: bool
    verdict: str  # "FAULT_CONFIRMED", "DISPUTE_DISMISSED", "INVALID_CLAIM"
    faulty_agent_id: Optional[str]
    slashing_penalty_bps: int
    reason: str
    resolution_hash: str
    slashing_payload: Optional[SlashingPayload] = None
    audit_trail: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.slashing_payload:
            d["slashing_payload"] = self.slashing_payload.to_dict()
        return d


class ArbitrationEngine:
    """
    Arbitrates multi-agent operational disputes against cryptographic proofs,
    delegation capabilities, and governance policies. Generates on-chain slashing payloads.
    """

    DEFAULT_PENALTIES_BPS = {
        DisputeType.TAMPERED_RECEIPT: 10000,  # 100% full slashing
        DisputeType.UNAUTHORIZED_TOOL: 2500,  # 25% slashing
        DisputeType.BUDGET_EXCEEDED: 1500,  # 15% slashing
        DisputeType.EXPIRED_DELEGATION: 1000,  # 10% slashing
        DisputeType.UNGROUNDED_ACTION: 500,  # 5% slashing
        DisputeType.POLICY_VIOLATION: 2000,  # 20% slashing
    }

    @classmethod
    def arbitrate(
        cls,
        claim: DisputeClaim,
        delegation_grant: Optional[DelegationCapability] = None,
        policy_guard: Optional[PolicyGuard] = None,
    ) -> DisputeResolutionReport:
        audit_trail: List[str] = []
        receipt = claim.receipt
        audit_trail.append(
            f"Received claim {claim.claim_id}: Type={claim.dispute_type.value} against {claim.target_agent_id}"
        )

        # Step 1: Verify basic receipt cryptographic integrity
        from .verifier import verify_trajectory_integrity
        traj_report = verify_trajectory_integrity(receipt)
        if not traj_report.is_valid:
            reason = f"Receipt Merkle root tampered or invalid trajectory: {traj_report.summary}"
            audit_trail.append(f"Cryptographic check failed: {reason}")
            return cls._build_resolution(
                claim_id=claim.claim_id,
                fault_confirmed=True,
                verdict="FAULT_CONFIRMED",
                faulty_agent_id=claim.target_agent_id,
                penalty_bps=cls.DEFAULT_PENALTIES_BPS[DisputeType.TAMPERED_RECEIPT],
                reason=reason,
                audit_trail=audit_trail,
            )

        # Step 2: Evaluate specific dispute type
        if claim.dispute_type == DisputeType.TAMPERED_RECEIPT:
            audit_trail.append("Merkle tree integrity verified intact. Tampering claim dismissed.")
            return cls._build_resolution(
                claim_id=claim.claim_id,
                fault_confirmed=False,
                verdict="DISPUTE_DISMISSED",
                faulty_agent_id=None,
                penalty_bps=0,
                reason="Receipt Merkle tree and leaf hashes are cryptographically authentic.",
                audit_trail=audit_trail,
            )

        elif claim.dispute_type == DisputeType.UNAUTHORIZED_TOOL:
            if not delegation_grant:
                return cls._build_resolution(
                    claim_id=claim.claim_id,
                    fault_confirmed=False,
                    verdict="INVALID_CLAIM",
                    faulty_agent_id=None,
                    penalty_bps=0,
                    reason="Missing delegation grant required to substantiate unauthorized tool claim.",
                    audit_trail=audit_trail,
                )

            allowed_scope = set(delegation_grant.scope)
            if "*" in allowed_scope:
                audit_trail.append("Grant permits wildcard scope (*). Claim dismissed.")
                return cls._build_resolution(
                    claim_id=claim.claim_id,
                    fault_confirmed=False,
                    verdict="DISPUTE_DISMISSED",
                    faulty_agent_id=None,
                    penalty_bps=0,
                    reason="Delegation grant authorizes unrestricted wildcard (*) tool access.",
                    audit_trail=audit_trail,
                )

            for idx, step in enumerate(receipt.steps):
                st = step.step_type if hasattr(step, "step_type") else step.get("type", step.get("step_type"))
                if isinstance(st, str):
                    try:
                        st = StepType(st.lower())
                    except Exception:
                        pass
                step_content = step.content if hasattr(step, "content") else step.get("content", "")
                step_meta = step.metadata if hasattr(step, "metadata") else step.get("metadata", {})

                tool = ""
                if isinstance(step_meta, dict):
                    tool = step_meta.get("tool_name", "")
                if not tool and isinstance(step_content, dict):
                    tool = step_content.get("tool_name", "")
                elif not tool and isinstance(step_content, str):
                    try:
                        cdata = json.loads(step_content)
                        if isinstance(cdata, dict):
                            tool = cdata.get("tool_name", "")
                    except Exception:
                        pass

                if st in (StepType.TOOL_CALL, "tool_call"):
                    if tool and tool not in allowed_scope:
                        reason = f"Agent invoked unauthorized tool '{tool}' at step {idx}. Allowed: {sorted(allowed_scope)}"
                        audit_trail.append(f"Violation detected: {reason}")
                        return cls._build_resolution(
                            claim_id=claim.claim_id,
                            fault_confirmed=True,
                            verdict="FAULT_CONFIRMED",
                            faulty_agent_id=claim.target_agent_id,
                            penalty_bps=cls.DEFAULT_PENALTIES_BPS[DisputeType.UNAUTHORIZED_TOOL],
                            reason=reason,
                            audit_trail=audit_trail,
                        )

            audit_trail.append("All invoked tools conform to delegation grant scope.")
            return cls._build_resolution(
                claim_id=claim.claim_id,
                fault_confirmed=False,
                verdict="DISPUTE_DISMISSED",
                faulty_agent_id=None,
                penalty_bps=0,
                reason="No unauthorized tool invocations found in receipt.",
                audit_trail=audit_trail,
            )

        elif claim.dispute_type == DisputeType.EXPIRED_DELEGATION:
            if not delegation_grant:
                return cls._build_resolution(
                    claim_id=claim.claim_id,
                    fault_confirmed=False,
                    verdict="INVALID_CLAIM",
                    faulty_agent_id=None,
                    penalty_bps=0,
                    reason="Missing delegation grant required to substantiate expiration claim.",
                    audit_trail=audit_trail,
                )
            for idx, step in enumerate(receipt.steps):
                if step.timestamp > delegation_grant.expires_at:
                    reason = f"Step {idx} executed at {step.timestamp} after grant expiration {delegation_grant.expires_at}."
                    audit_trail.append(f"Violation detected: {reason}")
                    return cls._build_resolution(
                        claim_id=claim.claim_id,
                        fault_confirmed=True,
                        verdict="FAULT_CONFIRMED",
                        faulty_agent_id=claim.target_agent_id,
                        penalty_bps=cls.DEFAULT_PENALTIES_BPS[DisputeType.EXPIRED_DELEGATION],
                        reason=reason,
                        audit_trail=audit_trail,
                    )
            return cls._build_resolution(
                claim_id=claim.claim_id,
                fault_confirmed=False,
                verdict="DISPUTE_DISMISSED",
                faulty_agent_id=None,
                penalty_bps=0,
                reason="All steps executed within valid grant time window.",
                audit_trail=audit_trail,
            )

        elif claim.dispute_type == DisputeType.BUDGET_EXCEEDED:
            if not delegation_grant or delegation_grant.max_budget_usd is None:
                return cls._build_resolution(
                    claim_id=claim.claim_id,
                    fault_confirmed=False,
                    verdict="INVALID_CLAIM",
                    faulty_agent_id=None,
                    penalty_bps=0,
                    reason="Delegation grant has no configured budget limit.",
                    audit_trail=audit_trail,
                )
            total_cost = sum(
                float(step.content.get("cost_usd", 0.0))
                for step in receipt.steps
                if isinstance(step.content, dict) and isinstance(step.content.get("cost_usd"), (int, float))
            )
            if total_cost > delegation_grant.max_budget_usd:
                reason = f"Total spend ${total_cost:.2f} exceeded authorized cap ${delegation_grant.max_budget_usd:.2f}."
                audit_trail.append(f"Violation detected: {reason}")
                return cls._build_resolution(
                    claim_id=claim.claim_id,
                    fault_confirmed=True,
                    verdict="FAULT_CONFIRMED",
                    faulty_agent_id=claim.target_agent_id,
                    penalty_bps=cls.DEFAULT_PENALTIES_BPS[DisputeType.BUDGET_EXCEEDED],
                    reason=reason,
                    audit_trail=audit_trail,
                )
            return cls._build_resolution(
                claim_id=claim.claim_id,
                fault_confirmed=False,
                verdict="DISPUTE_DISMISSED",
                faulty_agent_id=None,
                penalty_bps=0,
                reason=f"Total spend ${total_cost:.2f} is within limit ${delegation_grant.max_budget_usd:.2f}.",
                audit_trail=audit_trail,
            )

        elif claim.dispute_type == DisputeType.POLICY_VIOLATION:
            if not policy_guard:
                return cls._build_resolution(
                    claim_id=claim.claim_id,
                    fault_confirmed=False,
                    verdict="INVALID_CLAIM",
                    faulty_agent_id=None,
                    penalty_bps=0,
                    reason="Missing policy guard rules to evaluate policy violation claim.",
                    audit_trail=audit_trail,
                )
            rep = policy_guard.evaluate(receipt)
            if not rep.passed:
                reason = f"Policy guard detected {len(rep.violations)} violations: {'; '.join(v.rule_name for v in rep.violations)}"
                audit_trail.append(f"Violation detected: {reason}")
                return cls._build_resolution(
                    claim_id=claim.claim_id,
                    fault_confirmed=True,
                    verdict="FAULT_CONFIRMED",
                    faulty_agent_id=claim.target_agent_id,
                    penalty_bps=cls.DEFAULT_PENALTIES_BPS[DisputeType.POLICY_VIOLATION],
                    reason=reason,
                    audit_trail=audit_trail,
                )
            return cls._build_resolution(
                claim_id=claim.claim_id,
                fault_confirmed=False,
                verdict="DISPUTE_DISMISSED",
                faulty_agent_id=None,
                penalty_bps=0,
                reason="Receipt passed all policy guard rules without violation.",
                audit_trail=audit_trail,
            )

        elif claim.dispute_type == DisputeType.UNGROUNDED_ACTION:
            has_thought = False
            for idx, step in enumerate(receipt.steps):
                st = step.step_type if hasattr(step, "step_type") else step.get("type", step.get("step_type"))
                if st in (StepType.THOUGHT, StepType.OBSERVATION, "thought", "observation"):
                    has_thought = True
                elif st in (StepType.DECISION, "decision", StepType.TOOL_CALL, "tool_call"):
                    if not has_thought:
                        reason = f"Irreversible action executed at step {idx} without preceding deliberation."
                        audit_trail.append(f"Violation detected: {reason}")
                        return cls._build_resolution(
                            claim_id=claim.claim_id,
                            fault_confirmed=True,
                            verdict="FAULT_CONFIRMED",
                            faulty_agent_id=claim.target_agent_id,
                            penalty_bps=cls.DEFAULT_PENALTIES_BPS[DisputeType.UNGROUNDED_ACTION],
                            reason=reason,
                            audit_trail=audit_trail,
                        )
            return cls._build_resolution(
                claim_id=claim.claim_id,
                fault_confirmed=False,
                verdict="DISPUTE_DISMISSED",
                faulty_agent_id=None,
                penalty_bps=0,
                reason="All actions are causally grounded by prior deliberation.",
                audit_trail=audit_trail,
            )

        return cls._build_resolution(
            claim_id=claim.claim_id,
            fault_confirmed=False,
            verdict="INVALID_CLAIM",
            faulty_agent_id=None,
            penalty_bps=0,
            reason=f"Unknown dispute type {claim.dispute_type}",
            audit_trail=audit_trail,
        )

    @classmethod
    def _build_resolution(
        cls,
        claim_id: str,
        fault_confirmed: bool,
        verdict: str,
        faulty_agent_id: Optional[str],
        penalty_bps: int,
        reason: str,
        audit_trail: List[str],
    ) -> DisputeResolutionReport:
        raw_payload = f"{claim_id}:{verdict}:{faulty_agent_id}:{penalty_bps}:{reason}".encode("utf-8")
        res_hash = hashlib.sha256(raw_payload).hexdigest()

        payload: Optional[SlashingPayload] = None
        if fault_confirmed and faulty_agent_id:
            agent_hash = hashlib.sha256(faulty_agent_id.encode("utf-8")).hexdigest()
            evm_calldata = "0x82a5c43d" + agent_hash + hex(penalty_bps)[2:].zfill(64) + res_hash
            solana_ix = {
                "program_id": "WitnessSlash111111111111111111111111111111111",
                "accounts": [
                    {"pubkey": faulty_agent_id, "is_signer": False, "is_writable": True},
                    {"pubkey": "SlashPool111111111111111111111111111111111", "is_signer": False, "is_writable": True},
                ],
                "data": {
                    "instruction": "slash_agent",
                    "penalty_bps": penalty_bps,
                    "resolution_hash": res_hash,
                },
            }
            payload = SlashingPayload(
                target_agent_id=faulty_agent_id,
                slashing_bps=penalty_bps,
                fault_hash=res_hash,
                evm_calldata=evm_calldata,
                solana_instruction=solana_ix,
            )

        return DisputeResolutionReport(
            claim_id=claim_id,
            is_fault_confirmed=fault_confirmed,
            verdict=verdict,
            faulty_agent_id=faulty_agent_id,
            slashing_penalty_bps=penalty_bps,
            reason=reason,
            resolution_hash=res_hash,
            slashing_payload=payload,
            audit_trail=audit_trail,
        )
