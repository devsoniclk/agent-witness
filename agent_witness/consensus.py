from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from .models import AgentAttestation, ConsensusReceipt, WitnessReceipt
from .signer import AgentSigner


class MultiAgentConsensusEngine:
    """
    Coordinates multi-agent cryptographic attestation and threshold consensus
    over agent deliberation trajectories and action Merkle roots.
    """

    def __init__(
        self,
        trajectory_id: str,
        merkle_root: str,
        step_count: int,
        threshold: int = 1,
    ):
        self.trajectory_id = trajectory_id
        self.merkle_root = merkle_root
        self.step_count = step_count
        self.threshold = threshold
        self.attestations: List[AgentAttestation] = []

    @classmethod
    def from_receipt(cls, receipt: WitnessReceipt, threshold: int = 1) -> MultiAgentConsensusEngine:
        """Initializes a consensus engine from an existing single-agent receipt."""
        traj_id = f"traj-{receipt.agent_id}-{receipt.merkle_root[:12]}"
        return cls(
            trajectory_id=traj_id,
            merkle_root=receipt.merkle_root,
            step_count=receipt.step_count,
            threshold=threshold,
        )

    def add_attestation(
        self,
        signer: AgentSigner,
        agent_id: str,
        model_id: str,
        role: str,
        verdict: str = "APPROVE",
        comments: str = "",
    ) -> AgentAttestation:
        """
        Records an individual agent's cryptographic signature and audit verdict.
        """
        now = time.time()
        payload = f"{self.merkle_root}:{agent_id}:{role}:{verdict}:{model_id}:{int(now)}".encode("utf-8")
        signature = signer.sign(payload)

        att = AgentAttestation(
            agent_id=agent_id,
            agent_pubkey=signer.pubkey_hex,
            model_id=model_id,
            role=role,
            verdict=verdict.upper(),
            timestamp=now,
            signature=signature,
            comments=comments,
        )
        self.attestations.append(att)
        return att

    def finalize(self) -> ConsensusReceipt:
        """
        Packages all attestations into an immutable ConsensusReceipt.
        """
        return ConsensusReceipt(
            version="1.0.0",
            trajectory_id=self.trajectory_id,
            merkle_root=self.merkle_root,
            step_count=self.step_count,
            threshold=self.threshold,
            attestations=list(self.attestations),
            timestamp=time.time(),
        )


def verify_consensus_receipt(
    receipt: ConsensusReceipt,
    signers: Optional[Dict[str, AgentSigner]] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verifies multi-agent consensus receipt:
    1. Validates that threshold requirement is mathematically satisfiable.
    2. Verifies cryptographic signatures for each attestation where signer/key is available.
    3. Counts valid 'APPROVE' verdicts.
    4. Returns overall validity and granular report.
    """
    signers = signers or {}
    total = len(receipt.attestations)
    approved = 0
    rejected = 0
    signature_failures = []
    attestation_reports = []

    for att in receipt.attestations:
        payload = f"{receipt.merkle_root}:{att.agent_id}:{att.role}:{att.verdict}:{att.model_id}:{int(att.timestamp)}".encode("utf-8")
        sig_valid = True

        if att.agent_id in signers:
            signer = signers[att.agent_id]
            sig_valid = signer.verify(payload, att.signature)
            if not sig_valid:
                signature_failures.append(att.agent_id)

        if att.verdict == "APPROVE" and sig_valid:
            approved += 1
        elif att.verdict == "REJECT":
            rejected += 1

        attestation_reports.append({
            "agent_id": att.agent_id,
            "role": att.role,
            "model_id": att.model_id,
            "verdict": att.verdict,
            "signature_valid": sig_valid,
            "comments": att.comments,
        })

    is_satisfied = (approved >= receipt.threshold) and (len(signature_failures) == 0)

    report = {
        "trajectory_id": receipt.trajectory_id,
        "merkle_root": receipt.merkle_root,
        "threshold": receipt.threshold,
        "total_attestations": total,
        "approved_count": approved,
        "rejected_count": rejected,
        "consensus_reached": is_satisfied,
        "signature_failures": signature_failures,
        "attestations": attestation_reports,
    }

    return is_satisfied, report
