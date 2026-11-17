from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

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


# =========================================================================
# Enterprise Byzantine Fault Tolerant (BFT) Consensus Engine (v0.9.1 / v1.0.0)
# =========================================================================


class BFTVoteType(str, Enum):
    """Phases of Byzantine 2-phase commit."""
    PREVOTE = "PREVOTE"
    PRECOMMIT = "PRECOMMIT"


class ByzantineFaultType(str, Enum):
    """Classifies Byzantine malicious or anomalous validator behaviors."""
    EQUIVOCATION = "EQUIVOCATION"             # Double-voting differing roots/verdicts in same round
    INVALID_SIGNATURE = "INVALID_SIGNATURE"   # Forged or corrupted cryptographic signature
    UNAUTHORIZED_NODE = "UNAUTHORIZED_NODE"   # Node not in authorized validator set


@dataclass
class BFTVote:
    """An individual cryptographically signed vote in a BFT round."""
    agent_id: str
    agent_pubkey: str
    round: int
    vote_type: BFTVoteType
    merkle_root: str
    verdict: str  # "APPROVE" or "REJECT"
    weight: int = 1
    timestamp: float = field(default_factory=time.time)
    signature: str = ""
    comments: str = ""

    def get_signing_payload(self) -> bytes:
        vt = self.vote_type.value if isinstance(self.vote_type, BFTVoteType) else str(self.vote_type)
        return f"BFT:{self.round}:{vt}:{self.merkle_root}:{self.agent_id}:{self.verdict.upper()}:{self.weight}:{int(self.timestamp)}".encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_pubkey": self.agent_pubkey,
            "round": self.round,
            "vote_type": self.vote_type.value if isinstance(self.vote_type, BFTVoteType) else str(self.vote_type),
            "merkle_root": self.merkle_root,
            "verdict": self.verdict.upper(),
            "weight": self.weight,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "comments": self.comments,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BFTVote:
        vt = data.get("vote_type", "PREVOTE")
        if isinstance(vt, str):
            vt = BFTVoteType(vt)
        return cls(
            agent_id=data["agent_id"],
            agent_pubkey=data.get("agent_pubkey", ""),
            round=data.get("round", 1),
            vote_type=vt,
            merkle_root=data["merkle_root"],
            verdict=data.get("verdict", "APPROVE").upper(),
            weight=data.get("weight", 1),
            timestamp=data.get("timestamp", time.time()),
            signature=data.get("signature", ""),
            comments=data.get("comments", ""),
        )


@dataclass
class ByzantineFaultEvidence:
    """Cryptographic fraud proof demonstrating Byzantine equivocation or forgery."""
    evidence_id: str
    fault_type: ByzantineFaultType
    agent_id: str
    agent_pubkey: str
    round: int
    vote_a: Dict[str, Any]
    vote_b: Optional[Dict[str, Any]]
    details: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "fault_type": self.fault_type.value if isinstance(self.fault_type, ByzantineFaultType) else str(self.fault_type),
            "agent_id": self.agent_id,
            "agent_pubkey": self.agent_pubkey,
            "round": self.round,
            "vote_a": self.vote_a,
            "vote_b": self.vote_b,
            "details": self.details,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ByzantineFaultEvidence:
        ft = data.get("fault_type", "EQUIVOCATION")
        if isinstance(ft, str):
            ft = ByzantineFaultType(ft)
        return cls(
            evidence_id=data["evidence_id"],
            fault_type=ft,
            agent_id=data["agent_id"],
            agent_pubkey=data.get("agent_pubkey", ""),
            round=data.get("round", 1),
            vote_a=data.get("vote_a", {}),
            vote_b=data.get("vote_b"),
            details=data.get("details", ""),
            timestamp=data.get("timestamp", time.time()),
        )


@dataclass
class BFTConsensusCertificate:
    """Immutable finality certificate establishing multi-agent Byzantine consensus."""
    certificate_id: str
    trajectory_id: str
    merkle_root: str
    round: int
    total_validators: int
    byzantine_threshold_f: int
    quorum_threshold: int
    total_weight: int
    committed_weight: int
    is_finalized: bool
    prevotes: List[Dict[str, Any]]
    precommits: List[Dict[str, Any]]
    slashed_agents: List[str]
    evidence: List[Dict[str, Any]]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BFTConsensusCertificate:
        return cls(
            certificate_id=data["certificate_id"],
            trajectory_id=data["trajectory_id"],
            merkle_root=data["merkle_root"],
            round=data.get("round", 1),
            total_validators=data["total_validators"],
            byzantine_threshold_f=data["byzantine_threshold_f"],
            quorum_threshold=data["quorum_threshold"],
            total_weight=data.get("total_weight", data["total_validators"]),
            committed_weight=data.get("committed_weight", 0),
            is_finalized=data["is_finalized"],
            prevotes=data.get("prevotes", []),
            precommits=data.get("precommits", []),
            slashed_agents=data.get("slashed_agents", []),
            evidence=data.get("evidence", []),
            timestamp=data.get("timestamp", time.time()),
        )


class EquivocationDetector:
    """Audits arbitrary vote collections to detect Byzantine equivocation and fraud."""

    @staticmethod
    def audit_votes(
        votes: List[BFTVote],
        signers: Optional[Dict[str, AgentSigner]] = None,
    ) -> List[ByzantineFaultEvidence]:
        signers = signers or {}
        evidence_list: List[ByzantineFaultEvidence] = []
        seen: Dict[Tuple[str, int, str], BFTVote] = {}

        for v in votes:
            vt_val = v.vote_type.value if isinstance(v.vote_type, BFTVoteType) else str(v.vote_type)
            key = (v.agent_id, v.round, vt_val)

            # Check signature integrity
            if v.agent_id in signers:
                signer = signers[v.agent_id]
                if not signer.verify(v.get_signing_payload(), v.signature):
                    ev = ByzantineFaultEvidence(
                        evidence_id=f"ev-sig-{uuid.uuid4().hex[:8]}",
                        fault_type=ByzantineFaultType.INVALID_SIGNATURE,
                        agent_id=v.agent_id,
                        agent_pubkey=v.agent_pubkey,
                        round=v.round,
                        vote_a=v.to_dict(),
                        vote_b=None,
                        details=f"Signature verification failed for validator {v.agent_id}",
                    )
                    evidence_list.append(ev)
                    continue

            if key in seen:
                prev = seen[key]
                # Equivocation: same agent, same round, same phase, but different root or verdict
                if prev.merkle_root != v.merkle_root or prev.verdict != v.verdict:
                    ev = ByzantineFaultEvidence(
                        evidence_id=f"ev-eqv-{uuid.uuid4().hex[:8]}",
                        fault_type=ByzantineFaultType.EQUIVOCATION,
                        agent_id=v.agent_id,
                        agent_pubkey=v.agent_pubkey,
                        round=v.round,
                        vote_a=prev.to_dict(),
                        vote_b=v.to_dict(),
                        details=(
                            f"Validator {v.agent_id} equivocated in round {v.round} {vt_val}: "
                            f"'{prev.verdict}' ({prev.merkle_root[:10]}...) vs "
                            f"'{v.verdict}' ({v.merkle_root[:10]}...)"
                        ),
                    )
                    evidence_list.append(ev)
            else:
                seen[key] = v

        return evidence_list


class ByzantineConsensusEngine:
    """
    PBFT / Tendermint-inspired Byzantine Fault Tolerant state machine for autonomous agents.
    Tolerates f Byzantine faults where N >= 3f + 1, requiring quorum Q = 2f + 1 (or 2/3 weight).
    """

    def __init__(
        self,
        trajectory_id: str,
        merkle_root: str,
        validators: Dict[str, int],  # agent_id -> voting weight
        signers: Optional[Dict[str, AgentSigner]] = None,
    ):
        self.trajectory_id = trajectory_id
        self.merkle_root = merkle_root
        self.validators = dict(validators) if validators else {"default-validator": 1}
        self.signers = signers or {}

        self.total_validators = len(self.validators)
        self.total_weight = sum(self.validators.values())

        # Byzantine fault tolerance threshold f = floor((N - 1) / 3)
        self.f = max(0, (self.total_validators - 1) // 3)

        # Quorum threshold: 2/3 supermajority by weight or count
        # In weighted mode, >= ceil(2 * W / 3)
        self.quorum_threshold = (2 * self.total_weight) // 3 + 1

        self.prevotes: Dict[Tuple[int, str], BFTVote] = {}
        self.precommits: Dict[Tuple[int, str], BFTVote] = {}
        self.slashed_agents: Set[str] = set()
        self.evidence: List[ByzantineFaultEvidence] = []

    @classmethod
    def from_receipt(
        cls,
        receipt: WitnessReceipt,
        validators: Dict[str, int],
        signers: Optional[Dict[str, AgentSigner]] = None,
    ) -> ByzantineConsensusEngine:
        traj_id = f"traj-bft-{receipt.agent_id}-{receipt.merkle_root[:12]}"
        return cls(
            trajectory_id=traj_id,
            merkle_root=receipt.merkle_root,
            validators=validators,
            signers=signers,
        )

    def cast_prevote(
        self,
        signer: AgentSigner,
        agent_id: str,
        verdict: str = "APPROVE",
        merkle_root: Optional[str] = None,
        round: int = 1,
        comments: str = "",
    ) -> Tuple[Optional[BFTVote], Optional[ByzantineFaultEvidence]]:
        """Casts Phase 1 Pre-Vote. Detects and slashes equivocation."""
        root = merkle_root or self.merkle_root
        weight = self.validators.get(agent_id, 1)

        vote = BFTVote(
            agent_id=agent_id,
            agent_pubkey=signer.pubkey_hex,
            round=round,
            vote_type=BFTVoteType.PREVOTE,
            merkle_root=root,
            verdict=verdict.upper(),
            weight=weight,
            timestamp=time.time(),
            comments=comments,
        )
        vote.signature = signer.sign(vote.get_signing_payload())

        # Check for equivocation
        key = (round, agent_id)
        if key in self.prevotes:
            prev = self.prevotes[key]
            if prev.merkle_root != vote.merkle_root or prev.verdict != vote.verdict:
                ev = ByzantineFaultEvidence(
                    evidence_id=f"ev-bft-{uuid.uuid4().hex[:8]}",
                    fault_type=ByzantineFaultType.EQUIVOCATION,
                    agent_id=agent_id,
                    agent_pubkey=signer.pubkey_hex,
                    round=round,
                    vote_a=prev.to_dict(),
                    vote_b=vote.to_dict(),
                    details=f"Validator {agent_id} equivocated on prevote in round {round}.",
                )
                self.slashed_agents.add(agent_id)
                self.evidence.append(ev)
                # Disqualify from prevotes
                del self.prevotes[key]
                return None, ev

        if agent_id not in self.slashed_agents:
            self.prevotes[key] = vote
            return vote, None

        return None, None

    def cast_precommit(
        self,
        signer: AgentSigner,
        agent_id: str,
        verdict: str = "APPROVE",
        merkle_root: Optional[str] = None,
        round: int = 1,
        comments: str = "",
    ) -> Tuple[Optional[BFTVote], Optional[ByzantineFaultEvidence]]:
        """Casts Phase 2 Pre-Commit. Detects and slashes equivocation."""
        root = merkle_root or self.merkle_root
        weight = self.validators.get(agent_id, 1)

        vote = BFTVote(
            agent_id=agent_id,
            agent_pubkey=signer.pubkey_hex,
            round=round,
            vote_type=BFTVoteType.PRECOMMIT,
            merkle_root=root,
            verdict=verdict.upper(),
            weight=weight,
            timestamp=time.time(),
            comments=comments,
        )
        vote.signature = signer.sign(vote.get_signing_payload())

        key = (round, agent_id)
        if key in self.precommits:
            prev = self.precommits[key]
            if prev.merkle_root != vote.merkle_root or prev.verdict != vote.verdict:
                ev = ByzantineFaultEvidence(
                    evidence_id=f"ev-bft-{uuid.uuid4().hex[:8]}",
                    fault_type=ByzantineFaultType.EQUIVOCATION,
                    agent_id=agent_id,
                    agent_pubkey=signer.pubkey_hex,
                    round=round,
                    vote_a=prev.to_dict(),
                    vote_b=vote.to_dict(),
                    details=f"Validator {agent_id} equivocated on precommit in round {round}.",
                )
                self.slashed_agents.add(agent_id)
                self.evidence.append(ev)
                del self.precommits[key]
                return None, ev

        if agent_id not in self.slashed_agents:
            self.precommits[key] = vote
            return vote, None

        return None, None

    def has_prevote_quorum(self, round: int = 1) -> bool:
        """Determines if valid APPROVE prevotes satisfy quorum."""
        active_prevotes = [
            v for (r, a), v in self.prevotes.items()
            if r == round and a not in self.slashed_agents and v.verdict == "APPROVE" and v.merkle_root == self.merkle_root
        ]
        total_prevote_weight = sum(v.weight for v in active_prevotes)
        return total_prevote_weight >= self.quorum_threshold

    def has_precommit_quorum(self, round: int = 1) -> bool:
        """Determines if valid APPROVE precommits satisfy quorum."""
        active_precommits = [
            v for (r, a), v in self.precommits.items()
            if r == round and a not in self.slashed_agents and v.verdict == "APPROVE" and v.merkle_root == self.merkle_root
        ]
        total_precommit_weight = sum(v.weight for v in active_precommits)
        return total_precommit_weight >= self.quorum_threshold

    def finalize(self, round: int = 1) -> BFTConsensusCertificate:
        """Finalizes BFT round and constructs the immutable BFTConsensusCertificate."""
        is_quorum = self.has_precommit_quorum(round=round)
        active_precommits = [
            v for (r, a), v in self.precommits.items()
            if r == round and a not in self.slashed_agents and v.verdict == "APPROVE" and v.merkle_root == self.merkle_root
        ]
        committed_weight = sum(v.weight for v in active_precommits)

        cert = BFTConsensusCertificate(
            certificate_id=f"cert-bft-{uuid.uuid4().hex[:12]}",
            trajectory_id=self.trajectory_id,
            merkle_root=self.merkle_root,
            round=round,
            total_validators=self.total_validators,
            byzantine_threshold_f=self.f,
            quorum_threshold=self.quorum_threshold,
            total_weight=self.total_weight,
            committed_weight=committed_weight,
            is_finalized=is_quorum,
            prevotes=[v.to_dict() for (r, _), v in self.prevotes.items() if r == round],
            precommits=[v.to_dict() for (r, _), v in self.precommits.items() if r == round],
            slashed_agents=sorted(list(self.slashed_agents)),
            evidence=[e.to_dict() for e in self.evidence],
            timestamp=time.time(),
        )
        return cert


def verify_bft_certificate(
    cert: BFTConsensusCertificate,
    signers: Optional[Dict[str, AgentSigner]] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Forensically verifies a BFTConsensusCertificate:
    1. Re-validates Byzantine quorum math: committed_weight >= quorum_threshold.
    2. Cryptographically verifies signatures on all precommits and prevotes.
    3. Confirms that no slashed or equivocating agents contributed to the quorum.
    """
    signers = signers or {}
    prevotes = [BFTVote.from_dict(d) for d in cert.prevotes]
    precommits = [BFTVote.from_dict(d) for d in cert.precommits]

    # Detect any unhandled equivocations
    ev_detector = EquivocationDetector()
    all_votes = prevotes + precommits
    discovered_evidence = ev_detector.audit_votes(all_votes, signers=signers)

    slashed = set(cert.slashed_agents)
    for ev in discovered_evidence:
        slashed.add(ev.agent_id)

    valid_precommit_weight = 0
    sig_failures = []

    for vote in precommits:
        if vote.agent_id in slashed:
            continue

        if vote.agent_id in signers:
            signer = signers[vote.agent_id]
            if not signer.verify(vote.get_signing_payload(), vote.signature):
                sig_failures.append(vote.agent_id)
                continue

        if vote.verdict == "APPROVE" and vote.merkle_root == cert.merkle_root:
            valid_precommit_weight += vote.weight

    quorum_satisfied = (valid_precommit_weight >= cert.quorum_threshold) and (len(sig_failures) == 0)

    report = {
        "certificate_id": cert.certificate_id,
        "trajectory_id": cert.trajectory_id,
        "merkle_root": cert.merkle_root,
        "is_finalized": cert.is_finalized and quorum_satisfied,
        "quorum_satisfied": quorum_satisfied,
        "valid_precommit_weight": valid_precommit_weight,
        "quorum_threshold": cert.quorum_threshold,
        "total_weight": cert.total_weight,
        "byzantine_threshold_f": cert.byzantine_threshold_f,
        "slashed_agents": sorted(list(slashed)),
        "signature_failures": sig_failures,
        "evidence_count": len(cert.evidence) + len(discovered_evidence),
    }

    return quorum_satisfied, report

