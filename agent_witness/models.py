from __future__ import annotations

import enum
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class StepType(str, enum.Enum):
    OBSERVATION = "observation"
    THOUGHT = "thought"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    DECISION = "decision"


@dataclass
class DeliberationStep:
    step_type: StepType
    index: int
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_canonical_bytes(self) -> bytes:
        """Returns deterministic UTF-8 bytes for cryptographic leaf hashing."""
        meta_str = ";".join(f"{k}={v}" for k, v in sorted(self.metadata.items()))
        canonical = f"{self.index}:{self.step_type.value}:{self.content}:{meta_str}:{int(self.timestamp * 1000)}"
        return canonical.encode("utf-8")


@dataclass
class MerkleProof:
    leaf_index: int
    leaf_hash: str
    audit_path: List[Dict[str, str]]  # [{"direction": "left"|"right", "hash": "hex"}]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WitnessReceipt:
    version: str
    agent_id: str
    agent_pubkey: str
    model_id: str
    system_prompt_hash: str
    merkle_root: str
    step_count: int
    timestamp: float
    signature: str
    steps: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def receipt_id(self) -> str:
        return f"rcpt_{self.merkle_root[:16]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProofBundle:
    """
    Selective disclosure proof package.
    Proves that a single step occurred in an attested deliberation trajectory
    without disclosing other private thoughts, prompts, or tool actions.
    """
    version: str
    agent_id: str
    agent_pubkey: str
    model_id: str
    merkle_root: str
    signature: str
    disclosed_step: Dict[str, Any]
    merkle_proof: MerkleProof

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["merkle_proof"] = self.merkle_proof.to_dict()
        return d


@dataclass
class AgentAttestation:
    """Attestation from an individual agent participating in multi-agent consensus."""
    agent_id: str
    agent_pubkey: str
    model_id: str
    role: str
    verdict: str  # e.g., "APPROVE", "REJECT"
    timestamp: float
    signature: str
    comments: str = ""

    def to_canonical_bytes(self, merkle_root: str) -> bytes:
        payload = f"{merkle_root}:{self.agent_id}:{self.role}:{self.verdict}:{self.model_id}:{int(self.timestamp)}"
        return payload.encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConsensusReceipt:
    """
    Multi-agent threshold attestation receipt.
    Proves that multiple autonomous agents audited and agreed upon a trajectory Merkle root.
    """
    version: str
    trajectory_id: str
    merkle_root: str
    step_count: int
    threshold: int
    attestations: List[AgentAttestation]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["attestations"] = [a.to_dict() for a in self.attestations]
        return d


@dataclass
class LogRecord:
    """An entry in the append-only transparency log ledger."""
    log_index: int
    receipt_id: str
    agent_id: str
    agent_pubkey: str
    merkle_root: str
    step_count: int
    timestamp: float
    signature: str
    entry_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LogCheckpoint:
    """Signed Tree Head (STH) checkpoint representing the state of the transparency log."""
    tree_size: int
    log_root: str
    timestamp: float
    signer_pubkey: str
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConsistencyProof:
    """Proof that log tree at size m is an exact prefix extension of tree at size n."""
    old_size: int
    new_size: int
    old_root: str
    new_root: str
    proof_hashes: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LogInclusionProof:
    """Proof that a specific receipt entry exists in the transparency log."""
    log_index: int
    entry_hash: str
    tree_size: int
    log_root: str
    audit_path: List[Dict[str, str]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
