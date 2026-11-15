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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
