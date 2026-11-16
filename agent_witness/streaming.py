from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .merkle import compute_leaf_hash, compute_parent_hash
from .models import DeliberationStep, StepType
from .signer import AgentSigner


@dataclass
class StreamingStepReceipt:
    """Incremental receipt emitted during an active streaming deliberation session."""
    session_id: str
    step_index: int
    step_type: str
    content_hash: str
    leaf_hash: str
    rolling_merkle_root: str
    timestamp: float
    time_delta_ms: float
    signature: str
    causal_parent_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CausalProvenanceRecord:
    """Links an external tool call or decision to preceding thoughts and observations."""
    step_index: int
    step_type: str
    scratchpad_hash: str
    prior_thought_indices: List[int]
    reasoning_duration_ms: float
    grounded: bool
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class StreamingActionSession:
    """
    High-throughput incremental Merkle action accumulator for autonomous AI agents.
    Allows real-time append of deliberation steps with dynamic rolling frontier updates,
    O(1) amortized leaf insertion, and intermediate cryptographic receipts.
    """

    def __init__(
        self,
        session_id: str,
        agent_id: str,
        signer: Optional[AgentSigner] = None,
    ):
        self.session_id = session_id
        self.agent_id = agent_id
        self.signer = signer or AgentSigner()
        self.steps: List[DeliberationStep] = []
        self.leaf_hashes: List[str] = []
        self.frontier: List[Optional[bytes]] = []  # Incremental Merkle frontier slots (bytes)
        self.start_time: float = time.time()
        self.last_step_time: float = self.start_time
        self.intermediate_receipts: List[StreamingStepReceipt] = []

    def _update_frontier(self, leaf_bytes: bytes) -> bytes:
        """
        Inserts leaf into rolling Merkle frontier and calculates current rolling root.
        Standard binary carry-propagation accumulator.
        """
        carry: Optional[bytes] = leaf_bytes
        i = 0
        while True:
            if i >= len(self.frontier):
                self.frontier.append(carry)
                break
            if self.frontier[i] is None:
                self.frontier[i] = carry
                break
            else:
                # Merge with existing node at height i
                left = self.frontier[i]
                right = carry
                assert left is not None and right is not None
                carry = compute_parent_hash(left, right)
                self.frontier[i] = None
                i += 1

        # Compute current rolling root by folding non-empty frontier slots
        active_nodes = [node for node in self.frontier if node is not None]
        if not active_nodes:
            return leaf_bytes
        curr = active_nodes[0]
        for node in active_nodes[1:]:
            curr = compute_parent_hash(node, curr)
        return curr

    def append_step(
        self,
        step_type: StepType,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StreamingStepReceipt:
        """
        Appends a deliberation step, updates rolling Merkle frontier, and signs an intermediate receipt.
        """
        now = time.time()
        delta_ms = (now - self.last_step_time) * 1000.0
        self.last_step_time = now

        step = DeliberationStep(
            step_type=step_type,
            index=len(self.steps),
            content=content,
            metadata=metadata or {},
            timestamp=now,
        )
        self.steps.append(step)

        leaf_bytes = compute_leaf_hash(step)
        leaf_hash = leaf_bytes.hex()
        self.leaf_hashes.append(leaf_hash)

        rolling_root = self._update_frontier(leaf_bytes).hex()
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        # Prior causal leaf hash
        causal_parent = self.leaf_hashes[-2] if len(self.leaf_hashes) >= 2 else None

        receipt_canonical = f"{self.session_id}:{step.index}:{leaf_hash}:{rolling_root}:{int(now * 1000)}"
        sig = self.signer.sign(receipt_canonical.encode("utf-8"))

        receipt = StreamingStepReceipt(
            session_id=self.session_id,
            step_index=step.index,
            step_type=step.step_type.value,
            content_hash=content_hash,
            leaf_hash=leaf_hash,
            rolling_merkle_root=rolling_root,
            timestamp=now,
            time_delta_ms=delta_ms,
            signature=sig,
            causal_parent_hash=causal_parent,
        )
        self.intermediate_receipts.append(receipt)
        return receipt

    def get_session_summary(self) -> Dict[str, Any]:
        """Returns the current state and rolling Merkle summary of the streaming session."""
        rolling_root = self.intermediate_receipts[-1].rolling_merkle_root if self.intermediate_receipts else "0" * 64
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "step_count": len(self.steps),
            "rolling_merkle_root": rolling_root,
            "start_time": self.start_time,
            "duration_seconds": time.time() - self.start_time,
            "intermediate_receipt_count": len(self.intermediate_receipts),
        }


class DeliberationProvenanceTracker:
    """
    Audits streaming trajectories for thought-to-action groundedness and deliberation provenance.
    Ensures high-impact tool calls and irreversible decisions were preceded by proper reflection.
    """

    @staticmethod
    def audit_groundedness(
        steps: List[DeliberationStep],
        max_reasoning_gap_ms: float = 30000.0,
    ) -> List[CausalProvenanceRecord]:
        records: List[CausalProvenanceRecord] = []
        recent_thoughts: List[int] = []
        scratchpad_buffer = ""

        for s in steps:
            if s.step_type in (StepType.THOUGHT, StepType.OBSERVATION):
                recent_thoughts.append(s.index)
                scratchpad_buffer += f"\n[{s.step_type.value}]: {s.content}"

            scratch_hash = hashlib.sha256(scratchpad_buffer.encode("utf-8")).hexdigest()

            if s.step_type in (StepType.TOOL_CALL, StepType.DECISION):
                warnings = []
                grounded = True

                if not recent_thoughts:
                    grounded = False
                    warnings.append("Action executed without prior thought or observation deliberation.")

                # Calculate reasoning duration from earliest recent thought
                earliest_thought_time = steps[recent_thoughts[0]].timestamp if recent_thoughts else s.timestamp
                reasoning_duration_ms = (s.timestamp - earliest_thought_time) * 1000.0

                if reasoning_duration_ms > max_reasoning_gap_ms and recent_thoughts:
                    warnings.append(f"Reasoning context age ({reasoning_duration_ms:.0f}ms) exceeds max gap ({max_reasoning_gap_ms:.0f}ms).")

                record = CausalProvenanceRecord(
                    step_index=s.index,
                    step_type=s.step_type.value,
                    scratchpad_hash=scratch_hash,
                    prior_thought_indices=list(recent_thoughts),
                    reasoning_duration_ms=reasoning_duration_ms,
                    grounded=grounded,
                    warnings=warnings,
                )
                records.append(record)
                # Reset thoughts for next action cycle
                recent_thoughts.clear()

        return records
