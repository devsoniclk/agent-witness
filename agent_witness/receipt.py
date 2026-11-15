import hashlib
import json
import time
from typing import Any, Dict, List, Optional
from .merkle import MerkleTree, compute_leaf_hash, verify_merkle_proof
from .models import DeliberationStep, MerkleProof, StepType, WitnessReceipt
from .signer import AgentSigner


class WitnessEngine:
    """
    Session engine that records an agent's reasoning steps, builds a Merkle Action Tree,
    and produces tamper-evident Witness Receipts.
    """

    def __init__(
        self,
        agent_id: str,
        model_id: str,
        system_prompt: str,
        signer: Optional[AgentSigner] = None,
    ):
        self.agent_id = agent_id
        self.model_id = model_id
        self.system_prompt_hash = hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()
        self.signer = signer or AgentSigner()
        self.steps: List[DeliberationStep] = []

    def record_step(self, step_type: StepType, content: str, metadata: Optional[Dict[str, Any]] = None) -> DeliberationStep:
        """Records a deliberation step (observation, thought, tool call, or decision)."""
        step = DeliberationStep(
            step_type=step_type,
            index=len(self.steps),
            content=content,
            metadata=metadata or {},
            timestamp=time.time(),
        )
        self.steps.append(step)
        return step

    def finalize_receipt(self) -> WitnessReceipt:
        """
        Builds the Merkle Action Tree, signs the Merkle Root, and returns an immutable WitnessReceipt.
        """
        tree = MerkleTree(self.steps)
        merkle_root = tree.root_hex

        # Construct attestation payload
        payload = f"{self.agent_id}:{self.model_id}:{self.system_prompt_hash}:{merkle_root}:{len(self.steps)}"
        signature = self.signer.sign(payload.encode("utf-8"))

        step_dicts = [
            {
                "index": s.index,
                "type": s.step_type.value,
                "content": s.content,
                "metadata": s.metadata,
                "timestamp": s.timestamp,
                "leaf_hash": compute_leaf_hash(s).hex(),
            }
            for s in self.steps
        ]

        return WitnessReceipt(
            version="1.0.0",
            agent_id=self.agent_id,
            agent_pubkey=self.signer.pubkey_hex,
            model_id=self.model_id,
            system_prompt_hash=self.system_prompt_hash,
            merkle_root=merkle_root,
            step_count=len(self.steps),
            timestamp=time.time(),
            signature=signature,
            steps=step_dicts,
        )

    def generate_proof_for_step(self, step_index: int) -> MerkleProof:
        """Generates a Merkle inclusion proof for a specific step."""
        tree = MerkleTree(self.steps)
        return tree.generate_proof(step_index)

    @staticmethod
    def verify_receipt(receipt: WitnessReceipt, signer: AgentSigner) -> bool:
        """
        Verifies the internal consistency and cryptographic signature of a WitnessReceipt.
        """
        # 1. Verify signature on root
        payload = f"{receipt.agent_id}:{receipt.model_id}:{receipt.system_prompt_hash}:{receipt.merkle_root}:{receipt.step_count}"
        if not signer.verify(payload.encode("utf-8"), receipt.signature):
            return False

        # 2. Reconstruct Merkle Tree from steps
        rebuilt_steps: List[DeliberationStep] = []
        for s in receipt.steps:
            st = DeliberationStep(
                step_type=StepType(s["type"]),
                index=s["index"],
                content=s["content"],
                metadata=s.get("metadata", {}),
                timestamp=s.get("timestamp", 0.0),
            )
            rebuilt_steps.append(st)

        rebuilt_tree = MerkleTree(rebuilt_steps)
        return rebuilt_tree.root_hex == receipt.merkle_root
