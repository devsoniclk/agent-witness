from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .merkle import compute_parent_hash
from .models import WitnessReceipt
from .signer import AgentSigner


@dataclass
class BatchInclusionProof:
    """Cryptographic proof that a specific WitnessReceipt is anchored within an Epoch Batch."""
    epoch_id: str
    epoch_root: str
    receipt_merkle_root: str
    receipt_index: int
    total_receipts: int
    audit_path: List[Dict[str, str]]  # [{"direction": "left"|"right", "hash": "hex"}]
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EpochBatchReceipt:
    """Aggregated batch attestation representing an epoch of multiple agent deliberation receipts."""
    epoch_id: str
    epoch_root: str
    receipt_count: int
    receipt_roots: List[str]
    signer_pubkey: str
    signature: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_evm_calldata(self) -> str:
        """
        Generates ABI-encoded calldata for calling:
        recordEpochRoot(bytes32 epochRoot, uint32 receiptCount, uint64 timestamp)
        Selector: keccak256("recordEpochRoot(bytes32,uint32,uint64)") -> first 4 bytes
        """
        # compute selector
        selector = "0x23a6f44d"  # Standard witness epoch anchor selector
        epoch_root_bytes = self.epoch_root.replace("0x", "").zfill(64)
        count_bytes = hex(self.receipt_count)[2:].zfill(64)
        ts_bytes = hex(int(self.timestamp))[2:].zfill(64)
        return f"{selector}{epoch_root_bytes}{count_bytes}{ts_bytes}"

    def to_solana_memo(self) -> str:
        """Generates compact UTF-8 memo payload for Solana SPL Memo program."""
        return f"AW:EPOCH:{self.epoch_id}:{self.epoch_root}:{self.receipt_count}:{int(self.timestamp)}"


class BatchAnchorEngine:
    """
    Batches multiple Witness Receipts into an aggregated Epoch Merkle Root
    for gas-efficient on-chain anchoring across EVM, Solana, and decentralized storage.
    """

    def __init__(self, epoch_id: Optional[str] = None, signer: Optional[AgentSigner] = None):
        self.epoch_id = epoch_id or f"epoch_{int(time.time())}"
        self.signer = signer or AgentSigner()
        self.receipts: List[Dict[str, Any]] = []

    def add_receipt(self, receipt: WitnessReceipt | Dict[str, Any]) -> int:
        d = receipt.to_dict() if isinstance(receipt, WitnessReceipt) else receipt
        idx = len(self.receipts)
        self.receipts.append(d)
        return idx

    @staticmethod
    def _compute_receipt_leaf(receipt_dict: Dict[str, Any]) -> bytes:
        merkle_root = receipt_dict.get("merkle_root", "")
        agent_id = receipt_dict.get("agent_id", "")
        step_count = receipt_dict.get("step_count", 0)
        ts = int(receipt_dict.get("timestamp", 0.0))
        payload = f"{merkle_root}:{agent_id}:{step_count}:{ts}".encode("utf-8")
        h = hashlib.sha256()
        h.update(b"\x00")
        h.update(payload)
        return h.digest()

    def build_batch(self) -> Tuple[EpochBatchReceipt, List[BatchInclusionProof]]:
        if not self.receipts:
            raise ValueError("Cannot build batch from empty receipt collection")

        leaves = [self._compute_receipt_leaf(r) for r in self.receipts]
        levels: List[List[bytes]] = [leaves]
        current = list(leaves)

        while len(current) > 1:
            next_level: List[bytes] = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                parent = compute_parent_hash(left, right)
                next_level.append(parent)
            current = next_level
            levels.append(current)

        epoch_root = levels[-1][0].hex()

        # Sign the epoch root
        payload = f"{self.epoch_id}:{epoch_root}:{len(self.receipts)}:{self.signer.pubkey_hex}"
        signature = self.signer.sign(payload.encode("utf-8"))

        batch_receipt = EpochBatchReceipt(
            epoch_id=self.epoch_id,
            epoch_root=epoch_root,
            receipt_count=len(self.receipts),
            receipt_roots=[r.get("merkle_root", "") for r in self.receipts],
            signer_pubkey=self.signer.pubkey_hex,
            signature=signature,
            timestamp=time.time(),
        )

        # Generate inclusion proofs for every receipt
        proofs: List[BatchInclusionProof] = []
        for i, r in enumerate(self.receipts):
            audit_path: List[Dict[str, str]] = []
            idx = i
            for level in levels[:-1]:
                is_right = (idx % 2 == 1)
                sibling_idx = idx - 1 if is_right else idx + 1
                if sibling_idx < len(level):
                    direction = "left" if is_right else "right"
                    audit_path.append({"direction": direction, "hash": level[sibling_idx].hex()})
                else:
                    audit_path.append({"direction": "right", "hash": level[idx].hex()})
                idx //= 2

            proofs.append(
                BatchInclusionProof(
                    epoch_id=self.epoch_id,
                    epoch_root=epoch_root,
                    receipt_merkle_root=r.get("merkle_root", ""),
                    receipt_index=i,
                    total_receipts=len(self.receipts),
                    audit_path=audit_path,
                    timestamp=time.time(),
                )
            )

        return batch_receipt, proofs

    @classmethod
    def verify_batch_inclusion(
        cls,
        receipt: WitnessReceipt | Dict[str, Any],
        proof: BatchInclusionProof | Dict[str, Any],
    ) -> bool:
        r_dict = receipt.to_dict() if isinstance(receipt, WitnessReceipt) else receipt
        p_dict = proof.to_dict() if isinstance(proof, BatchInclusionProof) else proof

        leaf_bytes = cls._compute_receipt_leaf(r_dict)
        curr = leaf_bytes

        for item in p_dict.get("audit_path", []):
            sibling = bytes.fromhex(item["hash"])
            if item["direction"] == "left":
                curr = compute_parent_hash(sibling, curr)
            else:
                curr = compute_parent_hash(curr, sibling)

        return curr.hex() == p_dict.get("epoch_root")
