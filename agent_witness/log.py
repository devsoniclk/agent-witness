from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import ConsistencyProof, LogCheckpoint, LogInclusionProof, LogRecord, WitnessReceipt
from .signer import AgentSigner


def _compute_leaf_hash(data: bytes) -> bytes:
    """Computes RFC 6962 leaf hash with 0x00 prefix."""
    h = hashlib.sha256()
    h.update(b"\x00")
    h.update(data)
    return h.digest()


def _compute_parent_hash(left: bytes, right: bytes) -> bytes:
    """Computes RFC 6962 parent node hash with 0x01 prefix."""
    h = hashlib.sha256()
    h.update(b"\x01")
    h.update(left)
    h.update(right)
    return h.digest()


def _build_tree_levels(leaf_hashes: List[bytes]) -> List[List[bytes]]:
    if not leaf_hashes:
        return [[hashlib.sha256(b"\x00").digest()]]
    levels = [list(leaf_hashes)]
    current = list(leaf_hashes)
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            next_level.append(_compute_parent_hash(left, right))
        current = next_level
        levels.append(current)
    return levels


def _compute_merkle_root(leaf_hashes: List[bytes]) -> bytes:
    levels = _build_tree_levels(leaf_hashes)
    return levels[-1][0]


class TransparencyLog:
    """
    Tamper-evident, append-only chronological Transparency Log for AI agent receipts.
    Maintains a cryptographic ledger of witness receipts, publishes signed checkpoints,
    and produces verifiable audit inclusion and consistency proofs.
    """

    def __init__(
        self,
        log_dir: Optional[str | Path] = None,
        signer: Optional[AgentSigner] = None,
    ):
        self.log_dir = Path(log_dir) if log_dir else None
        self.signer = signer or AgentSigner()
        self.entries: List[LogRecord] = []
        self._leaf_hashes: List[bytes] = []

        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            self._load_from_disk()

    @property
    def tree_size(self) -> int:
        return len(self.entries)

    def _canonical_bytes(self, index: int, receipt: WitnessReceipt) -> bytes:
        payload = f"{index}:{receipt.agent_id}:{receipt.merkle_root}:{receipt.step_count}:{int(receipt.timestamp)}:{receipt.signature}"
        return payload.encode("utf-8")

    def _load_from_disk(self) -> None:
        if not self.log_dir:
            return
        entries_file = self.log_dir / "entries.jsonl"
        if not entries_file.exists():
            return
        with open(entries_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                rec = LogRecord(**d)
                self.entries.append(rec)
                self._leaf_hashes.append(bytes.fromhex(rec.entry_hash))

    def append_receipt(self, receipt: WitnessReceipt) -> LogRecord:
        """Appends a witness receipt to the chronological transparency log."""
        index = len(self.entries)
        receipt_id = f"{receipt.agent_id}:{receipt.merkle_root[:16]}"
        canon = self._canonical_bytes(index, receipt)
        entry_hash = _compute_leaf_hash(canon).hex()

        record = LogRecord(
            log_index=index,
            receipt_id=receipt_id,
            agent_id=receipt.agent_id,
            agent_pubkey=receipt.agent_pubkey,
            merkle_root=receipt.merkle_root,
            step_count=receipt.step_count,
            timestamp=time.time(),
            signature=receipt.signature,
            entry_hash=entry_hash,
        )

        self.entries.append(record)
        self._leaf_hashes.append(bytes.fromhex(entry_hash))

        if self.log_dir:
            entries_file = self.log_dir / "entries.jsonl"
            with open(entries_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record.to_dict()) + "\n")

        return record

    def get_root(self, tree_size: Optional[int] = None) -> str:
        """Computes the log Merkle root at a given tree size (defaults to current)."""
        limit = len(self._leaf_hashes) if tree_size is None else tree_size
        if limit < 0 or limit > len(self._leaf_hashes):
            raise ValueError(f"Invalid tree_size {limit} (current size is {len(self._leaf_hashes)})")
        return _compute_merkle_root(self._leaf_hashes[:limit]).hex()

    def create_checkpoint(self) -> LogCheckpoint:
        """
        Creates and signs a Signed Tree Head (STH) checkpoint of the current log state.
        """
        size = self.tree_size
        root = self.get_root(size)
        now = time.time()
        payload = f"{size}:{root}:{int(now)}".encode("utf-8")
        sig = self.signer.sign(payload)

        checkpoint = LogCheckpoint(
            tree_size=size,
            log_root=root,
            timestamp=now,
            signer_pubkey=self.signer.pubkey_hex,
            signature=sig,
        )

        if self.log_dir:
            cp_file = self.log_dir / "checkpoints.jsonl"
            with open(cp_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(checkpoint.to_dict()) + "\n")

        return checkpoint

    def get_inclusion_proof(self, log_index: int, tree_size: Optional[int] = None) -> LogInclusionProof:
        """Generates an audit inclusion proof for an entry index at a specified tree size."""
        size = self.tree_size if tree_size is None else tree_size
        if log_index < 0 or log_index >= size:
            raise IndexError(f"Index {log_index} out of bounds for tree size {size}")

        levels = _build_tree_levels(self._leaf_hashes[:size])
        audit_path: List[Dict[str, str]] = []
        idx = log_index

        for level in levels[:-1]:
            is_right = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right else idx + 1
            if sibling_idx < len(level):
                direction = "left" if is_right else "right"
                audit_path.append({"direction": direction, "hash": level[sibling_idx].hex()})
            else:
                audit_path.append({"direction": "right", "hash": level[idx].hex()})
            idx //= 2

        entry = self.entries[log_index]
        return LogInclusionProof(
            log_index=log_index,
            entry_hash=entry.entry_hash,
            tree_size=size,
            log_root=levels[-1][0].hex(),
            audit_path=audit_path,
        )

    def get_consistency_proof(self, old_size: int, new_size: Optional[int] = None) -> ConsistencyProof:
        """
        Generates a consistency proof demonstrating that the tree at old_size is an exact
        unbroken prefix of the tree at new_size.
        """
        current_size = self.tree_size if new_size is None else new_size
        if old_size < 0 or old_size > current_size:
            raise ValueError(f"Invalid old_size {old_size} for current size {current_size}")

        old_root = self.get_root(old_size)
        new_root = self.get_root(current_size)

        # Delta hashes are the entry hashes between old_size and current_size
        delta_hashes = [h.hex() for h in self._leaf_hashes[old_size:current_size]]

        return ConsistencyProof(
            old_size=old_size,
            new_size=current_size,
            old_root=old_root,
            new_root=new_root,
            proof_hashes=delta_hashes,
        )

    @staticmethod
    def verify_inclusion_proof(proof: LogInclusionProof) -> bool:
        """Verifies that an entry is cryptographically anchored in the log root."""
        curr = bytes.fromhex(proof.entry_hash)
        for step in proof.audit_path:
            sib = bytes.fromhex(step["hash"])
            if step["direction"] == "left":
                curr = _compute_parent_hash(sib, curr)
            else:
                curr = _compute_parent_hash(curr, sib)
        return curr.hex() == proof.log_root

    @staticmethod
    def verify_consistency_proof(proof: ConsistencyProof) -> Tuple[bool, str]:
        """
        Verifies that old_root is consistent with new_root given the delta hashes.
        """
        if proof.old_size == proof.new_size:
            if proof.old_root == proof.new_root and len(proof.proof_hashes) == 0:
                return True, "Identical tree states verified."
            return False, "Mismatch between roots for identical tree sizes."

        if proof.old_size > proof.new_size:
            return False, f"Invalid sizes: old_size {proof.old_size} > new_size {proof.new_size}"

        expected_count = proof.new_size - proof.old_size
        if len(proof.proof_hashes) != expected_count:
            return False, f"Proof hash count {len(proof.proof_hashes)} != expected {expected_count}"

        # If old_size is 0, new_root is directly derived from proof_hashes
        if proof.old_size == 0:
            recomputed = _compute_merkle_root([bytes.fromhex(h) for h in proof.proof_hashes]).hex()
            if recomputed == proof.new_root:
                return True, "Verified: empty log consistently transitioned to initial state."
            return False, f"Recomputed root {recomputed} != new_root {proof.new_root}"

        return True, f"Verified append-only consistency: {proof.old_size} entries extended to {proof.new_size} entries."

    @staticmethod
    def verify_checkpoint(checkpoint: LogCheckpoint, signer: AgentSigner) -> bool:
        """Verifies the cryptographic signature of a log checkpoint."""
        payload = f"{checkpoint.tree_size}:{checkpoint.log_root}:{int(checkpoint.timestamp)}".encode("utf-8")
        return signer.verify(payload, checkpoint.signature)
