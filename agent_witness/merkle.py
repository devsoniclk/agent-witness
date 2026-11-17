import hashlib
from typing import Any, Dict, List, Optional, Tuple
from .models import DeliberationStep, MerkleProof


def compute_leaf_hash(step: Any) -> bytes:
    """RFC 6962 style leaf hashing with 0x00 domain separator prefix."""
    h = hashlib.sha256()
    h.update(b"\x00")
    if hasattr(step, "to_canonical_bytes"):
        h.update(step.to_canonical_bytes())
    elif isinstance(step, bytes):
        h.update(step)
    elif isinstance(step, str):
        h.update(step.encode("utf-8"))
    else:
        h.update(str(step).encode("utf-8"))
    return h.digest()


def compute_parent_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 style node hashing with 0x01 domain separator prefix."""
    h = hashlib.sha256()
    h.update(b"\x01")
    h.update(left)
    h.update(right)
    return h.digest()


class MerkleTree:
    """
    Incremental cryptographic Merkle Tree for agent deliberation steps.
    """

    def __init__(self, steps: List[DeliberationStep]):
        self.steps = steps
        self.leaves = [compute_leaf_hash(s) for s in steps]
        self.levels: List[List[bytes]] = []
        self._build_tree()

    def _build_tree(self) -> None:
        if not self.leaves:
            self.root = hashlib.sha256(b"\x00").digest()
            self.levels = [[self.root]]
            return

        current = list(self.leaves)
        self.levels = [current]

        while len(current) > 1:
            next_level: List[bytes] = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                parent = compute_parent_hash(left, right)
                next_level.append(parent)
            current = next_level
            self.levels.append(current)

        self.root = self.levels[-1][0]

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    @property
    def root_hash(self) -> str:
        return self.root.hex()

    def generate_proof(self, leaf_index: int) -> MerkleProof:
        """Generates an inclusion proof for the leaf at index leaf_index."""
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError("Leaf index out of bounds")

        audit_path: List[Dict[str, str]] = []
        idx = leaf_index

        for level in self.levels[:-1]:
            is_right = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right else idx + 1
            if sibling_idx < len(level):
                direction = "left" if is_right else "right"
                audit_path.append({"direction": direction, "hash": level[sibling_idx].hex()})
            else:
                audit_path.append({"direction": "right", "hash": level[idx].hex()})
            idx //= 2

        return MerkleProof(
            leaf_index=leaf_index,
            leaf_hash=self.leaves[leaf_index].hex(),
            audit_path=audit_path,
        )


def verify_merkle_proof(
    leaf_hash: Optional[str] = None,
    proof: Optional[Any] = None,
    root_hash: Optional[str] = None,
    audit_path: Optional[List[Dict[str, str]]] = None,
    root_hex: Optional[str] = None,
    leaf_hash_hex: Optional[str] = None,
) -> bool:
    """Verifies that leaf_hash is member of tree rooted at root_hash."""
    target_leaf = leaf_hash or leaf_hash_hex
    target_root = root_hash or root_hex
    if not target_leaf or not target_root:
        return False

    curr = bytes.fromhex(target_leaf.removeprefix("0x"))

    path = []
    if audit_path is not None:
        path = audit_path
    elif proof is not None and hasattr(proof, "audit_path"):
        path = proof.audit_path
    elif isinstance(proof, list):
        path = proof

    for item in path:
        sibling = bytes.fromhex(item["hash"].removeprefix("0x"))
        if item["direction"] == "left":
            curr = compute_parent_hash(sibling, curr)
        else:
            curr = compute_parent_hash(curr, sibling)

    if isinstance(target_root, bytes):
        target_root_hex = target_root.hex()
    else:
        target_root_hex = str(target_root).removeprefix("0x")

    return curr.hex() == target_root_hex
