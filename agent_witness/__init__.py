"""
agent-witness: Cryptographic action attestation & Merkle audit receipts
for autonomous AI agents.
"""

from .merkle import MerkleTree, compute_leaf_hash, verify_merkle_proof
from .models import DeliberationStep, MerkleProof, StepType, WitnessReceipt
from .receipt import WitnessEngine
from .signer import AgentSigner

__version__ = "0.1.0"
__all__ = [
    "WitnessEngine",
    "AgentSigner",
    "MerkleTree",
    "compute_leaf_hash",
    "verify_merkle_proof",
    "WitnessReceipt",
    "DeliberationStep",
    "StepType",
    "MerkleProof",
]
