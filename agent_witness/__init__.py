"""
agent-witness: Cryptographic action attestation & Merkle audit receipts
for autonomous AI agents.
"""

from .eip712 import EIP712Domain, compute_eip712_digest, hash_witness_receipt, keccak256
from .merkle import MerkleTree, compute_leaf_hash, compute_parent_hash, verify_merkle_proof
from .middleware import async_witness_scope, witness_action, witness_scope
from .models import DeliberationStep, MerkleProof, ProofBundle, StepType, WitnessReceipt
from .proof import export_proof_bundle, verify_proof_bundle
from .receipt import WitnessEngine
from .signer import AgentSigner

__version__ = "0.2.0"
__all__ = [
    "WitnessEngine",
    "AgentSigner",
    "MerkleTree",
    "compute_leaf_hash",
    "compute_parent_hash",
    "verify_merkle_proof",
    "WitnessReceipt",
    "DeliberationStep",
    "StepType",
    "MerkleProof",
    "ProofBundle",
    "export_proof_bundle",
    "verify_proof_bundle",
    "witness_action",
    "witness_scope",
    "async_witness_scope",
    "EIP712Domain",
    "compute_eip712_digest",
    "hash_witness_receipt",
    "keccak256",
]
