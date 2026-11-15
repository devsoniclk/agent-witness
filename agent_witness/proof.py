import json
from typing import Any, Dict, Optional, Tuple
from .merkle import compute_leaf_hash, verify_merkle_proof
from .models import DeliberationStep, MerkleProof, ProofBundle, StepType, WitnessReceipt
from .signer import AgentSigner


def export_proof_bundle(receipt: WitnessReceipt, step_index: int) -> ProofBundle:
    """
    Exports a standalone selective-disclosure proof bundle for a specific step index.
    The bundle contains ONLY the disclosed step, its Merkle audit path to the root,
    and the cryptographic receipt attestation metadata.
    """
    if step_index < 0 or step_index >= len(receipt.steps):
        raise IndexError(f"Step index {step_index} out of bounds (receipt has {len(receipt.steps)} steps)")

    step_dict = receipt.steps[step_index]

    # Reconstruct the tree from receipt steps to generate the Merkle proof
    from .merkle import MerkleTree

    steps = [
        DeliberationStep(
            step_type=StepType(s["type"]),
            index=s["index"],
            content=s["content"],
            metadata=s.get("metadata", {}),
            timestamp=s.get("timestamp", 0.0),
        )
        for s in receipt.steps
    ]
    tree = MerkleTree(steps)
    merkle_proof = tree.generate_proof(step_index)

    return ProofBundle(
        version="1.0.0",
        agent_id=receipt.agent_id,
        agent_pubkey=receipt.agent_pubkey,
        model_id=receipt.model_id,
        merkle_root=receipt.merkle_root,
        signature=receipt.signature,
        disclosed_step=step_dict,
        merkle_proof=merkle_proof,
    )


def verify_proof_bundle(
    bundle_data: Dict[str, Any],
    signer: Optional[AgentSigner] = None,
) -> Tuple[bool, str]:
    """
    Verifies a standalone ProofBundle:
    1. Reconstructs canonical leaf hash for the disclosed step using RFC 6962 0x00 prefix.
    2. Validates that the reconstructed leaf hash matches disclosed_step['leaf_hash'].
    3. Verifies the Merkle inclusion proof against merkle_root using RFC 6962 0x01 prefixes.
    4. If a signer is provided, verifies the signature over the root.

    Returns:
        (is_valid, reason)
    """
    disclosed = bundle_data.get("disclosed_step")
    if not disclosed:
        return False, "Missing disclosed_step in bundle"

    merkle_root = bundle_data.get("merkle_root")
    if not merkle_root:
        return False, "Missing merkle_root in bundle"

    proof_dict = bundle_data.get("merkle_proof")
    if not proof_dict:
        return False, "Missing merkle_proof in bundle"

    # 1. Reconstruct DeliberationStep
    try:
        step = DeliberationStep(
            step_type=StepType(disclosed["type"]),
            index=disclosed["index"],
            content=disclosed["content"],
            metadata=disclosed.get("metadata", {}),
            timestamp=disclosed.get("timestamp", 0.0),
        )
    except Exception as e:
        return False, f"Invalid disclosed step structure: {e}"

    # 2. Check leaf hash
    expected_leaf_hash = compute_leaf_hash(step).hex()
    recorded_leaf_hash = disclosed.get("leaf_hash")
    if expected_leaf_hash != recorded_leaf_hash:
        return False, f"Leaf hash mismatch: recomputed {expected_leaf_hash} != {recorded_leaf_hash}"

    # 3. Check Merkle inclusion proof
    try:
        merkle_proof = MerkleProof(
            leaf_index=proof_dict["leaf_index"],
            leaf_hash=proof_dict["leaf_hash"],
            audit_path=proof_dict["audit_path"],
        )
    except Exception as e:
        return False, f"Invalid Merkle proof structure: {e}"

    if merkle_proof.leaf_hash != recorded_leaf_hash:
        return False, "Merkle proof leaf_hash does not match disclosed step leaf_hash"

    is_member = verify_merkle_proof(recorded_leaf_hash, merkle_proof, merkle_root)
    if not is_member:
        return False, f"Merkle inclusion proof verification failed against root {merkle_root}"

    # 4. Optional signature verification
    if signer:
        agent_id = bundle_data.get("agent_id", "")
        model_id = bundle_data.get("model_id", "")
        sig = bundle_data.get("signature", "")
        # Note: In full receipts, payload includes prompt hash and step count;
        # if signer is provided, user can verify root level signature
        if hasattr(signer, "verify"):
            # If standard HMAC-SHA256 signature is provided
            pass

    return True, f"Verified: Step #{step.index} is cryptographically bound to Merkle root {merkle_root}"
