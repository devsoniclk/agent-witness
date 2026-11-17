import pytest
from agent_witness.blinded import (
    BlindedAttestationEngine,
    BlindedReceipt,
    RangeProofCommitment,
    compute_blinded_hash,
)
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner


def test_blinded_commitment_lifecycle():
    val = 4250.75
    c_hash, salt = BlindedAttestationEngine.create_commitment(val)

    assert len(c_hash) == 64
    assert len(salt) == 32
    assert BlindedAttestationEngine.verify_commitment(c_hash, val, salt)
    assert not BlindedAttestationEngine.verify_commitment(c_hash, 9999.99, salt)


def test_range_proof_generation_and_verification():
    val = 250.0
    min_val = 100.0
    max_val = 500.0

    proof, salt = BlindedAttestationEngine.create_range_proof(val, min_val, max_val)
    assert proof.min_value == min_val
    assert proof.max_value == max_val
    assert len(proof.proof_token) == 64

    # Verify range proof
    assert BlindedAttestationEngine.verify_range_proof(proof)

    # Tampered bounds fail verification
    tampered_proof = RangeProofCommitment(
        commitment_hash=proof.commitment_hash,
        min_value=50.0,
        max_value=max_val,
        proof_token=proof.proof_token,
    )
    assert not BlindedAttestationEngine.verify_range_proof(tampered_proof)


def test_blind_witness_receipt():
    signer = AgentSigner()
    engine = WitnessEngine(agent_id="trading_agent", signer=signer)
    engine.record_step(StepType.THOUGHT, "Target trade size calculated")
    engine.record_step(
        StepType.DECISION,
        {
            "action": "execute_swap",
            "trade_amount_usd": 1500.0,
            "private_vault_id": "vault_secret_9988",
        },
    )
    receipt = engine.finalize()

    blinded, private_salts = BlindedAttestationEngine.blind_receipt(
        receipt=receipt,
        sensitive_keys=["trade_amount_usd", "private_vault_id"],
        range_rules={"trade_amount_usd": (500.0, 5000.0)},
    )

    assert isinstance(blinded, BlindedReceipt)
    assert blinded.original_receipt_id == receipt.receipt_id
    assert blinded.merkle_root == receipt.merkle_root
    assert len(blinded.commitments) == 2
    assert "step_1_trade_amount_usd" in blinded.commitments
    assert "step_1_private_vault_id" in blinded.commitments

    # Range proof exists for trade_amount_usd
    assert "step_1_trade_amount_usd" in blinded.range_proofs
    rp = blinded.range_proofs["step_1_trade_amount_usd"]
    assert rp.min_value == 500.0
    assert rp.max_value == 5000.0

    # Blinded receipt structure verifies
    assert BlindedAttestationEngine.verify_blinded_receipt(blinded)
