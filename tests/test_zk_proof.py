from __future__ import annotations

import json
import pytest

from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner
from agent_witness.zk_proof import (
    ZKAttestationProof,
    ZKConstraintSet,
    ZKProofEngine,
)


def test_zk_proof_generation_and_verification():
    signer = AgentSigner()
    engine = WitnessEngine(
        agent_id="zk-agent-01",
        model_id="gemini-flash",
        system_prompt="ZK Private Deliberation",
        signer=signer,
    )
    engine.record_step(StepType.THOUGHT, "Analyzing financial market data", metadata={"duration_ms": 45.0})
    engine.record_step(StepType.TOOL_CALL, "fetch_orderbook", metadata={"tool_name": "fetch_orderbook", "duration_ms": 120.0, "amount": 250.0})
    engine.record_step(StepType.DECISION, "Execute conservative hedge", metadata={"duration_ms": 15.0})
    receipt = engine.finalize_receipt()

    zk_engine = ZKProofEngine(signer=signer)

    constraints = ZKConstraintSet(
        max_steps=5,
        max_duration_ms=500.0,
        allowed_tools=["fetch_orderbook", "calculate_slippage"],
        allowed_models=["gemini-flash", "gemini-pro"],
        max_financial_spend=1000.0,
    )

    proof = zk_engine.generate_attestation(receipt, constraints)
    assert proof.proof_id.startswith("zk_")
    assert proof.receipt_merkle_root == receipt.merkle_root
    assert "step_count_commitment" in proof.commitments
    assert len(proof.fiat_shamir_challenge) == 64

    # Verify proof
    report = zk_engine.verify_attestation(proof, constraints, expected_merkle_root=receipt.merkle_root)
    assert report.is_verified is True
    assert len(report.errors) == 0
    assert report.checked_constraints["step_range"] is True
    assert report.checked_constraints["duration_range"] is True
    assert report.checked_constraints["model_membership"] is True
    assert report.checked_constraints["tools_subset"] is True
    assert report.checked_constraints["financial_spend_range"] is True


def test_zk_proof_constraint_violations():
    signer = AgentSigner()
    engine = WitnessEngine(
        agent_id="zk-violator",
        model_id="gemini-flash",
        system_prompt="Test",
        signer=signer,
    )
    for i in range(10):
        engine.record_step(StepType.THOUGHT, f"Thinking step {i}")
    receipt = engine.finalize_receipt()

    zk_engine = ZKProofEngine(signer=signer)

    # Prove with too few steps
    invalid_constraints = ZKConstraintSet(max_steps=5)
    with pytest.raises(ValueError, match="Constraint violation: actual steps"):
        zk_engine.generate_attestation(receipt, invalid_constraints)


def test_zk_proof_tamper_detection():
    signer = AgentSigner()
    engine = WitnessEngine(agent_id="zk-tamper", model_id="gpt-4", system_prompt="Test", signer=signer)
    engine.record_step(StepType.DECISION, "All clear")
    receipt = engine.finalize_receipt()

    zk_engine = ZKProofEngine(signer=signer)
    constraints = ZKConstraintSet(max_steps=5)
    proof = zk_engine.generate_attestation(receipt, constraints)

    # Tamper with challenge
    tampered_data = proof.to_dict()
    tampered_data["fiat_shamir_challenge"] = "0" * 64

    report = zk_engine.verify_attestation(tampered_data, constraints)
    assert report.is_verified is False
    assert any("Fiat-Shamir challenge integrity failed" in e for e in report.errors)
