import json
import pytest
from agent_witness.consensus import MultiAgentConsensusEngine
from agent_witness.log import TransparencyLog
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner
from agent_witness.verifier import verify_trajectory_integrity


def create_sample_receipt(signer=None):
    s = signer or AgentSigner()
    engine = WitnessEngine(
        agent_id="test-agent-alpha",
        model_id="gpt-4o",
        system_prompt="Autonomous verification test system.",
        signer=s,
    )
    engine.record_step(StepType.OBSERVATION, "Discovered market imbalance at pool 0x1234")
    engine.record_step(StepType.THOUGHT, "Calculating optimal arbitrage path across DEXes")
    engine.record_step(StepType.TOOL_CALL, "dex_router.quote", metadata={"route": "Raydium->Orca"})
    engine.record_step(StepType.TOOL_RESULT, "Quote returned 1.4% gross spread", metadata={"spread_bps": 140})
    engine.record_step(StepType.DECISION, "Execute atomic swap transaction", metadata={"amount_in": 1000})
    return engine.finalize_receipt(), s, engine.system_prompt_hash


def test_verifier_clean_trajectory():
    receipt, signer, prompt_hash = create_sample_receipt()
    report = verify_trajectory_integrity(receipt, signer=signer, expected_prompt_hash=prompt_hash)

    assert report.is_valid is True
    assert report.failed_checks == 0
    assert report.passed_checks == len(report.checks)
    assert report.step_count == 5
    assert "Verified" in report.summary

    text_out = report.to_text()
    assert "PASS - CRYPTOGRAPHICALLY VALID" in text_out
    assert "SCHEMA_INTEGRITY" in text_out
    assert "STEP_CONTINUITY" in text_out
    assert "TEMPORAL_MONOTONICITY" in text_out
    assert "LEAF_HASH_INTEGRITY" in text_out
    assert "MERKLE_ROOT_VERIFICATION" in text_out
    assert "SIGNATURE_AUTHENTICITY" in text_out
    assert "SYSTEM_PROMPT_HASH" in text_out


def test_verifier_tampered_step_content():
    receipt, signer, _ = create_sample_receipt()
    # Malicious actor changes step content without re-signing or updating leaf hash
    receipt.steps[1]["content"] = "Transfer all treasury funds to attacker address"

    report = verify_trajectory_integrity(receipt, signer=signer)
    assert report.is_valid is False
    assert report.failed_checks >= 1

    check_names_failed = [c.name for c in report.checks if c.status == "FAIL"]
    assert "LEAF_HASH_INTEGRITY" in check_names_failed
    assert "MERKLE_ROOT_VERIFICATION" in check_names_failed


def test_verifier_step_continuity_discontinuous():
    receipt, signer, _ = create_sample_receipt()
    # Omit step index 2 to simulate dropped or concealed step
    del receipt.steps[2]

    report = verify_trajectory_integrity(receipt, signer=signer)
    assert report.is_valid is False
    check_names_failed = [c.name for c in report.checks if c.status == "FAIL"]
    assert "STEP_CONTINUITY" in check_names_failed


def test_verifier_timestamp_regression():
    receipt, signer, _ = create_sample_receipt()
    # Introduce negative time delta (time travel tampering)
    receipt.steps[3]["timestamp"] = receipt.steps[1]["timestamp"] - 100.0

    report = verify_trajectory_integrity(receipt, signer=signer)
    assert report.is_valid is False
    check_names_failed = [c.name for c in report.checks if c.status == "FAIL"]
    assert "TEMPORAL_MONOTONICITY" in check_names_failed


def test_verifier_prompt_hash_mismatch():
    receipt, signer, _ = create_sample_receipt()
    wrong_prompt_hash = "0" * 64
    report = verify_trajectory_integrity(receipt, signer=signer, expected_prompt_hash=wrong_prompt_hash)

    assert report.is_valid is False
    check_names_failed = [c.name for c in report.checks if c.status == "FAIL"]
    assert "SYSTEM_PROMPT_HASH" in check_names_failed


def test_verifier_signature_tamper():
    receipt, signer, _ = create_sample_receipt()
    other_signer = AgentSigner()
    # Verify with another signer whose key does not match
    report = verify_trajectory_integrity(receipt, signer=other_signer)

    assert report.is_valid is False
    check_names_failed = [c.name for c in report.checks if c.status == "FAIL"]
    assert "SIGNATURE_AUTHENTICITY" in check_names_failed


def test_verifier_transparency_log_inclusion(tmp_path):
    receipt, signer, _ = create_sample_receipt()
    log = TransparencyLog(log_dir=str(tmp_path / ".log"), signer=signer)
    log.append_receipt(receipt)

    report = verify_trajectory_integrity(receipt, signer=signer, transparency_log=log)
    assert report.is_valid is True
    check_names_passed = [c.name for c in report.checks if c.status == "PASS"]
    assert "TRANSPARENCY_LOG_INCLUSION" in check_names_passed


def test_verifier_consensus_quorum():
    receipt, signer, _ = create_sample_receipt()
    consensus = MultiAgentConsensusEngine.from_receipt(receipt, threshold=2)

    auditor_1 = AgentSigner()
    auditor_2 = AgentSigner()

    consensus.add_attestation(auditor_1, "auditor-sec-1", "model-1", "SecurityAuditor", "APPROVE")
    consensus.add_attestation(auditor_2, "auditor-risk-2", "model-2", "RiskGovernor", "APPROVE")

    c_receipt = consensus.finalize()

    report = verify_trajectory_integrity(receipt, signer=signer, consensus_receipt=c_receipt)
    assert report.is_valid is True
    check_names_passed = [c.name for c in report.checks if c.status == "PASS"]
    assert "CONSENSUS_QUORUM" in check_names_passed


def test_verifier_dict_and_text_roundtrip():
    receipt, signer, _ = create_sample_receipt()
    report = verify_trajectory_integrity(receipt.to_dict())

    d = report.to_dict()
    assert isinstance(d, dict)
    assert d["is_valid"] is True
    assert d["agent_id"] == "test-agent-alpha"
    assert len(d["checks"]) >= 5

    text = report.to_text()
    assert "AGENT WITNESS FORENSIC TRAJECTORY AUDIT" in text
