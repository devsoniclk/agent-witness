from __future__ import annotations

import pytest

from agent_witness.consensus import MultiAgentConsensusEngine, verify_consensus_receipt
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner


def _create_sample_receipt():
    engine = WitnessEngine(
        agent_id="lead-planner",
        model_id="o3-mini",
        system_prompt="Strategic Planner",
    )
    engine.record_step(StepType.OBSERVATION, "Liquidity depth verified on Hyperliquid")
    engine.record_step(StepType.TOOL_CALL, "hyperliquid.market_order('BTC-PERP', size=1.5)")
    engine.record_step(StepType.DECISION, "Execute delta-neutral hedge")
    return engine.finalize_receipt()


def test_multi_agent_consensus_unanimous():
    receipt = _create_sample_receipt()

    signer_planner = AgentSigner()
    signer_auditor = AgentSigner()
    signer_risk = AgentSigner()

    engine = MultiAgentConsensusEngine.from_receipt(receipt, threshold=3)

    engine.add_attestation(
        signer=signer_planner,
        agent_id="planner-agent",
        model_id="o3-mini",
        role="PLANNER",
        verdict="APPROVE",
    )
    engine.add_attestation(
        signer=signer_auditor,
        agent_id="code-auditor",
        model_id="claude-3-7-sonnet",
        role="AUDITOR",
        verdict="APPROVE",
        comments="Code and parameters audited safe",
    )
    engine.add_attestation(
        signer=signer_risk,
        agent_id="risk-gate",
        model_id="gpt-4o",
        role="RISK_GATE",
        verdict="APPROVE",
        comments="Within max allowable slippage",
    )

    consensus_receipt = engine.finalize()

    signers_map = {
        "planner-agent": signer_planner,
        "code-auditor": signer_auditor,
        "risk-gate": signer_risk,
    }

    is_valid, report = verify_consensus_receipt(consensus_receipt, signers=signers_map)

    assert is_valid is True
    assert report["consensus_reached"] is True
    assert report["approved_count"] == 3
    assert report["threshold"] == 3
    assert len(report["signature_failures"]) == 0


def test_multi_agent_consensus_threshold_met():
    receipt = _create_sample_receipt()
    signer_1 = AgentSigner()
    signer_2 = AgentSigner()
    signer_3 = AgentSigner()

    # Require 2 of 3 votes
    engine = MultiAgentConsensusEngine.from_receipt(receipt, threshold=2)

    engine.add_attestation(signer_1, "agent-1", "gpt-4o", "WORKER_1", verdict="APPROVE")
    engine.add_attestation(signer_2, "agent-2", "gpt-4o", "WORKER_2", verdict="APPROVE")
    engine.add_attestation(signer_3, "agent-3", "gpt-4o", "WORKER_3", verdict="REJECT", comments="High volatility")

    rec = engine.finalize()
    signers = {"agent-1": signer_1, "agent-2": signer_2, "agent-3": signer_3}

    is_valid, report = verify_consensus_receipt(rec, signers=signers)
    assert is_valid is True
    assert report["approved_count"] == 2
    assert report["rejected_count"] == 1


def test_multi_agent_consensus_threshold_unmet():
    receipt = _create_sample_receipt()
    signer_1 = AgentSigner()
    signer_2 = AgentSigner()

    # Require 2 of 2 votes, but one rejects
    engine = MultiAgentConsensusEngine.from_receipt(receipt, threshold=2)
    engine.add_attestation(signer_1, "agent-1", "gpt-4o", "ROLE_1", verdict="APPROVE")
    engine.add_attestation(signer_2, "agent-2", "gpt-4o", "ROLE_2", verdict="REJECT")

    rec = engine.finalize()
    is_valid, report = verify_consensus_receipt(rec)

    assert is_valid is False
    assert report["approved_count"] == 1
    assert report["consensus_reached"] is False


def test_multi_agent_consensus_tampered_signature():
    receipt = _create_sample_receipt()
    signer_1 = AgentSigner()
    signer_tamper = AgentSigner()

    engine = MultiAgentConsensusEngine.from_receipt(receipt, threshold=1)
    att = engine.add_attestation(signer_1, "agent-1", "gpt-4o", "ROLE", verdict="APPROVE")

    rec = engine.finalize()
    # Check against another key (tampered)
    is_valid, report = verify_consensus_receipt(rec, signers={"agent-1": signer_tamper})
    assert is_valid is False
    assert "agent-1" in report["signature_failures"]
