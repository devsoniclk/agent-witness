import pytest
from agent_witness.delegation import create_delegation_grant
from agent_witness.dispute import (
    ArbitrationEngine,
    DisputeClaim,
    DisputeResolutionReport,
    DisputeType,
)
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner


def test_dispute_unauthorized_tool_fault():
    root_signer = AgentSigner()
    agent_signer = AgentSigner()

    grant = create_delegation_grant(
        parent_signer=root_signer,
        parent_agent_id="root",
        child_agent_id="agent_trader",
        child_pubkey=agent_signer.pubkey_hex,
        scope=["market_check", "get_balance"],
    )

    # Rogue agent calls forbidden tool "transfer_funds"
    engine = WitnessEngine(agent_id="agent_trader", signer=agent_signer)
    engine.record_step(StepType.THOUGHT, "Transferring funds")
    engine.record_step(StepType.TOOL_CALL, {"tool_name": "transfer_funds"})
    receipt = engine.finalize()

    claim = DisputeClaim(
        claim_id="disp_001",
        challenger_id="auditor_node",
        target_agent_id="agent_trader",
        receipt=receipt,
        dispute_type=DisputeType.UNAUTHORIZED_TOOL,
    )

    report = ArbitrationEngine.arbitrate(claim, delegation_grant=grant)

    assert report.is_fault_confirmed is True
    assert report.verdict == "FAULT_CONFIRMED"
    assert report.faulty_agent_id == "agent_trader"
    assert report.slashing_penalty_bps == 2500
    assert "transfer_funds" in report.reason
    assert report.slashing_payload is not None
    assert report.slashing_payload.evm_calldata.startswith("0x82a5c43d")


def test_dispute_tampered_merkle_root():
    signer = AgentSigner()
    engine = WitnessEngine(agent_id="agent_x", signer=signer)
    engine.record_step(StepType.THOUGHT, "Valid thought")
    receipt = engine.finalize()

    # Artificially tamper with the declared Merkle root
    receipt.merkle_root = "0" * 64

    claim = DisputeClaim(
        claim_id="disp_tamper_001",
        challenger_id="security_oracle",
        target_agent_id="agent_x",
        receipt=receipt,
        dispute_type=DisputeType.TAMPERED_RECEIPT,
    )

    report = ArbitrationEngine.arbitrate(claim)
    assert report.is_fault_confirmed is True
    assert report.verdict == "FAULT_CONFIRMED"
    assert report.slashing_penalty_bps == 10000  # 100% slashing for tampered root


def test_dispute_dismissed_when_compliant():
    root_signer = AgentSigner()
    agent_signer = AgentSigner()

    grant = create_delegation_grant(
        parent_signer=root_signer,
        parent_agent_id="root",
        child_agent_id="agent_compliant",
        child_pubkey=agent_signer.pubkey_hex,
        scope=["market_check"],
    )

    engine = WitnessEngine(agent_id="agent_compliant", signer=agent_signer)
    engine.record_step(StepType.THOUGHT, "Checking market")
    engine.record_step(StepType.TOOL_CALL, {"tool_name": "market_check"})
    receipt = engine.finalize()

    claim = DisputeClaim(
        claim_id="disp_false_001",
        challenger_id="rival_agent",
        target_agent_id="agent_compliant",
        receipt=receipt,
        dispute_type=DisputeType.UNAUTHORIZED_TOOL,
    )

    report = ArbitrationEngine.arbitrate(claim, delegation_grant=grant)
    assert report.is_fault_confirmed is False
    assert report.verdict == "DISPUTE_DISMISSED"
    assert report.slashing_payload is None
