import time
import pytest
from agent_witness.delegation import (
    DelegationCapability,
    DelegationDAGVerifier,
    DelegationLineageReport,
    create_delegation_grant,
)
from agent_witness.models import DeliberationStep, StepType, WitnessReceipt
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner


def test_create_and_verify_grant():
    parent_signer = AgentSigner()
    child_signer = AgentSigner()

    grant = create_delegation_grant(
        parent_signer=parent_signer,
        parent_agent_id="agent_root",
        child_agent_id="agent_sub_1",
        child_pubkey=child_signer.pubkey_hex,
        scope=["web_search", "run_test"],
        expires_in_seconds=3600.0,
        max_budget_usd=50.0,
    )

    assert grant.parent_agent_id == "agent_root"
    assert grant.child_agent_id == "agent_sub_1"
    assert grant.parent_pubkey == parent_signer.pubkey_hex
    assert "web_search" in grant.scope
    assert grant.max_budget_usd == 50.0
    assert len(grant.parent_signature) == 64

    # Verification passes
    assert DelegationDAGVerifier.verify_grant_signature(grant, parent_signer)


def test_delegation_dag_lineage_valid():
    root_signer = AgentSigner()
    sub1_signer = AgentSigner()
    worker_signer = AgentSigner()

    grant1 = create_delegation_grant(
        parent_signer=root_signer,
        parent_agent_id="root",
        child_agent_id="sub1",
        child_pubkey=sub1_signer.pubkey_hex,
        scope=["web_search", "math", "write_file"],
        expires_in_seconds=3600.0,
        max_budget_usd=100.0,
    )

    grant2 = create_delegation_grant(
        parent_signer=sub1_signer,
        parent_agent_id="sub1",
        child_agent_id="worker1",
        child_pubkey=worker_signer.pubkey_hex,
        scope=["web_search", "math"],  # Restrictive sub-scope
        expires_in_seconds=1800.0,
        max_budget_usd=25.0,
    )

    # Worker executes action receipt
    engine = WitnessEngine(agent_id="worker1", signer=worker_signer)
    engine.record_step(StepType.THOUGHT, "Need to search docs")
    engine.record_step(StepType.TOOL_CALL, {"tool_name": "web_search", "cost_usd": 0.05})
    receipt = engine.finalize()

    report = DelegationDAGVerifier.verify_lineage(
        root_agent_id="root",
        grants=[grant1, grant2],
        action_receipts=[receipt],
        parent_signers={"root": root_signer, "sub1": sub1_signer},
    )

    assert report.is_valid is True
    assert report.chain_depth == 2
    assert report.nodes_verified == 2
    assert len(report.violations) == 0


def test_delegation_unauthorized_scope_escalation():
    root_signer = AgentSigner()
    sub1_signer = AgentSigner()

    grant1 = create_delegation_grant(
        parent_signer=root_signer,
        parent_agent_id="root",
        child_agent_id="sub1",
        child_pubkey=sub1_signer.pubkey_hex,
        scope=["read_only"],
        expires_in_seconds=3600.0,
    )

    # Sub1 tries to grant write_file to worker
    worker_signer = AgentSigner()
    grant2 = create_delegation_grant(
        parent_signer=sub1_signer,
        parent_agent_id="sub1",
        child_agent_id="worker1",
        child_pubkey=worker_signer.pubkey_hex,
        scope=["read_only", "write_file"],  # Unauthorized escalation
        expires_in_seconds=1800.0,
    )

    report = DelegationDAGVerifier.verify_lineage(
        root_agent_id="root",
        grants=[grant1, grant2],
        parent_signers={"root": root_signer, "sub1": sub1_signer},
    )

    assert report.is_valid is False
    assert any("escalates unauthorized scopes" in v for v in report.violations)


def test_delegation_budget_exceeded():
    root_signer = AgentSigner()
    worker_signer = AgentSigner()

    grant = create_delegation_grant(
        parent_signer=root_signer,
        parent_agent_id="root",
        child_agent_id="worker1",
        child_pubkey=worker_signer.pubkey_hex,
        scope=["api_call"],
        max_budget_usd=10.0,
        expires_in_seconds=3600.0,
    )

    engine = WitnessEngine(agent_id="worker1", signer=worker_signer)
    engine.record_step(StepType.TOOL_CALL, {"tool_name": "api_call", "cost_usd": 15.50})
    receipt = engine.finalize()

    report = DelegationDAGVerifier.verify_lineage(
        root_agent_id="root",
        grants=[grant],
        action_receipts=[receipt],
        parent_signers={"root": root_signer},
    )

    assert report.is_valid is False
    assert any("exceeded budget" in v for v in report.violations)
