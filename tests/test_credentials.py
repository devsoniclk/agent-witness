from __future__ import annotations

import json
import time
import pytest

from agent_witness.credentials import (
    AgentCredentialEngine,
    CredentialProof,
    CredentialSubject,
    VerifiableAgentCredential,
    did_key_to_pubkey,
    pubkey_to_did_key,
)
from agent_witness.receipt import WitnessEngine
from agent_witness.models import StepType
from agent_witness.signer import AgentSigner


def test_did_key_derivation_and_roundtrip():
    signer = AgentSigner()
    did = pubkey_to_did_key(signer.pubkey_hex)
    assert did.startswith("did:key:z")

    recovered_hex = did_key_to_pubkey(did)
    assert recovered_hex == signer.pubkey_hex[:64]


def test_issue_and_verify_verifiable_agent_credential():
    issuer_signer = AgentSigner()
    engine = AgentCredentialEngine(issuer_signer=issuer_signer)

    agent_signer = AgentSigner()
    cred = engine.issue_credential(
        agent_id="test-agent-007",
        agent_pubkey=agent_signer.pubkey_hex,
        roles=["autonomous_executor", "defi_arbitrageur"],
        capabilities=["order_submit", "balance_query", "web_fetch"],
        allowed_models=["openbot-v1", "gpt-4o"],
        max_financial_limit=50000.0,
        sponsor_identity="corp.openbot.safety",
        validity_days=14,
    )

    assert cred.id.startswith("urn:uuid:")
    assert cred.issuer == engine.issuer_did
    assert cred.credential_subject.agent_id == "test-agent-007"
    assert cred.credential_subject.max_financial_limit == 50000.0
    assert cred.proof.proof_purpose == "assertionMethod"

    # Verify credential
    rep = engine.verify_credential(cred, trusted_issuer_did=engine.issuer_did)
    assert rep.is_valid is True
    assert rep.is_expired is False
    assert len(rep.errors) == 0


def test_credential_expiration_validation():
    engine = AgentCredentialEngine()
    agent_signer = AgentSigner()

    cred = engine.issue_credential(
        agent_id="exp-agent",
        agent_pubkey=agent_signer.pubkey_hex,
        validity_days=1,
    )

    # Check future time beyond 1 day
    future_ts = time.time() + 86400 * 2
    rep = engine.verify_credential(cred, now=future_ts)
    assert rep.is_valid is False
    assert rep.is_expired is True
    assert any("expired" in err.lower() for err in rep.errors)


def test_credential_receipt_binding():
    issuer_signer = AgentSigner()
    engine = AgentCredentialEngine(issuer_signer=issuer_signer)

    agent_signer = AgentSigner()
    cred = engine.issue_credential(
        agent_id="binding-agent",
        agent_pubkey=agent_signer.pubkey_hex,
        capabilities=["search_web", "read_file"],
        allowed_models=["qwen-3.5"],
    )

    # Create conforming receipt
    w_engine = WitnessEngine(
        agent_id="binding-agent",
        model_id="qwen-3.5",
        system_prompt="Test System",
        signer=agent_signer,
    )
    w_engine.record_step(StepType.TOOL_CALL, "search_web", metadata={"tool_name": "search_web"})
    receipt = w_engine.finalize_receipt()

    valid, violations = engine.bind_receipt(receipt, cred)
    assert valid is True
    assert len(violations) == 0

    # Test unauthorized model
    unauth_engine = WitnessEngine(
        agent_id="binding-agent",
        model_id="unauthorized-model-xyz",
        system_prompt="Test System",
        signer=agent_signer,
    )
    unauth_receipt = unauth_engine.finalize_receipt()
    valid2, violations2 = engine.bind_receipt(unauth_receipt, cred)
    assert valid2 is False
    assert any("not authorized" in v for v in violations2)

    # Test unauthorized tool
    tool_engine = WitnessEngine(
        agent_id="binding-agent",
        model_id="qwen-3.5",
        system_prompt="Test System",
        signer=agent_signer,
    )
    tool_engine.record_step(StepType.TOOL_CALL, "delete_database", metadata={"tool_name": "delete_database"})
    tool_receipt = tool_engine.finalize_receipt()
    valid3, violations3 = engine.bind_receipt(tool_receipt, cred)
    assert valid3 is False
    assert any("not in authorized capability" in v for v in violations3)
