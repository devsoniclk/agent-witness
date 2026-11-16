import json
import pytest
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.redaction import RedactionEngine, SaltedCommitment, SelectiveDisclosureReceipt
from agent_witness.signer import AgentSigner


def test_salted_commitment_creation_and_verification():
    commitment, val = SaltedCommitment.create("api_key", "sk_live_123456789abcdef")
    assert commitment.field_name == "api_key"
    assert len(commitment.commitment_hash) == 64
    assert commitment.verify("sk_live_123456789abcdef") is True
    assert commitment.verify("wrong_key") is False


def test_redaction_engine_step_indices():
    signer = AgentSigner()
    engine = WitnessEngine("agent-gov", "gpt-4", "System Prompt", signer=signer)
    engine.record_step(StepType.OBSERVATION, "User requested payroll processing.")
    engine.record_step(StepType.THOUGHT, "Confidential reasoning: checking salary levels and tax rates.")
    engine.record_step(StepType.TOOL_CALL, "payroll.query_ssn(user_id='emp_99')")
    engine.record_step(StepType.TOOL_RESULT, "SSN: 000-12-3456; Salary: $250,000")
    engine.record_step(StepType.DECISION, "Approve wire payment for payroll run.")
    receipt = engine.finalize_receipt()

    # Redact steps 1, 2, and 3
    redacted = RedactionEngine.redact_receipt(receipt, redact_steps=[1, 2, 3], redact_reason="PII Protection")

    assert isinstance(redacted, SelectiveDisclosureReceipt)
    assert redacted.redacted_step_indices == [1, 2, 3]
    assert "[REDACTED: PII Protection]" in redacted.steps[1]["content"]
    assert "[REDACTED: PII Protection]" in redacted.steps[2]["content"]
    assert "[REDACTED: PII Protection]" in redacted.steps[3]["content"]

    # Step 0 and Step 4 remain plaintext
    assert "User requested payroll processing." in redacted.steps[0]["content"]
    assert "Approve wire payment" in redacted.steps[4]["content"]

    # Merkle root MUST match original receipt
    assert redacted.merkle_root == receipt.merkle_root

    # Verify selective disclosure cryptographically
    is_valid, msg = RedactionEngine.verify_selective_disclosure(redacted, signer=signer)
    assert is_valid is True
    assert "Selective disclosure receipt verified" in msg


def test_redaction_engine_regex_pattern_matching():
    signer = AgentSigner()
    engine = WitnessEngine("agent-infra", "claude-3-opus", "System Prompt", signer=signer)
    engine.record_step(StepType.OBSERVATION, "Connecting to production database.")
    engine.record_step(StepType.TOOL_CALL, "curl -H 'Bearer eyJhbGciOiJIUzI1NiJ9.secret_token' https://api.prod/v1")
    engine.record_step(StepType.TOOL_RESULT, "HTTP 200 OK: session established")
    receipt = engine.finalize_receipt()

    # Automatically redact sensitive patterns (Bearer token)
    redacted = RedactionEngine.redact_receipt(receipt)
    assert 1 in redacted.redacted_step_indices
    assert "[REDACTED:" in redacted.steps[1]["content"]

    # Merkle root integrity intact
    is_valid, msg = RedactionEngine.verify_selective_disclosure(redacted, signer=signer)
    assert is_valid is True


def test_redaction_tampered_leaf_hash_fails():
    signer = AgentSigner()
    engine = WitnessEngine("agent-test", "model-x", "System Prompt", signer=signer)
    engine.record_step(StepType.OBSERVATION, "Step 0")
    engine.record_step(StepType.THOUGHT, "Confidential Step 1")
    receipt = engine.finalize_receipt()

    redacted = RedactionEngine.redact_receipt(receipt, redact_steps=[1])

    # Tamper with the preserved leaf hash of the redacted step
    redacted.steps[1]["leaf_hash"] = "0" * 64

    is_valid, msg = RedactionEngine.verify_selective_disclosure(redacted, signer=signer)
    assert is_valid is False
    assert "does not match" in msg
