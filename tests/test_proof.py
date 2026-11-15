import pytest
from agent_witness.models import StepType
from agent_witness.proof import export_proof_bundle, verify_proof_bundle
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner


def test_export_and_verify_proof_bundle():
    signer = AgentSigner()
    engine = WitnessEngine(
        agent_id="vault-agent-07",
        model_id="claude-3-7-sonnet",
        system_prompt="You manage vault deposits.",
        signer=signer,
    )

    engine.record_step(StepType.OBSERVATION, "Balance is 500,000 USDC")
    engine.record_step(StepType.THOUGHT, "Yield rate in Vault A is 14.2% APY")
    engine.record_step(StepType.TOOL_CALL, "deposit(amount=100000, vault='0x1234')")
    engine.record_step(StepType.TOOL_RESULT, "deposit_tx=0xabcdef123 status=confirmed")
    engine.record_step(StepType.DECISION, "Allocation updated successfully")

    receipt = engine.finalize_receipt()

    # Disclose only step #2 (the tool call)
    bundle = export_proof_bundle(receipt, step_index=2)

    assert bundle.agent_id == "vault-agent-07"
    assert bundle.merkle_root == receipt.merkle_root
    assert bundle.disclosed_step["index"] == 2
    assert "deposit(" in bundle.disclosed_step["content"]

    # Verify bundle standalone
    is_valid, reason = verify_proof_bundle(bundle.to_dict())
    assert is_valid, reason
    assert "Verified" in reason


def test_proof_bundle_tamper_leaf_content():
    engine = WitnessEngine(
        agent_id="test-agent",
        model_id="gpt-4o",
        system_prompt="Test system prompt",
    )
    engine.record_step(StepType.OBSERVATION, "Step 0")
    engine.record_step(StepType.DECISION, "Step 1: Authorized $100 transfer")
    receipt = engine.finalize_receipt()

    bundle = export_proof_bundle(receipt, step_index=1)
    bundle_dict = bundle.to_dict()

    # Tamper with the disclosed content
    bundle_dict["disclosed_step"]["content"] = "Step 1: Authorized $1,000,000 transfer"

    is_valid, reason = verify_proof_bundle(bundle_dict)
    assert not is_valid
    assert "Leaf hash mismatch" in reason


def test_proof_bundle_tamper_merkle_root():
    engine = WitnessEngine(
        agent_id="test-agent",
        model_id="gpt-4o",
        system_prompt="Test system prompt",
    )
    engine.record_step(StepType.OBSERVATION, "Step 0")
    engine.record_step(StepType.DECISION, "Step 1")
    receipt = engine.finalize_receipt()

    bundle = export_proof_bundle(receipt, step_index=1)
    bundle_dict = bundle.to_dict()

    # Tamper with root
    bundle_dict["merkle_root"] = "0" * 64

    is_valid, reason = verify_proof_bundle(bundle_dict)
    assert not is_valid
    assert "failed against root" in reason


def test_export_proof_out_of_bounds():
    engine = WitnessEngine("agent", "model", "prompt")
    engine.record_step(StepType.OBSERVATION, "Only step")
    receipt = engine.finalize_receipt()

    with pytest.raises(IndexError):
        export_proof_bundle(receipt, step_index=5)
