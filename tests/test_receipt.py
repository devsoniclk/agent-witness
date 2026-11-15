from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner


def test_witness_engine_lifecycle():
    signer = AgentSigner()
    engine = WitnessEngine(
        agent_id="agent-trader-01",
        model_id="claude-3-7-sonnet",
        system_prompt="You are an autonomous treasury execution bot.",
        signer=signer,
    )

    engine.record_step(StepType.OBSERVATION, "Gas price is 15 Gwei")
    engine.record_step(StepType.THOUGHT, "Gas is within target threshold; proceeding")
    engine.record_step(StepType.DECISION, "Execute rebalance transaction", metadata={"amount_usdc": 5000})

    receipt = engine.finalize_receipt()

    assert receipt.agent_id == "agent-trader-01"
    assert receipt.step_count == 3
    assert len(receipt.merkle_root) == 64
    assert len(receipt.signature) == 64

    # Verify receipt authenticity
    assert WitnessEngine.verify_receipt(receipt, signer)


def test_witness_engine_tamper_signature_fails():
    signer = AgentSigner()
    engine = WitnessEngine(
        agent_id="agent-trader-01",
        model_id="claude-3-7-sonnet",
        system_prompt="Standard system prompt",
        signer=signer,
    )
    engine.record_step(StepType.DECISION, "Send 100 USDC")
    receipt = engine.finalize_receipt()

    # Tamper with an internal step
    receipt.steps[0]["content"] = "Send 1,000,000 USDC"

    # Re-verification must fail because reconstructed Merkle root won't match signature
    assert not WitnessEngine.verify_receipt(receipt, signer)
