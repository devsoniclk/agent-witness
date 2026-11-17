import pytest

from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.rollup import RollupBatchAggregator, RollupBatchReceipt, RollupInclusionProof
from agent_witness.signer import AgentSigner


def make_receipt(agent_name: str, step_content: str):
    signer = AgentSigner()
    engine = WitnessEngine(
        agent_id=agent_name,
        signer=signer,
        model_id="gpt-4o",
        system_prompt="Test system prompt",
    )
    engine.record_step(StepType.OBSERVATION, f"Obs: {step_content}")
    engine.record_step(StepType.DECISION, f"Decision: {step_content}")
    return engine.finalize_receipt()


def test_rollup_aggregate_and_verify():
    r1 = make_receipt("agent_1", "Action A")
    r2 = make_receipt("agent_2", "Action B")
    r3 = make_receipt("agent_3", "Action C")
    r4 = make_receipt("agent_4", "Action D")

    batch, super_tree = RollupBatchAggregator.aggregate([r1, r2, r3, r4])
    assert batch.receipt_count == 4
    assert batch.total_steps == 8
    assert batch.super_merkle_root == super_tree.root_hex
    assert len(batch.participating_agents) == 4
    assert batch.calldata_compression_ratio > 1.0

    # Signature verification
    assert RollupBatchAggregator.verify_batch_receipt(batch) is True

    # Inclusion proof verification
    proof = RollupBatchAggregator.generate_inclusion_proof(batch, super_tree, r2.merkle_root)
    assert proof.receipt_merkle_root == r2.merkle_root
    assert proof.leaf_index == 1
    assert RollupBatchAggregator.verify_inclusion_proof(proof) is True


def test_rollup_invalid_inclusion_proof_fails():
    r1 = make_receipt("agent_1", "Action A")
    r2 = make_receipt("agent_2", "Action B")
    batch, super_tree = RollupBatchAggregator.aggregate([r1, r2])

    proof = RollupBatchAggregator.generate_inclusion_proof(batch, super_tree, r1.merkle_root)
    # Corrupt proof receipt root
    tampered_proof = RollupInclusionProof(
        receipt_merkle_root="0x" + "9" * 64,
        batch_id=proof.batch_id,
        super_merkle_root=proof.super_merkle_root,
        leaf_index=proof.leaf_index,
        audit_path=proof.audit_path,
    )
    assert RollupBatchAggregator.verify_inclusion_proof(tampered_proof) is False
