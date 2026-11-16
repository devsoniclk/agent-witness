import json
import pytest
from agent_witness.batch_anchor import BatchAnchorEngine, BatchInclusionProof, EpochBatchReceipt
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner


def test_batch_anchor_engine_lifecycle():
    signer = AgentSigner()
    engine = BatchAnchorEngine(epoch_id="epoch_test_100", signer=signer)

    # Create 3 receipts
    receipts = []
    for i in range(3):
        w_engine = WitnessEngine(f"agent-{i}", "model-1", f"Prompt {i}")
        w_engine.record_step(StepType.OBSERVATION, f"Step observation {i}")
        w_engine.record_step(StepType.DECISION, f"Step decision {i}")
        rec = w_engine.finalize_receipt()
        receipts.append(rec)
        engine.add_receipt(rec)

    assert len(engine.receipts) == 3

    batch_receipt, proofs = engine.build_batch()

    assert isinstance(batch_receipt, EpochBatchReceipt)
    assert batch_receipt.epoch_id == "epoch_test_100"
    assert batch_receipt.receipt_count == 3
    assert len(batch_receipt.epoch_root) == 64
    assert len(proofs) == 3

    # Check EVM calldata & Solana memo
    evm_calldata = batch_receipt.to_evm_calldata()
    assert evm_calldata.startswith("0x23a6f44d")
    assert batch_receipt.epoch_root in evm_calldata

    solana_memo = batch_receipt.to_solana_memo()
    assert solana_memo.startswith("AW:EPOCH:epoch_test_100:")

    # Verify batch inclusion proofs
    for i, proof in enumerate(proofs):
        assert isinstance(proof, BatchInclusionProof)
        assert proof.epoch_root == batch_receipt.epoch_root
        assert proof.receipt_index == i
        is_included = BatchAnchorEngine.verify_batch_inclusion(receipts[i], proof)
        assert is_included is True

    # Tampered receipt inclusion fails
    tampered_rec = receipts[0].to_dict()
    tampered_rec["merkle_root"] = "f" * 64
    assert BatchAnchorEngine.verify_batch_inclusion(tampered_rec, proofs[0]) is False
