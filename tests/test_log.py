from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from agent_witness.log import TransparencyLog
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner


def _create_dummy_receipt(agent_id: str, action: str):
    engine = WitnessEngine(
        agent_id=agent_id,
        model_id="gpt-4o",
        system_prompt="Test transparency log",
    )
    engine.record_step(StepType.OBSERVATION, f"Observed market condition for {action}")
    engine.record_step(StepType.DECISION, f"Execute {action}")
    return engine.finalize_receipt()


def test_transparency_log_append_and_root():
    log = TransparencyLog()
    assert log.tree_size == 0

    r1 = _create_dummy_receipt("agent-01", "trade_1")
    rec1 = log.append_receipt(r1)

    assert log.tree_size == 1
    assert rec1.log_index == 0
    assert len(log.get_root()) == 64

    r2 = _create_dummy_receipt("agent-02", "trade_2")
    rec2 = log.append_receipt(r2)

    assert log.tree_size == 2
    assert rec2.log_index == 1
    assert log.get_root(1) != log.get_root(2)


def test_transparency_log_inclusion_proof():
    log = TransparencyLog()
    receipts = [_create_dummy_receipt(f"agent-{i}", f"action_{i}") for i in range(5)]
    for r in receipts:
        log.append_receipt(r)

    assert log.tree_size == 5
    current_root = log.get_root()

    for idx in range(5):
        proof = log.get_inclusion_proof(idx)
        assert proof.log_index == idx
        assert proof.log_root == current_root
        assert TransparencyLog.verify_inclusion_proof(proof) is True

    # Tampered inclusion proof must fail
    proof_0 = log.get_inclusion_proof(0)
    proof_0.entry_hash = "deadbeef" * 8
    assert TransparencyLog.verify_inclusion_proof(proof_0) is False


def test_transparency_log_consistency_proof():
    log = TransparencyLog()
    for i in range(8):
        log.append_receipt(_create_dummy_receipt(f"agent-{i}", f"action_{i}"))

    # Consistency between size 3 and size 8
    proof = log.get_consistency_proof(old_size=3, new_size=8)
    assert proof.old_size == 3
    assert proof.new_size == 8
    assert len(proof.proof_hashes) == 5

    valid, reason = TransparencyLog.verify_consistency_proof(proof)
    assert valid is True
    assert "Verified append-only consistency" in reason

    # Inconsistent sizes
    proof.old_size = 9
    valid, reason = TransparencyLog.verify_consistency_proof(proof)
    assert valid is False


def test_transparency_log_checkpoint_signing_and_verification():
    signer = AgentSigner()
    log = TransparencyLog(signer=signer)

    for i in range(3):
        log.append_receipt(_create_dummy_receipt(f"agent-{i}", f"action_{i}"))

    cp = log.create_checkpoint()
    assert cp.tree_size == 3
    assert cp.signer_pubkey == signer.pubkey_hex
    assert TransparencyLog.verify_checkpoint(cp, signer) is True

    # Tampered checkpoint must fail
    cp.log_root = "0" * 64
    assert TransparencyLog.verify_checkpoint(cp, signer) is False


def test_transparency_log_disk_persistence():
    with tempfile.TemporaryDirectory() as td:
        log_dir = Path(td)
        log1 = TransparencyLog(log_dir=log_dir)

        r1 = _create_dummy_receipt("agent-p1", "persist_1")
        r2 = _create_dummy_receipt("agent-p2", "persist_2")
        log1.append_receipt(r1)
        log1.append_receipt(r2)
        root1 = log1.get_root()

        # Reopen log in fresh instance
        log2 = TransparencyLog(log_dir=log_dir)
        assert log2.tree_size == 2
        assert log2.get_root() == root1
        assert log2.entries[0].receipt_id == f"agent-p1:{r1.merkle_root[:16]}"
