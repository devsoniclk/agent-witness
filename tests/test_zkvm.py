import json
import pytest

from agent_witness.models import StepType, WitnessReceipt
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner
from agent_witness.zkvm import (
    DEFAULT_RISC0_IMAGE_ID,
    DEFAULT_SP1_VKEY,
    ZKVMDeliberationEngine,
    ZKVMReceipt,
)


@pytest.fixture
def sample_receipt():
    signer = AgentSigner()
    engine = WitnessEngine(
        agent_id="test_agent_zkvm",
        signer=signer,
        model_id="gpt-4o",
        system_prompt="You are a safe financial agent.",
    )
    engine.record_step(StepType.OBSERVATION, "User requested transfer of 500 USDC")
    engine.record_step(StepType.THOUGHT, "Checking whitelist policy")
    engine.record_step(StepType.TOOL_CALL, "transfer_erc20(amount=500, to=0xabc)")
    engine.record_step(StepType.TOOL_RESULT, "transfer_tx_hash=0x123")
    return engine.finalize_receipt()


def test_zkvm_generate_and_verify_risc0(sample_receipt):
    zk_rcpt = ZKVMDeliberationEngine.generate_receipt(
        receipt=sample_receipt,
        zkvm_system="risc0",
    )
    assert zk_rcpt.zkvm_system == "risc0"
    assert zk_rcpt.program_id == DEFAULT_RISC0_IMAGE_ID
    assert zk_rcpt.journal["merkle_root"] == sample_receipt.merkle_root
    assert zk_rcpt.journal["status_code"] == 0
    assert "transfer_erc20(amount=500, to=0xabc)" in zk_rcpt.journal["authorized_actions"]

    # Verify
    report = ZKVMDeliberationEngine.verify_receipt(
        zkvm_receipt=zk_rcpt,
        expected_merkle_root=sample_receipt.merkle_root,
    )
    assert report.is_valid is True
    assert report.policy_satisfied is True
    assert report.status_code == 0


def test_zkvm_generate_and_verify_sp1(sample_receipt):
    custom_vkey = "0x" + "a" * 64
    zk_rcpt = ZKVMDeliberationEngine.generate_receipt(
        receipt=sample_receipt,
        zkvm_system="sp1",
        program_id=custom_vkey,
    )
    assert zk_rcpt.zkvm_system == "sp1"
    assert zk_rcpt.program_id == custom_vkey

    report = ZKVMDeliberationEngine.verify_receipt(
        zkvm_receipt=zk_rcpt,
        allowed_program_ids=[custom_vkey],
    )
    assert report.is_valid is True
    assert report.policy_satisfied is True


def test_zkvm_tampered_journal_fails(sample_receipt):
    zk_rcpt = ZKVMDeliberationEngine.generate_receipt(
        receipt=sample_receipt,
        zkvm_system="risc0",
    )
    # Corrupt journal digest
    tampered_rcpt = ZKVMReceipt(
        receipt_id=zk_rcpt.receipt_id,
        zkvm_system=zk_rcpt.zkvm_system,
        program_id=zk_rcpt.program_id,
        journal=zk_rcpt.journal,
        journal_bytes_hex=zk_rcpt.journal_bytes_hex,
        journal_digest="0x" + "0" * 64,
        seal_hex=zk_rcpt.seal_hex,
    )
    report = ZKVMDeliberationEngine.verify_receipt(tampered_rcpt)
    assert report.is_valid is False


def test_zkvm_disallowed_program_id_fails(sample_receipt):
    zk_rcpt = ZKVMDeliberationEngine.generate_receipt(
        receipt=sample_receipt,
        zkvm_system="risc0",
    )
    report = ZKVMDeliberationEngine.verify_receipt(
        zkvm_receipt=zk_rcpt,
        allowed_program_ids=["0x" + "f" * 64],
    )
    assert report.is_valid is False
