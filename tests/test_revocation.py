from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.revocation import (
    RevocationEntry,
    RevocationReason,
    RevocationRegistry,
)
from agent_witness.signer import AgentSigner


def test_revocation_registry_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        reg_file = Path(tmpdir) / "revocations.json"
        reg = RevocationRegistry(storage_path=reg_file)

        agent_pubkey = "a1b2c3d4" * 8
        is_rev, entry = reg.is_revoked(agent_pubkey)
        assert is_rev is False
        assert entry is None

        # Issue non-revocation attestation
        att = reg.attest_non_revocation(agent_pubkey)
        assert att.is_active is True
        assert att.target_identifier == agent_pubkey
        assert att.registry_size == 0

        # Revoke agent
        entry = reg.revoke(
            target_identifier=agent_pubkey,
            target_type="AGENT_PUBKEY",
            reason=RevocationReason.OPERATOR_KILL_SWITCH,
            emergency_halt=True,
        )
        assert entry.target_identifier == agent_pubkey
        assert entry.reason == RevocationReason.OPERATOR_KILL_SWITCH

        is_rev2, entry2 = reg.is_revoked(agent_pubkey)
        assert is_rev2 is True
        assert entry2 is not None
        assert entry2.entry_id == entry.entry_id

        # Verify persistence reload
        reg_reloaded = RevocationRegistry(storage_path=reg_file)
        is_rev3, _ = reg_reloaded.is_revoked(agent_pubkey)
        assert is_rev3 is True


def test_revocation_receipt_gate():
    signer = AgentSigner()
    reg = RevocationRegistry()

    engine = WitnessEngine(agent_id="agent-rogue", model_id="qwen", system_prompt="Test", signer=signer)
    engine.record_step(StepType.DECISION, "Attempt unauthorized withdrawal")
    receipt = engine.finalize_receipt()

    # Initially active
    active, err = reg.verify_witness_receipt_active(receipt)
    assert active is True
    assert err is None

    # Kill switch triggered
    reg.revoke(receipt.agent_pubkey, reason=RevocationReason.ROGUE_BEHAVIOR)

    active2, err2 = reg.verify_witness_receipt_active(receipt)
    assert active2 is False
    assert "revoked: ROGUE_BEHAVIOR" in err2
