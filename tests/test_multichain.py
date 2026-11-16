from __future__ import annotations

import hashlib
import json
import pytest

from agent_witness.multichain import (
    MultiChainAnchorDispatcher,
    compute_anchor_instruction_discriminator,
    b58encode,
    b58decode,
    SolanaAnchorPayload,
    EVMAnchorPayload,
    CrossChainAttestationBundle,
)
from agent_witness.signer import AgentSigner


def test_anchor_discriminator_computation():
    disc = compute_anchor_instruction_discriminator("anchor_epoch_root")
    assert len(disc) == 8
    expected = hashlib.sha256(b"global:anchor_epoch_root").digest()[:8]
    assert disc == expected


def test_b58_roundtrip():
    data = b"witness_crypto_solana_test_bytes_123"
    encoded = b58encode(data)
    decoded = b58decode(encoded)
    assert decoded == data


def test_solana_pda_derivation():
    dispatcher = MultiChainAnchorDispatcher()
    prog_id = "Witnss1111111111111111111111111111111111111"
    authority = "11111111111111111111111111111111"
    
    pda1, bump1 = dispatcher.derive_solana_pda(prog_id, authority, "epoch-42")
    pda2, bump2 = dispatcher.derive_solana_pda(prog_id, authority, "epoch-42")
    
    assert pda1 == pda2
    assert bump1 == bump2
    assert len(pda1) > 20


def test_build_solana_anchor_payload():
    dispatcher = MultiChainAnchorDispatcher()
    dummy_root = "0x" + "a" * 64
    payload = dispatcher.build_solana_anchor_payload(
        merkle_root=dummy_root,
        identifier="epoch-100",
        receipt_count=5,
    )
    assert isinstance(payload, SolanaAnchorPayload)
    assert payload.program_id == MultiChainAnchorDispatcher.DEFAULT_SOLANA_PROGRAM_ID
    assert len(payload.accounts) == 3
    assert payload.accounts[0]["role"] == "witness_state"
    assert len(payload.instruction_data_hex) > 64


def test_build_evm_anchor_payload():
    dispatcher = MultiChainAnchorDispatcher()
    dummy_root = "0x" + "b" * 64
    payload = dispatcher.build_evm_anchor_payload(
        merkle_root=dummy_root,
        identifier="epoch-200",
        receipt_count=12,
        chain_id=8453,
    )
    assert isinstance(payload, EVMAnchorPayload)
    assert payload.chain_id == 8453
    assert payload.chain_name == "Base"
    assert payload.calldata_hex.startswith("0x")
    assert len(payload.calldata_hex) > 100


def test_cross_chain_bundle_quorum():
    dispatcher = MultiChainAnchorDispatcher()
    dummy_root = "0x" + "c" * 64
    bundle = dispatcher.create_cross_chain_bundle(
        merkle_root=dummy_root,
        identifier="epoch-multi",
        chains=["solana", "base", "arbitrum"],
        receipt_count=20,
        quorum_threshold=2,
    )
    assert isinstance(bundle, CrossChainAttestationBundle)
    assert bundle.quorum_threshold == 2
    assert bundle.total_chains == 3
    assert bundle.verified is True
    assert "solana" in bundle.anchors
    assert "base" in bundle.anchors
    assert "arbitrum" in bundle.anchors
    assert len(bundle.signature) > 0

    assert MultiChainAnchorDispatcher.verify_bundle_signature(bundle) is True
