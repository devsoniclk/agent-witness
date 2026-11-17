import pytest

from agent_witness.crosschain import (
    CrossChainAttestationDispatcher,
    CrossChainProtocol,
    LZ_ENDPOINT_IDS,
    CCIP_CHAIN_SELECTORS,
)
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner


@pytest.fixture
def sample_receipt():
    signer = AgentSigner()
    engine = WitnessEngine(
        agent_id="crosschain_agent",
        signer=signer,
        model_id="claude-3-5-sonnet",
        system_prompt="You are a multi-chain liquidity manager.",
    )
    engine.record_step(StepType.OBSERVATION, "Detected price divergence on Arbitrum vs Ethereum")
    engine.record_step(StepType.TOOL_CALL, "rebalance_vault(amount=1000)")
    return engine.finalize_receipt()


def test_prepare_layerzero_v2(sample_receipt):
    receiver = "0x" + "2" * 40
    payload = CrossChainAttestationDispatcher.prepare_layerzero_v2(
        receipt=sample_receipt,
        dst_chain="ethereum",
        receiver_address=receiver,
        gas_limit=200000,
    )
    assert payload.dst_eid == LZ_ENDPOINT_IDS["ethereum"]
    assert payload.dst_chain == "ethereum"
    assert payload.receiver_address == receiver
    assert payload.payload_bytes_hex.startswith("0x")
    assert payload.options_hex.startswith("0x000301")
    assert payload.message_guid.startswith("0x")
    assert payload.estimated_fee_usd > 0.0


def test_prepare_chainlink_ccip(sample_receipt):
    receiver = "0x" + "3" * 40
    payload = CrossChainAttestationDispatcher.prepare_chainlink_ccip(
        receipt=sample_receipt,
        dst_chain="base",
        receiver_address=receiver,
        gas_limit=180000,
    )
    assert payload.dst_chain_selector == CCIP_CHAIN_SELECTORS["base"]
    assert payload.dst_chain == "base"
    assert payload.data_hex.startswith("0x")
    assert payload.message_id.startswith("0x")
    assert payload.estimated_fee_usd > 0.0


def test_crosschain_dispatch_end_to_end(sample_receipt):
    receiver = "0x" + "4" * 40
    record = CrossChainAttestationDispatcher.dispatch(
        receipt=sample_receipt,
        protocol="layerzero_v2",
        dst_chain="optimism",
        receiver_address=receiver,
        src_chain="arbitrum",
    )
    assert record.protocol == "layerzero_v2"
    assert record.dst_chain == "optimism"
    assert record.src_chain == "arbitrum"
    assert record.receipt_merkle_root == sample_receipt.merkle_root
    assert record.target_verifier_contract == receiver
    assert record.message_guid_or_id.startswith("0x")


def test_estimate_fees_multiple_chains():
    eth_est = CrossChainAttestationDispatcher.estimate_fees("layerzero_v2", "ethereum")
    arb_est = CrossChainAttestationDispatcher.estimate_fees("layerzero_v2", "arbitrum")
    assert eth_est["fee_usd"] > arb_est["fee_usd"]
    assert eth_est["dest_gas_wei"] > arb_est["dest_gas_wei"]
