import json
import tempfile
from pathlib import Path
import pytest

from agent_witness.mcp_server import WitnessMCPServer
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner


@pytest.fixture
def mcp_server():
    server = WitnessMCPServer()
    server.engine.record_step(StepType.OBSERVATION, "Observation for v8 MCP test")
    server.engine.record_step(StepType.TOOL_CALL, "execute_trade(amount=100)")
    server.handle_call_tool("witness_finalize_receipt", {})
    return server


def test_mcp_zkvm_generate_and_verify(mcp_server):
    gen_res = mcp_server.handle_call_tool("witness_generate_zkvm_receipt", {"zkvm_system": "risc0"})
    assert gen_res["status"] == "success"
    zkvm_rcpt = gen_res["zkvm_receipt"]
    assert zkvm_rcpt["zkvm_system"] == "risc0"

    ver_res = mcp_server.handle_call_tool("witness_verify_zkvm_receipt", {"zkvm_receipt": zkvm_rcpt})
    assert ver_res["is_valid"] is True
    assert ver_res["policy_satisfied"] is True


def test_mcp_crosschain_dispatch_and_estimate(mcp_server):
    est_res = mcp_server.handle_call_tool("witness_estimate_crosschain_fees", {
        "protocol": "layerzero_v2",
        "dst_chain": "ethereum",
    })
    assert "total_fee_eth" in est_res
    assert est_res["fee_usd"] > 0.0

    disp_res = mcp_server.handle_call_tool("witness_dispatch_crosschain_attestation", {
        "protocol": "layerzero_v2",
        "dst_chain": "base",
        "receiver_address": "0x" + "5" * 40,
    })
    assert disp_res["status"] == "dispatched"
    assert disp_res["protocol"] == "layerzero_v2"
    assert disp_res["message_guid_or_id"].startswith("0x")


def test_mcp_rollup_batch_and_verify(mcp_server):
    # Create two temporary receipt files
    signer = AgentSigner()
    engine1 = WitnessEngine(agent_id="agent_a", signer=signer, model_id="gpt-4o", system_prompt="sys")
    engine1.record_step(StepType.OBSERVATION, "A")
    r1 = engine1.finalize_receipt()

    engine2 = WitnessEngine(agent_id="agent_b", signer=signer, model_id="gpt-4o", system_prompt="sys")
    engine2.record_step(StepType.OBSERVATION, "B")
    r2 = engine2.finalize_receipt()

    with tempfile.TemporaryDirectory() as tmpdir:
        p1 = Path(tmpdir) / "r1.witness.json"
        p2 = Path(tmpdir) / "r2.witness.json"
        p1.write_text(json.dumps(r1.to_dict()), encoding="utf-8")
        p2.write_text(json.dumps(r2.to_dict()), encoding="utf-8")

        agg_res = mcp_server.handle_call_tool("witness_aggregate_rollup_batch", {
            "receipt_files": [str(p1), str(p2)],
        })
        assert agg_res["status"] == "success"
        assert agg_res["receipt_count"] == 2
        batch_dict = agg_res["batch_receipt"]

        ver_res = mcp_server.handle_call_tool("witness_verify_rollup_batch", {
            "batch_receipt": batch_dict,
        })
        assert ver_res["is_valid"] is True
        assert ver_res["batch_signature_valid"] is True
