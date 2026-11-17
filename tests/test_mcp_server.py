import json
from pathlib import Path
import pytest

from agent_witness.mcp_server import WitnessMCPServer


def test_mcp_server_tool_definitions(tmp_path):
    server = WitnessMCPServer(log_dir=str(tmp_path / ".witness_log"))
    tools = server.get_tool_definitions()

    tool_names = [t["name"] for t in tools]
    assert "witness_record_action" in tool_names
    assert "witness_finalize_receipt" in tool_names
    assert "witness_audit_trajectory" in tool_names
    assert "witness_export_proof" in tool_names
    assert "witness_verify_proof" in tool_names
    assert "witness_log_append" in tool_names
    assert "witness_log_checkpoint" in tool_names
    assert "witness_log_verify_consistency" in tool_names
    assert "witness_attest_consensus" in tool_names
    assert "witness_generate_dossier" in tool_names
    # v0.5.0 tools
    assert "witness_redact_receipt" in tool_names
    assert "witness_evaluate_policy" in tool_names
    assert "witness_batch_anchor" in tool_names
    # v0.6.0 tools
    assert "witness_anchor_multichain" in tool_names
    assert "witness_session_stream" in tool_names
    assert "witness_audit_compliance" in tool_names
    # v0.7.0 tools
    assert "witness_issue_credential" in tool_names
    assert "witness_verify_credential" in tool_names
    assert "witness_generate_zk_attestation" in tool_names
    assert "witness_verify_zk_attestation" in tool_names
    assert "witness_check_revocation" in tool_names
    assert "witness_delegate_capability" in tool_names
    assert "witness_verify_delegation_dag" in tool_names
    assert "witness_blind_receipt" in tool_names
    assert "witness_arbitrate_dispute" in tool_names
    # v0.8.0 tools
    assert "witness_generate_zkvm_receipt" in tool_names
    assert "witness_verify_zkvm_receipt" in tool_names
    assert "witness_dispatch_crosschain_attestation" in tool_names
    assert "witness_estimate_crosschain_fees" in tool_names
    assert "witness_aggregate_rollup_batch" in tool_names
    assert "witness_verify_rollup_batch" in tool_names
    # v0.9.0 tools
    assert "witness_bridge_execute_pipeline" in tool_names
    assert "witness_bridge_verify_pipeline" in tool_names
    assert len(tools) == 33


def test_mcp_server_lifecycle_record_and_finalize(tmp_path):
    server = WitnessMCPServer(log_dir=str(tmp_path / ".witness_log"))

    r1 = server.handle_call_tool("witness_record_action", {
        "step_type": "observation",
        "content": "Oracle price feed update observed at 142.50 USD",
        "metadata": {"feed": "PYTH/SOL"},
    })
    assert r1["status"] == "recorded"
    assert r1["step_index"] == 0

    r2 = server.handle_call_tool("witness_record_action", {
        "step_type": "thought",
        "content": "Price within acceptable bounds; no liquidation trigger required",
    })
    assert r2["status"] == "recorded"
    assert r2["step_index"] == 1

    r3 = server.handle_call_tool("witness_record_action", {
        "step_type": "decision",
        "content": "Maintain current margin ratio",
    })
    assert r3["status"] == "recorded"
    assert r3["step_index"] == 2

    # Finalize
    receipt_file = str(tmp_path / "test_receipt.json")
    final_res = server.handle_call_tool("witness_finalize_receipt", {"output_file": receipt_file})
    assert final_res["status"] == "finalized"
    assert final_res["step_count"] == 3
    assert len(final_res["merkle_root"]) == 64
    assert Path(receipt_file).exists()

    # Audit trajectory
    audit_res = server.handle_call_tool("witness_audit_trajectory", {})
    assert audit_res["is_valid"] is True
    assert audit_res["failed_checks"] == 0


def test_mcp_server_proof_export_and_verify(tmp_path):
    server = WitnessMCPServer(log_dir=str(tmp_path / ".witness_log"))
    server.handle_call_tool("witness_record_action", {"step_type": "observation", "content": "Initial step"})
    server.handle_call_tool("witness_record_action", {"step_type": "decision", "content": "Final step"})
    server.handle_call_tool("witness_finalize_receipt", {})

    proof_file = str(tmp_path / "proof_step_1.json")
    exp_res = server.handle_call_tool("witness_export_proof", {
        "step_index": 1,
        "output_file": proof_file,
    })
    assert exp_res["status"] == "exported"
    assert Path(proof_file).exists()

    # Verify proof
    ver_res = server.handle_call_tool("witness_verify_proof", {"proof_file": proof_file})
    assert ver_res["is_valid"] is True
    assert ver_res["disclosed_step_index"] == 1


def test_mcp_server_transparency_log_workflow(tmp_path):
    log_dir = str(tmp_path / "log_vault")
    server = WitnessMCPServer(log_dir=log_dir)

    server.handle_call_tool("witness_record_action", {"step_type": "decision", "content": "Action 1"})
    server.handle_call_tool("witness_finalize_receipt", {})

    append_res = server.handle_call_tool("witness_log_append", {})
    assert append_res["status"] == "appended"
    assert append_res["log_tree_size"] == 1

    checkpoint_res = server.handle_call_tool("witness_log_checkpoint", {})
    assert checkpoint_res["status"] == "checkpoint_created"
    assert checkpoint_res["tree_size"] == 1
    assert len(checkpoint_res["log_root"]) == 64

    # Second receipt to verify consistency
    server.engine.record_step(server.engine.steps[0].step_type, "Action 2")
    server.handle_call_tool("witness_finalize_receipt", {})
    server.handle_call_tool("witness_log_append", {})

    consist_res = server.handle_call_tool("witness_log_verify_consistency", {"old_size": 1, "new_size": 2})
    assert consist_res["is_consistent"] is True


def test_mcp_server_attest_consensus(tmp_path):
    server = WitnessMCPServer(log_dir=str(tmp_path / ".witness_log"))
    server.handle_call_tool("witness_record_action", {"step_type": "decision", "content": "Consensus test"})
    fin = server.handle_call_tool("witness_finalize_receipt", {})
    root = fin["merkle_root"]

    res = server.handle_call_tool("witness_attest_consensus", {
        "merkle_root": root,
        "agent_id": "auditor-agent-01",
        "role": "SecurityVerifier",
        "verdict": "APPROVE",
        "threshold": 1,
        "comments": "Audited and verified compliant",
    })
    assert res["status"] == "attestation_recorded"
    assert res["consensus_reached"] is True
    assert res["approved_count"] == 1


def test_mcp_server_generate_dossier(tmp_path):
    server = WitnessMCPServer(log_dir=str(tmp_path / ".witness_log"))
    server.handle_call_tool("witness_record_action", {"step_type": "observation", "content": "Sensors nominal"})
    server.handle_call_tool("witness_record_action", {"step_type": "decision", "content": "Deploy changes"})
    server.handle_call_tool("witness_finalize_receipt", {})

    out_html = str(tmp_path / "dossier.html")
    res = server.handle_call_tool("witness_generate_dossier", {"output_file": out_html})
    assert res["status"] == "generated"
    assert Path(out_html).exists()
    content = Path(out_html).read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "Agent Witness" in content


def test_mcp_server_v050_tools(tmp_path):
    server = WitnessMCPServer(log_dir=str(tmp_path / ".witness_log"))
    server.handle_call_tool("witness_record_action", {"step_type": "observation", "content": "Starting pipeline"})
    server.handle_call_tool("witness_record_action", {"step_type": "thought", "content": "Private secret api_key: sk_live_9988776655"})
    server.handle_call_tool("witness_record_action", {"step_type": "decision", "content": "Approved execution"})
    rec_file = str(tmp_path / "receipt_v050.json")
    server.handle_call_tool("witness_finalize_receipt", {"output_file": rec_file})

    # Redact tool
    red_file = str(tmp_path / "redacted_v050.json")
    red_res = server.handle_call_tool("witness_redact_receipt", {
        "receipt_file": rec_file,
        "redact_steps": [1],
        "output_file": red_file,
    })
    assert red_res["status"] == "redacted"
    assert red_res["is_cryptographically_valid"] is True
    assert Path(red_file).exists()

    # Policy tool
    pol_res = server.handle_call_tool("witness_evaluate_policy", {
        "receipt_file": rec_file,
        "max_steps": 50,
    })
    assert pol_res["is_compliant"] is True
    assert pol_res["total_violations"] == 0

    # Batch anchor tool
    anc_file = str(tmp_path / "batch_anchor.json")
    anc_res = server.handle_call_tool("witness_batch_anchor", {
        "receipt_files": [rec_file],
        "epoch_id": "epoch_alpha",
        "output_file": anc_file,
    })
    assert anc_res["status"] == "anchored"
    assert anc_res["receipt_count"] == 1
    assert anc_res["evm_calldata"].startswith("0x23a6f44d")
    assert anc_res["solana_memo"].startswith("AW:EPOCH:epoch_alpha:")
    assert Path(anc_file).exists()


def test_mcp_server_json_rpc_dispatch(tmp_path):
    server = WitnessMCPServer(log_dir=str(tmp_path / ".witness_log"))

    # initialize
    init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    init_res = server.handle_request(init_req)
    assert init_res["result"]["serverInfo"]["name"] == "agent-witness-mcp"
    assert init_res["result"]["serverInfo"]["version"] == "0.9.0"

    # notifications/initialized
    notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    assert server.handle_request(notif) is None

    # tools/list
    list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    list_res = server.handle_request(list_req)
    assert len(list_res["result"]["tools"]) == 33

    # tools/call
    call_req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "witness_record_action",
            "arguments": {"step_type": "thought", "content": "Testing JSON-RPC call"},
        },
    }
    call_res = server.handle_request(call_req)
    content_text = call_res["result"]["content"][0]["text"]
    parsed = json.loads(content_text)
    assert parsed["status"] == "recorded"

    # ping
    ping_res = server.handle_request({"jsonrpc": "2.0", "id": 4, "method": "ping"})
    assert ping_res["result"] == {}

    # unknown method
    err_res = server.handle_request({"jsonrpc": "2.0", "id": 5, "method": "unknown_tool_foo"})
    assert err_res["error"]["code"] == -32601
