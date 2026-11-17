from __future__ import annotations

import json
import pytest

from agent_witness.mcp_server import WitnessMCPServer
from agent_witness.models import StepType


def test_mcp_server_initialization_version():
    server = WitnessMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {},
    }
    resp = server.handle_request(req)
    assert resp["result"]["serverInfo"]["version"] in ("0.6.0", "0.7.0", "0.8.0")


def test_mcp_tools_list_has_v6_tools():
    server = WitnessMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    }
    resp = server.handle_request(req)
    tool_names = [t["name"] for t in resp["result"]["tools"]]
    assert "witness_anchor_multichain" in tool_names
    assert "witness_session_stream" in tool_names
    assert "witness_audit_compliance" in tool_names
    assert len(tool_names) >= 16


def test_mcp_tool_witness_session_stream():
    server = WitnessMCPServer()
    res = server.handle_call_tool(
        "witness_session_stream",
        {
            "session_id": "stream-mcp-test",
            "action": "append",
            "step_type": "thought",
            "content": "Evaluating multi-chain bridge parameters.",
        },
    )
    assert res["session_id"] == "stream-mcp-test"
    assert res["step_index"] == 0
    assert len(res["rolling_merkle_root"]) == 64
    assert res["total_steps"] == 1


def test_mcp_tool_witness_anchor_multichain():
    server = WitnessMCPServer()
    # First record action & finalize
    server.handle_call_tool("witness_record_action", {"step_type": "decision", "content": "Swap 10 SOL for USDC"})
    final_res = server.handle_call_tool("witness_finalize_receipt", {})

    anchor_res = server.handle_call_tool(
        "witness_anchor_multichain",
        {
            "chains": ["solana", "base"],
            "quorum_threshold": 2,
        },
    )
    assert anchor_res["status"] == "cross_chain_anchored"
    assert "solana" in anchor_res["anchors"]
    assert "base" in anchor_res["anchors"]
    assert anchor_res["verified"] is True
