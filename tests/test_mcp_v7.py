from __future__ import annotations

import json
import tempfile
from pathlib import Path
import pytest

from agent_witness.mcp_server import WitnessMCPServer


def test_mcp_server_v7_initialization_and_tool_count():
    with tempfile.TemporaryDirectory() as tmpdir:
        server = WitnessMCPServer(log_dir=tmpdir)
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        }
        resp = server.handle_request(init_req)
        assert resp["result"]["serverInfo"]["version"] == "0.9.0"

        tools_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        tools_resp = server.handle_request(tools_req)
        tools = tools_resp["result"]["tools"]
        tool_names = {t["name"] for t in tools}

        assert len(tools) >= 33
        assert "witness_issue_credential" in tool_names
        assert "witness_verify_credential" in tool_names
        assert "witness_generate_zk_attestation" in tool_names
        assert "witness_verify_zk_attestation" in tool_names
        assert "witness_check_revocation" in tool_names
        assert "witness_delegate_capability" in tool_names
        assert "witness_verify_delegation_dag" in tool_names
        assert "witness_blind_receipt" in tool_names
        assert "witness_arbitrate_dispute" in tool_names


def test_mcp_credential_tools():
    with tempfile.TemporaryDirectory() as tmpdir:
        server = WitnessMCPServer(log_dir=tmpdir)

        # 1. Issue credential
        issue_req = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "witness_issue_credential",
                "arguments": {
                    "agent_id": "mcp-agent-01",
                    "roles": ["executor"],
                    "capabilities": ["search_web"],
                    "max_financial_limit": 500.0,
                },
            },
        }
        resp = server.handle_request(issue_req)
        data = json.loads(resp["result"]["content"][0]["text"])
        assert data["status"] == "success"
        cred = data["credential"]

        # 2. Verify credential
        verify_req = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "witness_verify_credential",
                "arguments": {
                    "credential": cred,
                },
            },
        }
        v_resp = server.handle_request(verify_req)
        v_data = json.loads(v_resp["result"]["content"][0]["text"])
        assert v_data["is_valid"] is True


def test_mcp_zk_and_revocation_tools():
    with tempfile.TemporaryDirectory() as tmpdir:
        server = WitnessMCPServer(log_dir=tmpdir)

        # Record action and finalize
        server.handle_call_tool("witness_record_action", {"step_type": "thought", "content": "Analyzing"})
        server.handle_call_tool("witness_record_action", {"step_type": "decision", "content": "Concluded"})
        fin_resp = server.handle_call_tool("witness_finalize_receipt", {})

        # Generate ZK proof
        zk_gen = server.handle_call_tool(
            "witness_generate_zk_attestation",
            {"max_steps": 5, "max_duration_ms": 1000.0},
        )
        assert zk_gen["status"] == "success"
        proof = zk_gen["proof"]

        # Verify ZK proof
        zk_ver = server.handle_call_tool(
            "witness_verify_zk_attestation",
            {"proof": proof, "max_steps": 5, "max_duration_ms": 1000.0},
        )
        assert zk_ver["is_verified"] is True

        # Check revocation
        rev_check = server.handle_call_tool(
            "witness_check_revocation",
            {"target_identifier": "some_agent_pubkey"},
        )
        assert rev_check["is_revoked"] is False

        # Trigger revocation
        rev_trigger = server.handle_call_tool(
            "witness_check_revocation",
            {
                "target_identifier": "some_agent_pubkey",
                "revoke_now": True,
                "reason": "OPERATOR_KILL_SWITCH",
            },
        )
        assert rev_trigger["status"] == "revoked"

        # Verify it is now revoked
        rev_check2 = server.handle_call_tool(
            "witness_check_revocation",
            {"target_identifier": "some_agent_pubkey"},
        )
        assert rev_check2["is_revoked"] is True


def test_mcp_delegation_blinded_and_dispute_tools():
    with tempfile.TemporaryDirectory() as tmpdir:
        server = WitnessMCPServer(log_dir=tmpdir)

        # 1. Delegate capability
        del_resp = server.handle_call_tool(
            "witness_delegate_capability",
            {
                "child_agent_id": "child_bot_01",
                "child_pubkey": "ab" * 32,
                "scope": ["web_search", "run_tests"],
                "max_budget_usd": 100.0,
            },
        )
        assert del_resp["status"] == "success"
        grant = del_resp["grant"]

        # 2. Verify delegation DAG
        v_dag = server.handle_call_tool(
            "witness_verify_delegation_dag",
            {
                "root_agent_id": server.agent_id,
                "grants": [grant],
            },
        )
        assert v_dag["is_valid"] is True
        assert v_dag["chain_depth"] == 1

        # 3. Record steps and blind receipt
        server.handle_call_tool("witness_record_action", {"step_type": "thought", "content": "Preparing trade"})
        server.handle_call_tool("witness_record_action", {"step_type": "decision", "content": "Swap 500 USDC"})
        fin_resp = server.handle_call_tool("witness_finalize_receipt", {})

        blind_resp = server.handle_call_tool(
            "witness_blind_receipt",
            {
                "sensitive_keys": ["token", "amount"],
            },
        )
        assert blind_resp["status"] == "success"
        assert "blinded_receipt" in blind_resp

        # 4. Arbitrate dispute
        dispute_resp = server.handle_call_tool(
            "witness_arbitrate_dispute",
            {
                "claim_id": "claim_test_101",
                "challenger_id": "verifier_node",
                "target_agent_id": server.agent_id,
                "dispute_type": "tampered_receipt",
            },
        )
        assert dispute_resp["verdict"] == "DISPUTE_DISMISSED"
