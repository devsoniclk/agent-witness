import json
import pytest
from agent_witness.mcp_server import WitnessMCPServer


class TestMCPBridgeTools:

    def setup_method(self):
        self.server = WitnessMCPServer(log_dir="/tmp/test_mcp_bridge_log")

    def test_witness_bridge_execute_pipeline_tool(self):
        steps = [
            {
                "step_name": "validate_environment",
                "tx_simulation": {
                    "unitsConsumed": 21_000,
                    "err": None,
                    "logs": ["Program 11111111111111111111111111111111 invoke [1]"],
                },
            },
            {
                "step_name": "execute_trade",
                "cu_limit": 100_000,
            },
        ]

        res = self.server.handle_call_tool(
            "witness_bridge_execute_pipeline",
            {
                "agent_id": "mcp-trader-agent",
                "steps": steps,
                "generate_zkvm": True,
                "zkvm_system": "sp1",
                "crosschain_protocol": "layerzero_v2",
                "target_chain": "base",
            },
        )

        assert "pipeline_id" in res
        assert res["agent_id"] == "mcp-trader-agent"
        assert res["total_steps"] == 2
        assert res["final_status"] == "COMMITTED"
        assert res["zkvm_receipt"]["zkvm_system"] == "sp1"
        assert res["crosschain_dispatch"]["dst_chain"] == "base"

        # Verify through the verify tool
        ver_res = self.server.handle_call_tool(
            "witness_bridge_verify_pipeline",
            {"pipeline_receipt": res},
        )

        assert ver_res["valid"] is True
        assert ver_res["signature_valid"] is True
        assert ver_res["zkvm_valid"] is True
        assert ver_res["crosschain_valid"] is True
