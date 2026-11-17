import json
import os
import shutil
import tempfile
import pytest

from agent_witness.bridge import (
    AgentLifecycleBridge,
    EndToEndExecutionReceipt,
    BridgeVerificationReport,
    SandboxMeta,
    SimulationMeta,
)
from agent_witness.signer import AgentSigner


class TestAgentLifecycleBridge:

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp(prefix="witness_bridge_test_")
        self.file_a = os.path.join(self.temp_dir, "config.json")
        with open(self.file_a, "w") as f:
            json.dump({"api_key": "initial_key", "threshold": 100}, f)

    def teardown_method(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_successful_lifecycle_step(self):
        bridge = AgentLifecycleBridge(
            agent_id="test-agent-01",
            workspace_root=self.temp_dir,
            auto_rollback_on_cu_exceeded=True,
            max_cu_threshold=300_000,
        )

        def mutate_config():
            with open(self.file_a, "w") as f:
                json.dump({"api_key": "mutated_key", "threshold": 200}, f)
            return "SUCCESS_CONFIG_UPDATE"

        # Safe simulation input (50k CU, no error)
        sim_input = {
            "unitsConsumed": 52_400,
            "err": None,
            "logs": [
                "Program 11111111111111111111111111111111 invoke [1]",
                "Program 11111111111111111111111111111111 success",
            ],
        }

        receipt, res = bridge.execute_step(
            step_name="update_configuration",
            action_func=mutate_config,
            target_files=[self.file_a],
            tx_simulation_input=sim_input,
            cu_limit=200_000,
        )

        assert res == "SUCCESS_CONFIG_UPDATE"
        assert receipt.status == "COMMITTED"
        assert receipt.sandbox is not None
        assert not receipt.sandbox.reverted
        assert receipt.simulation is not None
        assert receipt.simulation.success is True
        assert receipt.simulation.total_compute_units == 52_400

        # Verify disk retained mutation
        with open(self.file_a, "r") as f:
            data = json.load(f)
        assert data["api_key"] == "mutated_key"

    def test_simulation_failure_triggers_automatic_rollback(self):
        bridge = AgentLifecycleBridge(
            agent_id="test-agent-02",
            workspace_root=self.temp_dir,
            auto_rollback_on_cu_exceeded=True,
            max_cu_threshold=100_000,
        )

        def dangerous_action():
            with open(self.file_a, "w") as f:
                json.dump({"corrupted": True}, f)
            return "CORRUPTED"

        # Simulating excessive compute unit usage (150k > 100k threshold)
        over_budget_sim = {
            "unitsConsumed": 150_000,
            "err": None,
            "logs": ["Program ComputeBudget111111111111111111111111111111 invoke [1]"],
        }

        receipt, res = bridge.execute_step(
            step_name="dangerous_swap",
            action_func=dangerous_action,
            target_files=[self.file_a],
            tx_simulation_input=over_budget_sim,
            cu_limit=100_000,
        )

        assert receipt.status == "REVERTED"
        assert receipt.sandbox.reverted is True
        assert res is None

        # Verify disk was reverted back to initial state
        with open(self.file_a, "r") as f:
            data = json.load(f)
        assert data.get("api_key") == "initial_key"
        assert "corrupted" not in data

    def test_execution_exception_triggers_revert(self):
        bridge = AgentLifecycleBridge(
            agent_id="test-agent-03",
            workspace_root=self.temp_dir,
        )

        def failing_action():
            with open(self.file_a, "w") as f:
                f.write("half_written_garbage")
            raise ValueError("Unexpected API timeout during broadcast")

        receipt, res = bridge.execute_step(
            step_name="failing_broadcast",
            action_func=failing_action,
            target_files=[self.file_a],
        )

        assert receipt.status == "REVERTED"
        assert receipt.sandbox.reverted is True
        assert "ValueError" in receipt.metadata.get("error", "")

        # Verify disk was restored
        with open(self.file_a, "r") as f:
            data = json.load(f)
        assert data.get("api_key") == "initial_key"

    def test_lifecycle_scope_context_manager(self):
        bridge = AgentLifecycleBridge(
            agent_id="test-agent-04",
            workspace_root=self.temp_dir,
        )

        with bridge.lifecycle_scope("safe_scope", target_files=[self.file_a]):
            with open(self.file_a, "w") as f:
                json.dump({"scoped": True}, f)

        assert len(bridge.steps) == 1
        assert bridge.steps[0].status == "COMMITTED"
        with open(self.file_a, "r") as f:
            assert json.load(f)["scoped"] is True

        # Test scope reverting on error
        with pytest.raises(RuntimeError):
            with bridge.lifecycle_scope("failing_scope", target_files=[self.file_a]):
                with open(self.file_a, "w") as f:
                    f.write("corrupted_scope")
                raise RuntimeError("Critical error in scope")

        assert len(bridge.steps) == 2
        assert bridge.steps[1].status == "REVERTED"
        with open(self.file_a, "r") as f:
            assert json.load(f).get("scoped") is True

    def test_pipeline_finalization_with_zkvm_and_crosschain(self):
        bridge = AgentLifecycleBridge(
            agent_id="agent-zkvm-cc",
            workspace_root=self.temp_dir,
        )

        bridge.execute_step(
            step_name="step_one",
            action_func=lambda: "result_1",
            target_files=[self.file_a],
        )
        bridge.execute_step(
            step_name="step_two",
            action_func=lambda: "result_2",
            target_files=[self.file_a],
        )

        receipt = bridge.finalize_pipeline(
            generate_zkvm=True,
            zkvm_system="risc0",
            crosschain_protocol="layerzero_v2",
            target_chain="arbitrum",
        )

        assert receipt.pipeline_id.startswith("pipeline_")
        assert receipt.total_steps == 2
        assert receipt.committed_steps == 2
        assert receipt.reverted_steps == 0
        assert receipt.final_status == "COMMITTED"
        assert receipt.zkvm_receipt is not None
        assert receipt.zkvm_receipt["zkvm_system"] == "risc0"
        assert receipt.crosschain_dispatch is not None
        assert receipt.crosschain_dispatch["dst_chain"] == "arbitrum"

        # Verify receipt end-to-end
        report = AgentLifecycleBridge.verify_pipeline_receipt(receipt)
        assert report.valid is True
        assert report.signature_valid is True
        assert report.zkvm_valid is True
        assert report.crosschain_valid is True
        assert report.sandbox_consistent is True
        assert report.simulation_compliant is True
        assert len(report.violations) == 0
