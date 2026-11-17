import json
import subprocess
import sys
import tempfile
import pytest


def test_cli_bridge_run_and_verify():
    with tempfile.TemporaryDirectory() as tmpdir:
        spec_file = f"{tmpdir}/spec.json"
        receipt_file = f"{tmpdir}/receipt.json"

        steps = [
            {
                "step_name": "preflight_check",
                "tx_simulation": {
                    "unitsConsumed": 24_000,
                    "err": None,
                    "logs": ["Program 11111111111111111111111111111111 invoke [1]"],
                },
            },
            {
                "step_name": "execute_settlement",
                "cu_limit": 150_000,
            },
        ]
        with open(spec_file, "w") as f:
            json.dump(steps, f)

        # Run CLI bridge run
        cmd_run = [
            sys.executable,
            "-m",
            "agent_witness.cli",
            "bridge",
            "run",
            "--agent-id",
            "cli-test-agent",
            "--spec-file",
            spec_file,
            "--generate-zkvm",
            "--zkvm-system",
            "risc0",
            "--crosschain",
            "layerzero_v2",
            "--target-chain",
            "arbitrum",
            "-o",
            receipt_file,
        ]
        res = subprocess.run(cmd_run, capture_output=True, text=True)
        assert res.returncode == 0
        assert f"Pipeline receipt saved to {receipt_file}" in res.stdout

        with open(receipt_file, "r") as f:
            rcpt_data = json.load(f)
        assert rcpt_data["agent_id"] == "cli-test-agent"
        assert rcpt_data["total_steps"] == 2
        assert rcpt_data["zkvm_receipt"] is not None
        assert rcpt_data["crosschain_dispatch"] is not None

        # Run CLI bridge verify
        cmd_ver = [
            sys.executable,
            "-m",
            "agent_witness.cli",
            "bridge",
            "verify",
            "--receipt-file",
            receipt_file,
            "--json",
        ]
        res_ver = subprocess.run(cmd_ver, capture_output=True, text=True)
        assert res_ver.returncode == 0
        ver_data = json.loads(res_ver.stdout)
        assert ver_data["valid"] is True
        assert ver_data["signature_valid"] is True
        assert ver_data["zkvm_valid"] is True
        assert ver_data["crosschain_valid"] is True
