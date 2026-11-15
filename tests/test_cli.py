import json
import subprocess
import sys
import tempfile
from pathlib import Path
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine


def test_cli_inspect_and_verify():
    repo_root = Path(__file__).parent.parent

    # Create a valid receipt file
    engine = WitnessEngine(
        agent_id="test-agent",
        model_id="gpt-4o",
        system_prompt="Audit test agent",
    )
    engine.record_step(StepType.OBSERVATION, "Observation step")
    engine.record_step(StepType.DECISION, "Decision step")
    receipt = engine.finalize_receipt()

    with tempfile.NamedTemporaryFile("w", suffix=".witness", delete=False) as tf:
        json.dump(receipt.to_dict(), tf)
        tf_path = tf.name

    try:
        # 1. Test inspect
        res = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "inspect", tf_path],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res.returncode == 0
        assert "AGENT WITNESS CRYPTOGRAPHIC RECEIPT" in res.stdout
        assert "test-agent" in res.stdout

        # 2. Test verify
        res = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "verify", tf_path],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res.returncode == 0
        assert "VERIFIED: Merkle root" in res.stdout
    finally:
        Path(tf_path).unlink(missing_ok=True)


def test_cli_export_proof_and_verify_proof():
    repo_root = Path(__file__).parent.parent

    engine = WitnessEngine(
        agent_id="proof-cli-agent",
        model_id="claude-3-7-sonnet",
        system_prompt="Selective disclosure CLI agent",
    )
    engine.record_step(StepType.OBSERVATION, "Balance is 100 SOL")
    engine.record_step(StepType.TOOL_CALL, "jupiter.swap(SOL -> USDC)")
    engine.record_step(StepType.DECISION, "Swap routed successfully")
    receipt = engine.finalize_receipt()

    with tempfile.NamedTemporaryFile("w", suffix=".witness", delete=False) as tf:
        json.dump(receipt.to_dict(), tf)
        receipt_path = tf.name

    with tempfile.NamedTemporaryFile("w", suffix=".proof.json", delete=False) as pf:
        proof_path = pf.name

    try:
        # 1. Test export-proof
        res_exp = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_witness.cli",
                "export-proof",
                receipt_path,
                "--step",
                "1",
                "--output",
                proof_path,
            ],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_exp.returncode == 0
        assert "Selective disclosure proof exported" in res_exp.stdout

        # 2. Test verify-proof
        res_ver = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "verify-proof", proof_path],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_ver.returncode == 0
        assert "PROOF VERIFICATION: SUCCESS" in res_ver.stdout
        assert "jupiter.swap" in res_ver.stdout
    finally:
        Path(receipt_path).unlink(missing_ok=True)
        Path(proof_path).unlink(missing_ok=True)
