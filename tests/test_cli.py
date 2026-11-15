import json
import subprocess
import sys
import tempfile
from pathlib import Path
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner


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
