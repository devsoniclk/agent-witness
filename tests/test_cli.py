from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from agent_witness.consensus import MultiAgentConsensusEngine
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


def test_cli_report_html():
    repo_root = Path(__file__).parent.parent

    engine = WitnessEngine("cli-report-agent", "gpt-4o", "HTML Report Agent")
    engine.record_step(StepType.OBSERVATION, "Market depth adequate")
    engine.record_step(StepType.DECISION, "Execution authorized")
    receipt = engine.finalize_receipt()

    with tempfile.NamedTemporaryFile("w", suffix=".witness", delete=False) as tf:
        json.dump(receipt.to_dict(), tf)
        receipt_path = tf.name

    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as hf:
        html_path = hf.name

    try:
        res = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "report", receipt_path, "--html", html_path],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res.returncode == 0
        assert "Interactive HTML dossier generated" in res.stdout
        assert Path(html_path).exists()
        assert "<!DOCTYPE html>" in Path(html_path).read_text(encoding="utf-8")
    finally:
        Path(receipt_path).unlink(missing_ok=True)
        Path(html_path).unlink(missing_ok=True)


def test_cli_log_commands():
    repo_root = Path(__file__).parent.parent

    engine = WitnessEngine("log-cli-agent", "gpt-4o", "Log CLI Agent")
    engine.record_step(StepType.OBSERVATION, "Step 1")
    engine.record_step(StepType.DECISION, "Step 2")
    receipt = engine.finalize_receipt()

    with tempfile.NamedTemporaryFile("w", suffix=".witness", delete=False) as tf:
        json.dump(receipt.to_dict(), tf)
        receipt_path = tf.name

    with tempfile.TemporaryDirectory() as td:
        log_dir = td

        # 1. log append
        res_app = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "log", "append", receipt_path, "--log-dir", log_dir],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_app.returncode == 0
        assert "Receipt appended to transparency log" in res_app.stdout

        # 2. log status
        res_stat = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "log", "status", "--log-dir", log_dir],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_stat.returncode == 0
        assert "Total Entries:      1" in res_stat.stdout

        # 3. log checkpoint
        res_cp = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "log", "checkpoint", "--log-dir", log_dir],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_cp.returncode == 0
        assert "SIGNED LOG CHECKPOINT" in res_cp.stdout

    Path(receipt_path).unlink(missing_ok=True)


def test_cli_consensus_verify():
    repo_root = Path(__file__).parent.parent

    engine = WitnessEngine("con-agent", "gpt-4o", "Consensus Agent")
    engine.record_step(StepType.DECISION, "Action")
    receipt = engine.finalize_receipt()

    signer = AgentSigner()
    con_engine = MultiAgentConsensusEngine.from_receipt(receipt, threshold=1)
    con_engine.add_attestation(signer, "agent-validator", "gpt-4o", "AUDITOR", verdict="APPROVE")
    con_rec = con_engine.finalize()

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as cf:
        json.dump(con_rec.to_dict(), cf)
        cf_path = cf.name

    try:
        res = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "consensus", "verify", cf_path],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res.returncode == 0
        assert "MULTI-AGENT CONSENSUS VERIFICATION" in res.stdout
        assert "Consensus Reached:  YES - VALID" in res.stdout
    finally:
        Path(cf_path).unlink(missing_ok=True)


def test_cli_audit_command():
    repo_root = Path(__file__).parent.parent

    engine = WitnessEngine("audit-agent", "gpt-4o", "Audit Agent System Prompt")
    engine.record_step(StepType.OBSERVATION, "Initial sensor reading")
    engine.record_step(StepType.DECISION, "Execute trade safely")
    receipt = engine.finalize_receipt()

    with tempfile.NamedTemporaryFile("w", suffix=".witness", delete=False) as tf:
        json.dump(receipt.to_dict(), tf)
        receipt_path = tf.name

    try:
        # Text output
        res = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "audit", receipt_path],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res.returncode == 0
        assert "AGENT WITNESS FORENSIC TRAJECTORY AUDIT" in res.stdout
        assert "PASS - CRYPTOGRAPHICALLY VALID" in res.stdout

        # JSON output
        res_json = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "audit", receipt_path, "--json"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_json.returncode == 0
        parsed = json.loads(res_json.stdout)
        assert parsed["is_valid"] is True
        assert parsed["step_count"] == 2
    finally:
        Path(receipt_path).unlink(missing_ok=True)


def test_cli_mcp_command_stdio():
    repo_root = Path(__file__).parent.parent

    # Send initialize request via stdin
    init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n"

    proc = subprocess.Popen(
        [sys.executable, "-m", "agent_witness.cli", "mcp"],
        cwd=str(repo_root),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"PYTHONPATH": str(repo_root)},
    )
    stdout, stderr = proc.communicate(input=init_req, timeout=5)

    assert proc.returncode == 0
    res = json.loads(stdout.strip())
    assert res["result"]["serverInfo"]["name"] == "agent-witness-mcp"
    assert res["result"]["serverInfo"]["version"] == "0.4.0"

