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
    assert res["result"]["serverInfo"]["version"] in ("0.7.0", "0.8.0", "0.9.0")



def test_cli_v050_commands():
    repo_root = Path(__file__).parent.parent

    engine = WitnessEngine("cli-v5-agent", "gpt-4o", "System Prompt V5")
    engine.record_step(StepType.OBSERVATION, "Received request")
    engine.record_step(StepType.THOUGHT, "Secret key: sk_live_112233445566")
    engine.record_step(StepType.DECISION, "Approved request")
    receipt = engine.finalize_receipt()

    with tempfile.NamedTemporaryFile("w", suffix=".witness", delete=False) as tf:
        json.dump(receipt.to_dict(), tf)
        rf_path = tf.name

    with tempfile.NamedTemporaryFile("w", suffix=".redacted.json", delete=False) as rf:
        red_path = rf.name

    with tempfile.NamedTemporaryFile("w", suffix=".batch.json", delete=False) as bf:
        batch_path = bf.name

    try:
        # 1. Redact command
        res_red = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "redact", rf_path, "--steps", "1", "--output", red_path],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_red.returncode == 0
        assert "SELECTIVE DISCLOSURE REDACTION ENGINE" in res_red.stdout
        assert "Cryptographic Status:  VALID" in res_red.stdout

        # 2. Policy command (Pass)
        res_pol = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "policy", rf_path, "--max-steps", "50"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_pol.returncode == 0
        assert "AGENT WITNESS POLICY COMPLIANCE REPORT" in res_pol.stdout
        assert "Overall Verdict:    COMPLIANT" in res_pol.stdout

        # 3. Batch anchor command
        res_anc = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "batch-anchor", rf_path, "--epoch-id", "epoch_test_v5", "--output", batch_path, "--evm", "--solana"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_anc.returncode == 0
        assert "EPOCH BATCH MERKLE ANCHOR ENGINE" in res_anc.stdout
        assert "Epoch ID:           epoch_test_v5" in res_anc.stdout
        assert "0x23a6f44d" in res_anc.stdout
        assert "AW:EPOCH:epoch_test_v5:" in res_anc.stdout
    finally:
        Path(rf_path).unlink(missing_ok=True)
        Path(red_path).unlink(missing_ok=True)
        Path(batch_path).unlink(missing_ok=True)


def test_cli_v060_commands():
    repo_root = Path(__file__).parent.parent

    engine = WitnessEngine("cli-v6-agent", "gpt-4o", "System Prompt V6")
    engine.record_step(StepType.OBSERVATION, "Telemetry normal")
    engine.record_step(StepType.THOUGHT, "Planning execution")
    engine.record_step(StepType.DECISION, "Execute trade", metadata={"amount_usd": 150.0})
    receipt = engine.finalize_receipt()

    with tempfile.NamedTemporaryFile("w", suffix=".witness", delete=False) as tf:
        json.dump(receipt.to_dict(), tf)
        rf_path = tf.name

    with tempfile.NamedTemporaryFile("w", suffix=".bundle.json", delete=False) as bf:
        bundle_path = bf.name

    try:
        # 1. multichain-anchor command
        res_mc = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "multichain-anchor", rf_path, "--chains", "solana,base", "--quorum", "2", "--output", bundle_path],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_mc.returncode == 0
        assert "CROSS-CHAIN ATTESTATION & ANCHOR DISPATCHER" in res_mc.stdout
        assert "Solana Anchor State" in res_mc.stdout
        assert Path(bundle_path).exists()

        # 2. compliance command
        res_comp = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "compliance", rf_path, "--max-value", "5000"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_comp.returncode == 0
        assert "COMPLIANCE & ANOMALY EVALUATION" in res_comp.stdout
        assert "Compliance Status:  COMPLIANT" in res_comp.stdout
    finally:
        Path(rf_path).unlink(missing_ok=True)
        Path(bundle_path).unlink(missing_ok=True)


def test_cli_v070_commands():
    repo_root = Path(__file__).parent.parent

    engine = WitnessEngine("cli-v7-agent", "gemini-flash", "System Prompt V7")
    engine.record_step(StepType.THOUGHT, "Analyzing financial constraints")
    engine.record_step(StepType.TOOL_CALL, "execute_trade", metadata={"tool_name": "execute_trade", "amount": 50.0})
    engine.record_step(StepType.DECISION, "Signed order")
    receipt = engine.finalize_receipt()

    with tempfile.NamedTemporaryFile("w", suffix=".witness", delete=False) as tf:
        json.dump(receipt.to_dict(), tf)
        rf_path = tf.name

    with tempfile.NamedTemporaryFile("w", suffix=".cred.json", delete=False) as cf:
        cred_path = cf.name

    with tempfile.NamedTemporaryFile("w", suffix=".zk.json", delete=False) as zf:
        zk_path = zf.name

    with tempfile.NamedTemporaryFile("w", suffix=".rev.json", delete=False) as rf:
        rev_path = rf.name

    try:
        # 1. credential issue
        res_ci = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "credential", "issue", "--agent-id", "cli-v7-agent", "-o", cred_path],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_ci.returncode == 0
        assert Path(cred_path).exists()

        # 2. credential verify
        res_cv = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "credential", "verify", cred_path, "--json"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_cv.returncode == 0
        c_rep = json.loads(res_cv.stdout)
        assert c_rep["is_valid"] is True

        # 3. zk prove
        res_zp = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "zk", "prove", rf_path, "--max-steps", "10", "-o", zk_path],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_zp.returncode == 0
        assert Path(zk_path).exists()

        # 4. zk verify
        res_zv = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "zk", "verify", zk_path, "--max-steps", "10", "--json"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_zv.returncode == 0
        z_rep = json.loads(res_zv.stdout)
        assert z_rep["is_verified"] is True

        # 5. revocation check
        res_rc = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "revocation", "check", "agent_test_pubkey", "--registry-file", rev_path, "--json"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_rc.returncode == 0
        r_rep = json.loads(res_rc.stdout)
        assert r_rep["is_revoked"] is False

        # 6. revocation revoke
        res_rr = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "revocation", "revoke", "agent_test_pubkey", "--registry-file", rev_path],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_rr.returncode == 0
        assert "EMERGENCY REVOCATION NOTICE ISSUED" in res_rr.stdout
    finally:
        Path(rf_path).unlink(missing_ok=True)
        Path(cred_path).unlink(missing_ok=True)
        Path(zk_path).unlink(missing_ok=True)
        Path(rev_path).unlink(missing_ok=True)


def test_cli_v8_zkvm_crosschain_rollup():
    repo_root = Path(__file__).parent.parent
    signer = AgentSigner()
    engine = WitnessEngine(agent_id="cli_v8_agent", signer=signer, model_id="gpt-4o", system_prompt="Test")
    engine.record_step(StepType.OBSERVATION, "Testing v0.8.0 CLI features")
    engine.record_step(StepType.TOOL_CALL, "execute_task()")
    receipt = engine.finalize_receipt()

    with tempfile.NamedTemporaryFile("w", suffix=".witness.json", delete=False) as f:
        json.dump(receipt.to_dict(), f)
        rf_path = f.name

    zkvm_path = rf_path + ".zkvm.json"
    batch_path = rf_path + ".batch.json"

    try:
        # 1. zkvm generate
        res_zg = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "zkvm", "generate", "--receipt-file", rf_path, "-o", zkvm_path],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_zg.returncode == 0
        assert Path(zkvm_path).exists()

        # 2. zkvm verify
        res_zv = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "zkvm", "verify", "--zkvm-file", zkvm_path, "--json"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_zv.returncode == 0
        z_rep = json.loads(res_zv.stdout)
        assert z_rep["is_valid"] is True

        # 3. crosschain estimate
        res_ce = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "crosschain", "estimate", "--protocol", "layerzero_v2", "--dst-chain", "arbitrum", "--json"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_ce.returncode == 0
        ce_data = json.loads(res_ce.stdout)
        assert ce_data["fee_usd"] > 0

        # 4. crosschain dispatch
        res_cd = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "crosschain", "dispatch", "--receipt-file", rf_path, "--protocol", "chainlink_ccip", "--dst-chain", "base", "--json"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_cd.returncode == 0
        cd_data = json.loads(res_cd.stdout)
        assert cd_data["protocol"] == "chainlink_ccip"

        # 5. rollup aggregate
        res_ra = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "rollup", "aggregate", "--receipt-files", rf_path, "-o", batch_path],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_ra.returncode == 0
        assert Path(batch_path).exists()

        # 6. rollup verify
        res_rv = subprocess.run(
            [sys.executable, "-m", "agent_witness.cli", "rollup", "verify", "--batch-file", batch_path, "--json"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(repo_root)},
        )
        assert res_rv.returncode == 0
        rv_data = json.loads(res_rv.stdout)
        assert rv_data["is_valid"] is True
    finally:
        Path(rf_path).unlink(missing_ok=True)
        Path(zkvm_path).unlink(missing_ok=True)
        Path(batch_path).unlink(missing_ok=True)
