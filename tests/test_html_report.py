from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from agent_witness.consensus import MultiAgentConsensusEngine
from agent_witness.html_report import render_html_report
from agent_witness.models import StepType
from agent_witness.proof import export_proof_bundle
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner


def _build_receipt():
    engine = WitnessEngine(
        agent_id="test-dossier-agent",
        model_id="claude-3-7-sonnet",
        system_prompt="Audit dossier generator test",
    )
    engine.record_step(StepType.OBSERVATION, "Balance is 10,000 USDC")
    engine.record_step(StepType.THOUGHT, "Evaluating swap route on Uniswap v3")
    engine.record_step(StepType.TOOL_CALL, "uniswap.exact_input_single(...)")
    engine.record_step(StepType.TOOL_RESULT, "tx=0x123abc confirmed")
    engine.record_step(StepType.DECISION, "Swap finalized")
    return engine.finalize_receipt()


def test_html_report_witness_receipt():
    receipt = _build_receipt()
    html_out = render_html_report(receipt, title="Witness Test Dossier")

    assert "<!DOCTYPE html>" in html_out
    assert "agent-witness" in html_out
    assert "test-dossier-agent" in html_out
    assert "claude-3-7-sonnet" in html_out
    assert receipt.merkle_root in html_out
    assert "uniswap.exact_input_single" in html_out
    assert "<svg" in html_out


def test_html_report_proof_bundle():
    receipt = _build_receipt()
    bundle = export_proof_bundle(receipt, step_index=2)

    html_out = render_html_report(bundle)
    assert "SELECTIVE DISCLOSURE VERIFIED" in html_out
    assert "uniswap.exact_input_single" in html_out
    assert bundle.merkle_root in html_out


def test_html_report_consensus_receipt():
    receipt = _build_receipt()
    signer = AgentSigner()
    engine = MultiAgentConsensusEngine.from_receipt(receipt, threshold=1)
    engine.add_attestation(signer, "subagent-alpha", "gpt-4o", "AUDITOR", verdict="APPROVE")
    con_receipt = engine.finalize()

    html_out = render_html_report(con_receipt)
    assert "CONSENSUS VERIFIED" in html_out
    assert "subagent-alpha" in html_out
    assert "AUDITOR" in html_out


def test_html_report_file_export():
    receipt = _build_receipt()
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as tf:
        out_path = tf.name

    try:
        render_html_report(receipt, output_file=out_path)
        content = Path(out_path).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert receipt.agent_id in content
    finally:
        Path(out_path).unlink(missing_ok=True)
