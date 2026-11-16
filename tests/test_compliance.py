from __future__ import annotations

import time
import pytest

from agent_witness.compliance import ComplianceAnomalyDetector, ComplianceAuditReport, AnomalyIncident
from agent_witness.models import WitnessReceipt
from agent_witness.signer import AgentSigner


def test_compliance_detector_clean_receipt():
    signer = AgentSigner()
    now = time.time()
    steps = [
        {"index": 0, "type": "thought", "content": "Reviewing system health.", "timestamp": now - 10.0},
        {"index": 1, "type": "tool_call", "content": "check_status", "timestamp": now - 2.0, "metadata": {"amount_usd": 10.0}},
    ]
    receipt = WitnessReceipt(
        version="0.6.0",
        agent_id="agent-compliance-test",
        agent_pubkey=signer.pubkey_hex,
        model_id="test-model",
        system_prompt_hash="a" * 64,
        merkle_root="b" * 64,
        step_count=2,
        timestamp=now,
        signature="c" * 128,
        steps=steps,
    )

    detector = ComplianceAnomalyDetector(max_cumulative_value=500.0, max_velocity_per_min=100.0)
    report = detector.audit_receipt(receipt, expected_authority=signer.pubkey_hex)

    assert isinstance(report, ComplianceAuditReport)
    assert report.is_compliant is True
    assert report.risk_score == 0.0
    assert len(report.incidents) == 0
    assert report.cumulative_value_tracked == 10.0


def test_compliance_detector_flags_anomalies():
    signer = AgentSigner()
    now = time.time()
    steps = [
        {"index": 0, "type": "tool_call", "content": "transfer", "timestamp": now - 1.0, "metadata": {"amount_usd": 8000.0}},
        {"index": 1, "type": "tool_call", "content": "transfer", "timestamp": now - 0.5, "metadata": {"amount_usd": 5000.0}},
        {"index": 2, "type": "tool_call", "content": "out_of_order", "timestamp": now - 2.0},  # Time went backwards
    ]
    receipt = WitnessReceipt(
        version="0.6.0",
        agent_id="agent-compliance-test",
        agent_pubkey=signer.pubkey_hex,
        model_id="test-model",
        system_prompt_hash="a" * 64,
        merkle_root="b" * 64,
        step_count=3,
        timestamp=now,
        signature="c" * 128,
        steps=steps,
    )

    detector = ComplianceAnomalyDetector(max_cumulative_value=10000.0)
    report = detector.audit_receipt(receipt, expected_authority="other_unauthorized_pubkey")

    assert report.is_compliant is False
    assert report.risk_score > 50.0

    incident_types = [inc.incident_type for inc in report.incidents]
    assert "AUTHORITY_DRIFT" in incident_types
    assert "CUMULATIVE_VALUE_BREACH" in incident_types
    assert "TEMPORAL_OUT_OF_ORDER" in incident_types
