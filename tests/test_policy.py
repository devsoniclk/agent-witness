import pytest
from agent_witness.models import StepType
from agent_witness.policy import (
    DisallowedToolsRule,
    ExecutionDurationRule,
    MaxStepsRule,
    ModelWhitelistRule,
    PolicyGuard,
    RequiredApprovalRule,
    StepRepetitionRule,
)
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner
from agent_witness.verifier import verify_trajectory_integrity


def test_max_steps_rule():
    engine = WitnessEngine("agent-1", "model-1", "Prompt")
    for i in range(15):
        engine.record_step(StepType.THOUGHT, f"Thought {i}")
    receipt = engine.finalize_receipt()

    rule_pass = MaxStepsRule(max_steps=20)
    assert len(rule_pass.evaluate(receipt)) == 0

    rule_fail = MaxStepsRule(max_steps=10)
    violations = rule_fail.evaluate(receipt)
    assert len(violations) == 1
    assert violations[0].rule_name == "MAX_STEPS_LIMIT"
    assert violations[0].severity == "HIGH"


def test_disallowed_tools_rule():
    engine = WitnessEngine("agent-shell", "model-x", "Prompt")
    engine.record_step(StepType.OBSERVATION, "Ready")
    engine.record_step(StepType.TOOL_CALL, "rm -rf /tmp/data", metadata={"tool_name": "rm"})
    receipt = engine.finalize_receipt()

    rule = DisallowedToolsRule()
    violations = rule.evaluate(receipt)
    assert len(violations) == 1
    assert violations[0].rule_name == "DISALLOWED_TOOLS"
    assert violations[0].severity == "CRITICAL"
    assert violations[0].step_index == 1


def test_required_approval_rule():
    # Case A: Sensitive tool without preceding approval
    engine1 = WitnessEngine("agent-fin", "model-y", "Prompt")
    engine1.record_step(StepType.THOUGHT, "Ready to pay.")
    engine1.record_step(StepType.TOOL_CALL, "transfer_funds(amount=50000)", metadata={"tool_name": "transfer_funds"})
    receipt1 = engine1.finalize_receipt()

    rule = RequiredApprovalRule()
    violations1 = rule.evaluate(receipt1)
    assert len(violations1) == 1
    assert violations1[0].rule_name == "REQUIRED_HUMAN_APPROVAL"

    # Case B: Sensitive tool preceded by explicit decision
    engine2 = WitnessEngine("agent-fin", "model-y", "Prompt")
    engine2.record_step(StepType.DECISION, "User signed confirmation card for wire transfer #1042.")
    engine2.record_step(StepType.TOOL_CALL, "transfer_funds(amount=50000)", metadata={"tool_name": "transfer_funds"})
    receipt2 = engine2.finalize_receipt()

    violations2 = rule.evaluate(receipt2)
    assert len(violations2) == 0


def test_step_repetition_loop_detection():
    engine = WitnessEngine("agent-loop", "model-z", "Prompt")
    engine.record_step(StepType.THOUGHT, "Analyzing database schema...")
    engine.record_step(StepType.THOUGHT, "Analyzing database schema...")
    engine.record_step(StepType.THOUGHT, "Analyzing database schema...")
    receipt = engine.finalize_receipt()

    rule = StepRepetitionRule(max_consecutive=3)
    violations = rule.evaluate(receipt)
    assert len(violations) == 1
    assert violations[0].rule_name == "REPETITIVE_DELIBERATION_LOOP"


def test_policy_guard_and_verifier_integration():
    signer = AgentSigner()
    engine = WitnessEngine("agent-clean", "claude-3-5-sonnet", "Prompt", signer=signer)
    engine.record_step(StepType.OBSERVATION, "System online.")
    engine.record_step(StepType.DECISION, "Proceed with verified parameters.")
    engine.record_step(StepType.TOOL_CALL, "read_file(path='/var/log/syslog')", metadata={"tool_name": "read_file"})
    receipt = engine.finalize_receipt()

    guard = PolicyGuard.default_rules()
    pguard = PolicyGuard(rules=guard)
    report = pguard.evaluate(receipt)
    assert report.is_compliant is True
    assert report.verdict == "COMPLIANT"

    # Verify trajectory integrity with policy guard
    audit_report = verify_trajectory_integrity(receipt, signer=signer, policy_guard=pguard)
    assert audit_report.is_valid is True
    policy_check = next(c for c in audit_report.checks if c.name == "POLICY_COMPLIANCE")
    assert policy_check.status == "PASS"
