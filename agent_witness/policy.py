from __future__ import annotations

import abc
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

from .models import StepType, WitnessReceipt


@dataclass
class PolicyViolation:
    """An identified violation or warning resulting from policy evaluation."""
    rule_name: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "WARNING"
    message: str
    step_index: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PolicyRule(abc.ABC):
    """Abstract base class for all agent trajectory policy rules."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the policy rule."""
        pass

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Human-readable description of what this rule enforces."""
        pass

    @abc.abstractmethod
    def evaluate(self, receipt: WitnessReceipt | Dict[str, Any]) -> List[PolicyViolation]:
        """Evaluates the receipt and returns a list of violations (empty if compliant)."""
        pass


class MaxStepsRule(PolicyRule):
    """Guards against runaway deliberation loops or excessive reasoning steps."""

    def __init__(self, max_steps: int = 50):
        self.max_steps = max_steps

    @property
    def name(self) -> str:
        return "MAX_STEPS_LIMIT"

    @property
    def description(self) -> str:
        return f"Enforces trajectory step count does not exceed {self.max_steps} steps."

    def evaluate(self, receipt: WitnessReceipt | Dict[str, Any]) -> List[PolicyViolation]:
        d = receipt.to_dict() if isinstance(receipt, WitnessReceipt) else receipt
        step_count = d.get("step_count", len(d.get("steps", [])))
        if step_count > self.max_steps:
            return [
                PolicyViolation(
                    rule_name=self.name,
                    severity="HIGH",
                    message=f"Trajectory exceeded step ceiling: {step_count} > {self.max_steps}",
                    metadata={"actual_steps": step_count, "max_allowed": self.max_steps},
                )
            ]
        return []


class DisallowedToolsRule(PolicyRule):
    """Prohibits execution of high-risk or blacklisted system commands and APIs."""

    DEFAULT_DISALLOWED = {"rm", "eval", "exec", "sh", "bash", "sudo", "drop_table", "delete_all"}

    def __init__(self, blacklisted_tools: Optional[List[str]] = None):
        self.blacklisted_tools = set(blacklisted_tools or self.DEFAULT_DISALLOWED)

    @property
    def name(self) -> str:
        return "DISALLOWED_TOOLS"

    @property
    def description(self) -> str:
        return f"Prohibits invoking unauthorized tools: {', '.join(sorted(self.blacklisted_tools))}."

    def evaluate(self, receipt: WitnessReceipt | Dict[str, Any]) -> List[PolicyViolation]:
        d = receipt.to_dict() if isinstance(receipt, WitnessReceipt) else receipt
        violations: List[PolicyViolation] = []
        steps = d.get("steps", [])

        for s in steps:
            stype = str(s.get("type", "")).lower()
            if stype == StepType.TOOL_CALL.value:
                meta = s.get("metadata", {})
                tool_name = meta.get("tool_name", meta.get("tool", ""))
                content = str(s.get("content", ""))

                # Check tool_name or content match
                invoked_tool = tool_name.lower().strip()
                for banned in self.blacklisted_tools:
                    if banned == invoked_tool or f"{banned} " in content.lower() or f"{banned}(" in content.lower():
                        violations.append(
                            PolicyViolation(
                                rule_name=self.name,
                                severity="CRITICAL",
                                message=f"Disallowed tool '{banned}' invoked in step #{s.get('index')}",
                                step_index=s.get("index"),
                                metadata={"tool": banned, "content_snippet": content[:80]},
                            )
                        )
                        break
        return violations


class RequiredApprovalRule(PolicyRule):
    """Ensures that high-risk actions are preceded by an explicit decision or user approval step."""

    DEFAULT_SENSITIVE = {"transfer_funds", "execute_order", "delete_database", "deploy_production", "wire_payment"}

    def __init__(self, sensitive_tools: Optional[List[str]] = None):
        self.sensitive_tools = set(sensitive_tools or self.DEFAULT_SENSITIVE)

    @property
    def name(self) -> str:
        return "REQUIRED_HUMAN_APPROVAL"

    @property
    def description(self) -> str:
        return "Requires that sensitive financial or destructive tool calls are preceded by explicit authorization."

    def evaluate(self, receipt: WitnessReceipt | Dict[str, Any]) -> List[PolicyViolation]:
        d = receipt.to_dict() if isinstance(receipt, WitnessReceipt) else receipt
        violations: List[PolicyViolation] = []
        steps = d.get("steps", [])

        for i, s in enumerate(steps):
            stype = str(s.get("type", "")).lower()
            if stype == StepType.TOOL_CALL.value:
                meta = s.get("metadata", {})
                tool_name = meta.get("tool_name", meta.get("tool", "")).lower().strip()
                is_sensitive = any(st in tool_name for st in self.sensitive_tools)

                if is_sensitive:
                    # Check if previous step was an explicit decision or approval
                    has_preceding_approval = False
                    if i > 0:
                        prev_step = steps[i - 1]
                        prev_type = str(prev_step.get("type", "")).lower()
                        prev_meta = prev_step.get("metadata", {})
                        if prev_type == StepType.DECISION.value or prev_meta.get("approved") is True:
                            has_preceding_approval = True

                    if not has_preceding_approval and not meta.get("approved"):
                        violations.append(
                            PolicyViolation(
                                rule_name=self.name,
                                severity="HIGH",
                                message=f"Sensitive action '{tool_name}' executed at step #{s.get('index')} without prior approval step",
                                step_index=s.get("index"),
                                metadata={"tool_name": tool_name},
                            )
                        )
        return violations


class ExecutionDurationRule(PolicyRule):
    """Enforces an upper bound on trajectory total runtime."""

    def __init__(self, max_duration_seconds: float = 300.0):
        self.max_duration_seconds = max_duration_seconds

    @property
    def name(self) -> str:
        return "EXECUTION_DURATION_LIMIT"

    @property
    def description(self) -> str:
        return f"Ensures trajectory execution duration does not exceed {self.max_duration_seconds}s."

    def evaluate(self, receipt: WitnessReceipt | Dict[str, Any]) -> List[PolicyViolation]:
        d = receipt.to_dict() if isinstance(receipt, WitnessReceipt) else receipt
        steps = d.get("steps", [])
        if len(steps) >= 2:
            start_t = steps[0].get("timestamp", 0.0)
            end_t = steps[-1].get("timestamp", 0.0)
            duration = max(0.0, end_t - start_t)
            if duration > self.max_duration_seconds:
                return [
                    PolicyViolation(
                        rule_name=self.name,
                        severity="MEDIUM",
                        message=f"Trajectory duration exceeded limit: {duration:.2f}s > {self.max_duration_seconds}s",
                        metadata={"duration": duration, "limit": self.max_duration_seconds},
                    )
                ]
        return []


class ModelWhitelistRule(PolicyRule):
    """Ensures trajectory was generated by an approved foundation model."""

    def __init__(self, allowed_models: List[str]):
        self.allowed_models = set(allowed_models)

    @property
    def name(self) -> str:
        return "MODEL_WHITELIST"

    @property
    def description(self) -> str:
        return f"Ensures model ID is in authorized set: {', '.join(sorted(self.allowed_models))}."

    def evaluate(self, receipt: WitnessReceipt | Dict[str, Any]) -> List[PolicyViolation]:
        d = receipt.to_dict() if isinstance(receipt, WitnessReceipt) else receipt
        model_id = d.get("model_id", "unknown")
        if model_id not in self.allowed_models:
            return [
                PolicyViolation(
                    rule_name=self.name,
                    severity="HIGH",
                    message=f"Model '{model_id}' is not in approved whitelist",
                    metadata={"model_id": model_id, "allowed": list(self.allowed_models)},
                )
            ]
        return []


class StepRepetitionRule(PolicyRule):
    """Detects degenerate reasoning loops where identical thoughts are repeated consecutively."""

    def __init__(self, max_consecutive: int = 3):
        self.max_consecutive = max_consecutive

    @property
    def name(self) -> str:
        return "REPETITIVE_DELIBERATION_LOOP"

    @property
    def description(self) -> str:
        return f"Detects runaway loops with >={self.max_consecutive} consecutive identical steps."

    def evaluate(self, receipt: WitnessReceipt | Dict[str, Any]) -> List[PolicyViolation]:
        d = receipt.to_dict() if isinstance(receipt, WitnessReceipt) else receipt
        steps = d.get("steps", [])
        violations: List[PolicyViolation] = []

        consecutive = 1
        last_content = None

        for s in steps:
            content = str(s.get("content", "")).strip()
            if content and content == last_content:
                consecutive += 1
                if consecutive >= self.max_consecutive:
                    violations.append(
                        PolicyViolation(
                            rule_name=self.name,
                            severity="MEDIUM",
                            message=f"Agent stuck in loop: repeated identical step content {consecutive} times at step #{s.get('index')}",
                            step_index=s.get("index"),
                            metadata={"consecutive_count": consecutive, "snippet": content[:60]},
                        )
                    )
                    break
            else:
                consecutive = 1
                last_content = content

        return violations


@dataclass
class PolicyEvaluationReport:
    """Comprehensive policy compliance report for a deliberation trajectory."""
    is_compliant: bool
    verdict: str  # "COMPLIANT", "VIOLATIONS_DETECTED", "WARNINGS_ONLY"
    total_violations: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    violations: List[PolicyViolation]
    rules_checked: int
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["violations"] = [v.to_dict() for v in self.violations]
        return d

    def to_text(self) -> str:
        lines = [
            "=" * 68,
            " AGENT WITNESS POLICY COMPLIANCE REPORT",
            "=" * 68,
            f"Overall Verdict:    {self.verdict}",
            f"Rules Evaluated:    {self.rules_checked}",
            f"Total Violations:   {self.total_violations} (Critical: {self.critical_count}, High: {self.high_count}, Med: {self.medium_count}, Low: {self.low_count})",
            "-" * 68,
        ]
        if not self.violations:
            lines.append("  [✓] All enterprise safety and execution policies satisfied.")
        else:
            lines.append("Violations & Warnings:")
            for v in self.violations:
                step_str = f" [Step #{v.step_index}]" if v.step_index is not None else ""
                lines.append(f"  [!] [{v.severity}] {v.rule_name}{step_str}: {v.message}")
        lines.append("=" * 68)
        return "\n".join(lines)


class PolicyGuard:
    """
    Evaluator engine that checks Witness Receipts against modular enterprise policies.
    """

    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        self.rules: List[PolicyRule] = rules if rules is not None else self.default_rules()

    @classmethod
    def default_rules(cls) -> List[PolicyRule]:
        """Standard production ruleset for autonomous agent governance."""
        return [
            MaxStepsRule(max_steps=100),
            DisallowedToolsRule(),
            RequiredApprovalRule(),
            ExecutionDurationRule(max_duration_seconds=600.0),
            StepRepetitionRule(max_consecutive=3),
        ]

    def evaluate(self, receipt: WitnessReceipt | Dict[str, Any]) -> PolicyEvaluationReport:
        all_violations: List[PolicyViolation] = []
        for rule in self.rules:
            all_violations.extend(rule.evaluate(receipt))

        crit = sum(1 for v in all_violations if v.severity == "CRITICAL")
        high = sum(1 for v in all_violations if v.severity == "HIGH")
        med = sum(1 for v in all_violations if v.severity == "MEDIUM")
        low = sum(1 for v in all_violations if v.severity in ("LOW", "WARNING"))

        is_compliant = (crit == 0 and high == 0)
        if not all_violations:
            verdict = "COMPLIANT"
        elif is_compliant:
            verdict = "WARNINGS_ONLY"
        else:
            verdict = "VIOLATIONS_DETECTED"

        return PolicyEvaluationReport(
            is_compliant=is_compliant,
            verdict=verdict,
            total_violations=len(all_violations),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            violations=all_violations,
            rules_checked=len(self.rules),
        )
