from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .models import WitnessReceipt
from .signer import AgentSigner


@dataclass
class AnomalyIncident:
    """Represents a specific compliance anomaly detected within an action sequence."""
    incident_type: str
    step_index: int
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ComplianceAuditReport:
    """Comprehensive compliance and anomaly evaluation report for witness receipts."""
    report_id: str
    is_compliant: bool
    risk_score: float  # 0.0 (pristine) to 100.0 (high risk)
    incidents: List[AnomalyIncident]
    total_steps_checked: int
    cumulative_value_tracked: float
    signer_pubkey: str
    signature: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ComplianceAnomalyDetector:
    """
    Automated risk and anomaly evaluation engine for autonomous agent action streams.
    Detects high-velocity loop spasms, financial value-at-risk cap breaches,
    unauthorized authority drift, and temporal replay anomalies.
    """

    def __init__(
        self,
        max_velocity_per_min: float = 60.0,
        max_cumulative_value: float = 10000.0,
        max_clock_skew_sec: float = 300.0,
        signer: Optional[AgentSigner] = None,
    ):
        self.max_velocity_per_min = max_velocity_per_min
        self.max_cumulative_value = max_cumulative_value
        self.max_clock_skew_sec = max_clock_skew_sec
        self.signer = signer or AgentSigner()

    def audit_receipt(
        self,
        receipt: WitnessReceipt,
        expected_authority: Optional[str] = None,
    ) -> ComplianceAuditReport:
        incidents: List[AnomalyIncident] = []
        cumulative_value = 0.0
        now = time.time()

        steps = receipt.steps
        step_count = len(steps)

        # 1. Check Authority Drift
        if expected_authority:
            if receipt.agent_pubkey.lower() != expected_authority.lower() and receipt.agent_id != expected_authority:
                incidents.append(
                    AnomalyIncident(
                        incident_type="AUTHORITY_DRIFT",
                        step_index=-1,
                        severity="CRITICAL",
                        description=f"Signer pubkey {receipt.agent_pubkey} does not match expected authority {expected_authority}.",
                        context={"receipt_pubkey": receipt.agent_pubkey, "expected": expected_authority},
                    )
                )

        # 2. Check Temporal Integrity of receipt timestamp
        if abs(receipt.timestamp - now) > self.max_clock_skew_sec:
            incidents.append(
                AnomalyIncident(
                    incident_type="TEMPORAL_CLOCK_SKEW",
                    step_index=-1,
                    severity="HIGH",
                    description=f"Receipt timestamp skew ({abs(receipt.timestamp - now):.1f}s) exceeds max skew ({self.max_clock_skew_sec}s).",
                    context={"receipt_timestamp": receipt.timestamp, "evaluated_at": now},
                )
            )

        # 3. Step-by-step checks
        prev_ts = None
        for i, s in enumerate(steps):
            ts = s.get("timestamp", 0.0)
            meta = s.get("metadata", {})

            # Check timestamp ordering
            if prev_ts is not None and ts < prev_ts:
                incidents.append(
                    AnomalyIncident(
                        incident_type="TEMPORAL_OUT_OF_ORDER",
                        step_index=i,
                        severity="CRITICAL",
                        description=f"Step {i} timestamp ({ts}) occurs before preceding step ({prev_ts}).",
                        context={"step_index": i, "timestamp": ts, "prev_timestamp": prev_ts},
                    )
                )
            prev_ts = ts

            # Check financial / asset value accumulation
            for val_key in ["amount_usd", "value", "transfer_amount", "amount", "budget"]:
                if val_key in meta and isinstance(meta[val_key], (int, float)):
                    val = float(meta[val_key])
                    cumulative_value += val
                    if cumulative_value > self.max_cumulative_value:
                        incidents.append(
                            AnomalyIncident(
                                incident_type="CUMULATIVE_VALUE_BREACH",
                                step_index=i,
                                severity="HIGH",
                                description=f"Cumulative value {cumulative_value:.2f} exceeded cap of {self.max_cumulative_value:.2f}.",
                                context={"breach_step": i, "cumulative_value": cumulative_value, "cap": self.max_cumulative_value},
                            )
                        )
                        break

        # 4. Velocity Anomaly
        if steps and len(steps) > 1:
            duration = max(1.0, steps[-1].get("timestamp", now) - steps[0].get("timestamp", now))
            velocity_per_min = (len(steps) / duration) * 60.0
            if velocity_per_min > self.max_velocity_per_min:
                incidents.append(
                    AnomalyIncident(
                        incident_type="VELOCITY_ANOMALY",
                        step_index=len(steps) - 1,
                        severity="MEDIUM",
                        description=f"Action velocity ({velocity_per_min:.1f} steps/min) exceeds limit ({self.max_velocity_per_min:.1f}).",
                        context={"velocity_per_min": velocity_per_min, "threshold": self.max_velocity_per_min},
                    )
                )

        # Calculate composite risk score (0 to 100)
        risk = 0.0
        for inc in incidents:
            if inc.severity == "CRITICAL":
                risk += 50.0
            elif inc.severity == "HIGH":
                risk += 25.0
            elif inc.severity == "MEDIUM":
                risk += 10.0
            else:
                risk += 5.0
        risk_score = min(100.0, risk)
        is_compliant = risk_score < 25.0

        report_id = f"compliance-{receipt.merkle_root[:16]}-{int(now)}"
        canonical = f"{report_id}:{is_compliant}:{risk_score}:{len(incidents)}:{int(now)}"
        sig = self.signer.sign(canonical.encode("utf-8"))

        return ComplianceAuditReport(
            report_id=report_id,
            is_compliant=is_compliant,
            risk_score=risk_score,
            incidents=incidents,
            total_steps_checked=step_count,
            cumulative_value_tracked=cumulative_value,
            signer_pubkey=self.signer.pubkey_hex,
            signature=sig,
            timestamp=now,
        )
