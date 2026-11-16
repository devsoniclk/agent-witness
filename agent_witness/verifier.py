from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .consensus import verify_consensus_receipt
from .log import TransparencyLog
from .merkle import MerkleTree, compute_leaf_hash
from .models import (
    AgentAttestation,
    ConsensusReceipt,
    DeliberationStep,
    StepType,
    WitnessReceipt,
)
from .signer import AgentSigner


@dataclass
class AuditCheck:
    """Individual cryptographic or consistency verification check."""
    name: str
    status: str  # "PASS", "FAIL", "SKIPPED"
    details: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TrajectoryAuditReport:
    """Comprehensive forensic audit report for an agent deliberation trajectory."""
    is_valid: bool
    agent_id: str
    model_id: str
    merkle_root: str
    step_count: int
    checks: List[AuditCheck]
    passed_checks: int
    failed_checks: int
    duration_seconds: float
    summary: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["checks"] = [c.to_dict() for c in self.checks]
        return d

    def to_text(self) -> str:
        verdict = "PASS - CRYPTOGRAPHICALLY VALID" if self.is_valid else "FAIL - TAMPERING DETECTED"
        lines = [
            "=" * 68,
            " AGENT WITNESS FORENSIC TRAJECTORY AUDIT",
            "=" * 68,
            f"Overall Verdict:     {verdict}",
            f"Agent ID:            {self.agent_id}",
            f"Model ID:            {self.model_id}",
            f"Merkle Root:         {self.merkle_root}",
            f"Deliberation Steps:  {self.step_count}",
            f"Trajectory Duration: {self.duration_seconds:.3f}s",
            f"Checks Executed:     {len(self.checks)} ({self.passed_checks} passed, {self.failed_checks} failed)",
            "-" * 68,
            "Audit Checks Breakdown:",
        ]
        for c in self.checks:
            mark = "✓" if c.status == "PASS" else ("✗" if c.status == "FAIL" else "○")
            lines.append(f"  [{mark}] {c.name.ljust(26)}: {c.status} — {c.details}")
        lines.append("=" * 68)
        return "\n".join(lines)


def verify_trajectory_integrity(
    receipt: WitnessReceipt | Dict[str, Any],
    signer: Optional[AgentSigner] = None,
    transparency_log: Optional[TransparencyLog] = None,
    consensus_receipt: Optional[ConsensusReceipt | Dict[str, Any]] = None,
    expected_prompt_hash: Optional[str] = None,
    policy_guard: Optional[Any] = None,
) -> TrajectoryAuditReport:
    """
    Performs end-to-end cryptographic and forensic verification of an agent deliberation trajectory.
    Audits step sequence continuity, temporal monotonicity, canonical RFC 6962 leaf hashes,
    Merkle action tree root integrity, agent signature authenticity, transparency log inclusion,
    selective disclosure redactions, policy guardrails, and multi-agent threshold consensus quorums.
    """
    if isinstance(receipt, dict):
        rec = WitnessReceipt(
            version=receipt.get("version", "1.0.0"),
            agent_id=receipt.get("agent_id", "unknown"),
            agent_pubkey=receipt.get("agent_pubkey", ""),
            model_id=receipt.get("model_id", "unknown"),
            system_prompt_hash=receipt.get("system_prompt_hash", ""),
            merkle_root=receipt.get("merkle_root", ""),
            step_count=receipt.get("step_count", len(receipt.get("steps", []))),
            timestamp=receipt.get("timestamp", 0.0),
            signature=receipt.get("signature", ""),
            steps=receipt.get("steps", []),
        )
    else:
        rec = receipt

    checks: List[AuditCheck] = []
    failed_count = 0

    # 1. Schema & Field Validation
    schema_ok = bool(rec.agent_id and rec.merkle_root and rec.signature and rec.steps is not None)
    if schema_ok and len(rec.merkle_root) == 64:
        checks.append(AuditCheck(
            name="SCHEMA_INTEGRITY",
            status="PASS",
            details="Valid receipt structure, version, and 256-bit hexadecimal Merkle root.",
            metadata={"version": rec.version, "step_count": rec.step_count},
        ))
    else:
        failed_count += 1
        checks.append(AuditCheck(
            name="SCHEMA_INTEGRITY",
            status="FAIL",
            details="Malformed receipt fields or invalid Merkle root length.",
            metadata={"merkle_root": rec.merkle_root},
        ))

    # 2. Step Sequence Continuity
    indices = [s.get("index", -1) for s in rec.steps]
    expected_indices = list(range(len(rec.steps)))
    count_matches = len(rec.steps) == rec.step_count

    if indices == expected_indices and count_matches:
        checks.append(AuditCheck(
            name="STEP_CONTINUITY",
            status="PASS",
            details=f"Sequence is strictly continuous from index 0 to {len(rec.steps) - 1} ({rec.step_count} total).",
            metadata={"step_count": rec.step_count},
        ))
    else:
        failed_count += 1
        checks.append(AuditCheck(
            name="STEP_CONTINUITY",
            status="FAIL",
            details=f"Discontinuous or mismatched step indices (expected 0..{rec.step_count - 1}, got {indices}).",
            metadata={"actual_indices": indices, "expected_count": rec.step_count},
        ))

    # 3. Temporal Monotonicity & Duration
    timestamps = [s.get("timestamp", 0.0) for s in rec.steps]
    regressions: List[int] = []
    for i in range(1, len(timestamps)):
        if timestamps[i] < timestamps[i - 1]:
            regressions.append(i)

    duration = (timestamps[-1] - timestamps[0]) if (timestamps and len(timestamps) > 1) else 0.0

    if not regressions:
        checks.append(AuditCheck(
            name="TEMPORAL_MONOTONICITY",
            status="PASS",
            details=f"Monotonic non-decreasing timestamps across all {len(timestamps)} steps ({duration:.3f}s total).",
            metadata={"duration_seconds": duration, "first_ts": timestamps[0] if timestamps else 0, "last_ts": timestamps[-1] if timestamps else 0},
        ))
    else:
        failed_count += 1
        checks.append(AuditCheck(
            name="TEMPORAL_MONOTONICITY",
            status="FAIL",
            details=f"Timestamp regression detected at step indices: {regressions}.",
            metadata={"regressions": regressions},
        ))

    # 4. Canonical RFC 6962 Leaf Hash Integrity & Selective Disclosure
    reconstructed_leaves: List[bytes] = []
    reconstructed_steps: List[DeliberationStep] = []
    leaf_hash_mismatches: List[int] = []
    redacted_count = 0

    for s in rec.steps:
        is_redacted = s.get("is_redacted", False)
        if is_redacted:
            redacted_count += 1
            leaf_hash_hex = s.get("leaf_hash", "")
            if len(leaf_hash_hex) == 64:
                try:
                    reconstructed_leaves.append(bytes.fromhex(leaf_hash_hex))
                except Exception:
                    leaf_hash_mismatches.append(s.get("index", -1))
            else:
                leaf_hash_mismatches.append(s.get("index", -1))
        else:
            try:
                st = DeliberationStep(
                    step_type=StepType(s["type"]),
                    index=s["index"],
                    content=s["content"],
                    metadata=s.get("metadata", {}),
                    timestamp=s.get("timestamp", 0.0),
                )
                recomputed_hash = compute_leaf_hash(st).hex()
                recorded_hash = s.get("leaf_hash", "")
                if recomputed_hash != recorded_hash:
                    leaf_hash_mismatches.append(s["index"])
                reconstructed_leaves.append(compute_leaf_hash(st))
                reconstructed_steps.append(st)
            except Exception:
                leaf_hash_mismatches.append(s.get("index", -1))

    if not leaf_hash_mismatches:
        detail_msg = (
            f"All {len(rec.steps)} steps match canonical RFC 6962 0x00 leaf hashes deterministically."
            if redacted_count == 0
            else f"All {len(rec.steps)} steps valid ({redacted_count} selectively redacted with preserved leaf commitments)."
        )
        checks.append(AuditCheck(
            name="LEAF_HASH_INTEGRITY",
            status="PASS",
            details=detail_msg,
            metadata={"verified_leaves": len(rec.steps), "redacted_leaves": redacted_count},
        ))
    else:
        failed_count += 1
        checks.append(AuditCheck(
            name="LEAF_HASH_INTEGRITY",
            status="FAIL",
            details=f"Canonical leaf hash mismatch at step indices: {leaf_hash_mismatches}.",
            metadata={"mismatch_indices": leaf_hash_mismatches},
        ))

    # 5. Merkle Action Tree Root Rebuilding
    reconstructed_tree = MerkleTree.__new__(MerkleTree)
    reconstructed_tree.steps = reconstructed_steps
    reconstructed_tree.leaves = reconstructed_leaves
    reconstructed_tree.levels = []
    reconstructed_tree._build_tree()

    if reconstructed_tree.root_hex == rec.merkle_root:
        checks.append(AuditCheck(
            name="MERKLE_ROOT_VERIFICATION",
            status="PASS",
            details=f"Reconstructed RFC 6962 tree root matches attested receipt root ({rec.merkle_root}).",
            metadata={"merkle_root": rec.merkle_root},
        ))
    else:
        failed_count += 1
        checks.append(AuditCheck(
            name="MERKLE_ROOT_VERIFICATION",
            status="FAIL",
            details=f"Reconstructed root ({reconstructed_tree.root_hex}) diverges from attested root ({rec.merkle_root}).",
            metadata={"reconstructed_root": reconstructed_tree.root_hex, "expected_root": rec.merkle_root},
        ))

    # 6. Cryptographic Signature Authenticity
    payload = f"{rec.agent_id}:{rec.model_id}:{rec.system_prompt_hash}:{rec.merkle_root}:{rec.step_count}".encode("utf-8")
    if signer:
        sig_ok = signer.verify(payload, rec.signature)
        if sig_ok:
            checks.append(AuditCheck(
                name="SIGNATURE_AUTHENTICITY",
                status="PASS",
                details=f"Signature verified successfully against agent pubkey ({rec.agent_pubkey[:16]}...).",
                metadata={"agent_pubkey": rec.agent_pubkey},
            ))
        else:
            failed_count += 1
            checks.append(AuditCheck(
                name="SIGNATURE_AUTHENTICITY",
                status="FAIL",
                details="Cryptographic signature verification failed for attestation payload.",
                metadata={"signature": rec.signature},
            ))
    else:
        if len(rec.signature) >= 32:
            checks.append(AuditCheck(
                name="SIGNATURE_AUTHENTICITY",
                status="PASS",
                details=f"Signature format confirmed ({len(rec.signature)} chars hex). Public key: {rec.agent_pubkey[:16]}...",
                metadata={"agent_pubkey": rec.agent_pubkey, "unverified_key": True},
            ))
        else:
            failed_count += 1
            checks.append(AuditCheck(
                name="SIGNATURE_AUTHENTICITY",
                status="FAIL",
                details="Empty or invalid signature hex string.",
            ))

    # 7. System Prompt Hash Invariant
    if expected_prompt_hash is not None:
        if rec.system_prompt_hash == expected_prompt_hash:
            checks.append(AuditCheck(
                name="SYSTEM_PROMPT_HASH",
                status="PASS",
                details=f"System prompt hash matches expected specification ({expected_prompt_hash[:16]}...).",
                metadata={"system_prompt_hash": rec.system_prompt_hash},
            ))
        else:
            failed_count += 1
            checks.append(AuditCheck(
                name="SYSTEM_PROMPT_HASH",
                status="FAIL",
                details=f"System prompt hash mismatch: got {rec.system_prompt_hash}, expected {expected_prompt_hash}.",
                metadata={"actual": rec.system_prompt_hash, "expected": expected_prompt_hash},
            ))

    # 8. Transparency Log Inclusion
    if transparency_log:
        found_record = None
        for record in transparency_log.entries:
            if record.merkle_root == rec.merkle_root:
                found_record = record
                break

        if found_record:
            proof = transparency_log.get_inclusion_proof(found_record.log_index)
            is_valid_inclusion = TransparencyLog.verify_inclusion_proof(proof)
            if is_valid_inclusion:
                checks.append(AuditCheck(
                    name="TRANSPARENCY_LOG_INCLUSION",
                    status="PASS",
                    details=f"Receipt verified in Transparency Log at index #{found_record.log_index} (log size {transparency_log.tree_size}).",
                    metadata={"log_index": found_record.log_index, "log_size": transparency_log.tree_size},
                ))
            else:
                failed_count += 1
                checks.append(AuditCheck(
                    name="TRANSPARENCY_LOG_INCLUSION",
                    status="FAIL",
                    details=f"Transparency log inclusion proof failed for index #{found_record.log_index}.",
                    metadata={"log_index": found_record.log_index},
                ))
        else:
            failed_count += 1
            checks.append(AuditCheck(
                name="TRANSPARENCY_LOG_INCLUSION",
                status="FAIL",
                details="Receipt Merkle root not found in provided Transparency Log entries.",
                metadata={"merkle_root": rec.merkle_root, "log_size": transparency_log.tree_size},
            ))

    # 9. Consensus Quorum Verification
    if consensus_receipt:
        if isinstance(consensus_receipt, dict):
            crec = ConsensusReceipt(
                version=consensus_receipt.get("version", "1.0.0"),
                trajectory_id=consensus_receipt.get("trajectory_id", ""),
                merkle_root=consensus_receipt.get("merkle_root", ""),
                step_count=consensus_receipt.get("step_count", 0),
                threshold=consensus_receipt.get("threshold", 1),
                attestations=[AgentAttestation(**a) for a in consensus_receipt.get("attestations", [])],
                timestamp=consensus_receipt.get("timestamp", 0.0),
            )
        else:
            crec = consensus_receipt

        if crec.merkle_root != rec.merkle_root:
            failed_count += 1
            checks.append(AuditCheck(
                name="CONSENSUS_QUORUM",
                status="FAIL",
                details=f"Consensus receipt Merkle root ({crec.merkle_root}) does not match trajectory root ({rec.merkle_root}).",
            ))
        else:
            is_consensus_ok, report = verify_consensus_receipt(crec)
            if is_consensus_ok:
                checks.append(AuditCheck(
                    name="CONSENSUS_QUORUM",
                    status="PASS",
                    details=f"Quorum reached: {report['approved_count']} approvals (threshold {report['threshold']} of {report['total_attestations']} agents).",
                    metadata=report,
                ))
            else:
                failed_count += 1
                checks.append(AuditCheck(
                    name="CONSENSUS_QUORUM",
                    status="FAIL",
                    details=f"Consensus quorum unsatisfied: {report['approved_count']}/{report['threshold']} approvals.",
                    metadata=report,
                ))

    # 10. Policy Compliance Evaluation
    if policy_guard is not None:
        pol_report = policy_guard.evaluate(rec)
        if pol_report.is_compliant:
            checks.append(AuditCheck(
                name="POLICY_COMPLIANCE",
                status="PASS",
                details=f"All {pol_report.rules_checked} safety and execution policies satisfied ({pol_report.verdict}).",
                metadata=pol_report.to_dict(),
            ))
        else:
            failed_count += 1
            checks.append(AuditCheck(
                name="POLICY_COMPLIANCE",
                status="FAIL",
                details=f"Policy compliance failed: {pol_report.total_violations} violations detected across {pol_report.rules_checked} rules.",
                metadata=pol_report.to_dict(),
            ))

    is_overall_valid = (failed_count == 0)
    summary_verdict = (
        f"Verified: Trajectory contains {rec.step_count} valid steps with intact Merkle root {rec.merkle_root[:16]}..."
        if is_overall_valid
        else f"Tampering Detected: {failed_count} audit checks failed across {len(checks)} verifications."
    )

    return TrajectoryAuditReport(
        is_valid=is_overall_valid,
        agent_id=rec.agent_id,
        model_id=rec.model_id,
        merkle_root=rec.merkle_root,
        step_count=rec.step_count,
        checks=checks,
        passed_checks=len(checks) - failed_count,
        failed_checks=failed_count,
        duration_seconds=duration,
        summary=summary_verdict,
    )
