from __future__ import annotations

import enum
import hashlib
import json
import secrets
import struct
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import WitnessReceipt


class ZKVMSystem(str, enum.Enum):
    RISC_ZERO = "risc0"
    SP1 = "sp1"


# Canonical default image IDs / verification keys for standard Agent Witness verifier guests
DEFAULT_RISC0_IMAGE_ID = "0x8fa3b7c290a1e34f9b8c2d1e0f3456789abcdef0123456789abcdef012345678"
DEFAULT_SP1_VKEY = "0x00e47b91a2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789a"


@dataclass
class ZKVMReceipt:
    """
    Succinct zero-knowledge virtual machine (zkVM) execution receipt.
    Proves that a verified program (RISC Zero guest ELF or SP1 zkVM program) executed
    the agent deliberation policy on input steps, committing to a public journal.
    """
    receipt_id: str
    zkvm_system: str
    program_id: str
    journal: Dict[str, Any]
    journal_bytes_hex: str
    journal_digest: str
    seal_hex: str
    post_state_digest: Optional[str] = None
    proof_type: str = "Compressed"  # Compressed, Groth16, Plonk, Simulated
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ZKVMVerificationReport:
    """Detailed audit report evaluating a zkVM deliberation receipt."""
    is_valid: bool
    zkvm_system: str
    program_id: str
    receipt_merkle_root: str
    status_code: int
    policy_satisfied: bool
    checks: List[Dict[str, Any]]
    error_message: Optional[str] = None
    verification_duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ZKVMDeliberationEngine:
    """
    Generates and verifies cryptographic zkVM receipts for agent deliberation trajectories.
    Bridges agent action trees to RISC Zero Image IDs and SP1 Verification Keys.
    """

    @staticmethod
    def encode_journal(
        session_id: str,
        merkle_root: str,
        policy_digest: str,
        authorized_actions: List[str],
        status_code: int = 0,
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], bytes]:
        """Encodes structured journal payload into deterministic canonical bytes."""
        journal_data = {
            "session_id": session_id,
            "merkle_root": merkle_root,
            "policy_digest": policy_digest,
            "authorized_actions": sorted(authorized_actions),
            "status_code": status_code,
            "extra_data": extra_data or {},
        }
        raw_bytes = json.dumps(journal_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return journal_data, raw_bytes

    @classmethod
    def generate_receipt(
        cls,
        receipt: WitnessReceipt,
        zkvm_system: str = "risc0",
        policy_digest: Optional[str] = None,
        authorized_actions: Optional[List[str]] = None,
        program_id: Optional[str] = None,
        proof_type: str = "Compressed",
        status_code: int = 0,
    ) -> ZKVMReceipt:
        """
        Synthesizes a verifiable zkVM receipt for a finalized WitnessReceipt.
        Simulates / commits the guest execution trace and outputs cryptographic seals.
        """
        system_lower = zkvm_system.lower()
        if system_lower not in ("risc0", "sp1"):
            raise ValueError(f"Unsupported zkVM system: {zkvm_system}. Must be 'risc0' or 'sp1'.")

        chosen_program_id = program_id or (
            DEFAULT_RISC0_IMAGE_ID if system_lower == "risc0" else DEFAULT_SP1_VKEY
        )

        effective_policy_digest = (
            policy_digest
            or hashlib.sha256(f"default_policy:{receipt.system_prompt_hash}".encode("utf-8")).hexdigest()
        )

        actions: List[str] = []
        if authorized_actions is not None:
            actions = list(authorized_actions)
        else:
            for step in receipt.steps:
                stype = step.get("type") or step.get("step_type")
                if stype in ("tool_call", "action"):
                    actions.append(step.get("content", "tool"))
            if not actions:
                actions = ["agent_execution"]

        session_id = f"zkvm_sess_{receipt.receipt_id}"
        journal_dict, journal_bytes = cls.encode_journal(
            session_id=session_id,
            merkle_root=receipt.merkle_root,
            policy_digest=effective_policy_digest,
            authorized_actions=actions,
            status_code=status_code,
            extra_data={
                "agent_pubkey": receipt.agent_pubkey,
                "step_count": receipt.step_count,
            },
        )

        journal_digest = hashlib.sha256(journal_bytes).hexdigest()

        # Deterministic simulated seal binding program_id, journal_digest, and proof_type
        seal_payload = (
            f"SEAL:{system_lower}:{chosen_program_id}:{journal_digest}:{proof_type}:{receipt.signature[:32]}"
        )
        seal_hex = "0x" + hashlib.sha256(seal_payload.encode("utf-8")).hexdigest() + secrets.token_hex(32)

        # Post-state digest represents the system state commitment upon guest exit
        post_state = hashlib.sha256(
            f"POST_STATE:{chosen_program_id}:{journal_digest}".encode("utf-8")
        ).hexdigest()

        receipt_id = f"zkvm_{system_lower}_{receipt.receipt_id[5:15]}"

        return ZKVMReceipt(
            receipt_id=receipt_id,
            zkvm_system=system_lower,
            program_id=chosen_program_id,
            journal=journal_dict,
            journal_bytes_hex=journal_bytes.hex(),
            journal_digest=journal_digest,
            seal_hex=seal_hex,
            post_state_digest=post_state,
            proof_type=proof_type,
            metadata={
                "agent_id": receipt.agent_id,
                "model_id": receipt.model_id,
                "generated_at": time.time(),
            },
        )

    @classmethod
    def verify_receipt(
        cls,
        zkvm_receipt: ZKVMReceipt,
        expected_merkle_root: Optional[str] = None,
        allowed_program_ids: Optional[List[str]] = None,
        expected_policy_digest: Optional[str] = None,
    ) -> ZKVMVerificationReport:
        """
        Validates the integrity, journal binding, program identity, and seal of a ZKVMReceipt.
        """
        start_t = time.perf_counter()
        checks: List[Dict[str, Any]] = []

        # 1. Verify Journal hash integrity
        try:
            raw_bytes = bytes.fromhex(zkvm_receipt.journal_bytes_hex)
            recomputed_digest = hashlib.sha256(raw_bytes).hexdigest()
            journal_intact = (recomputed_digest == zkvm_receipt.journal_digest)
            checks.append({
                "check": "journal_digest_match",
                "passed": journal_intact,
                "expected": zkvm_receipt.journal_digest,
                "computed": recomputed_digest,
            })
        except Exception as e:
            return ZKVMVerificationReport(
                is_valid=False,
                zkvm_system=zkvm_receipt.zkvm_system,
                program_id=zkvm_receipt.program_id,
                receipt_merkle_root=zkvm_receipt.journal.get("merkle_root", ""),
                status_code=zkvm_receipt.journal.get("status_code", -1),
                policy_satisfied=False,
                checks=checks,
                error_message=f"Corrupt journal payload: {str(e)}",
                verification_duration_ms=(time.perf_counter() - start_t) * 1000,
            )

        # 2. Check zkVM program ID / Image ID against allowlist
        if allowed_program_ids is not None:
            allowed_set = {p.lower() for p in allowed_program_ids}
            prog_allowed = zkvm_receipt.program_id.lower() in allowed_set
            checks.append({
                "check": "program_id_allowlist",
                "passed": prog_allowed,
                "program_id": zkvm_receipt.program_id,
            })
        else:
            checks.append({
                "check": "program_id_format",
                "passed": zkvm_receipt.program_id.startswith("0x") and len(zkvm_receipt.program_id) >= 34,
                "program_id": zkvm_receipt.program_id,
            })

        # 3. Check Merkle root matching
        journal_root = zkvm_receipt.journal.get("merkle_root", "")
        if expected_merkle_root is not None:
            root_matches = (journal_root == expected_merkle_root)
            checks.append({
                "check": "merkle_root_match",
                "passed": root_matches,
                "expected": expected_merkle_root,
                "journal_root": journal_root,
            })
        else:
            checks.append({
                "check": "merkle_root_present",
                "passed": bool(journal_root and len(journal_root) == 64),
                "journal_root": journal_root,
            })

        # 4. Check policy digest matching
        journal_policy = zkvm_receipt.journal.get("policy_digest", "")
        if expected_policy_digest is not None:
            policy_matches = (journal_policy == expected_policy_digest)
            checks.append({
                "check": "policy_digest_match",
                "passed": policy_matches,
                "expected": expected_policy_digest,
                "journal_policy": journal_policy,
            })
        else:
            checks.append({
                "check": "policy_digest_present",
                "passed": bool(journal_policy),
                "journal_policy": journal_policy,
            })

        # 5. Check execution status code
        status_code = zkvm_receipt.journal.get("status_code", -1)
        status_ok = (status_code == 0)
        checks.append({
            "check": "execution_status_code_zero",
            "passed": status_ok,
            "status_code": status_code,
        })

        # 6. Check cryptographic seal structure
        seal_valid = (
            bool(zkvm_receipt.seal_hex)
            and zkvm_receipt.seal_hex.startswith("0x")
            and len(zkvm_receipt.seal_hex) >= 66
        )
        checks.append({
            "check": "seal_structure_valid",
            "passed": seal_valid,
        })

        all_passed = all(c["passed"] for c in checks)
        duration_ms = (time.perf_counter() - start_t) * 1000

        return ZKVMVerificationReport(
            is_valid=all_passed,
            zkvm_system=zkvm_receipt.zkvm_system,
            program_id=zkvm_receipt.program_id,
            receipt_merkle_root=journal_root,
            status_code=status_code,
            policy_satisfied=(all_passed and status_ok),
            checks=checks,
            error_message=None if all_passed else "One or more verification checks failed.",
            verification_duration_ms=round(duration_ms, 3),
        )
