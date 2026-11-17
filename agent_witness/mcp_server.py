from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .batch_anchor import BatchAnchorEngine, EpochBatchReceipt
from .compliance import ComplianceAnomalyDetector
from .consensus import MultiAgentConsensusEngine, verify_consensus_receipt
from .html_report import render_html_report
from .log import TransparencyLog
from .models import (
    AgentAttestation,
    ConsensusReceipt,
    DeliberationStep,
    ProofBundle,
    StepType,
    WitnessReceipt,
)
from .blinded import BlindedAttestationEngine, BlindedReceipt
from .credentials import AgentCredentialEngine, VerifiableAgentCredential, pubkey_to_did_key
from .delegation import DelegationCapability, DelegationDAGVerifier, create_delegation_grant
from .dispute import ArbitrationEngine, DisputeClaim, DisputeType
from .multichain import MultiChainAnchorDispatcher
from .policy import (
    DisallowedToolsRule,
    ExecutionDurationRule,
    MaxStepsRule,
    PolicyGuard,
    RequiredApprovalRule,
    StepRepetitionRule,
)
from .proof import export_proof_bundle, verify_proof_bundle
from .receipt import WitnessEngine
from .redaction import RedactionEngine
from .revocation import RevocationReason, RevocationRegistry
from .signer import AgentSigner
from .streaming import StreamingActionSession
from .verifier import verify_trajectory_integrity
from .zk_proof import ZKAttestationProof, ZKConstraintSet, ZKProofEngine


class WitnessMCPServer:
    """
    Standard-compliant Model Context Protocol (MCP) stdio server for agent-witness.
    Provides cryptographic action attestation, Merkle audit trees, transparency logging,
    selective disclosure redaction, policy governance, and multi-agent consensus to AI agents.
    """

    PROTOCOL_VERSION = "2024-11-05"

    def __init__(
        self,
        agent_id: str = "agent-mcp-witness",
        model_id: str = "openbot-v1",
        system_prompt: str = "Autonomous Agent Attestation System",
        log_dir: str = ".witness_log",
    ):
        self.agent_id = agent_id
        self.model_id = model_id
        self.system_prompt = system_prompt
        self.log_dir = log_dir
        self.signer = AgentSigner()
        self.engine = WitnessEngine(
            agent_id=self.agent_id,
            model_id=self.model_id,
            system_prompt=self.system_prompt,
            signer=self.signer,
        )
        self.last_receipt: Optional[WitnessReceipt] = None
        self.log = TransparencyLog(log_dir=self.log_dir, signer=self.signer)
        self.active_consensus: Dict[str, MultiAgentConsensusEngine] = {}
        self.active_sessions: Dict[str, StreamingActionSession] = {}
        self.multichain_dispatcher = MultiChainAnchorDispatcher(signer=self.signer)
        self.compliance_detector = ComplianceAnomalyDetector(signer=self.signer)
        self.credential_engine = AgentCredentialEngine(issuer_signer=self.signer)
        self.zk_engine = ZKProofEngine(signer=self.signer)
        self.revocation_registry = RevocationRegistry(authority_signer=self.signer)

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "witness_record_action",
                "description": "Record an agent deliberation step (observation, thought, tool_call, tool_result, decision) with deterministic cryptographic leaf hashing.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "step_type": {
                            "type": "string",
                            "enum": ["observation", "thought", "tool_call", "tool_result", "decision"],
                            "description": "Type of action or deliberation step.",
                        },
                        "content": {
                            "type": "string",
                            "description": "Detailed text content or serialized execution payload of the step.",
                        },
                        "metadata": {
                            "type": "object",
                            "description": "Optional arbitrary metadata dictionary (e.g., latency, tool name, parameters).",
                        },
                    },
                    "required": ["step_type", "content"],
                },
            },
            {
                "name": "witness_finalize_receipt",
                "description": "Compile recorded steps into an RFC 6962 Merkle Action Tree, sign the Merkle Root with the agent key, and return an immutable WitnessReceipt.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "output_file": {
                            "type": "string",
                            "description": "Optional file path to persist the signed WitnessReceipt JSON.",
                        },
                    },
                },
            },
            {
                "name": "witness_audit_trajectory",
                "description": "Execute comprehensive multi-layer forensic audit on a deliberation trajectory (checking step continuity, timestamps, leaf hashes, Merkle root, signatures, log inclusion, consensus).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "receipt": {
                            "type": "object",
                            "description": "Optional inline receipt JSON dictionary. If omitted, audits the last finalized receipt.",
                        },
                        "receipt_file": {
                            "type": "string",
                            "description": "Optional path to a receipt JSON file.",
                        },
                        "log_dir": {
                            "type": "string",
                            "description": "Optional transparency log directory to audit inclusion against.",
                        },
                        "expected_prompt_hash": {
                            "type": "string",
                            "description": "Optional expected system prompt SHA-256 hash to verify against.",
                        },
                    },
                },
            },
            {
                "name": "witness_export_proof",
                "description": "Export a cryptographic selective disclosure proof bundle for a specific deliberation step, proving inclusion in the signed Merkle root without disclosing other steps.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "step_index": {
                            "type": "integer",
                            "description": "Zero-based index of the step to selectively disclose.",
                        },
                        "receipt_file": {
                            "type": "string",
                            "description": "Optional path to receipt file. Defaults to last finalized receipt.",
                        },
                        "output_file": {
                            "type": "string",
                            "description": "Optional path to save exported proof bundle JSON.",
                        },
                    },
                    "required": ["step_index"],
                },
            },
            {
                "name": "witness_verify_proof",
                "description": "Cryptographically verify a standalone selective disclosure proof bundle against its declared Merkle root and agent signature.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "proof_bundle": {
                            "type": "object",
                            "description": "Inline proof bundle dictionary.",
                        },
                        "proof_file": {
                            "type": "string",
                            "description": "Path to proof bundle JSON file.",
                        },
                    },
                },
            },
            {
                "name": "witness_log_append",
                "description": "Append a finalized WitnessReceipt into the append-only cryptographic transparency log ledger.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "receipt_file": {
                            "type": "string",
                            "description": "Optional path to receipt JSON file. Defaults to last finalized receipt.",
                        },
                        "log_dir": {
                            "type": "string",
                            "description": "Optional transparency log directory (default: current configured log dir).",
                        },
                    },
                },
            },
            {
                "name": "witness_log_checkpoint",
                "description": "Generate a cryptographically signed Signed Tree Head (STH) checkpoint of the current transparency log.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "log_dir": {
                            "type": "string",
                            "description": "Optional transparency log directory.",
                        },
                    },
                },
            },
            {
                "name": "witness_log_verify_consistency",
                "description": "Verify RFC 6962 append-only consistency between two tree sizes of the transparency log, proving history was never modified or truncated.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "old_size": {
                            "type": "integer",
                            "description": "Past tree size to verify against.",
                        },
                        "new_size": {
                            "type": "integer",
                            "description": "Newer tree size. If omitted, uses latest current tree size.",
                        },
                    },
                    "required": ["old_size"],
                },
            },
            {
                "name": "witness_attest_consensus",
                "description": "Cast an agent attestation vote (APPROVE / REJECT) towards M-of-N threshold consensus on an action trajectory Merkle root.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "merkle_root": {
                            "type": "string",
                            "description": "Target trajectory Merkle root to attest.",
                        },
                        "agent_id": {
                            "type": "string",
                            "description": "Unique identifier of the voting agent.",
                        },
                        "role": {
                            "type": "string",
                            "description": "Agent consensus role (e.g., 'auditor', 'arbiter', 'peer').",
                        },
                        "verdict": {
                            "type": "string",
                            "enum": ["APPROVE", "REJECT"],
                            "description": "Consensus vote verdict (default: APPROVE).",
                        },
                        "threshold": {
                            "type": "integer",
                            "description": "Required threshold quorum of positive votes (default: 1).",
                        },
                        "comments": {
                            "type": "string",
                            "description": "Optional rationale or audit notes.",
                        },
                    },
                    "required": ["merkle_root", "agent_id", "role"],
                },
            },
            {
                "name": "witness_generate_dossier",
                "description": "Generate an interactive, standalone dark-mode HTML forensic audit dossier for an attested deliberation trajectory.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "receipt_file": {
                            "type": "string",
                            "description": "Optional path to receipt file. Defaults to last finalized receipt.",
                        },
                        "output_file": {
                            "type": "string",
                            "description": "Output path for the HTML report file.",
                        },
                    },
                    "required": ["output_file"],
                },
            },
            {
                "name": "witness_redact_receipt",
                "description": "Conceal confidential thoughts, sensitive tool payloads, or PII from a receipt while preserving 100% cryptographic Merkle root verifiability.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "receipt_file": {
                            "type": "string",
                            "description": "Optional path to receipt file. Defaults to last finalized receipt.",
                        },
                        "redact_steps": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "List of step indices to selectively redact.",
                        },
                        "redact_reason": {
                            "type": "string",
                            "description": "Redaction reason or category (default: 'Confidential').",
                        },
                        "output_file": {
                            "type": "string",
                            "description": "Optional file path to persist redacted receipt JSON.",
                        },
                    },
                },
            },
            {
                "name": "witness_evaluate_policy",
                "description": "Audit a deliberation trajectory against enterprise governance policies (max steps, disallowed tools, required human approval, duration limits).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "receipt_file": {
                            "type": "string",
                            "description": "Optional path to receipt file. Defaults to last finalized receipt.",
                        },
                        "max_steps": {
                            "type": "integer",
                            "description": "Max allowed deliberation steps (default: 100).",
                        },
                        "disallowed_tools": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional custom list of prohibited tool names.",
                        },
                    },
                },
            },
            {
                "name": "witness_batch_anchor",
                "description": "Aggregate multiple WitnessReceipts into an Epoch Merkle Root, producing turnkey EVM calldata and Solana memo payloads for gas-efficient on-chain anchoring.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "receipt_files": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of file paths to receipt JSON files to include in epoch batch.",
                        },
                        "epoch_id": {
                            "type": "string",
                            "description": "Optional identifier for the epoch batch.",
                        },
                        "output_file": {
                            "type": "string",
                            "description": "Optional path to save epoch batch receipt JSON.",
                        },
                    },
                    "required": ["receipt_files"],
                },
            },
            {
                "name": "witness_anchor_multichain",
                "description": "Generate cross-chain anchor transaction payloads across Solana Anchor state programs (with PDA derivation) and EVM L1/L2 contracts.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "receipt_file": {
                            "type": "string",
                            "description": "Optional path to receipt file. Defaults to last finalized receipt.",
                        },
                        "merkle_root": {
                            "type": "string",
                            "description": "Optional direct 32-byte Merkle root hex string.",
                        },
                        "identifier": {
                            "type": "string",
                            "description": "Identifier for epoch or session (default: 'epoch-default').",
                        },
                        "chains": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Chains to generate anchor payloads for (e.g. ['solana', 'base', 'arbitrum']).",
                        },
                        "quorum_threshold": {
                            "type": "integer",
                            "description": "Threshold number of chains required for cross-chain quorum (default: 2).",
                        },
                    },
                },
            },
            {
                "name": "witness_session_stream",
                "description": "Append an action to an incremental streaming action session, computing dynamic rolling Merkle frontier roots with O(1) amortized cost.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {
                            "type": "string",
                            "description": "Unique session identifier.",
                        },
                        "action": {
                            "type": "string",
                            "enum": ["append", "status"],
                            "description": "Action to perform (default: 'append').",
                        },
                        "step_type": {
                            "type": "string",
                            "enum": ["observation", "thought", "tool_call", "tool_result", "decision"],
                            "description": "Type of step to append.",
                        },
                        "content": {
                            "type": "string",
                            "description": "Content of the step.",
                        },
                        "metadata": {
                            "type": "object",
                            "description": "Optional step metadata.",
                        },
                    },
                    "required": ["session_id"],
                },
            },
            {
                "name": "witness_audit_compliance",
                "description": "Perform automated compliance and anomaly evaluation (velocity bursts, cumulative asset value limits, authority drift, timestamp skews).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "receipt_file": {
                            "type": "string",
                            "description": "Optional path to receipt file. Defaults to last finalized receipt.",
                        },
                        "max_velocity_per_min": {
                            "type": "number",
                            "description": "Maximum allowed action steps per minute (default: 60.0).",
                        },
                        "max_cumulative_value": {
                            "type": "number",
                            "description": "Maximum cumulative financial asset transfer limit (default: 10000.0).",
                        },
                        "expected_authority": {
                            "type": "string",
                            "description": "Expected agent public key or authority identifier.",
                        },
                    },
                },
            },
            {
                "name": "witness_issue_credential",
                "description": "Issue a W3C-compliant Verifiable Agent Credential binding agent DID, capability boundary, allowed models, and sponsor identity.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string", "description": "Agent identifier string."},
                        "agent_pubkey": {"type": "string", "description": "Agent public key in hex (defaults to server signer pubkey)."},
                        "roles": {"type": "array", "items": {"type": "string"}, "description": "Delegated role names."},
                        "capabilities": {"type": "array", "items": {"type": "string"}, "description": "Authorized capability strings or tools."},
                        "allowed_models": {"type": "array", "items": {"type": "string"}, "description": "Allowed LLM model identifiers."},
                        "max_financial_limit": {"type": "number", "description": "Maximum authorized financial asset transfer ceiling."},
                        "sponsor_identity": {"type": "string", "description": "Human or organizational sponsor identifier."},
                        "validity_days": {"type": "integer", "description": "Credential validity period in days (default: 30)."},
                    },
                    "required": ["agent_id"],
                },
            },
            {
                "name": "witness_verify_credential",
                "description": "Cryptographically verify a Verifiable Agent Credential for expiration, issuer authenticity, and integrity.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "credential": {"type": "object", "description": "Verifiable Agent Credential object to verify."},
                        "trusted_issuer_did": {"type": "string", "description": "Optional trusted issuer DID string."},
                    },
                    "required": ["credential"],
                },
            },
            {
                "name": "witness_generate_zk_attestation",
                "description": "Generate a succinct zero-knowledge attestation proving trajectory compliance (step limits, latency ceiling, model/tool membership) without leaking sensitive prompt/output tokens.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "receipt_file": {"type": "string", "description": "Optional path to receipt JSON file."},
                        "max_steps": {"type": "integer", "description": "Maximum steps constraint to prove."},
                        "max_duration_ms": {"type": "number", "description": "Maximum duration in ms to prove."},
                        "allowed_tools": {"type": "array", "items": {"type": "string"}, "description": "Whitelist of authorized tools."},
                        "allowed_models": {"type": "array", "items": {"type": "string"}, "description": "Whitelist of authorized model IDs."},
                        "max_financial_spend": {"type": "number", "description": "Ceiling on cumulative financial value."},
                    },
                },
            },
            {
                "name": "witness_verify_zk_attestation",
                "description": "Mathematically verify a zero-knowledge constraint attestation proof against claimed bounds without trajectory inspection.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "proof": {"type": "object", "description": "ZKAttestationProof dictionary object."},
                        "max_steps": {"type": "integer", "description": "Claimed maximum steps."},
                        "max_duration_ms": {"type": "number", "description": "Claimed maximum duration ms."},
                        "allowed_tools": {"type": "array", "items": {"type": "string"}, "description": "Claimed allowed tools."},
                        "allowed_models": {"type": "array", "items": {"type": "string"}, "description": "Claimed allowed models."},
                        "max_financial_spend": {"type": "number", "description": "Claimed maximum financial spend."},
                        "expected_merkle_root": {"type": "string", "description": "Optional expected Merkle root."},
                    },
                    "required": ["proof"],
                },
            },
            {
                "name": "witness_check_revocation",
                "description": "Query the cryptographic revocation registry to verify that an agent public key, credential, or session is active and unrevoked.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_identifier": {"type": "string", "description": "Agent public key, credential ID, or session ID."},
                        "target_type": {"type": "string", "description": "Target type: AGENT_PUBKEY, CREDENTIAL_ID, or SESSION_ID (default: AGENT_PUBKEY)."},
                        "revoke_now": {"type": "boolean", "description": "Whether to trigger immediate revocation (emergency kill-switch)."},
                        "reason": {"type": "string", "description": "Revocation reason if revoke_now is true."},
                    },
                    "required": ["target_identifier"],
                },
            },
            {
                "name": "witness_delegate_capability",
                "description": "Issue and cryptographically sign a scoped delegation capability grant to a child subagent.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "child_agent_id": {"type": "string", "description": "Subagent or child agent identifier."},
                        "child_pubkey": {"type": "string", "description": "Public key in hex of the subagent."},
                        "scope": {"type": "array", "items": {"type": "string"}, "description": "Allowed tools or actions (e.g. ['web_search', 'run_test'] or ['*'])."},
                        "expires_in_seconds": {"type": "number", "description": "Grant validity duration in seconds (default: 3600.0)."},
                        "max_budget_usd": {"type": "number", "description": "Optional financial spend limit ceiling."},
                        "metadata": {"type": "object", "description": "Optional grant metadata."},
                    },
                    "required": ["child_agent_id", "child_pubkey", "scope"],
                },
            },
            {
                "name": "witness_verify_delegation_dag",
                "description": "Verify a multi-agent delegation DAG lineage, checking signatures, scopes, time validity, and budget caps.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "root_agent_id": {"type": "string", "description": "Root orchestrator agent identifier."},
                        "grants": {"type": "array", "items": {"type": "object"}, "description": "List of DelegationCapability grant objects."},
                        "receipt_file": {"type": "string", "description": "Optional receipt file to verify compliance against grants."},
                    },
                    "required": ["root_agent_id", "grants"],
                },
            },
            {
                "name": "witness_blind_receipt",
                "description": "Mask sensitive receipt fields with cryptographic commitments and generate verifiable range proofs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sensitive_keys": {"type": "array", "items": {"type": "string"}, "description": "Keys to blind (e.g. ['amount', 'token', 'confidence'])."},
                        "receipt_file": {"type": "string", "description": "Optional path to receipt JSON file."},
                        "range_rules": {"type": "object", "description": "Optional mapping of key to [min, max] range constraints."},
                    },
                    "required": ["sensitive_keys"],
                },
            },
            {
                "name": "witness_arbitrate_dispute",
                "description": "Arbitrate an operational dispute against agent receipts, delegation grants, and policy rules. Generates on-chain slashing payloads.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "claim_id": {"type": "string", "description": "Unique dispute claim identifier."},
                        "challenger_id": {"type": "string", "description": "Identifier of the entity filing the dispute."},
                        "target_agent_id": {"type": "string", "description": "Identifier of the agent accused of violation."},
                        "dispute_type": {"type": "string", "enum": ["unauthorized_tool", "expired_delegation", "budget_exceeded", "ungrounded_action", "tampered_receipt", "policy_violation"], "description": "Type of disputed violation."},
                        "receipt_file": {"type": "string", "description": "Optional path to receipt JSON file under dispute."},
                        "delegation_grant": {"type": "object", "description": "Optional DelegationCapability object."},
                    },
                    "required": ["claim_id", "challenger_id", "target_agent_id", "dispute_type"],
                },
            },
        ]

    def _resolve_receipt(self, arguments: Dict[str, Any]) -> Optional[WitnessReceipt]:
        if "receipt" in arguments and isinstance(arguments["receipt"], dict):
            return WitnessReceipt(**arguments["receipt"])
        elif "receipt_file" in arguments and arguments["receipt_file"]:
            p = Path(arguments["receipt_file"])
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                return WitnessReceipt(**data)
        return self.last_receipt

    def handle_call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if tool_name == "witness_record_action":
                step_type = StepType(arguments["step_type"])
                content = str(arguments["content"])
                metadata = arguments.get("metadata") or {}
                step = self.engine.record_step(step_type=step_type, content=content, metadata=metadata)
                return {
                    "status": "recorded",
                    "step_index": step.index,
                    "step_type": step.step_type.value,
                    "timestamp": step.timestamp,
                    "current_total_steps": len(self.engine.steps),
                }

            elif tool_name == "witness_finalize_receipt":
                receipt = self.engine.finalize_receipt()
                self.last_receipt = receipt

                out_file = arguments.get("output_file")
                if out_file:
                    p = Path(out_file)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(json.dumps(receipt.to_dict(), indent=2), encoding="utf-8")

                return {
                    "status": "finalized",
                    "merkle_root": receipt.merkle_root,
                    "step_count": receipt.step_count,
                    "agent_id": receipt.agent_id,
                    "agent_pubkey": receipt.agent_pubkey,
                    "model_id": receipt.model_id,
                    "system_prompt_hash": receipt.system_prompt_hash,
                    "signature": receipt.signature,
                    "receipt": receipt.to_dict(),
                }

            elif tool_name == "witness_audit_trajectory":
                receipt = self._resolve_receipt(arguments)
                if not receipt:
                    return {"error": "No receipt available to audit. Provide receipt, receipt_file, or finalize an active session."}

                log_dir = arguments.get("log_dir")
                log_instance = TransparencyLog(log_dir=log_dir) if log_dir else None
                report = verify_trajectory_integrity(
                    receipt=receipt,
                    signer=self.signer,
                    transparency_log=log_instance,
                    expected_prompt_hash=arguments.get("expected_prompt_hash"),
                )
                return report.to_dict()

            elif tool_name == "witness_export_proof":
                step_idx = int(arguments["step_index"])
                receipt = self._resolve_receipt(arguments)
                if not receipt:
                    return {"error": "No receipt available to export proof. Finalize a session or provide receipt_file."}

                bundle = export_proof_bundle(receipt, step_idx)
                out_file = arguments.get("output_file")
                if out_file:
                    p = Path(out_file)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(json.dumps(bundle.to_dict(), indent=2), encoding="utf-8")

                return {
                    "status": "exported",
                    "step_index": step_idx,
                    "disclosed_step_index": step_idx,
                    "merkle_root": bundle.merkle_root,
                    "proof_bundle": bundle.to_dict(),
                }

            elif tool_name == "witness_verify_proof":
                bundle_data = None
                if "proof_bundle" in arguments and isinstance(arguments["proof_bundle"], dict):
                    bundle_data = arguments["proof_bundle"]
                elif "proof_file" in arguments and arguments["proof_file"]:
                    p = Path(arguments["proof_file"])
                    if p.exists():
                        bundle_data = json.loads(p.read_text(encoding="utf-8"))

                if not bundle_data:
                    return {"error": "Must provide proof_bundle or valid proof_file."}

                is_valid, reason = verify_proof_bundle(bundle_data)
                disclosed = bundle_data.get("disclosed_step", {})
                return {
                    "is_valid": is_valid,
                    "reason": reason,
                    "merkle_root": bundle_data.get("merkle_root"),
                    "disclosed_step": disclosed,
                    "disclosed_step_index": disclosed.get("index", 0),
                }

            elif tool_name == "witness_log_append":
                receipt = self._resolve_receipt(arguments)
                if not receipt:
                    return {"error": "No receipt available to append to log. Finalize a session or provide receipt_file."}

                log_dir = arguments.get("log_dir")
                log_target = TransparencyLog(log_dir=log_dir, signer=self.signer) if log_dir else self.log

                record = log_target.append_receipt(receipt)
                return {
                    "status": "appended",
                    "log_index": record.log_index,
                    "entry_hash": record.entry_hash,
                    "log_tree_size": log_target.tree_size,
                    "log_root": log_target.get_root(),
                }

            elif tool_name == "witness_log_checkpoint":
                log_dir = arguments.get("log_dir")
                log_target = TransparencyLog(log_dir=log_dir, signer=self.signer) if log_dir else self.log
                cp = log_target.create_checkpoint()
                return {
                    "status": "checkpoint_created",
                    "tree_size": cp.tree_size,
                    "log_root": cp.log_root,
                    "signer_pubkey": cp.signer_pubkey,
                    "signature": cp.signature,
                    "timestamp": cp.timestamp,
                }

            elif tool_name == "witness_log_verify_consistency":
                old_size = int(arguments["old_size"])
                new_size = arguments.get("new_size")
                proof = self.log.get_consistency_proof(old_size, new_size)
                is_consistent, reason = TransparencyLog.verify_consistency_proof(proof)
                return {
                    "is_consistent": is_consistent,
                    "reason": reason,
                    "old_size": proof.old_size,
                    "new_size": proof.new_size,
                    "old_root": proof.old_root,
                    "new_root": proof.new_root,
                }

            elif tool_name == "witness_attest_consensus":
                root = str(arguments["merkle_root"])
                agent_id = str(arguments["agent_id"])
                role = str(arguments["role"])
                verdict = str(arguments.get("verdict", "APPROVE"))
                threshold = int(arguments.get("threshold", 1))
                comments = str(arguments.get("comments", ""))

                if root not in self.active_consensus:
                    self.active_consensus[root] = MultiAgentConsensusEngine(
                        trajectory_id=f"traj_{root[:8]}",
                        merkle_root=root,
                        step_count=1,
                        threshold=threshold,
                    )

                engine = self.active_consensus[root]
                signer = AgentSigner()

                attestation = engine.add_attestation(
                    signer=signer,
                    agent_id=agent_id,
                    model_id="agent-model",
                    role=role,
                    verdict=verdict,
                    comments=comments,
                )

                consensus_receipt = engine.finalize()
                is_satisfied, report = verify_consensus_receipt(consensus_receipt, signers={agent_id: signer})

                return {
                    "status": "attestation_recorded",
                    "merkle_root": root,
                    "agent_id": agent_id,
                    "role": role,
                    "verdict": verdict,
                    "approved_count": report["approved_count"],
                    "threshold": report["threshold"],
                    "consensus_reached": is_satisfied,
                    "attestation": attestation.to_dict(),
                    "consensus_receipt": consensus_receipt.to_dict(),
                }

            elif tool_name == "witness_generate_dossier":
                receipt = self._resolve_receipt(arguments)
                if not receipt:
                    return {"error": "No receipt available to generate dossier. Finalize a session or provide receipt_file."}

                out_file = str(arguments["output_file"])
                html = render_html_report(receipt.to_dict())
                p = Path(out_file)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(html, encoding="utf-8")

                return {
                    "status": "generated",
                    "output_file": str(p.resolve()),
                    "file_size_bytes": len(html),
                    "merkle_root": receipt.merkle_root,
                    "step_count": receipt.step_count,
                }

            elif tool_name == "witness_redact_receipt":
                receipt = self._resolve_receipt(arguments)
                if not receipt:
                    return {"error": "No receipt available to redact. Finalize a session or provide receipt_file."}

                redact_steps = arguments.get("redact_steps")
                reason = arguments.get("redact_reason", "Confidential / Redacted for Privacy")
                redacted_rec = RedactionEngine.redact_receipt(receipt, redact_steps=redact_steps, redact_reason=reason)

                is_valid, msg = RedactionEngine.verify_selective_disclosure(redacted_rec)

                out_file = arguments.get("output_file")
                if out_file:
                    p = Path(out_file)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(json.dumps(redacted_rec.to_dict(), indent=2), encoding="utf-8")

                return {
                    "status": "redacted",
                    "merkle_root": redacted_rec.merkle_root,
                    "redacted_step_indices": redacted_rec.redacted_step_indices,
                    "is_cryptographically_valid": is_valid,
                    "verification_message": msg,
                    "receipt": redacted_rec.to_dict(),
                }

            elif tool_name == "witness_evaluate_policy":
                receipt = self._resolve_receipt(arguments)
                if not receipt:
                    return {"error": "No receipt available to evaluate policy. Finalize a session or provide receipt_file."}

                rules = [
                    MaxStepsRule(max_steps=int(arguments.get("max_steps", 100))),
                    DisallowedToolsRule(blacklisted_tools=arguments.get("disallowed_tools")),
                    RequiredApprovalRule(),
                    ExecutionDurationRule(),
                    StepRepetitionRule(),
                ]
                guard = PolicyGuard(rules=rules)
                report = guard.evaluate(receipt)

                return {
                    "is_compliant": report.is_compliant,
                    "verdict": report.verdict,
                    "total_violations": report.total_violations,
                    "rules_checked": report.rules_checked,
                    "violations": [v.to_dict() for v in report.violations],
                }

            elif tool_name == "witness_batch_anchor":
                files = arguments.get("receipt_files", [])
                if not files:
                    return {"error": "Must provide list of receipt_files"}

                engine = BatchAnchorEngine(epoch_id=arguments.get("epoch_id"))
                for fpath in files:
                    data = json.loads(Path(fpath).read_text(encoding="utf-8"))
                    engine.add_receipt(data)

                batch_receipt, proofs = engine.build_batch()

                out_file = arguments.get("output_file")
                if out_file:
                    p = Path(out_file)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(json.dumps(batch_receipt.to_dict(), indent=2), encoding="utf-8")

                return {
                    "status": "anchored",
                    "epoch_id": batch_receipt.epoch_id,
                    "epoch_root": batch_receipt.epoch_root,
                    "receipt_count": batch_receipt.receipt_count,
                    "evm_calldata": batch_receipt.to_evm_calldata(),
                    "solana_memo": batch_receipt.to_solana_memo(),
                    "signature": batch_receipt.signature,
                }

            elif tool_name == "witness_anchor_multichain":
                merkle_root = arguments.get("merkle_root")
                if not merkle_root:
                    rec = self._resolve_receipt(arguments)
                    if rec:
                        merkle_root = rec.merkle_root
                    else:
                        return {"error": "Must provide either merkle_root or receipt_file"}

                identifier = arguments.get("identifier", "epoch-default")
                chains = arguments.get("chains")
                threshold = int(arguments.get("quorum_threshold", 2))

                bundle = self.multichain_dispatcher.create_cross_chain_bundle(
                    merkle_root=merkle_root,
                    identifier=identifier,
                    chains=chains,
                    quorum_threshold=threshold,
                )
                return {
                    "status": "cross_chain_anchored",
                    "bundle_id": bundle.bundle_id,
                    "merkle_root": bundle.merkle_root,
                    "participating_chains": bundle.participating_chains,
                    "quorum_threshold": bundle.quorum_threshold,
                    "verified": bundle.verified,
                    "anchors": bundle.anchors,
                    "signature": bundle.signature,
                }

            elif tool_name == "witness_session_stream":
                session_id = arguments["session_id"]
                action = arguments.get("action", "append")

                if session_id not in self.active_sessions:
                    self.active_sessions[session_id] = StreamingActionSession(
                        session_id=session_id,
                        agent_id=self.agent_id,
                        signer=self.signer,
                    )
                session = self.active_sessions[session_id]

                if action == "status":
                    return session.get_session_summary()

                step_type_str = arguments.get("step_type", "thought")
                step_type = StepType(step_type_str)
                content = arguments.get("content", "")
                metadata = arguments.get("metadata") or {}

                rec = session.append_step(step_type=step_type, content=content, metadata=metadata)
                return {
                    "session_id": session_id,
                    "step_index": rec.step_index,
                    "step_type": rec.step_type,
                    "leaf_hash": rec.leaf_hash,
                    "rolling_merkle_root": rec.rolling_merkle_root,
                    "time_delta_ms": rec.time_delta_ms,
                    "total_steps": len(session.steps),
                    "signature": rec.signature,
                }

            elif tool_name == "witness_audit_compliance":
                receipt = self._resolve_receipt(arguments)
                if not receipt:
                    return {"error": "No receipt available to audit. Finalize a session or provide receipt_file."}

                vel = float(arguments.get("max_velocity_per_min", 60.0))
                val_cap = float(arguments.get("max_cumulative_value", 10000.0))
                expected_auth = arguments.get("expected_authority")

                detector = ComplianceAnomalyDetector(
                    max_velocity_per_min=vel,
                    max_cumulative_value=val_cap,
                    signer=self.signer,
                )
                report = detector.audit_receipt(receipt, expected_authority=expected_auth)

                return {
                    "report_id": report.report_id,
                    "is_compliant": report.is_compliant,
                    "risk_score": report.risk_score,
                    "total_steps_checked": report.total_steps_checked,
                    "cumulative_value_tracked": report.cumulative_value_tracked,
                    "incidents_count": len(report.incidents),
                    "incidents": [inc.to_dict() for inc in report.incidents],
                    "signature": report.signature,
                }

            elif tool_name == "witness_issue_credential":
                agent_id = arguments.get("agent_id")
                agent_pubkey = arguments.get("agent_pubkey") or self.signer.pubkey_hex
                roles = arguments.get("roles")
                capabilities = arguments.get("capabilities")
                allowed_models = arguments.get("allowed_models")
                max_fin = float(arguments.get("max_financial_limit", 1000.0))
                sponsor = arguments.get("sponsor_identity", "org.devsoniclk.sponsor")
                valid_days = int(arguments.get("validity_days", 30))

                cred = self.credential_engine.issue_credential(
                    agent_id=agent_id,
                    agent_pubkey=agent_pubkey,
                    roles=roles,
                    capabilities=capabilities,
                    allowed_models=allowed_models,
                    max_financial_limit=max_fin,
                    sponsor_identity=sponsor,
                    validity_days=valid_days,
                )
                return {
                    "status": "success",
                    "credential": cred.to_dict(),
                    "credential_id": cred.id,
                    "issuer_did": cred.issuer,
                    "agent_did": cred.credential_subject.id,
                }

            elif tool_name == "witness_verify_credential":
                raw_cred = arguments.get("credential", {})
                trusted_issuer = arguments.get("trusted_issuer_did")
                report = self.credential_engine.verify_credential(
                    raw_cred,
                    trusted_issuer_did=trusted_issuer,
                )
                return report.to_dict()

            elif tool_name == "witness_generate_zk_attestation":
                receipt = self._resolve_receipt(arguments)
                if not receipt:
                    return {"error": "No receipt available. Finalize a session or provide receipt_file."}

                constraints = ZKConstraintSet(
                    max_steps=arguments.get("max_steps"),
                    max_duration_ms=arguments.get("max_duration_ms"),
                    allowed_tools=arguments.get("allowed_tools"),
                    allowed_models=arguments.get("allowed_models"),
                    max_financial_spend=arguments.get("max_financial_spend"),
                )
                proof = self.zk_engine.generate_attestation(receipt, constraints)
                return {
                    "status": "success",
                    "proof": proof.to_dict(),
                    "proof_id": proof.proof_id,
                    "merkle_root": proof.receipt_merkle_root,
                    "fiat_shamir_challenge": proof.fiat_shamir_challenge,
                }

            elif tool_name == "witness_verify_zk_attestation":
                proof_data = arguments.get("proof", {})
                claimed = ZKConstraintSet(
                    max_steps=arguments.get("max_steps"),
                    max_duration_ms=arguments.get("max_duration_ms"),
                    allowed_tools=arguments.get("allowed_tools"),
                    allowed_models=arguments.get("allowed_models"),
                    max_financial_spend=arguments.get("max_financial_spend"),
                )
                expected_root = arguments.get("expected_merkle_root")
                report = self.zk_engine.verify_attestation(proof_data, claimed, expected_merkle_root=expected_root)
                return report.to_dict()

            elif tool_name == "witness_check_revocation":
                target = arguments.get("target_identifier")
                if not target:
                    return {"error": "target_identifier is required"}

                revoke_now = arguments.get("revoke_now", False)
                if revoke_now:
                    reason = arguments.get("reason", RevocationReason.OPERATOR_KILL_SWITCH)
                    target_type = arguments.get("target_type", "AGENT_PUBKEY")
                    entry = self.revocation_registry.revoke(
                        target_identifier=target,
                        target_type=target_type,
                        reason=reason,
                    )
                    return {
                        "status": "revoked",
                        "revocation_entry": entry.to_dict(),
                        "revocation_root": self.revocation_registry.get_revocation_root(),
                    }

                is_rev, entry = self.revocation_registry.is_revoked(target)
                attestation = self.revocation_registry.attest_non_revocation(target)
                return {
                    "target_identifier": target,
                    "is_revoked": is_rev,
                    "revocation_entry": entry.to_dict() if entry else None,
                    "non_revocation_attestation": attestation.to_dict(),
                    "revocation_root": self.revocation_registry.get_revocation_root(),
                }

            elif tool_name == "witness_delegate_capability":
                child_id = arguments["child_agent_id"]
                child_pk = arguments["child_pubkey"]
                scope = arguments["scope"]
                exp = float(arguments.get("expires_in_seconds", 3600.0))
                max_b = float(arguments["max_budget_usd"]) if "max_budget_usd" in arguments and arguments["max_budget_usd"] is not None else None
                meta = arguments.get("metadata")

                grant = create_delegation_grant(
                    parent_signer=self.signer,
                    parent_agent_id=self.agent_id,
                    child_agent_id=child_id,
                    child_pubkey=child_pk,
                    scope=scope,
                    expires_in_seconds=exp,
                    max_budget_usd=max_b,
                    metadata=meta,
                )
                return {
                    "status": "success",
                    "grant": grant.to_dict(),
                    "grant_id": grant.grant_id,
                    "parent_pubkey": grant.parent_pubkey,
                    "signature": grant.parent_signature,
                }

            elif tool_name == "witness_verify_delegation_dag":
                root_id = arguments["root_agent_id"]
                raw_grants = arguments["grants"]
                grants = [DelegationCapability.from_dict(g) for g in raw_grants]
                receipts = None
                receipt = self._resolve_receipt(arguments)
                if receipt:
                    receipts = [receipt]

                report = DelegationDAGVerifier.verify_lineage(
                    root_agent_id=root_id,
                    grants=grants,
                    action_receipts=receipts,
                    parent_signers={self.agent_id: self.signer},
                )
                return report.to_dict()

            elif tool_name == "witness_blind_receipt":
                receipt = self._resolve_receipt(arguments)
                if not receipt:
                    return {"error": "No receipt available. Finalize a session or provide receipt_file."}
                sensitive_keys = arguments["sensitive_keys"]
                raw_rules = arguments.get("range_rules") or {}
                range_rules = {k: (float(v[0]), float(v[1])) for k, v in raw_rules.items()}
                blinded, private_salts = BlindedAttestationEngine.blind_receipt(
                    receipt=receipt,
                    sensitive_keys=sensitive_keys,
                    range_rules=range_rules,
                )
                return {
                    "status": "success",
                    "blinded_receipt": blinded.to_dict(),
                    "commitments_count": len(blinded.commitments),
                    "range_proofs_count": len(blinded.range_proofs),
                    "merkle_root": blinded.merkle_root,
                    "private_salts": private_salts,
                }

            elif tool_name == "witness_arbitrate_dispute":
                receipt = self._resolve_receipt(arguments)
                if not receipt:
                    return {"error": "No receipt available. Finalize a session or provide receipt_file."}
                claim_id = arguments["claim_id"]
                challenger_id = arguments["challenger_id"]
                target_agent_id = arguments["target_agent_id"]
                dispute_type_str = arguments["dispute_type"]
                dtype = DisputeType(dispute_type_str)
                raw_grant = arguments.get("delegation_grant")
                grant = DelegationCapability.from_dict(raw_grant) if raw_grant else None

                claim = DisputeClaim(
                    claim_id=claim_id,
                    challenger_id=challenger_id,
                    target_agent_id=target_agent_id,
                    receipt=receipt,
                    dispute_type=dtype,
                )
                res = ArbitrationEngine.arbitrate(claim, delegation_grant=grant)
                return res.to_dict()

            else:
                return {"error": f"Unknown tool: {tool_name}"}

        except Exception as e:
            return {"error": str(e)}

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": self.PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "agent-witness-mcp",
                        "version": "0.7.0",
                    },
                },
            }

        elif method == "notifications/initialized":
            return None

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": self.get_tool_definitions(),
                },
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            res = self.handle_call_tool(tool_name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(res, indent=2),
                        }
                    ]
                },
            }

        elif method == "ping":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {},
            }

        else:
            if req_id is not None:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}",
                    },
                }
            return None

    def run_stdio(self) -> None:
        """Run MCP JSON-RPC 2.0 loop reading lines from stdin and emitting to stdout."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                if resp:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
