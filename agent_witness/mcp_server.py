from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .batch_anchor import BatchAnchorEngine, EpochBatchReceipt
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
from .signer import AgentSigner
from .verifier import verify_trajectory_integrity


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
                        "version": "0.5.0",
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
