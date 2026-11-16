from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

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
from .proof import export_proof_bundle, verify_proof_bundle
from .receipt import WitnessEngine
from .signer import AgentSigner
from .verifier import verify_trajectory_integrity


class WitnessMCPServer:
    """
    Standard-compliant Model Context Protocol (MCP) stdio server for agent-witness.
    Provides cryptographic action attestation, Merkle audit trees, transparency logging,
    selective disclosure proofs, and multi-agent consensus to AI agents (OpenBot, Claude, Cursor).
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
                    },
                },
            },
            {
                "name": "witness_export_proof",
                "description": "Export a selective disclosure proof bundle for a single action step without disclosing other private agent thoughts or tool parameters.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "step_index": {
                            "type": "integer",
                            "description": "Zero-based step index to selectively disclose.",
                        },
                        "output_file": {
                            "type": "string",
                            "description": "Optional file path to write the standalone ProofBundle JSON.",
                        },
                    },
                    "required": ["step_index"],
                },
            },
            {
                "name": "witness_verify_proof",
                "description": "Cryptographically verify a standalone selective disclosure ProofBundle against its Merkle root without exposing unrevealed steps.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "proof": {
                            "type": "object",
                            "description": "ProofBundle dictionary.",
                        },
                        "proof_file": {
                            "type": "string",
                            "description": "Path to ProofBundle JSON file.",
                        },
                    },
                },
            },
            {
                "name": "witness_log_append",
                "description": "Append a finalized WitnessReceipt to the persistent append-only Chronological Transparency Log.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "receipt_file": {
                            "type": "string",
                            "description": "Optional path to receipt JSON file. If omitted, appends the last finalized receipt.",
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
                            "description": "The Merkle root of the trajectory being attested.",
                        },
                        "agent_id": {
                            "type": "string",
                            "description": "Identifier of the attesting agent (e.g., 'security-auditor-1').",
                        },
                        "role": {
                            "type": "string",
                            "description": "Role of the attesting agent (e.g., 'SecurityGuard', 'Verifier', 'RiskGovernor').",
                        },
                        "verdict": {
                            "type": "string",
                            "enum": ["APPROVE", "REJECT"],
                            "default": "APPROVE",
                        },
                        "threshold": {
                            "type": "integer",
                            "description": "M-of-N threshold required to finalize consensus.",
                            "default": 1,
                        },
                        "comments": {
                            "type": "string",
                            "description": "Optional auditor comments or evaluation reason.",
                        },
                    },
                    "required": ["merkle_root", "agent_id", "role"],
                },
            },
            {
                "name": "witness_generate_dossier",
                "description": "Generate an interactive, dark-mode standalone HTML audit dossier with embedded responsive SVG Merkle tree and audit tables.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "output_file": {
                            "type": "string",
                            "description": "Destination file path for the generated HTML dossier.",
                        },
                        "receipt_file": {
                            "type": "string",
                            "description": "Optional receipt file path. If omitted, renders the last finalized receipt.",
                        },
                    },
                    "required": ["output_file"],
                },
            },
        ]

    def _resolve_receipt(self, args: Dict[str, Any]) -> Optional[WitnessReceipt]:
        if "receipt" in args and isinstance(args["receipt"], dict):
            return WitnessReceipt(**args["receipt"])
        if "receipt_file" in args and args["receipt_file"]:
            p = Path(args["receipt_file"])
            if p.exists():
                with open(p, "r", encoding="utf-8") as f:
                    return WitnessReceipt(**json.load(f))
        return self.last_receipt

    def handle_call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if tool_name == "witness_record_action":
                st = StepType(arguments["step_type"])
                content = str(arguments["content"])
                meta = arguments.get("metadata", {})
                step = self.engine.record_step(st, content, meta)
                return {
                    "status": "recorded",
                    "step_index": step.index,
                    "step_type": step.step_type.value,
                    "timestamp": step.timestamp,
                    "current_step_count": len(self.engine.steps),
                }

            elif tool_name == "witness_finalize_receipt":
                receipt = self.engine.finalize_receipt()
                self.last_receipt = receipt

                out_file = arguments.get("output_file")
                if out_file:
                    p = Path(out_file)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    with open(p, "w", encoding="utf-8") as f:
                        json.dump(receipt.to_dict(), f, indent=2)

                return {
                    "status": "finalized",
                    "merkle_root": receipt.merkle_root,
                    "step_count": receipt.step_count,
                    "signature": receipt.signature,
                    "agent_pubkey": receipt.agent_pubkey,
                    "receipt": receipt.to_dict(),
                    "output_file": out_file,
                }

            elif tool_name == "witness_audit_trajectory":
                receipt = self._resolve_receipt(arguments)
                if not receipt:
                    return {"error": "No receipt available to audit. Provide receipt, receipt_file, or finalize an active session."}

                log_dir = arguments.get("log_dir")
                log_instance = TransparencyLog(log_dir=log_dir) if log_dir else None
                report = verify_trajectory_integrity(receipt, signer=self.signer, transparency_log=log_instance)
                return report.to_dict()

            elif tool_name == "witness_export_proof":
                step_idx = int(arguments["step_index"])
                receipt = self._resolve_receipt(arguments)
                if not receipt:
                    return {"error": "No receipt available. Finalize a session or provide receipt_file."}

                bundle = export_proof_bundle(receipt, step_idx)
                out_file = arguments.get("output_file")
                if out_file:
                    p = Path(out_file)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    with open(p, "w", encoding="utf-8") as f:
                        json.dump(bundle.to_dict(), f, indent=2)

                return {
                    "status": "exported",
                    "step_index": step_idx,
                    "merkle_root": bundle.merkle_root,
                    "proof_bundle": bundle.to_dict(),
                    "output_file": out_file,
                }

            elif tool_name == "witness_verify_proof":
                proof_data = arguments.get("proof")
                if not proof_data and "proof_file" in arguments:
                    p = Path(arguments["proof_file"])
                    if p.exists():
                        with open(p, "r", encoding="utf-8") as f:
                            proof_data = json.load(f)
                if not proof_data:
                    return {"error": "Missing proof dictionary or valid proof_file."}

                is_valid, reason = verify_proof_bundle(proof_data, signer=self.signer)
                return {
                    "is_valid": is_valid,
                    "reason": reason,
                    "merkle_root": proof_data.get("merkle_root"),
                    "disclosed_step_index": proof_data.get("disclosed_step", {}).get("index"),
                }

            elif tool_name == "witness_log_append":
                receipt = self._resolve_receipt(arguments)
                if not receipt:
                    return {"error": "No receipt available to append."}

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
                        trajectory_id=f"traj-{root[:12]}",
                        merkle_root=root,
                        step_count=len(self.engine.steps),
                        threshold=threshold,
                    )
                engine = self.active_consensus[root]
                engine.threshold = threshold

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
                        "version": "0.4.0",
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
