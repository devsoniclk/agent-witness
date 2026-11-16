from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

from .consensus import MultiAgentConsensusEngine, verify_consensus_receipt
from .html_report import render_html_report
from .log import TransparencyLog
from .mcp_server import WitnessMCPServer
from .models import AgentAttestation, ConsensusReceipt, DeliberationStep, ProofBundle, StepType, WitnessReceipt
from .proof import export_proof_bundle, verify_proof_bundle
from .receipt import WitnessEngine
from .signer import AgentSigner
from .verifier import verify_trajectory_integrity


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agent-witness",
        description="Cryptographic action attestation & Merkle receipt inspector for AI agents.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # inspect
    p_ins = subparsers.add_parser("inspect", help="Inspect a .witness receipt JSON file.")
    p_ins.add_argument("receipt_file", help="Path to .witness or JSON receipt file.")
    p_ins.add_argument("--html", "-o", help="Optional output path to generate an interactive HTML dossier.")

    # report
    p_rep = subparsers.add_parser("report", help="Generate an interactive dark-mode HTML dossier.")
    p_rep.add_argument("receipt_file", help="Path to receipt or proof file.")
    p_rep.add_argument("--html", "-o", required=True, help="Destination HTML report file path.")

    # verify
    p_ver = subparsers.add_parser("verify", help="Verify Merkle root integrity of a receipt.")
    p_ver.add_argument("receipt_file", help="Path to .witness or JSON receipt file.")

    # audit (v0.4.0)
    p_aud = subparsers.add_parser("audit", help="Run comprehensive multi-layer forensic audit on a receipt.")
    p_aud.add_argument("receipt_file", help="Path to .witness or JSON receipt file.")
    p_aud.add_argument("--log-dir", help="Optional transparency log directory to audit inclusion against.")
    p_aud.add_argument("--consensus", help="Optional consensus receipt file to audit quorum against.")
    p_aud.add_argument("--prompt-hash", help="Optional expected system prompt SHA-256 hash.")
    p_aud.add_argument("--json", action="store_true", help="Output audit report as JSON.")
    p_aud.add_argument("--html", help="Optional output path to generate an interactive HTML dossier.")

    # mcp (v0.4.0)
    p_mcp = subparsers.add_parser("mcp", help="Run JSON-RPC 2.0 stdio Model Context Protocol (MCP) server.")
    p_mcp.add_argument("--log-dir", default=".witness_log", help="Transparency log directory (default: .witness_log).")
    p_mcp.add_argument("--agent-id", default="agent-mcp-witness", help="Agent identifier.")
    p_mcp.add_argument("--model-id", default="openbot-v1", help="Model identifier.")

    # export-proof
    p_exp = subparsers.add_parser("export-proof", help="Export selective disclosure proof for a single step.")
    p_exp.add_argument("receipt_file", help="Path to .witness or JSON receipt file.")
    p_exp.add_argument("--step", type=int, required=True, help="Step index to disclose.")
    p_exp.add_argument("--output", "-o", help="Optional output path for the proof JSON bundle.")

    # verify-proof
    p_vpr = subparsers.add_parser("verify-proof", help="Verify a standalone selective disclosure proof bundle.")
    p_vpr.add_argument("proof_file", help="Path to proof bundle JSON file.")

    # consensus
    p_con = subparsers.add_parser("consensus", help="Multi-agent threshold consensus audit commands.")
    con_sub = p_con.add_subparsers(dest="con_command", required=True)
    p_cv = con_sub.add_parser("verify", help="Verify a multi-agent consensus receipt.")
    p_cv.add_argument("consensus_file", help="Path to consensus receipt JSON file.")

    # log
    p_log = subparsers.add_parser("log", help="Tamper-evident chronological transparency log commands.")
    log_sub = p_log.add_subparsers(dest="log_command", required=True)

    p_la = log_sub.add_parser("append", help="Append a receipt to transparency log.")
    p_la.add_argument("receipt_file", help="Path to .witness receipt file.")
    p_la.add_argument("--log-dir", default=".witness_log", help="Transparency log directory (default: .witness_log).")

    p_ls = log_sub.add_parser("status", help="Show transparency log status and Signed Tree Head.")
    p_ls.add_argument("--log-dir", default=".witness_log", help="Transparency log directory (default: .witness_log).")

    p_lc = log_sub.add_parser("checkpoint", help="Generate a signed log checkpoint (STH).")
    p_lc.add_argument("--log-dir", default=".witness_log", help="Transparency log directory (default: .witness_log).")

    args = parser.parse_args()

    if args.command == "inspect":
        with open(args.receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        receipt = WitnessReceipt(**data)
        print("==================================================================")
        print(" AGENT WITNESS CRYPTOGRAPHIC RECEIPT")
        print("==================================================================")
        print(f"Version:            {receipt.version}")
        print(f"Agent ID:           {receipt.agent_id}")
        print(f"Agent Pubkey:       {receipt.agent_pubkey[:16]}...")
        print(f"Model ID:           {receipt.model_id}")
        print(f"Prompt Hash:        {receipt.system_prompt_hash[:16]}...")
        print(f"Merkle Root:        {receipt.merkle_root}")
        print(f"Step Count:         {receipt.step_count}")
        print(f"Attestation Sig:    {receipt.signature[:24]}...")
        print("\n[Attested Deliberation Steps]")
        for s in receipt.steps:
            print(f"  #{s['index']:02d} [{s['type'].upper()}]: {s['content']}")
        print("==================================================================")

        if args.html:
            html = render_html_report(receipt, output_file=args.html)
            print(f"Interactive HTML dossier generated: {args.html}")

    elif args.command == "report":
        with open(args.receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        html = render_html_report(data, output_file=args.html)
        print(f"Interactive HTML dossier generated: {args.html}")

    elif args.command == "verify":
        with open(args.receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        receipt = WitnessReceipt(**data)
        report = verify_trajectory_integrity(receipt)
        if report.is_valid:
            print("==================================================================")
            print(" VERIFICATION SUCCESSFUL")
            print("==================================================================")
            print(f"VERIFIED: Merkle root {receipt.merkle_root} matches all {receipt.step_count} deliberation steps.")
            print("==================================================================")
        else:
            print("==================================================================")
            print(" VERIFICATION FAILED: INTEGRITY TAMPER DETECTED")
            print("==================================================================")
            print(report.summary)
            sys.exit(1)

    elif args.command == "audit":
        with open(args.receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        receipt = WitnessReceipt(**data)

        log_inst = TransparencyLog(log_dir=args.log_dir) if args.log_dir else None
        con_receipt = None
        if args.consensus:
            with open(args.consensus, "r", encoding="utf-8") as f:
                con_receipt = json.load(f)

        report = verify_trajectory_integrity(
            receipt=receipt,
            transparency_log=log_inst,
            consensus_receipt=con_receipt,
            expected_prompt_hash=args.prompt_hash,
        )

        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(report.to_text())

        if args.html:
            html = render_html_report(receipt.to_dict())
            Path(args.html).write_text(html, encoding="utf-8")
            print(f"\nInteractive HTML dossier exported to: {args.html}")

        if not report.is_valid:
            sys.exit(1)

    elif args.command == "mcp":
        server = WitnessMCPServer(
            agent_id=args.agent_id,
            model_id=args.model_id,
            log_dir=args.log_dir,
        )
        server.run_stdio()

    elif args.command == "export-proof":
        with open(args.receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        receipt = WitnessReceipt(**data)
        bundle = export_proof_bundle(receipt, args.step)
        bundle_json = json.dumps(bundle.to_dict(), indent=2)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(bundle_json)
            print(f"Selective disclosure proof exported to {args.output} (Step #{args.step})")
        else:
            print(bundle_json)

    elif args.command == "verify-proof":
        with open(args.proof_file, "r", encoding="utf-8") as f:
            bundle_data = json.load(f)

        is_valid, reason = verify_proof_bundle(bundle_data)
        if is_valid:
            print("==================================================================")
            print(" PROOF VERIFICATION: SUCCESS")
            print("==================================================================")
            print(reason)
            print(f"Disclosed Step:     #{bundle_data['disclosed_step']['index']} [{bundle_data['disclosed_step']['type'].upper()}]")
            print(f"Step Content:       {bundle_data['disclosed_step']['content']}")
            print(f"Merkle Root:        {bundle_data['merkle_root']}")
            print(f"Audit Path Length:  {len(bundle_data['merkle_proof']['audit_path'])}")
            print("==================================================================")
        else:
            print(f"PROOF VERIFICATION FAILED: {reason}")
            sys.exit(1)

    elif args.command == "consensus":
        if args.con_command == "verify":
            with open(args.consensus_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            rec = ConsensusReceipt(
                version=data["version"],
                trajectory_id=data["trajectory_id"],
                merkle_root=data["merkle_root"],
                step_count=data["step_count"],
                threshold=data["threshold"],
                attestations=[AgentAttestation(**a) for a in data["attestations"]],
                timestamp=data.get("timestamp", 0.0),
            )
            is_valid, report = verify_consensus_receipt(rec)
            print("==================================================================")
            print(" MULTI-AGENT CONSENSUS VERIFICATION")
            print("==================================================================")
            print(f"Trajectory ID:      {report['trajectory_id']}")
            print(f"Merkle Root:        {report['merkle_root']}")
            print(f"Threshold Quorum:   {report['threshold']} of {report['total_attestations']}")
            print(f"Approved Votes:     {report['approved_count']}")
            print(f"Consensus Reached:  {'YES - VALID' if is_valid else 'NO - FAILED'}")
            print("\n[Agent Attestations]")
            for a in report["attestations"]:
                print(f"  • {a['agent_id']} ({a['role']}) -> {a['verdict']} [sig_valid={a['signature_valid']}]")
            print("==================================================================")
            if not is_valid:
                sys.exit(1)

    elif args.command == "log":
        log = TransparencyLog(log_dir=args.log_dir)

        if args.log_command == "append":
            with open(args.receipt_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            receipt = WitnessReceipt(**data)
            record = log.append_receipt(receipt)
            print(f"Receipt appended to transparency log at index #{record.log_index}")
            print(f"Log Size: {log.tree_size} | Entry Hash: {record.entry_hash}")
            print(f"Current Log Root: {log.get_root()}")

        elif args.log_command == "status":
            print("==================================================================")
            print(" TRANSPARENCY LOG STATUS")
            print("==================================================================")
            print(f"Log Directory:      {args.log_dir}")
            print(f"Total Entries:      {log.tree_size}")
            if log.tree_size > 0:
                print(f"Log Merkle Root:    {log.get_root()}")
                last = log.entries[-1]
                print(f"Latest Receipt ID:  {last.receipt_id}")
                print(f"Latest Timestamp:   {last.timestamp}")
            print("==================================================================")

        elif args.log_command == "checkpoint":
            cp = log.create_checkpoint()
            print("==================================================================")
            print(" SIGNED LOG CHECKPOINT (STH)")
            print("==================================================================")
            print(f"Tree Size:          {cp.tree_size}")
            print(f"Log Root:           {cp.log_root}")
            print(f"Signer Pubkey:      {cp.signer_pubkey}")
            print(f"Signature:          {cp.signature}")
            print("==================================================================")


if __name__ == "__main__":
    main()
