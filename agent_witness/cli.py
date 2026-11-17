from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

from .batch_anchor import BatchAnchorEngine
from .blinded import BlindedAttestationEngine, BlindedReceipt
from .compliance import ComplianceAnomalyDetector
from .consensus import MultiAgentConsensusEngine, verify_consensus_receipt
from .credentials import AgentCredentialEngine, VerifiableAgentCredential, pubkey_to_did_key
from .delegation import DelegationCapability, DelegationDAGVerifier, create_delegation_grant
from .dispute import ArbitrationEngine, DisputeClaim, DisputeType
from .html_report import render_html_report
from .log import TransparencyLog
from .mcp_server import WitnessMCPServer
from .models import AgentAttestation, ConsensusReceipt, DeliberationStep, ProofBundle, StepType, WitnessReceipt
from .multichain import MultiChainAnchorDispatcher
from .policy import (
    DisallowedToolsRule,
    ExecutionDurationRule,
    MaxStepsRule,
    ModelWhitelistRule,
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

    # redact (v0.5.0)
    p_red = subparsers.add_parser("redact", help="Selectively redact confidential steps while preserving cryptographic Merkle root.")
    p_red.add_argument("receipt_file", help="Path to .witness or JSON receipt file.")
    p_red.add_argument("--steps", "-s", help="Comma-separated list of step indices to redact (e.g. 1,3,4).")
    p_red.add_argument("--reason", default="Confidential / Redacted for Privacy", help="Redaction label.")
    p_red.add_argument("--output", "-o", required=True, help="Output JSON path for redacted receipt.")

    # policy (v0.5.0)
    p_pol = subparsers.add_parser("policy", help="Audit receipt against enterprise governance and safety policies.")
    p_pol.add_argument("receipt_file", help="Path to .witness or JSON receipt file.")
    p_pol.add_argument("--max-steps", type=int, default=100, help="Max allowed steps.")
    p_pol.add_argument("--disallowed-tools", help="Comma-separated list of prohibited tools.")
    p_pol.add_argument("--allowed-models", help="Comma-separated list of allowed model IDs.")
    p_pol.add_argument("--json", action="store_true", help="Output policy report as JSON.")

    # batch-anchor (v0.5.0)
    p_anc = subparsers.add_parser("batch-anchor", help="Batch multiple receipts into an aggregated Epoch Merkle Root.")
    p_anc.add_argument("receipt_files", nargs="+", help="Paths to receipt JSON files.")
    p_anc.add_argument("--epoch-id", help="Optional epoch batch identifier.")
    p_anc.add_argument("--output", "-o", help="Optional output path to save batch receipt.")
    p_anc.add_argument("--evm", action="store_true", help="Display EVM calldata.")
    p_anc.add_argument("--solana", action="store_true", help="Display Solana SPL memo payload.")

    # multichain-anchor (v0.6.0)
    p_mc = subparsers.add_parser("multichain-anchor", help="Generate cross-chain anchor payloads across Solana and EVM.")
    p_mc.add_argument("receipt_file", help="Path to .witness or JSON receipt file.")
    p_mc.add_argument("--chains", default="solana,base,arbitrum", help="Comma-separated chain list.")
    p_mc.add_argument("--quorum", type=int, default=2, help="Threshold quorum required.")
    p_mc.add_argument("--output", "-o", help="Optional output path to save attestation bundle.")
    p_mc.add_argument("--json", action="store_true", help="Output bundle as JSON.")

    # compliance (v0.6.0)
    p_comp = subparsers.add_parser("compliance", help="Evaluate velocity, risk cap, and temporal compliance anomalies.")
    p_comp.add_argument("receipt_file", help="Path to .witness or JSON receipt file.")
    p_comp.add_argument("--max-velocity", type=float, default=60.0, help="Max steps per minute.")
    p_comp.add_argument("--max-value", type=float, default=10000.0, help="Max cumulative financial value.")
    p_comp.add_argument("--expected-authority", help="Expected agent authority identifier or pubkey.")
    p_comp.add_argument("--json", action="store_true", help="Output compliance report as JSON.")

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

    # credential
    p_cred = subparsers.add_parser("credential", help="W3C Verifiable Agent Credential operations.")
    cred_sub = p_cred.add_subparsers(dest="cred_command", required=True)

    p_ci = cred_sub.add_parser("issue", help="Issue a signed Verifiable Agent Credential.")
    p_ci.add_argument("--agent-id", required=True, help="Agent identifier.")
    p_ci.add_argument("--agent-pubkey", help="Agent public key in hex (defaults to new derived key).")
    p_ci.add_argument("--roles", help="Comma-separated role strings.")
    p_ci.add_argument("--capabilities", help="Comma-separated capability or tool strings.")
    p_ci.add_argument("--allowed-models", help="Comma-separated allowed model identifiers.")
    p_ci.add_argument("--max-financial-limit", type=float, default=1000.0, help="Maximum financial spend limit.")
    p_ci.add_argument("--sponsor", default="org.devsoniclk.sponsor", help="Sponsor identity.")
    p_ci.add_argument("--validity-days", type=int, default=30, help="Validity period in days.")
    p_ci.add_argument("-o", "--output", help="Output file path for issued credential JSON.")

    p_cv = cred_sub.add_parser("verify", help="Verify a Verifiable Agent Credential.")
    p_cv.add_argument("credential_file", help="Path to credential JSON file.")
    p_cv.add_argument("--trusted-issuer-did", help="Optional expected issuer DID.")
    p_cv.add_argument("--json", action="store_true", help="Output verification report in JSON format.")

    # zk
    p_zk = subparsers.add_parser("zk", help="Zero-Knowledge action constraint attestation commands.")
    zk_sub = p_zk.add_subparsers(dest="zk_command", required=True)

    p_zp = zk_sub.add_parser("prove", help="Generate a zero-knowledge attestation proof for a receipt.")
    p_zp.add_argument("receipt_file", help="Path to receipt JSON file.")
    p_zp.add_argument("--max-steps", type=int, help="Maximum steps constraint.")
    p_zp.add_argument("--max-duration-ms", type=float, help="Maximum duration ms constraint.")
    p_zp.add_argument("--allowed-tools", help="Comma-separated whitelist of allowed tools.")
    p_zp.add_argument("--allowed-models", help="Comma-separated whitelist of allowed models.")
    p_zp.add_argument("--max-spend", type=float, help="Maximum financial spend limit.")
    p_zp.add_argument("-o", "--output", help="Output file path for generated ZK proof JSON.")

    p_zv = zk_sub.add_parser("verify", help="Verify a zero-knowledge attestation proof.")
    p_zv.add_argument("proof_file", help="Path to ZK proof JSON file.")
    p_zv.add_argument("--max-steps", type=int, help="Claimed max steps.")
    p_zv.add_argument("--max-duration-ms", type=float, help="Claimed max duration ms.")
    p_zv.add_argument("--allowed-tools", help="Comma-separated claimed allowed tools.")
    p_zv.add_argument("--allowed-models", help="Comma-separated claimed allowed models.")
    p_zv.add_argument("--max-spend", type=float, help="Claimed max spend.")
    p_zv.add_argument("--root", help="Expected receipt Merkle root.")
    p_zv.add_argument("--json", action="store_true", help="Output verification report in JSON format.")

    # revocation
    p_rev = subparsers.add_parser("revocation", help="Cryptographic revocation registry operations.")
    rev_sub = p_rev.add_subparsers(dest="rev_command", required=True)

    p_rr = rev_sub.add_parser("revoke", help="Publish a signed revocation notice.")
    p_rr.add_argument("target_identifier", help="Agent pubkey, credential ID, or session ID.")
    p_rr.add_argument("--type", default="AGENT_PUBKEY", choices=["AGENT_PUBKEY", "CREDENTIAL_ID", "SESSION_ID"], help="Target type.")
    p_rr.add_argument("--reason", default="OPERATOR_KILL_SWITCH", help="Revocation reason code.")
    p_rr.add_argument("--registry-file", default=".witness_revocations.json", help="Path to revocation registry file.")

    p_rc = rev_sub.add_parser("check", help="Check revocation status and generate non-revocation attestation.")
    p_rc.add_argument("target_identifier", help="Target identifier to check.")
    p_rc.add_argument("--registry-file", default=".witness_revocations.json", help="Path to revocation registry file.")
    p_rc.add_argument("--json", action="store_true", help="Output report in JSON format.")

    # delegate
    p_del = subparsers.add_parser("delegate", help="Hierarchical subagent delegation capabilities.")
    del_sub = p_del.add_subparsers(dest="del_command", required=True)

    p_dg = del_sub.add_parser("grant", help="Issue a signed capability grant to a subagent.")
    p_dg.add_argument("child_agent_id", help="Target child agent identifier.")
    p_dg.add_argument("child_pubkey", help="Target child agent public key in hex.")
    p_dg.add_argument("--scope", default="*", help="Comma-separated allowed tools (or * for all).")
    p_dg.add_argument("--expires", type=float, default=3600.0, help="Expiration in seconds.")
    p_dg.add_argument("--budget", type=float, help="Optional financial spend cap USD.")
    p_dg.add_argument("-o", "--output", help="Optional output path for grant JSON.")
    p_dg.add_argument("--json", action="store_true", help="Output grant as JSON.")

    p_dv = del_sub.add_parser("verify", help="Verify a delegation DAG lineage.")
    p_dv.add_argument("grants_file", help="Path to JSON file containing list of grants.")
    p_dv.add_argument("--root", required=True, help="Expected root orchestrator agent ID.")
    p_dv.add_argument("--receipt-file", help="Optional receipt file to verify compliance.")
    p_dv.add_argument("--json", action="store_true", help="Output verification report as JSON.")

    # blind
    p_bl = subparsers.add_parser("blind", help="Mask sensitive fields with commitments and range proofs.")
    p_bl.add_argument("receipt_file", help="Path to .witness or JSON receipt file.")
    p_bl.add_argument("--keys", required=True, help="Comma-separated sensitive keys to blind.")
    p_bl.add_argument("-o", "--output", help="Optional output path for blinded receipt JSON.")
    p_bl.add_argument("--json", action="store_true", help="Output blinded receipt as JSON.")

    # dispute
    p_disp = subparsers.add_parser("dispute", help="Arbitrate agent disputes and generate slashing payloads.")
    p_disp.add_argument("receipt_file", help="Path to disputed .witness receipt JSON.")
    p_disp.add_argument("--claim-id", default="dispute_auto_001", help="Dispute claim identifier.")
    p_disp.add_argument("--challenger", default="challenger_001", help="Challenger entity identifier.")
    p_disp.add_argument("--target", required=True, help="Accused agent identifier.")
    p_disp.add_argument("--type", required=True, choices=["unauthorized_tool", "expired_delegation", "budget_exceeded", "ungrounded_action", "tampered_receipt", "policy_violation"], help="Dispute violation type.")
    p_disp.add_argument("--grant-file", help="Optional delegation grant JSON file.")
    p_disp.add_argument("--json", action="store_true", help="Output dispute resolution as JSON.")

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
        print(f"Deliberation Steps: {receipt.step_count}")
        print(f"Merkle Action Root: {receipt.merkle_root}")
        print(f"Signature:          {receipt.signature[:32]}...")
        print("------------------------------------------------------------------")
        print(f"{'Idx':<4} {'Type':<12} {'Leaf Hash':<16} {'Preview'}")
        print("------------------------------------------------------------------")
        for s in receipt.steps:
            st = s.get("type", "").upper()
            lh = s.get("leaf_hash", "")[:12] + "..."
            content = s.get("content", "").replace("\n", " ")[:36]
            print(f"#{s.get('index', 0):<3} {st:<12} {lh:<16} {content}")
        print("==================================================================")

        if args.html:
            render_html_report(receipt, output_file=args.html)
            print(f"Interactive HTML dossier generated: {args.html}")

    elif args.command == "report":
        with open(args.receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        render_html_report(data, output_file=args.html)
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

        log_inst = None
        if args.log_dir:
            log_inst = TransparencyLog(log_dir=args.log_dir)

        consensus_rec = None
        if args.consensus:
            with open(args.consensus, "r", encoding="utf-8") as f:
                cdata = json.load(f)
            consensus_rec = ConsensusReceipt(
                version=cdata["version"],
                trajectory_id=cdata["trajectory_id"],
                merkle_root=cdata["merkle_root"],
                step_count=cdata["step_count"],
                threshold=cdata["threshold"],
                attestations=[AgentAttestation(**a) for a in cdata["attestations"]],
                timestamp=cdata.get("timestamp", 0.0),
            )

        report = verify_trajectory_integrity(
            receipt=receipt,
            transparency_log=log_inst,
            consensus_receipt=consensus_rec,
            expected_prompt_hash=args.prompt_hash,
        )

        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(report.to_text())

        if args.html:
            render_html_report(data, output_file=args.html)
            print(f"\nAudit dossier written to {args.html}")

        if not report.is_valid:
            sys.exit(1)

    elif args.command == "mcp":
        server = WitnessMCPServer(
            agent_id=args.agent_id,
            model_id=args.model_id,
            log_dir=args.log_dir,
        )
        server.run_stdio()

    elif args.command == "redact":
        with open(args.receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        step_indices = None
        if args.steps:
            step_indices = [int(x.strip()) for x in args.steps.split(",") if x.strip()]

        redacted_rec = RedactionEngine.redact_receipt(
            receipt=data,
            redact_steps=step_indices,
            redact_reason=args.reason,
        )

        is_valid, msg = RedactionEngine.verify_selective_disclosure(redacted_rec)

        p = Path(args.output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(redacted_rec.to_dict(), indent=2), encoding="utf-8")

        print("==================================================================")
        print(" SELECTIVE DISCLOSURE REDACTION ENGINE")
        print("==================================================================")
        print(f"Original Receipt:      {args.receipt_file}")
        print(f"Redacted Output:       {args.output}")
        print(f"Redacted Step Indices: {redacted_rec.redacted_step_indices}")
        print(f"Merkle Root Preserved: {redacted_rec.merkle_root}")
        print(f"Cryptographic Status:  {'VALID' if is_valid else 'INVALID'} ({msg})")
        print("==================================================================")
        if not is_valid:
            sys.exit(1)

    elif args.command == "policy":
        with open(args.receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        rules = [
            MaxStepsRule(max_steps=args.max_steps),
            RequiredApprovalRule(),
            ExecutionDurationRule(),
            StepRepetitionRule(),
        ]
        if args.disallowed_tools:
            banned = [t.strip() for t in args.disallowed_tools.split(",") if t.strip()]
            rules.append(DisallowedToolsRule(blacklisted_tools=banned))
        else:
            rules.append(DisallowedToolsRule())

        if args.allowed_models:
            models = [m.strip() for m in args.allowed_models.split(",") if m.strip()]
            rules.append(ModelWhitelistRule(allowed_models=models))

        guard = PolicyGuard(rules=rules)
        report = guard.evaluate(data)

        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(report.to_text())

        if not report.is_compliant:
            sys.exit(1)

    elif args.command == "batch-anchor":
        engine = BatchAnchorEngine(epoch_id=args.epoch_id)
        for rf in args.receipt_files:
            with open(rf, "r", encoding="utf-8") as f:
                engine.add_receipt(json.load(f))

        batch_receipt, proofs = engine.build_batch()

        print("==================================================================")
        print(" EPOCH BATCH MERKLE ANCHOR ENGINE")
        print("==================================================================")
        print(f"Epoch ID:           {batch_receipt.epoch_id}")
        print(f"Receipt Count:      {batch_receipt.receipt_count}")
        print(f"Epoch Merkle Root:  {batch_receipt.epoch_root}")
        print(f"Signer Pubkey:      {batch_receipt.signer_pubkey}")
        print(f"Batch Signature:    {batch_receipt.signature[:32]}...")

        if args.evm or not args.solana:
            print(f"\n[EVM Calldata]\n{batch_receipt.to_evm_calldata()}")
        if args.solana or not args.evm:
            print(f"\n[Solana Memo Payload]\n{batch_receipt.to_solana_memo()}")
        print("==================================================================")

        if args.output:
            p = Path(args.output)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(batch_receipt.to_dict(), indent=2), encoding="utf-8")
            print(f"Batch receipt saved to: {args.output}")

    elif args.command == "multichain-anchor":
        with open(args.receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        root = data.get("merkle_root") or data.get("epoch_root")
        chain_list = [c.strip() for c in args.chains.split(",") if c.strip()]
        dispatcher = MultiChainAnchorDispatcher()
        bundle = dispatcher.create_cross_chain_bundle(
            merkle_root=root,
            identifier=Path(args.receipt_file).stem,
            chains=chain_list,
            quorum_threshold=args.quorum,
        )

        if args.json:
            print(json.dumps(bundle.to_dict(), indent=2))
        else:
            print("==================================================================")
            print(" CROSS-CHAIN ATTESTATION & ANCHOR DISPATCHER")
            print("==================================================================")
            print(f"Bundle ID:          {bundle.bundle_id}")
            print(f"Merkle Root:        {bundle.merkle_root}")
            print(f"Chains Anchored:    {', '.join(bundle.participating_chains)}")
            print(f"Quorum Threshold:   {bundle.quorum_threshold} of {bundle.total_chains} (Verified: {bundle.verified})")
            print(f"Signer Pubkey:      {bundle.signer_pubkey}")
            if "solana" in bundle.anchors:
                sol = bundle.anchors["solana"]
                print(f"\n[Solana Anchor State]\n  PDA: {sol['pda_address']} (bump {sol['bump_seed']})\n  IX Data: {sol['instruction_data_hex'][:32]}...")
            for ch in bundle.participating_chains:
                if ch != "solana":
                    evm = bundle.anchors[ch]
                    print(f"\n[{evm['chain_name']} Calldata]\n  {evm['calldata_hex'][:50]}...")
            print("==================================================================")

        if args.output:
            p = Path(args.output)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(bundle.to_dict(), indent=2), encoding="utf-8")
            print(f"Cross-chain bundle saved to: {args.output}")

    elif args.command == "compliance":
        with open(args.receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        receipt = WitnessReceipt(**data)
        detector = ComplianceAnomalyDetector(
            max_velocity_per_min=args.max_velocity,
            max_cumulative_value=args.max_value,
        )
        report = detector.audit_receipt(receipt, expected_authority=args.expected_authority)

        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print("==================================================================")
            print(" COMPLIANCE & ANOMALY EVALUATION")
            print("==================================================================")
            print(f"Report ID:          {report.report_id}")
            print(f"Compliance Status:  {'COMPLIANT' if report.is_compliant else 'NON-COMPLIANT'}")
            print(f"Risk Score:         {report.risk_score:.1f} / 100.0")
            print(f"Total Steps:        {report.total_steps_checked}")
            print(f"Tracked Value:      ${report.cumulative_value_tracked:.2f}")
            print(f"Incidents Detected: {len(report.incidents)}")
            for inc in report.incidents:
                print(f"  [{inc.severity}] {inc.incident_type} (Step {inc.step_index}): {inc.description}")
            print("==================================================================")

        if not report.is_compliant:
            sys.exit(1)

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

    elif args.command == "credential":
        engine = AgentCredentialEngine()

        if args.cred_command == "issue":
            pubkey = args.agent_pubkey or engine.issuer_signer.pubkey_hex
            roles = [r.strip() for r in args.roles.split(",")] if args.roles else ["autonomous_executor"]
            caps = [c.strip() for c in args.capabilities.split(",")] if args.capabilities else ["*"]
            models = [m.strip() for m in args.allowed_models.split(",")] if args.allowed_models else ["*"]

            cred = engine.issue_credential(
                agent_id=args.agent_id,
                agent_pubkey=pubkey,
                roles=roles,
                capabilities=caps,
                allowed_models=models,
                max_financial_limit=args.max_financial_limit,
                sponsor_identity=args.sponsor,
                validity_days=args.validity_days,
            )
            data = cred.to_dict()
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                print(f"Issued credential saved to {args.output}")
            else:
                print(json.dumps(data, indent=2))

        elif args.cred_command == "verify":
            with open(args.credential_file, "r", encoding="utf-8") as f:
                cdata = json.load(f)
            rep = engine.verify_credential(cdata, trusted_issuer_did=args.trusted_issuer_did)
            if args.json:
                print(json.dumps(rep.to_dict(), indent=2))
            else:
                print("==================================================================")
                print(" VERIFIABLE AGENT CREDENTIAL VERIFICATION")
                print("==================================================================")
                print(f"Status:             {'VALID' if rep.is_valid else 'INVALID'}")
                print(f"Credential ID:      {rep.credential_id}")
                print(f"Issuer DID:         {rep.issuer_did}")
                print(f"Agent DID:          {rep.agent_did}")
                print(f"Expired:            {rep.is_expired}")
                if rep.errors:
                    print(f"Errors:             {', '.join(rep.errors)}")
                print("==================================================================")
            if not rep.is_valid:
                sys.exit(1)

    elif args.command == "zk":
        engine = ZKProofEngine()

        if args.zk_command == "prove":
            with open(args.receipt_file, "r", encoding="utf-8") as f:
                rdata = json.load(f)
            receipt = WitnessReceipt(**rdata)

            tools = [t.strip() for t in args.allowed_tools.split(",")] if args.allowed_tools else None
            models = [m.strip() for m in args.allowed_models.split(",")] if args.allowed_models else None
            constraints = ZKConstraintSet(
                max_steps=args.max_steps,
                max_duration_ms=args.max_duration_ms,
                allowed_tools=tools,
                allowed_models=models,
                max_financial_spend=args.max_spend,
            )
            proof = engine.generate_attestation(receipt, constraints)
            data = proof.to_dict()
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                print(f"Zero-Knowledge attestation proof saved to {args.output}")
            else:
                print(json.dumps(data, indent=2))

        elif args.zk_command == "verify":
            with open(args.proof_file, "r", encoding="utf-8") as f:
                pdata = json.load(f)
            tools = [t.strip() for t in args.allowed_tools.split(",")] if args.allowed_tools else None
            models = [m.strip() for m in args.allowed_models.split(",")] if args.allowed_models else None
            claimed = ZKConstraintSet(
                max_steps=args.max_steps,
                max_duration_ms=args.max_duration_ms,
                allowed_tools=tools,
                allowed_models=models,
                max_financial_spend=args.max_spend,
            )
            rep = engine.verify_attestation(pdata, claimed, expected_merkle_root=args.root)
            if args.json:
                print(json.dumps(rep.to_dict(), indent=2))
            else:
                print("==================================================================")
                print(" ZERO-KNOWLEDGE CONSTRAINT ATTESTATION VERIFICATION")
                print("==================================================================")
                print(f"Status:             {'VERIFIED' if rep.is_verified else 'FAILED'}")
                print(f"Proof ID:           {rep.proof_id}")
                print(f"Merkle Root:        {rep.receipt_merkle_root}")
                print(f"Checked Constraints:{rep.checked_constraints}")
                if rep.errors:
                    print(f"Errors:             {', '.join(rep.errors)}")
                print("==================================================================")
            if not rep.is_verified:
                sys.exit(1)

    elif args.command == "revocation":
        reg = RevocationRegistry(storage_path=args.registry_file)

        if args.rev_command == "revoke":
            entry = reg.revoke(
                target_identifier=args.target_identifier,
                target_type=args.type,
                reason=args.reason,
            )
            print("==================================================================")
            print(" EMERGENCY REVOCATION NOTICE ISSUED")
            print("==================================================================")
            print(f"Entry ID:           {entry.entry_id}")
            print(f"Target:             {entry.target_identifier} ({entry.target_type})")
            print(f"Reason:             {entry.reason}")
            print(f"Authority Pubkey:   {entry.revoked_by_pubkey[:16]}...")
            print(f"New Merkle Root:    {reg.get_revocation_root()}")
            print("==================================================================")

        elif args.rev_command == "check":
            is_rev, entry = reg.is_revoked(args.target_identifier)
            attestation = reg.attest_non_revocation(args.target_identifier)
            if args.json:
                print(json.dumps({
                    "is_revoked": is_rev,
                    "target": args.target_identifier,
                    "entry": entry.to_dict() if entry else None,
                    "attestation": attestation.to_dict(),
                }, indent=2))
            else:
                print("==================================================================")
                print(" REVOCATION STATUS CHECK")
                print("==================================================================")
                print(f"Target Identifier:  {args.target_identifier}")
                print(f"Active Status:      {'ACTIVE (UNREVOKED)' if not is_rev else 'REVOKED'}")
                if is_rev and entry:
                    print(f"Revocation Reason:  {entry.reason}")
                    print(f"Revoked At:         {entry.revoked_at}")
                print(f"Registry Root:      {reg.get_revocation_root()}")
                print("==================================================================")
            if is_rev:
                sys.exit(1)

    elif args.command == "delegate":
        if args.del_command == "grant":
            signer = AgentSigner()
            scope = [s.strip() for s in args.scope.split(",")] if args.scope != "*" else ["*"]
            grant = create_delegation_grant(
                parent_signer=signer,
                parent_agent_id="root_orchestrator",
                child_agent_id=args.child_agent_id,
                child_pubkey=args.child_pubkey,
                scope=scope,
                expires_in_seconds=args.expires,
                max_budget_usd=args.budget,
            )
            data = grant.to_dict()
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                print(f"Delegation capability grant saved to {args.output}")
            elif args.json:
                print(json.dumps(data, indent=2))
            else:
                print("==================================================================")
                print(" SUBAGENT DELEGATION CAPABILITY GRANT ISSUED")
                print("==================================================================")
                print(f"Grant ID:           {grant.grant_id}")
                print(f"Child Agent ID:     {grant.child_agent_id}")
                print(f"Child Pubkey:       {grant.child_pubkey[:16]}...")
                print(f"Authorized Scope:   {grant.scope}")
                print(f"Expires At:         {grant.expires_at}")
                if grant.max_budget_usd:
                    print(f"Max Budget:         ${grant.max_budget_usd:.2f}")
                print(f"Signature:          {grant.parent_signature[:32]}...")
                print("==================================================================")

        elif args.del_command == "verify":
            with open(args.grants_file, "r", encoding="utf-8") as f:
                gdata = json.load(f)
            grants = [DelegationCapability.from_dict(g) for g in (gdata if isinstance(gdata, list) else [gdata])]
            receipts = None
            if args.receipt_file:
                with open(args.receipt_file, "r", encoding="utf-8") as f:
                    rdata = json.load(f)
                receipts = [WitnessReceipt(**rdata)]
            report = DelegationDAGVerifier.verify_lineage(
                root_agent_id=args.root,
                grants=grants,
                action_receipts=receipts,
            )
            if args.json:
                print(json.dumps(report.to_dict(), indent=2))
            else:
                print("==================================================================")
                print(" DELEGATION DAG LINEAGE VERIFICATION")
                print("==================================================================")
                print(f"Status:             {'VERIFIED' if report.is_valid else 'VIOLATIONS DETECTED'}")
                print(f"Root Agent:         {report.root_agent_id}")
                print(f"Chain Depth:        {report.chain_depth}")
                print(f"Delegated Tools:    {report.delegated_tools}")
                if report.violations:
                    print("Violations:")
                    for v in report.violations:
                        print(f"  - {v}")
                print("==================================================================")
            if not report.is_valid:
                sys.exit(1)

    elif args.command == "blind":
        with open(args.receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        receipt = WitnessReceipt(**data)
        keys = [k.strip() for k in args.keys.split(",")]
        blinded, salts = BlindedAttestationEngine.blind_receipt(receipt, sensitive_keys=keys)
        out_data = {
            "blinded_receipt": blinded.to_dict(),
            "private_salts": salts,
        }
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(out_data, f, indent=2)
            print(f"Blinded receipt saved to {args.output}")
        elif args.json:
            print(json.dumps(out_data, indent=2))
        else:
            print("==================================================================")
            print(" PRIVACY-PRESERVING BLINDED ATTESTATION RECEIPT")
            print("==================================================================")
            print(f"Original Receipt:   {blinded.original_receipt_id}")
            print(f"Merkle Root:        {blinded.merkle_root}")
            print(f"Commitments Count:  {len(blinded.commitments)}")
            print(f"Blinded Keys:       {list(blinded.commitments.keys())}")
            print(f"Range Proofs Count: {len(blinded.range_proofs)}")
            print("==================================================================")

    elif args.command == "dispute":
        with open(args.receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        receipt = WitnessReceipt(**data)
        grant = None
        if args.grant_file:
            with open(args.grant_file, "r", encoding="utf-8") as f:
                gdata = json.load(f)
            grant = DelegationCapability.from_dict(gdata)

        claim = DisputeClaim(
            claim_id=args.claim_id,
            challenger_id=args.challenger,
            target_agent_id=args.target,
            receipt=receipt,
            dispute_type=DisputeType(args.type),
        )
        res = ArbitrationEngine.arbitrate(claim, delegation_grant=grant)
        if args.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print("==================================================================")
            print(" AUTONOMOUS DISPUTE ARBITRATION REPORT")
            print("==================================================================")
            print(f"Claim ID:           {res.claim_id}")
            print(f"Verdict:            {res.verdict}")
            print(f"Fault Confirmed:    {res.is_fault_confirmed}")
            if res.faulty_agent_id:
                print(f"Faulty Agent:       {res.faulty_agent_id}")
                print(f"Slashing Penalty:   {res.slashing_penalty_bps} bps ({res.slashing_penalty_bps/100:.1f}%)")
            print(f"Reason:             {res.reason}")
            print(f"Resolution Hash:    {res.resolution_hash}")
            if res.slashing_payload:
                print(f"EVM Calldata:       {res.slashing_payload.evm_calldata[:32]}...")
            print("==================================================================")
        if res.is_fault_confirmed:
            sys.exit(2)


if __name__ == "__main__":
    main()
