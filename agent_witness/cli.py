import argparse
import json
import sys
from pathlib import Path
from .models import DeliberationStep, ProofBundle, StepType, WitnessReceipt
from .proof import export_proof_bundle, verify_proof_bundle
from .receipt import WitnessEngine
from .signer import AgentSigner


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agent-witness",
        description="Cryptographic action attestation & Merkle receipt inspector for AI agents.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # inspect
    p_ins = subparsers.add_parser("inspect", help="Inspect a .witness receipt JSON file.")
    p_ins.add_argument("receipt_file", help="Path to .witness or JSON receipt file.")

    # verify
    p_ver = subparsers.add_parser("verify", help="Verify Merkle root integrity of a receipt.")
    p_ver.add_argument("receipt_file", help="Path to .witness or JSON receipt file.")

    # export-proof
    p_exp = subparsers.add_parser("export-proof", help="Export selective disclosure proof for a single step.")
    p_exp.add_argument("receipt_file", help="Path to .witness or JSON receipt file.")
    p_exp.add_argument("--step", type=int, required=True, help="Step index to disclose.")
    p_exp.add_argument("--output", "-o", help="Optional output path for the proof JSON bundle.")

    # verify-proof
    p_vpr = subparsers.add_parser("verify-proof", help="Verify a standalone selective disclosure proof bundle.")
    p_vpr.add_argument("proof_file", help="Path to proof bundle JSON file.")

    args = parser.parse_args()

    if args.command == "inspect":
        with open(args.receipt_file, "r") as f:
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

    elif args.command == "verify":
        with open(args.receipt_file, "r") as f:
            data = json.load(f)
        receipt = WitnessReceipt(**data)
        from .merkle import MerkleTree

        steps = [
            DeliberationStep(
                step_type=StepType(s["type"]),
                index=s["index"],
                content=s["content"],
                metadata=s.get("metadata", {}),
                timestamp=s.get("timestamp", 0.0),
            )
            for s in receipt.steps
        ]
        tree = MerkleTree(steps)
        if tree.root_hex == receipt.merkle_root:
            print(f"VERIFIED: Merkle root {receipt.merkle_root} matches all {len(steps)} deliberation steps.")
        else:
            print(f"TAMPER DETECTED: Computed root {tree.root_hex} != receipt root {receipt.merkle_root}")
            sys.exit(1)

    elif args.command == "export-proof":
        with open(args.receipt_file, "r") as f:
            data = json.load(f)
        receipt = WitnessReceipt(**data)
        bundle = export_proof_bundle(receipt, args.step)
        bundle_json = json.dumps(bundle.to_dict(), indent=2)

        if args.output:
            with open(args.output, "w") as out_f:
                out_f.write(bundle_json)
            print(f"Selective disclosure proof exported to {args.output} (Step #{args.step})")
        else:
            print(bundle_json)

    elif args.command == "verify-proof":
        with open(args.proof_file, "r") as f:
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


if __name__ == "__main__":
    main()
