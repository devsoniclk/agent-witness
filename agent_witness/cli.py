import argparse
import json
import sys
from .receipt import WitnessEngine, WitnessReceipt
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

    args = parser.parse_args()

    if args.command in ("inspect", "verify"):
        with open(args.receipt_file, "r") as f:
            data = json.load(f)

        receipt = WitnessReceipt(**data)

        if args.command == "inspect":
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
            # Reconstruct and check root
            from .models import DeliberationStep, StepType
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


if __name__ == "__main__":
    main()
