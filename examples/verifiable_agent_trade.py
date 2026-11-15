"""
Example: Creating and verifying a tamper-evident Agent Witness receipt
for an autonomous financial agent execution.
"""

from agent_witness import WitnessEngine, StepType, verify_merkle_proof

# 1. Initialize Witness Engine for an Autonomous Trading Agent
engine = WitnessEngine(
    agent_id="autonomous-arbitrage-agent-01",
    model_id="claude-3-7-sonnet",
    system_prompt="You are an autonomous treasury arbitrage bot. Never execute trades with slippage > 0.5%.",
)

# 2. Record full deliberation trajectory
engine.record_step(
    StepType.OBSERVATION,
    "Discovered 1.2% price divergence on ETH/USDC between Uniswap v3 and Curve.",
    metadata={"dex_a": "uniswap_v3", "dex_b": "curve", "spread_bps": 120},
)
engine.record_step(
    StepType.THOUGHT,
    "Simulating trade with 50,000 USDC. Estimated gross profit: $600. Gas estimate: $14.",
    metadata={"simulated_profit": 600, "gas_usd": 14},
)
engine.record_step(
    StepType.TOOL_CALL,
    "curve.swap(pool='0x0648...', amount_in=50000, min_out=49950)",
    metadata={"call_id": "call_987213"},
)
engine.record_step(
    StepType.TOOL_RESULT,
    "Transaction confirmed in block 21,894,012. Output: 50,586.20 USDC.",
    metadata={"tx_hash": "0x3a4f...e821"},
)
engine.record_step(
    StepType.DECISION,
    "Arbitrage executed successfully. Net profit: $586.20 USDC. Treasury updated.",
    metadata={"net_profit": 586.20},
)

# 3. Finalize and sign cryptographic receipt
receipt = engine.finalize_receipt()

print("==================================================================")
print(" VERIFIED AGENT WITNESS ATTESTATION RECEIPT")
print("==================================================================")
print(f"Receipt Version:     {receipt.version}")
print(f"Agent ID:            {receipt.agent_id}")
print(f"Model ID:            {receipt.model_id}")
print(f"Attested Steps:      {receipt.step_count}")
print(f"Merkle Root:         {receipt.merkle_root}")
print(f"Cryptographic Sig:   {receipt.signature[:32]}...")

# 4. Generate inclusion proof for Step #2 (The Tool Call)
proof = engine.generate_proof_for_step(2)
tool_leaf_hash = receipt.steps[2]["leaf_hash"]
is_valid = verify_merkle_proof(tool_leaf_hash, proof, receipt.merkle_root)

print(f"\nAudit Proof for Step #2 ('{receipt.steps[2]['content']}'):")
print(f"Proof Sibling Count: {len(proof.audit_path)}")
print(f"Merkle Verification: {'VALID (TAMPER-FREE)' if is_valid else 'INVALID'}")
print("==================================================================")
