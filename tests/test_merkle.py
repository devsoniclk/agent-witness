from agent_witness.merkle import MerkleTree, compute_leaf_hash, verify_merkle_proof
from agent_witness.models import DeliberationStep, StepType


def test_merkle_tree_construction_and_proof():
    steps = [
        DeliberationStep(StepType.OBSERVATION, 0, "Current BTC price is $92,400"),
        DeliberationStep(StepType.THOUGHT, 1, "RSI is oversold at 28.5; trigger buy order"),
        DeliberationStep(StepType.TOOL_CALL, 2, "binance.place_order(symbol='BTCUSDT', side='BUY')"),
        DeliberationStep(StepType.TOOL_RESULT, 3, "order_id=987654 status='FILLED'"),
        DeliberationStep(StepType.DECISION, 4, "Trade completed; notify risk desk"),
    ]

    tree = MerkleTree(steps)
    assert tree.root_hex is not None
    assert len(tree.root_hex) == 64

    # Generate and verify proof for each step
    for i, step in enumerate(steps):
        proof = tree.generate_proof(i)
        leaf_hash = compute_leaf_hash(step).hex()
        assert verify_merkle_proof(leaf_hash, proof, tree.root_hex)


def test_merkle_proof_tamper_detection():
    steps = [
        DeliberationStep(StepType.OBSERVATION, 0, "Account balance is 10 ETH"),
        DeliberationStep(StepType.DECISION, 1, "Send 1 ETH to Vault"),
    ]
    tree = MerkleTree(steps)
    proof = tree.generate_proof(1)

    # Tampered step content
    tampered_step = DeliberationStep(StepType.DECISION, 1, "Send 10 ETH to Hacker")
    tampered_hash = compute_leaf_hash(tampered_step).hex()

    # Tampered hash must fail verification against legitimate root
    assert not verify_merkle_proof(tampered_hash, proof, tree.root_hex)
