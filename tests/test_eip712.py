from agent_witness.eip712 import (
    EIP712Domain,
    compute_eip712_digest,
    hash_witness_receipt,
    keccak256,
)
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine


def test_keccak256_known_vectors():
    # Empty string
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

    # Known Ethereum string "hello"
    # keccak256("hello") = 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
    assert keccak256(b"hello").hex() == "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"


def test_eip712_domain_separator():
    domain = EIP712Domain(
        name="AgentWitness",
        version="1",
        chain_id=1,
        verifying_contract="0x1111111111111111111111111111111111111111",
    )
    sep = domain.separator()
    assert len(sep) == 32
    assert isinstance(sep, bytes)

    # Determinism check
    assert sep == domain.separator()


def test_eip712_digest_computation():
    engine = WitnessEngine(
        agent_id="agent-evm-01",
        model_id="claude-3-7-sonnet",
        system_prompt="EVM executor bot",
    )
    engine.record_step(StepType.OBSERVATION, "Balance: 10 ETH")
    engine.record_step(StepType.DECISION, "Execute swap")
    receipt = engine.finalize_receipt()

    domain = EIP712Domain(
        name="AgentWitness",
        version="1",
        chain_id=1,
        verifying_contract="0x1234567890123456789012345678901234567890",
    )

    digest = compute_eip712_digest(receipt, domain)
    assert len(digest) == 32
    assert isinstance(digest, bytes)

    # Struct hash check
    struct_hash = hash_witness_receipt(receipt)
    assert len(struct_hash) == 32
