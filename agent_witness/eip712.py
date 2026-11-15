from dataclasses import dataclass
from typing import Optional
from .models import WitnessReceipt


def keccak256(data: bytes) -> bytes:
    """
    Zero-dependency pure Python implementation of Ethereum's Keccak-256 hash function.
    Matches standard EVM opcode 0x20 (SHA3).
    """
    r = 136  # Rate for Keccak-256 (1088 bits)
    pad_len = r - (len(data) % r)
    if pad_len == 1:
        padded = data + b"\x81"
    else:
        padded = data + b"\x01" + b"\x00" * (pad_len - 2) + b"\x80"

    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    r_shifts = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ]

    state = [[0] * 5 for _ in range(5)]
    for b_idx in range(0, len(padded), r):
        block = padded[b_idx : b_idx + r]
        for i in range(r // 8):
            x = i % 5
            y = i // 5
            state[x][y] ^= int.from_bytes(block[i * 8 : (i + 1) * 8], "little")

        for round_idx in range(24):
            # Theta
            C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
            D = [C[(x + 4) % 5] ^ (((C[(x + 1) % 5] << 1) & 0xFFFFFFFFFFFFFFFF) | (C[(x + 1) % 5] >> 63)) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x][y] ^= D[x]

            # Rho & Pi
            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    shift = r_shifts[x][y]
                    lane = state[x][y]
                    rot_val = ((lane << shift) & 0xFFFFFFFFFFFFFFFF) | (lane >> (64 - shift) if shift else 0)
                    B[y][(2 * x + 3 * y) % 5] = rot_val

            # Chi
            for x in range(5):
                for y in range(5):
                    state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

            # Iota
            state[0][0] ^= RC[round_idx]

    out = bytearray()
    for i in range(4):  # 4 * 8 bytes = 32 bytes (256 bits)
        x = i % 5
        y = i // 5
        out.extend(state[x][y].to_bytes(8, "little"))
    return bytes(out)


# EIP-712 Type Strings
EIP712_DOMAIN_TYPE = b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
EIP712_DOMAIN_TYPEHASH = keccak256(EIP712_DOMAIN_TYPE)

AGENT_WITNESS_RECEIPT_TYPE = (
    b"AgentWitnessReceipt(string agentId,string modelId,bytes32 systemPromptHash,bytes32 merkleRoot,uint256 stepCount,uint256 timestamp)"
)
AGENT_WITNESS_RECEIPT_TYPEHASH = keccak256(AGENT_WITNESS_RECEIPT_TYPE)


@dataclass
class EIP712Domain:
    name: str = "AgentWitness"
    version: str = "1"
    chain_id: int = 1
    verifying_contract: str = "0x0000000000000000000000000000000000000000"

    def separator(self) -> bytes:
        """Computes the 32-byte EIP-712 domain separator."""
        name_hash = keccak256(self.name.encode("utf-8"))
        version_hash = keccak256(self.version.encode("utf-8"))
        chain_id_bytes = self.chain_id.to_bytes(32, "big")

        addr = self.verifying_contract.lower().replace("0x", "")
        addr_bytes = bytes.fromhex(addr.zfill(64))

        encoded = EIP712_DOMAIN_TYPEHASH + name_hash + version_hash + chain_id_bytes + addr_bytes
        return keccak256(encoded)


def hash_witness_receipt(receipt: WitnessReceipt) -> bytes:
    """
    Computes the EIP-712 struct hash for an AgentWitnessReceipt:
    keccak256(TYPEHASH || keccak256(agentId) || keccak256(modelId) || promptHash || merkleRoot || stepCount || timestamp)
    """
    agent_id_hash = keccak256(receipt.agent_id.encode("utf-8"))
    model_id_hash = keccak256(receipt.model_id.encode("utf-8"))

    prompt_hash_bytes = bytes.fromhex(receipt.system_prompt_hash.replace("0x", "").zfill(64))
    merkle_root_bytes = bytes.fromhex(receipt.merkle_root.replace("0x", "").zfill(64))
    step_count_bytes = receipt.step_count.to_bytes(32, "big")
    timestamp_bytes = int(receipt.timestamp).to_bytes(32, "big")

    encoded = (
        AGENT_WITNESS_RECEIPT_TYPEHASH
        + agent_id_hash
        + model_id_hash
        + prompt_hash_bytes
        + merkle_root_bytes
        + step_count_bytes
        + timestamp_bytes
    )
    return keccak256(encoded)


def compute_eip712_digest(receipt: WitnessReceipt, domain: Optional[EIP712Domain] = None) -> bytes:
    """
    Computes the final 32-byte EIP-712 signing digest:
    keccak256("\x19\x01" || domainSeparator || structHash)
    """
    dom = domain or EIP712Domain()
    domain_sep = dom.separator()
    struct_hash = hash_witness_receipt(receipt)
    return keccak256(b"\x19\x01" + domain_sep + struct_hash)
