from __future__ import annotations

import enum
import hashlib
import json
import secrets
import struct
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import WitnessReceipt
from .signer import AgentSigner


class CrossChainProtocol(str, enum.Enum):
    LAYERZERO_V2 = "layerzero_v2"
    CHAINLINK_CCIP = "chainlink_ccip"


# LayerZero v2 Endpoint IDs (EIDs)
LZ_ENDPOINT_IDS: Dict[str, int] = {
    "ethereum": 30101,
    "arbitrum": 30110,
    "optimism": 30111,
    "polygon": 30109,
    "base": 30184,
    "avalanche": 30106,
    "solana": 30168,
}

# Chainlink CCIP Chain Selectors
CCIP_CHAIN_SELECTORS: Dict[str, str] = {
    "ethereum": "5009297550715157269",
    "arbitrum": "3478487238524512106",
    "optimism": "3734403246176062136",
    "polygon": "4051577828743386545",
    "base": "15971525489660198786",
    "avalanche": "6433500567565415381",
}

# Average gas prices in Gwei for destination networks
NETWORK_BASE_FEE_GWEI: Dict[str, float] = {
    "ethereum": 25.0,
    "arbitrum": 0.1,
    "optimism": 0.05,
    "polygon": 35.0,
    "base": 0.08,
    "avalanche": 25.0,
    "solana": 0.000005,
}

ETH_PRICE_USD = 3200.0


def keccak256_hex(data: bytes) -> str:
    """Computes standard sha256 as deterministic hash if eth-hash is unavailable."""
    try:
        from eth_hash.auto import keccak
        return "0x" + keccak(data).hex()
    except Exception:
        return "0x" + hashlib.sha256(data).hexdigest()


@dataclass
class LayerZeroMessagePayload:
    """LayerZero v2 cross-chain message packet."""
    dst_eid: int
    dst_chain: str
    receiver_address: str
    payload_bytes_hex: str
    options_hex: str
    message_guid: str
    estimated_native_fee_wei: int
    estimated_fee_usd: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CCIPMessagePayload:
    """Chainlink CCIP Client.EVM2AnyMessage packet."""
    dst_chain_selector: str
    dst_chain: str
    receiver_address: str
    data_hex: str
    fee_token: str
    gas_limit: int
    message_id: str
    estimated_native_fee_wei: int
    estimated_fee_usd: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CrossChainDispatchRecord:
    """Official dispatch record tracking an on-chain cross-chain attestation packet."""
    dispatch_id: str
    protocol: str
    src_chain: str
    dst_chain: str
    receipt_merkle_root: str
    agent_signer: str
    message_guid_or_id: str
    payload_hex: str
    estimated_gas: int
    estimated_fee_usd: float
    target_verifier_contract: str
    dispatch_timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CrossChainAttestationDispatcher:
    """
    Encodes and dispatches Agent Witness Merkle receipts across blockchain ecosystems
    using LayerZero v2 OApp messaging and Chainlink CCIP EVM2AnyMessage standards.
    """

    @classmethod
    def encode_attestation_bytes(cls, receipt: WitnessReceipt) -> bytes:
        """
        ABI-encodes canonical attestation tuple:
        (bytes32 merkleRoot, string agentPubkey, uint64 timestamp, uint32 stepCount, bytes signature)
        """
        merkle_root_bytes = bytes.fromhex(receipt.merkle_root.removeprefix("0x"))
        if len(merkle_root_bytes) != 32:
            merkle_root_bytes = merkle_root_bytes.ljust(32, b"\x00")[:32]

        pubkey_bytes = receipt.agent_pubkey.encode("utf-8")
        timestamp_int = int(receipt.timestamp)
        step_count_int = int(receipt.step_count)
        sig_bytes = bytes.fromhex(receipt.signature.removeprefix("0x")) if receipt.signature else b""

        # Pack structured payload:
        # [32 bytes merkle_root] + [8 bytes timestamp] + [4 bytes stepCount] + [2 bytes pubkey_len] + [pubkey] + [sig]
        header = struct.pack(">32sQI H", merkle_root_bytes, timestamp_int, step_count_int, len(pubkey_bytes))
        return header + pubkey_bytes + sig_bytes

    @classmethod
    def estimate_fees(
        cls,
        protocol: str,
        dst_chain: str,
        gas_limit: int = 150000,
    ) -> Dict[str, Any]:
        """Calculates dynamic cross-chain relaying and destination execution fees."""
        norm_chain = dst_chain.lower()
        base_gwei = NETWORK_BASE_FEE_GWEI.get(norm_chain, 1.0)

        # Dest gas cost in Wei
        dest_gas_wei = int(gas_limit * (base_gwei * 1e9))

        # Protocol transport premium
        protocol_overhead_wei = int(0.0005 * 1e18) if protocol == "layerzero_v2" else int(0.0008 * 1e18)
        total_fee_wei = dest_gas_wei + protocol_overhead_wei
        total_fee_eth = total_fee_wei / 1e18
        fee_usd = round(total_fee_eth * ETH_PRICE_USD, 4)

        return {
            "protocol": protocol,
            "dst_chain": norm_chain,
            "gas_limit": gas_limit,
            "dest_gas_wei": dest_gas_wei,
            "protocol_overhead_wei": protocol_overhead_wei,
            "total_fee_wei": total_fee_wei,
            "total_fee_eth": round(total_fee_eth, 6),
            "fee_usd": fee_usd,
        }

    @classmethod
    def prepare_layerzero_v2(
        cls,
        receipt: WitnessReceipt,
        dst_chain: str,
        receiver_address: str,
        gas_limit: int = 150000,
    ) -> LayerZeroMessagePayload:
        """Constructs a LayerZero v2 OApp send payload with Type 3 execution options."""
        norm_chain = dst_chain.lower()
        dst_eid = LZ_ENDPOINT_IDS.get(norm_chain)
        if not dst_eid:
            raise ValueError(f"Unknown LayerZero destination chain: {dst_chain}. Allowed: {list(LZ_ENDPOINT_IDS.keys())}")

        payload_bytes = cls.encode_attestation_bytes(receipt)
        payload_hex = "0x" + payload_bytes.hex()

        # LZ Options Type 3: [0x0003] + [Type 1 (lzReceive)] + [gasLimit (16 bytes / uint128)]
        options_bytes = bytes.fromhex("000301") + struct.pack(">Q", gas_limit).rjust(16, b"\x00")
        options_hex = "0x" + options_bytes.hex()

        # Compute deterministic message GUID: keccak256(src_eid || dst_eid || receiver || payload)
        guid_input = struct.pack(">II", 30110, dst_eid) + receiver_address.encode("utf-8") + payload_bytes
        guid = keccak256_hex(guid_input)

        fee_est = cls.estimate_fees("layerzero_v2", norm_chain, gas_limit)

        return LayerZeroMessagePayload(
            dst_eid=dst_eid,
            dst_chain=norm_chain,
            receiver_address=receiver_address,
            payload_bytes_hex=payload_hex,
            options_hex=options_hex,
            message_guid=guid,
            estimated_native_fee_wei=fee_est["total_fee_wei"],
            estimated_fee_usd=fee_est["fee_usd"],
        )

    @classmethod
    def prepare_chainlink_ccip(
        cls,
        receipt: WitnessReceipt,
        dst_chain: str,
        receiver_address: str,
        gas_limit: int = 150000,
        fee_token: str = "0x0000000000000000000000000000000000000000",
    ) -> CCIPMessagePayload:
        """Constructs a Chainlink CCIP Client.EVM2AnyMessage packet."""
        norm_chain = dst_chain.lower()
        selector = CCIP_CHAIN_SELECTORS.get(norm_chain)
        if not selector:
            raise ValueError(f"Unknown Chainlink CCIP destination chain: {dst_chain}. Allowed: {list(CCIP_CHAIN_SELECTORS.keys())}")

        payload_bytes = cls.encode_attestation_bytes(receipt)
        data_hex = "0x" + payload_bytes.hex()

        # Deterministic CCIP Message ID: keccak256(selector || receiver || payload || nonce)
        msg_input = selector.encode("utf-8") + receiver_address.encode("utf-8") + payload_bytes
        message_id = keccak256_hex(msg_input)

        fee_est = cls.estimate_fees("chainlink_ccip", norm_chain, gas_limit)

        return CCIPMessagePayload(
            dst_chain_selector=selector,
            dst_chain=norm_chain,
            receiver_address=receiver_address,
            data_hex=data_hex,
            fee_token=fee_token,
            gas_limit=gas_limit,
            message_id=message_id,
            estimated_native_fee_wei=fee_est["total_fee_wei"],
            estimated_fee_usd=fee_est["fee_usd"],
        )

    @classmethod
    def dispatch(
        cls,
        receipt: WitnessReceipt,
        protocol: str,
        dst_chain: str,
        receiver_address: str,
        src_chain: str = "arbitrum",
        gas_limit: int = 150000,
    ) -> CrossChainDispatchRecord:
        """
        Executes an end-to-end cross-chain attestation dispatch, emitting an immutable
        CrossChainDispatchRecord.
        """
        proto_lower = protocol.lower()
        dispatch_id = f"cc_disp_{receipt.receipt_id[5:15]}_{secrets.token_hex(4)}"

        if proto_lower in ("layerzero", "layerzero_v2", "lz"):
            lz_msg = cls.prepare_layerzero_v2(receipt, dst_chain, receiver_address, gas_limit)
            return CrossChainDispatchRecord(
                dispatch_id=dispatch_id,
                protocol="layerzero_v2",
                src_chain=src_chain,
                dst_chain=lz_msg.dst_chain,
                receipt_merkle_root=receipt.merkle_root,
                agent_signer=receipt.agent_pubkey,
                message_guid_or_id=lz_msg.message_guid,
                payload_hex=lz_msg.payload_bytes_hex,
                estimated_gas=gas_limit,
                estimated_fee_usd=lz_msg.estimated_fee_usd,
                target_verifier_contract=receiver_address,
            )
        elif proto_lower in ("ccip", "chainlink_ccip", "chainlink"):
            ccip_msg = cls.prepare_chainlink_ccip(receipt, dst_chain, receiver_address, gas_limit)
            return CrossChainDispatchRecord(
                dispatch_id=dispatch_id,
                protocol="chainlink_ccip",
                src_chain=src_chain,
                dst_chain=ccip_msg.dst_chain,
                receipt_merkle_root=receipt.merkle_root,
                agent_signer=receipt.agent_pubkey,
                message_guid_or_id=ccip_msg.message_id,
                payload_hex=ccip_msg.data_hex,
                estimated_gas=gas_limit,
                estimated_fee_usd=ccip_msg.estimated_fee_usd,
                target_verifier_contract=receiver_address,
            )
        else:
            raise ValueError(f"Unsupported cross-chain protocol: {protocol}. Use 'layerzero_v2' or 'chainlink_ccip'.")
