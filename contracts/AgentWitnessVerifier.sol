// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title AgentWitnessVerifier
 * @notice Lightweight on-chain verifier for Agent Witness Merkle Action Receipts.
 * @dev Validates that an autonomous agent deliberation step was part of an attested Merkle root,
 *      and optionally verifies EIP-712 typed agent signatures via ecrecover.
 */
contract AgentWitnessVerifier {
    struct MerkleNode {
        bool isLeft;
        bytes32 nodeHash;
    }

    struct AgentWitnessReceiptData {
        string agentId;
        string modelId;
        bytes32 systemPromptHash;
        bytes32 merkleRoot;
        uint256 stepCount;
        uint256 timestamp;
    }

    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 public constant AGENT_WITNESS_RECEIPT_TYPEHASH =
        keccak256(
            "AgentWitnessReceipt(string agentId,string modelId,bytes32 systemPromptHash,bytes32 merkleRoot,uint256 stepCount,uint256 timestamp)"
        );

    bytes32 public immutable DOMAIN_SEPARATOR;

    event ReceiptVerified(bytes32 indexed merkleRoot, bytes32 indexed leafHash, uint256 leafIndex);
    event AttestationSignerVerified(address indexed signer, bytes32 indexed merkleRoot);

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("AgentWitness")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @notice Computes an RFC 6962 parent node hash from left and right children.
     */
    function computeParentHash(bytes32 left, bytes32 right) public pure returns (bytes32) {
        return sha256(abi.encodePacked(uint8(1), left, right));
    }

    /**
     * @notice Verifies a Merkle inclusion proof against a verified Merkle root.
     * @param leafHash The sha256 leaf hash of the deliberation step (prefixed with 0x00).
     * @param auditPath Sibling path from leaf to root.
     * @param expectedRoot The signed Merkle root of the receipt.
     */
    function verifyProof(
        bytes32 leafHash,
        MerkleNode[] calldata auditPath,
        bytes32 expectedRoot
    ) external pure returns (bool) {
        bytes32 current = leafHash;

        for (uint256 i = 0; i < auditPath.length; i++) {
            if (auditPath[i].isLeft) {
                current = computeParentHash(auditPath[i].nodeHash, current);
            } else {
                current = computeParentHash(current, auditPath[i].nodeHash);
            }
        }

        return current == expectedRoot;
    }

    /**
     * @notice Computes the EIP-712 struct hash for an agent receipt.
     */
    function hashReceipt(AgentWitnessReceiptData calldata receipt) public pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    AGENT_WITNESS_RECEIPT_TYPEHASH,
                    keccak256(bytes(receipt.agentId)),
                    keccak256(bytes(receipt.modelId)),
                    receipt.systemPromptHash,
                    receipt.merkleRoot,
                    receipt.stepCount,
                    receipt.timestamp
                )
            );
    }

    /**
     * @notice Verifies that an EIP-712 signed receipt was authored by expectedSigner.
     */
    function verifyReceiptSignature(
        AgentWitnessReceiptData calldata receipt,
        uint8 v,
        bytes32 r,
        bytes32 s,
        address expectedSigner
    ) external view returns (bool) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashReceipt(receipt)));
        address recovered = ecrecover(digest, v, r, s);
        return recovered == expectedSigner && recovered != address(0);
    }
}
