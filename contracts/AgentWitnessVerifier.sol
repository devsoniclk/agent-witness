// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title AgentWitnessVerifier
 * @notice Lightweight on-chain verifier for Agent Witness Merkle Action Receipts.
 * @dev Validates that an autonomous agent deliberation step was part of an attested Merkle root.
 */
contract AgentWitnessVerifier {
    struct MerkleNode {
        bool isLeft;
        bytes32 nodeHash;
    }

    event ReceiptVerified(bytes32 indexed merkleRoot, bytes32 indexed leafHash, uint256 leafIndex);

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
}
