use anchor_lang::prelude::*;
use solana_program::hash::hashv;

declare_id!("Witnss1111111111111111111111111111111111111");

#[program]
pub mod agent_witness {
    use super::*;

    /// Verifies an RFC 6962 Merkle inclusion proof for an autonomous AI agent action step.
    pub fn verify_action_proof(
        ctx: Context<VerifyActionProof>,
        leaf_hash: [u8; 32],
        audit_path: Vec<MerkleNode>,
        expected_root: [u8; 32],
    ) -> Result<()> {
        let is_valid = verify_merkle_membership(&leaf_hash, &audit_path, &expected_root);
        require!(is_valid, WitnessError::InvalidProof);

        emit!(ActionVerifiedEvent {
            signer: ctx.accounts.authority.key(),
            merkle_root: expected_root,
            leaf_hash,
        });

        Ok(())
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq)]
pub struct MerkleNode {
    pub is_left: bool,
    pub node_hash: [u8; 32],
}

#[derive(Accounts)]
pub struct VerifyActionProof<'info> {
    pub authority: Signer<'info>,
}

#[event]
pub struct ActionVerifiedEvent {
    pub signer: Pubkey,
    pub merkle_root: [u8; 32],
    pub leaf_hash: [u8; 32],
}

#[error_code]
pub enum WitnessError {
    #[msg("Merkle inclusion proof verification failed")]
    InvalidProof,
}

/// Helper function to compute RFC 6962 parent node hash:
/// SHA-256(0x01 || left || right)
pub fn compute_parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let prefix = [1u8];
    let h = hashv(&[&prefix, left, right]);
    h.to_bytes()
}

/// Verifies whether `leaf_hash` is a member of the Merkle Tree rooted at `expected_root`.
pub fn verify_merkle_membership(
    leaf_hash: &[u8; 32],
    audit_path: &[MerkleNode],
    expected_root: &[u8; 32],
) -> bool {
    let mut current = *leaf_hash;

    for node in audit_path {
        if node.is_left {
            current = compute_parent_hash(&node.node_hash, &current);
        } else {
            current = compute_parent_hash(&current, &node.node_hash);
        }
    }

    &current == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc6962_parent_hash() {
        let left = [0x11; 32];
        let right = [0x22; 32];
        let parent = compute_parent_hash(&left, &right);
        assert_ne!(parent, [0; 32]);
    }
}
