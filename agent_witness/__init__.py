"""
agent-witness: Cryptographic action attestation & Merkle audit receipts
for autonomous AI agents.
"""

from .batch_anchor import BatchAnchorEngine, BatchInclusionProof, EpochBatchReceipt
from .blinded import BlindedAttestationEngine, BlindedReceipt, RangeProofCommitment, compute_blinded_hash
from .compliance import AnomalyIncident, ComplianceAnomalyDetector, ComplianceAuditReport
from .consensus import MultiAgentConsensusEngine, verify_consensus_receipt
from .credentials import (
    AgentCredentialEngine,
    CredentialProof,
    CredentialSubject,
    CredentialVerificationReport,
    VerifiableAgentCredential,
    did_key_to_pubkey,
    pubkey_to_did_key,
)
from .crosschain import (
    CCIPMessagePayload,
    CrossChainAttestationDispatcher,
    CrossChainDispatchRecord,
    CrossChainProtocol,
    LayerZeroMessagePayload,
)
from .delegation import (
    DelegationCapability,
    DelegationDAGVerifier,
    DelegationLineageReport,
    create_delegation_grant,
)
from .dispute import (
    ArbitrationEngine,
    DisputeClaim,
    DisputeResolutionReport,
    DisputeType,
    SlashingPayload,
)
from .eip712 import EIP712Domain, compute_eip712_digest, hash_witness_receipt, keccak256
from .html_report import render_html_report
from .log import TransparencyLog
from .mcp_server import WitnessMCPServer
from .merkle import MerkleTree, compute_leaf_hash, compute_parent_hash, verify_merkle_proof
from .middleware import async_witness_scope, witness_action, witness_scope
from .models import (
    AgentAttestation,
    ConsensusReceipt,
    ConsistencyProof,
    DeliberationStep,
    LogCheckpoint,
    LogInclusionProof,
    LogRecord,
    MerkleProof,
    ProofBundle,
    StepType,
    WitnessReceipt,
)
from .multichain import (
    CrossChainAttestationBundle,
    EVMAnchorPayload,
    MultiChainAnchorDispatcher,
    SolanaAnchorPayload,
)
from .policy import (
    DisallowedToolsRule,
    ExecutionDurationRule,
    MaxStepsRule,
    ModelWhitelistRule,
    PolicyEvaluationReport,
    PolicyGuard,
    PolicyRule,
    PolicyViolation,
    RequiredApprovalRule,
    StepRepetitionRule,
)
from .proof import export_proof_bundle, verify_proof_bundle
from .receipt import WitnessEngine
from .redaction import RedactionEngine, SaltedCommitment, SelectiveDisclosureReceipt
from .revocation import (
    NonRevocationAttestation,
    RevocationEntry,
    RevocationReason,
    RevocationRegistry,
)
from .rollup import (
    RollupBatchAggregator,
    RollupBatchReceipt,
    RollupInclusionProof,
)
from .signer import AgentSigner
from .streaming import (
    CausalProvenanceRecord,
    DeliberationProvenanceTracker,
    StreamingActionSession,
    StreamingStepReceipt,
)
from .verifier import AuditCheck, TrajectoryAuditReport, verify_trajectory_integrity
from .zk_proof import (
    ZKAttestationProof,
    ZKConstraintSet,
    ZKProofEngine,
    ZKVerificationReport,
)
from .zkvm import (
    DEFAULT_RISC0_IMAGE_ID,
    DEFAULT_SP1_VKEY,
    ZKVMDeliberationEngine,
    ZKVMReceipt,
    ZKVMSystem,
    ZKVMVerificationReport,
)

__version__ = "0.8.0"
__all__ = [
    "WitnessEngine",
    "AgentSigner",
    "MerkleTree",
    "compute_leaf_hash",
    "compute_parent_hash",
    "verify_merkle_proof",
    "WitnessReceipt",
    "DeliberationStep",
    "StepType",
    "MerkleProof",
    "ProofBundle",
    "export_proof_bundle",
    "verify_proof_bundle",
    "witness_action",
    "witness_scope",
    "async_witness_scope",
    "EIP712Domain",
    "compute_eip712_digest",
    "hash_witness_receipt",
    "keccak256",
    # v0.3.0 extensions:
    "TransparencyLog",
    "LogRecord",
    "LogCheckpoint",
    "ConsistencyProof",
    "LogInclusionProof",
    "MultiAgentConsensusEngine",
    "AgentAttestation",
    "ConsensusReceipt",
    "verify_consensus_receipt",
    "render_html_report",
    # v0.4.0 extensions:
    "WitnessMCPServer",
    "verify_trajectory_integrity",
    "TrajectoryAuditReport",
    "AuditCheck",
    # v0.5.0 extensions:
    "RedactionEngine",
    "SelectiveDisclosureReceipt",
    "SaltedCommitment",
    "PolicyGuard",
    "PolicyRule",
    "PolicyViolation",
    "PolicyEvaluationReport",
    "MaxStepsRule",
    "DisallowedToolsRule",
    "RequiredApprovalRule",
    "ExecutionDurationRule",
    "ModelWhitelistRule",
    "StepRepetitionRule",
    "BatchAnchorEngine",
    "EpochBatchReceipt",
    "BatchInclusionProof",
    # v0.6.0 extensions:
    "MultiChainAnchorDispatcher",
    "SolanaAnchorPayload",
    "EVMAnchorPayload",
    "CrossChainAttestationBundle",
    "StreamingActionSession",
    "StreamingStepReceipt",
    "DeliberationProvenanceTracker",
    "CausalProvenanceRecord",
    "ComplianceAnomalyDetector",
    "ComplianceAuditReport",
    "AnomalyIncident",
    # v0.7.0 extensions:
    "AgentCredentialEngine",
    "VerifiableAgentCredential",
    "CredentialSubject",
    "CredentialProof",
    "CredentialVerificationReport",
    "pubkey_to_did_key",
    "did_key_to_pubkey",
    "ZKConstraintSet",
    "ZKAttestationProof",
    "ZKVerificationReport",
    "ZKProofEngine",
    "RevocationRegistry",
    "RevocationEntry",
    "RevocationReason",
    "NonRevocationAttestation",
    "DelegationCapability",
    "DelegationDAGVerifier",
    "DelegationLineageReport",
    "create_delegation_grant",
    "BlindedAttestationEngine",
    "BlindedReceipt",
    "RangeProofCommitment",
    "compute_blinded_hash",
    "ArbitrationEngine",
    "DisputeClaim",
    "DisputeResolutionReport",
    "DisputeType",
    "SlashingPayload",
    # v0.8.0 extensions:
    "ZKVMDeliberationEngine",
    "ZKVMReceipt",
    "ZKVMVerificationReport",
    "ZKVMSystem",
    "DEFAULT_RISC0_IMAGE_ID",
    "DEFAULT_SP1_VKEY",
    "CrossChainAttestationDispatcher",
    "CrossChainDispatchRecord",
    "CrossChainProtocol",
    "LayerZeroMessagePayload",
    "CCIPMessagePayload",
    "RollupBatchAggregator",
    "RollupBatchReceipt",
    "RollupInclusionProof",
]
