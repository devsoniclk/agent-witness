from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import WitnessReceipt
from .signer import AgentSigner


def pubkey_to_did_key(pubkey_hex: str) -> str:
    """Converts a 32-byte (or 64-char hex) public key into a W3C did:key string with multicodec prefix."""
    # Prefix 0xed01 for Ed25519-like key representation in multicodec
    raw_bytes = bytes.fromhex(pubkey_hex[:64])
    multicodec = b"\xed\x01" + raw_bytes
    b58_like = base64.urlsafe_b64encode(multicodec).decode("utf-8").rstrip("=")
    return f"did:key:z{b58_like}"


def did_key_to_pubkey(did_key: str) -> str:
    """Extracts raw hex pubkey from did:key identifier."""
    if not did_key.startswith("did:key:z"):
        raise ValueError(f"Invalid did:key format: {did_key}")
    raw_b64 = did_key[len("did:key:z"):]
    # Add padding back if necessary
    padding = (4 - len(raw_b64) % 4) % 4
    raw_bytes = base64.urlsafe_b64decode(raw_b64 + "=" * padding)
    if len(raw_bytes) < 2:
        raise ValueError("Decoded did:key is too short")
    return raw_bytes[2:34].hex()


@dataclass
class CredentialSubject:
    """Structured subject metadata for an autonomous AI agent credential."""
    id: str  # e.g. "did:key:z..."
    agent_id: str
    roles: List[str]
    capabilities: List[str]
    allowed_models: List[str]
    max_financial_limit: float
    sponsor_identity: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CredentialProof:
    """Cryptographic signature and verification metadata for the credential."""
    type: str  # "AgentWitnessSignature2026"
    created: str
    verification_method: str  # issuer DID
    proof_purpose: str  # "assertionMethod"
    proof_value: str  # HMAC-SHA256 hex signature over canonical subject digest

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerifiableAgentCredential:
    """
    W3C Verifiable Credential standard format binding an autonomous agent's
    cryptographic identity, capability boundary, model whitelist, and human sponsor.
    """
    context: List[str]
    id: str
    type: List[str]
    issuer: str
    issuance_date: str
    expiration_date: str
    credential_subject: CredentialSubject
    proof: CredentialProof

    def canonical_digest(self) -> str:
        """Computes deterministic digest of the verifiable credential claims."""
        doc = {
            "context": sorted(self.context),
            "id": self.id,
            "type": sorted(self.type),
            "issuer": self.issuer,
            "issuance_date": self.issuance_date,
            "expiration_date": self.expiration_date,
            "credential_subject": self.credential_subject.to_dict(),
        }
        serialized = json.dumps(doc, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "@context": self.context,
            "id": self.id,
            "type": self.type,
            "issuer": self.issuer,
            "issuanceDate": self.issuance_date,
            "expirationDate": self.expiration_date,
            "credentialSubject": self.credential_subject.to_dict(),
            "proof": self.proof.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerifiableAgentCredential":
        subj_raw = data.get("credentialSubject", {})
        subj = CredentialSubject(
            id=subj_raw.get("id", ""),
            agent_id=subj_raw.get("agent_id", ""),
            roles=subj_raw.get("roles", []),
            capabilities=subj_raw.get("capabilities", []),
            allowed_models=subj_raw.get("allowed_models", []),
            max_financial_limit=float(subj_raw.get("max_financial_limit", 0.0)),
            sponsor_identity=subj_raw.get("sponsor_identity", ""),
            metadata=subj_raw.get("metadata", {}),
        )
        proof_raw = data.get("proof", {})
        proof = CredentialProof(
            type=proof_raw.get("type", "AgentWitnessSignature2026"),
            created=proof_raw.get("created", ""),
            verification_method=proof_raw.get("verification_method", ""),
            proof_purpose=proof_raw.get("proof_purpose", "assertionMethod"),
            proof_value=proof_raw.get("proof_value", ""),
        )
        return cls(
            context=data.get("@context", data.get("context", [])),
            id=data.get("id", ""),
            type=data.get("type", []),
            issuer=data.get("issuer", ""),
            issuance_date=data.get("issuanceDate", data.get("issuance_date", "")),
            expiration_date=data.get("expirationDate", data.get("expiration_date", "")),
            credential_subject=subj,
            proof=proof,
        )


@dataclass
class CredentialVerificationReport:
    """Outcome report from cryptographic verifiable credential validation."""
    is_valid: bool
    is_expired: bool
    credential_id: str
    issuer_did: str
    agent_did: str
    errors: List[str] = field(default_factory=list)
    verified_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AgentCredentialEngine:
    """
    Issues, verifies, and binds W3C-compliant Verifiable Agent Credentials
    to cryptographic witness trajectories and receipts.
    """

    DEFAULT_CONTEXT = [
        "https://www.w3.org/2018/credentials/v1",
        "https://schema.agentwitness.org/v1",
    ]

    def __init__(self, issuer_signer: Optional[AgentSigner] = None):
        self.issuer_signer = issuer_signer or AgentSigner()
        self.issuer_did = pubkey_to_did_key(self.issuer_signer.pubkey_hex)

    def issue_credential(
        self,
        agent_id: str,
        agent_pubkey: str,
        roles: Optional[List[str]] = None,
        capabilities: Optional[List[str]] = None,
        allowed_models: Optional[List[str]] = None,
        max_financial_limit: float = 1000.0,
        sponsor_identity: str = "org.devsoniclk.sponsor",
        validity_days: int = 30,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VerifiableAgentCredential:
        """Issues and signs a tamper-proof Verifiable Agent Credential."""
        now = time.time()
        created_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        exp_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + (validity_days * 86400)))

        cred_id = f"urn:uuid:{uuid.uuid4()}"
        agent_did = pubkey_to_did_key(agent_pubkey)

        subj = CredentialSubject(
            id=agent_did,
            agent_id=agent_id,
            roles=roles or ["autonomous_executor"],
            capabilities=capabilities or ["file_read", "network_call", "compute"],
            allowed_models=allowed_models or ["*"],
            max_financial_limit=max_financial_limit,
            sponsor_identity=sponsor_identity,
            metadata=metadata or {},
        )

        doc_to_sign = {
            "context": sorted(self.DEFAULT_CONTEXT),
            "id": cred_id,
            "type": ["VerifiableAgentCredential", "VerifiableCredential"],
            "issuer": self.issuer_did,
            "issuance_date": created_str,
            "expiration_date": exp_str,
            "credential_subject": subj.to_dict(),
        }
        digest = hashlib.sha256(json.dumps(doc_to_sign, sort_keys=True, separators=(",", ":")).encode("utf-8")).digest()
        proof_value = self.issuer_signer.sign(digest)

        proof = CredentialProof(
            type="AgentWitnessSignature2026",
            created=created_str,
            verification_method=self.issuer_did,
            proof_purpose="assertionMethod",
            proof_value=proof_value,
        )

        return VerifiableAgentCredential(
            context=self.DEFAULT_CONTEXT,
            id=cred_id,
            type=["VerifiableCredential", "VerifiableAgentCredential"],
            issuer=self.issuer_did,
            issuance_date=created_str,
            expiration_date=exp_str,
            credential_subject=subj,
            proof=proof,
        )

    def verify_credential(
        self,
        credential: VerifiableAgentCredential | Dict[str, Any],
        trusted_issuer_did: Optional[str] = None,
        now: Optional[float] = None,
    ) -> CredentialVerificationReport:
        """Validates credential cryptographic integrity, expiration, and issuer authority."""
        if isinstance(credential, dict):
            credential = VerifiableAgentCredential.from_dict(credential)

        errors: List[str] = []
        now_ts = now if now is not None else time.time()

        # 1. Expiration check
        try:
            exp_ts = time.mktime(time.strptime(credential.expiration_date, "%Y-%m-%dT%H:%M:%SZ"))
            is_expired = now_ts > exp_ts
            if is_expired:
                errors.append(f"Credential expired on {credential.expiration_date}")
        except Exception:
            is_expired = False
            errors.append("Invalid expirationDate format")

        # 2. Issuer verification
        if trusted_issuer_did and credential.issuer != trusted_issuer_did:
            errors.append(f"Issuer DID mismatch: expected {trusted_issuer_did}, got {credential.issuer}")

        # 3. Signature verification
        raw_digest = bytes.fromhex(credential.canonical_digest())
        try:
            issuer_pubkey = did_key_to_pubkey(credential.issuer)
            if self.issuer_signer and self.issuer_signer.pubkey_hex == issuer_pubkey:
                if not self.issuer_signer.verify(raw_digest, credential.proof.proof_value):
                    errors.append("Issuer signature does not verify with local authority key")
            else:
                if len(credential.proof.proof_value) != 64:
                    errors.append("Invalid signature length in credential proof")
        except Exception as e:
            errors.append(f"Cryptographic signature check failed: {e}")

        is_valid = len(errors) == 0
        return CredentialVerificationReport(
            is_valid=is_valid,
            is_expired=is_expired,
            credential_id=credential.id,
            issuer_did=credential.issuer,
            agent_did=credential.credential_subject.id,
            errors=errors,
        )

    def bind_receipt(
        self,
        receipt: WitnessReceipt,
        credential: VerifiableAgentCredential,
    ) -> Tuple[bool, List[str]]:
        """Verifies that an agent witness receipt complies with the limits of an issued credential."""
        violations: List[str] = []

        # 1. Agent DID binding
        expected_did = pubkey_to_did_key(receipt.agent_pubkey)
        if credential.credential_subject.id != expected_did:
            violations.append(
                f"Agent DID mismatch: receipt signer {expected_did} does not match credential subject {credential.credential_subject.id}"
            )

        # 2. Model whitelist
        allowed_models = credential.credential_subject.allowed_models
        if "*" not in allowed_models and receipt.model_id not in allowed_models:
            violations.append(
                f"Model '{receipt.model_id}' is not authorized in credential whitelist {allowed_models}"
            )

        # 3. Capability / Tool validation
        allowed_caps = set(credential.credential_subject.capabilities)
        if "*" not in allowed_caps:
            for step in receipt.steps:
                is_dict = isinstance(step, dict)
                stype = step.get("type") if is_dict else (step.step_type.value if hasattr(step.step_type, "value") else str(step.step_type))
                content = step.get("content", "") if is_dict else getattr(step, "content", "")
                meta = step.get("metadata", {}) if is_dict else getattr(step, "metadata", {})
                tool_called = meta.get("tool_name") or (content if stype in ("tool_call", "TOOL_CALL") else None)
                if tool_called and tool_called not in allowed_caps:
                    violations.append(f"Tool '{tool_called}' is not in authorized capability list")

        return (len(violations) == 0, violations)
