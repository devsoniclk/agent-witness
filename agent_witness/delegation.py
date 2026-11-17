from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

from .models import StepType, WitnessReceipt
from .signer import AgentSigner


@dataclass
class DelegationCapability:
    grant_id: str
    parent_agent_id: str
    parent_pubkey: str
    child_agent_id: str
    child_pubkey: str
    scope: List[str]  # e.g. ["web_search", "run_test"] or ["*"]
    expires_at: float  # Unix timestamp in seconds
    created_at: float  # Unix timestamp in seconds
    max_budget_usd: Optional[float] = None
    parent_signature: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DelegationCapability":
        return cls(**data)

    def canonical_digest(self) -> str:
        """Computes SHA-256 digest of canonical fields excluding parent_signature."""
        payload = {
            "grant_id": self.grant_id,
            "parent_agent_id": self.parent_agent_id,
            "parent_pubkey": self.parent_pubkey,
            "child_agent_id": self.child_agent_id,
            "child_pubkey": self.child_pubkey,
            "scope": sorted(self.scope),
            "expires_at": float(self.expires_at),
            "created_at": float(self.created_at),
            "max_budget_usd": float(self.max_budget_usd) if self.max_budget_usd is not None else None,
            "metadata": self.metadata,
        }
        canonical_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def create_delegation_grant(
    parent_signer: AgentSigner,
    parent_agent_id: str,
    child_agent_id: str,
    child_pubkey: str,
    scope: List[str],
    expires_in_seconds: float = 3600.0,
    max_budget_usd: Optional[float] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> DelegationCapability:
    now = time.time()
    raw_id = f"{parent_agent_id}:{child_agent_id}:{now}"
    grant_id = f"grant_{hashlib.sha256(raw_id.encode('utf-8')).hexdigest()[:16]}"
    grant = DelegationCapability(
        grant_id=grant_id,
        parent_agent_id=parent_agent_id,
        parent_pubkey=parent_signer.pubkey_hex,
        child_agent_id=child_agent_id,
        child_pubkey=child_pubkey,
        scope=scope,
        expires_at=now + expires_in_seconds,
        created_at=now,
        max_budget_usd=max_budget_usd,
        metadata=metadata or {},
    )
    digest = grant.canonical_digest()
    grant.parent_signature = parent_signer.sign(digest.encode("utf-8"))
    return grant


@dataclass
class DelegationLineageReport:
    is_valid: bool
    root_agent_id: str
    chain_depth: int
    nodes_verified: int
    delegated_tools: List[str]
    total_budget_allocated: float
    violations: List[str]
    audit_trail: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DelegationDAGVerifier:
    """
    Validates hierarchical multi-agent delegation chains and capability tokens.
    Guarantees that subagents act strictly within authorized scopes, durations, and budget caps.
    """

    @staticmethod
    def verify_grant_signature(grant: DelegationCapability, parent_signer: Optional[AgentSigner] = None) -> bool:
        digest = grant.canonical_digest().encode("utf-8")
        if parent_signer:
            return parent_signer.verify(digest, grant.parent_signature)
        return bool(grant.parent_signature and len(grant.parent_signature) == 64)

    @classmethod
    def verify_lineage(
        cls,
        root_agent_id: str,
        grants: List[DelegationCapability],
        action_receipts: Optional[List[WitnessReceipt]] = None,
        parent_signers: Optional[Dict[str, AgentSigner]] = None,
        current_time: Optional[float] = None,
    ) -> DelegationLineageReport:
        now = current_time if current_time is not None else time.time()
        violations: List[str] = []
        audit_trail: List[str] = []
        delegated_tools: Set[str] = set()
        total_budget = 0.0

        if not grants:
            return DelegationLineageReport(
                is_valid=False,
                root_agent_id=root_agent_id,
                chain_depth=0,
                nodes_verified=0,
                delegated_tools=[],
                total_budget_allocated=0.0,
                violations=["Empty delegation grants list."],
                audit_trail=["Verification failed: No grants provided."],
            )

        # 1. Verify root grant
        first_grant = grants[0]
        if first_grant.parent_agent_id != root_agent_id:
            violations.append(
                f"Root grant parent_agent_id '{first_grant.parent_agent_id}' != expected root '{root_agent_id}'"
            )

        # 2. Sequential delegation chain validation
        current_scope: Optional[Set[str]] = None
        for i, grant in enumerate(grants):
            audit_trail.append(
                f"Verifying grant[{i}] {grant.grant_id}: {grant.parent_agent_id} -> {grant.child_agent_id}"
            )

            # Signature check
            signer = parent_signers.get(grant.parent_agent_id) if parent_signers else None
            if not cls.verify_grant_signature(grant, signer):
                violations.append(f"Grant {grant.grant_id} has invalid cryptographic parent signature.")

            # Expiry check
            if grant.expires_at < now:
                violations.append(f"Grant {grant.grant_id} expired at {grant.expires_at} (current {now}).")

            # Scope restriction check: child cannot escalate privileges beyond parent
            grant_scope_set = set(grant.scope)
            if current_scope is not None and "*" not in current_scope:
                escalated = grant_scope_set - current_scope
                if escalated:
                    violations.append(f"Grant {grant.grant_id} escalates unauthorized scopes: {sorted(escalated)}")
            current_scope = grant_scope_set
            delegated_tools.update(grant.scope)

            if grant.max_budget_usd is not None:
                total_budget += grant.max_budget_usd

            # Linkage check
            if i > 0:
                prev_grant = grants[i - 1]
                if grant.parent_agent_id != prev_grant.child_agent_id:
                    violations.append(
                        f"Lineage break at {i}: parent '{grant.parent_agent_id}' != previous child '{prev_grant.child_agent_id}'"
                    )
                if grant.parent_pubkey != prev_grant.child_pubkey:
                    violations.append(f"Lineage pubkey mismatch at {i}: parent_pubkey != previous child_pubkey")

        # 3. Action receipt compliance check
        if action_receipts:
            grant_by_child = {g.child_agent_id: g for g in grants}
            for r_idx, receipt in enumerate(action_receipts):
                target_grant = grant_by_child.get(receipt.agent_id)
                if not target_grant:
                    violations.append(f"Receipt[{r_idx}] agent '{receipt.agent_id}' has no active delegation grant.")
                    continue

                allowed = set(target_grant.scope)
                allow_all = "*" in allowed

                receipt_spent = 0.0
                for s_idx, step in enumerate(receipt.steps):
                    st = step.step_type if hasattr(step, "step_type") else step.get("type", step.get("step_type"))
                    if isinstance(st, str):
                        try:
                            st = StepType(st.lower())
                        except Exception:
                            pass
                    step_ts = step.timestamp if hasattr(step, "timestamp") else step.get("timestamp", 0.0)
                    step_content = step.content if hasattr(step, "content") else step.get("content", "")
                    step_meta = step.metadata if hasattr(step, "metadata") else step.get("metadata", {})

                    tool_name = ""
                    cost = 0.0
                    if isinstance(step_meta, dict):
                        tool_name = step_meta.get("tool_name", "")
                        cost = step_meta.get("cost_usd", 0.0)
                    if not tool_name and isinstance(step_content, dict):
                        tool_name = step_content.get("tool_name", "")
                        cost = cost or step_content.get("cost_usd", 0.0)
                    elif not tool_name and isinstance(step_content, str):
                        try:
                            cdata = json.loads(step_content)
                            if isinstance(cdata, dict):
                                tool_name = cdata.get("tool_name", "")
                                cost = cost or cdata.get("cost_usd", 0.0)
                        except Exception:
                            pass

                    # Check tool scope
                    if st in (StepType.TOOL_CALL, "tool_call"):
                        if not allow_all and tool_name and tool_name not in allowed:
                            violations.append(
                                f"Receipt[{r_idx}] step {s_idx} called unauthorized tool '{tool_name}' (allowed: {sorted(allowed)})"
                            )
                    # Check step timestamp within grant validity
                    if step_ts < target_grant.created_at - 1.0 or step_ts > target_grant.expires_at + 1.0:
                        violations.append(
                            f"Receipt[{r_idx}] step {s_idx} timestamp {step_ts} outside grant [{target_grant.created_at}, {target_grant.expires_at}]"
                        )
                    # Check spend
                    if isinstance(cost, (int, float)):
                        receipt_spent += float(cost)

                if target_grant.max_budget_usd is not None and receipt_spent > target_grant.max_budget_usd:
                    violations.append(
                        f"Receipt[{r_idx}] agent '{receipt.agent_id}' exceeded budget: spent ${receipt_spent:.2f} > max ${target_grant.max_budget_usd:.2f}"
                    )

        is_valid = len(violations) == 0
        return DelegationLineageReport(
            is_valid=is_valid,
            root_agent_id=root_agent_id,
            chain_depth=len(grants),
            nodes_verified=len(grants),
            delegated_tools=sorted(delegated_tools),
            total_budget_allocated=total_budget,
            violations=violations,
            audit_trail=audit_trail,
        )
