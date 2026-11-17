from __future__ import annotations

import pytest

from agent_witness.consensus import (
    BFTConsensusCertificate,
    BFTVote,
    BFTVoteType,
    ByzantineConsensusEngine,
    ByzantineFaultType,
    EquivocationDetector,
    verify_bft_certificate,
)
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine
from agent_witness.signer import AgentSigner


def _create_sample_receipt():
    engine = WitnessEngine(
        agent_id="lead-planner",
        model_id="o3-mini",
        system_prompt="Strategic Planner",
    )
    engine.record_step(StepType.OBSERVATION, "Liquidity depth verified on Hyperliquid")
    engine.record_step(StepType.TOOL_CALL, "hyperliquid.market_order('BTC-PERP', size=1.5)")
    engine.record_step(StepType.DECISION, "Execute delta-neutral hedge")
    return engine.finalize_receipt()


def test_bft_consensus_honest_quorum():
    """
    Test standard honest 4-node Byzantine consensus:
    N = 4, f = 1, Quorum = 2f + 1 = 3 out of 4 nodes.
    """
    receipt = _create_sample_receipt()
    validators = {
        "agent-alpha": 1,
        "agent-bravo": 1,
        "agent-charlie": 1,
        "agent-delta": 1,
    }
    signers = {
        "agent-alpha": AgentSigner(),
        "agent-bravo": AgentSigner(),
        "agent-charlie": AgentSigner(),
        "agent-delta": AgentSigner(),
    }

    engine = ByzantineConsensusEngine.from_receipt(
        receipt=receipt,
        validators=validators,
        signers=signers,
    )

    assert engine.total_validators == 4
    assert engine.f == 1
    assert engine.quorum_threshold == 3  # (2*4)//3 + 1 = 3

    # Phase 1: Pre-votes
    for agent_id in ["agent-alpha", "agent-bravo", "agent-charlie"]:
        vote, ev = engine.cast_prevote(
            signer=signers[agent_id],
            agent_id=agent_id,
            verdict="APPROVE",
            round=1,
        )
        assert vote is not None
        assert ev is None

    assert engine.has_prevote_quorum(round=1) is True

    # Phase 2: Pre-commits
    for agent_id in ["agent-alpha", "agent-bravo", "agent-charlie"]:
        vote, ev = engine.cast_precommit(
            signer=signers[agent_id],
            agent_id=agent_id,
            verdict="APPROVE",
            round=1,
        )
        assert vote is not None
        assert ev is None

    assert engine.has_precommit_quorum(round=1) is True

    # Finalize certificate
    cert = engine.finalize(round=1)
    assert cert.is_finalized is True
    assert cert.committed_weight == 3
    assert len(cert.slashed_agents) == 0

    # Forensic verification
    is_valid, report = verify_bft_certificate(cert, signers=signers)
    assert is_valid is True
    assert report["quorum_satisfied"] is True
    assert report["valid_precommit_weight"] == 3
    assert len(report["signature_failures"]) == 0


def test_bft_consensus_equivocation_detection_and_slashing():
    """
    Test Byzantine equivocation detection:
    A malicious validator votes APPROVE on one root and APPROVE on another root in the same round.
    The engine slashes the validator, creates cryptographic evidence, and excludes it from quorum.
    """
    receipt = _create_sample_receipt()
    validators = {
        "agent-honest-1": 1,
        "agent-honest-2": 1,
        "agent-byzantine": 1,
        "agent-honest-3": 1,
    }
    signers = {
        "agent-honest-1": AgentSigner(),
        "agent-honest-2": AgentSigner(),
        "agent-byzantine": AgentSigner(),
        "agent-honest-3": AgentSigner(),
    }

    engine = ByzantineConsensusEngine.from_receipt(
        receipt=receipt,
        validators=validators,
        signers=signers,
    )

    # Honest agents prevote
    engine.cast_prevote(signers["agent-honest-1"], "agent-honest-1", "APPROVE", round=1)
    engine.cast_prevote(signers["agent-honest-2"], "agent-honest-2", "APPROVE", round=1)

    # Byzantine agent votes first on legitimate root
    vote1, ev1 = engine.cast_prevote(signers["agent-byzantine"], "agent-byzantine", "APPROVE", round=1)
    assert vote1 is not None
    assert ev1 is None

    # Byzantine agent equivocates: votes on a different fraudulent root in same round
    fraud_root = "0xdeadbeef" * 8
    vote2, ev2 = engine.cast_prevote(signers["agent-byzantine"], "agent-byzantine", "APPROVE", merkle_root=fraud_root, round=1)
    assert vote2 is None
    assert ev2 is not None
    assert ev2.fault_type == ByzantineFaultType.EQUIVOCATION
    assert ev2.agent_id == "agent-byzantine"
    assert "agent-byzantine" in engine.slashed_agents

    # With byzantine node slashed, we have only 2 valid votes (need 3)
    assert engine.has_prevote_quorum(round=1) is False

    # 3rd honest agent arrives
    engine.cast_prevote(signers["agent-honest-3"], "agent-honest-3", "APPROVE", round=1)
    assert engine.has_prevote_quorum(round=1) is True

    # Precommit phase: honest agents precommit
    engine.cast_precommit(signers["agent-honest-1"], "agent-honest-1", "APPROVE", round=1)
    engine.cast_precommit(signers["agent-honest-2"], "agent-honest-2", "APPROVE", round=1)
    engine.cast_precommit(signers["agent-honest-3"], "agent-honest-3", "APPROVE", round=1)

    cert = engine.finalize(round=1)
    assert cert.is_finalized is True
    assert "agent-byzantine" in cert.slashed_agents
    assert len(cert.evidence) >= 1

    is_valid, report = verify_bft_certificate(cert, signers=signers)
    assert is_valid is True
    assert "agent-byzantine" in report["slashed_agents"]


def test_bft_consensus_insufficient_quorum():
    """
    Test when insufficient honest nodes approve (2 reject out of 4).
    Quorum must fail.
    """
    receipt = _create_sample_receipt()
    validators = {"a1": 1, "a2": 1, "a3": 1, "a4": 1}
    signers = {k: AgentSigner() for k in validators}

    engine = ByzantineConsensusEngine.from_receipt(receipt, validators=validators, signers=signers)

    engine.cast_prevote(signers["a1"], "a1", "APPROVE", round=1)
    engine.cast_prevote(signers["a2"], "a2", "REJECT", round=1)
    engine.cast_prevote(signers["a3"], "a3", "REJECT", round=1)
    engine.cast_prevote(signers["a4"], "a4", "APPROVE", round=1)

    assert engine.has_prevote_quorum(round=1) is False

    engine.cast_precommit(signers["a1"], "a1", "APPROVE", round=1)
    engine.cast_precommit(signers["a4"], "a4", "APPROVE", round=1)

    cert = engine.finalize(round=1)
    assert cert.is_finalized is False
    assert cert.committed_weight == 2

    is_valid, report = verify_bft_certificate(cert, signers=signers)
    assert is_valid is False
    assert report["quorum_satisfied"] is False


def test_bft_weighted_consensus():
    """
    Test weighted validator sets:
    Lead Architect: weight 3
    Security Auditor: weight 2
    Junior Worker: weight 1
    Total weight: 6. Quorum = (2 * 6)//3 + 1 = 5.
    Architect (3) + Auditor (2) = 5 (Satisfies quorum without worker).
    """
    receipt = _create_sample_receipt()
    validators = {
        "lead-architect": 3,
        "security-auditor": 2,
        "worker-agent": 1,
    }
    signers = {k: AgentSigner() for k in validators}

    engine = ByzantineConsensusEngine.from_receipt(receipt, validators=validators, signers=signers)
    assert engine.total_weight == 6
    assert engine.quorum_threshold == 5

    # Architect and auditor approve
    engine.cast_prevote(signers["lead-architect"], "lead-architect", "APPROVE", round=1)
    engine.cast_prevote(signers["security-auditor"], "security-auditor", "APPROVE", round=1)
    assert engine.has_prevote_quorum(round=1) is True

    engine.cast_precommit(signers["lead-architect"], "lead-architect", "APPROVE", round=1)
    engine.cast_precommit(signers["security-auditor"], "security-auditor", "APPROVE", round=1)
    assert engine.has_precommit_quorum(round=1) is True

    cert = engine.finalize(round=1)
    assert cert.is_finalized is True
    assert cert.committed_weight == 5

    is_valid, report = verify_bft_certificate(cert, signers=signers)
    assert is_valid is True
    assert report["valid_precommit_weight"] == 5


def test_equivocation_detector_standalone_audit():
    """Test standalone batch audit across multiple vote records."""
    signer = AgentSigner()
    vote_a = BFTVote(
        agent_id="rogue-node",
        agent_pubkey=signer.pubkey_hex,
        round=2,
        vote_type=BFTVoteType.PRECOMMIT,
        merkle_root="0xaaaa" * 16,
        verdict="APPROVE",
        timestamp=1000.0,
    )
    vote_a.signature = signer.sign(vote_a.get_signing_payload())

    vote_b = BFTVote(
        agent_id="rogue-node",
        agent_pubkey=signer.pubkey_hex,
        round=2,
        vote_type=BFTVoteType.PRECOMMIT,
        merkle_root="0xbbbb" * 16,
        verdict="APPROVE",
        timestamp=1001.0,
    )
    vote_b.signature = signer.sign(vote_b.get_signing_payload())

    detector = EquivocationDetector()
    evidence = detector.audit_votes([vote_a, vote_b], signers={"rogue-node": signer})

    assert len(evidence) == 1
    assert evidence[0].fault_type == ByzantineFaultType.EQUIVOCATION
    assert evidence[0].agent_id == "rogue-node"
    assert evidence[0].round == 2


def test_bft_mcp_server_integration():
    """Verify MCP tools witness_bft_consensus_run and witness_detect_equivocation."""
    import tempfile
    from agent_witness.mcp_server import WitnessMCPServer

    with tempfile.TemporaryDirectory() as td:
        srv = WitnessMCPServer(log_dir=td)
        res = srv.handle_call_tool(
            "witness_bft_consensus_run",
            {
                "merkle_root": "0x1234567890abcdef" * 4,
                "validators": {"node-1": 1, "node-2": 1, "node-3": 1, "node-4": 1},
            },
        )
        assert "certificate" in res
        assert res["certificate"]["is_finalized"] is True
        assert res["verification"]["quorum_satisfied"] is True

        # Test equivocation detector tool
        vote1 = {
            "agent_id": "bad-node",
            "agent_pubkey": "0x11",
            "round": 1,
            "vote_type": "PREVOTE",
            "merkle_root": "0x1111" * 16,
            "verdict": "APPROVE",
            "timestamp": 100.0,
        }
        vote2 = {
            "agent_id": "bad-node",
            "agent_pubkey": "0x11",
            "round": 1,
            "vote_type": "PREVOTE",
            "merkle_root": "0x2222" * 16,
            "verdict": "APPROVE",
            "timestamp": 101.0,
        }
        eq_res = srv.handle_call_tool("witness_detect_equivocation", {"votes": [vote1, vote2]})
        assert eq_res["evidence_count"] == 1
        assert eq_res["evidence"][0]["agent_id"] == "bad-node"
