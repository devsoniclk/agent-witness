from __future__ import annotations

import time
import pytest

from agent_witness.models import StepType, DeliberationStep
from agent_witness.streaming import (
    StreamingActionSession,
    StreamingStepReceipt,
    DeliberationProvenanceTracker,
    CausalProvenanceRecord,
)


def test_streaming_action_session_accumulates():
    session = StreamingActionSession(
        session_id="stream-sess-1",
        agent_id="test-agent",
    )
    r1 = session.append_step(StepType.THOUGHT, "Analyzing swap route on Raydium.")
    assert isinstance(r1, StreamingStepReceipt)
    assert r1.step_index == 0
    assert r1.rolling_merkle_root is not None
    assert len(r1.rolling_merkle_root) == 64

    r2 = session.append_step(StepType.TOOL_CALL, "execute_swap", metadata={"amount": 100})
    assert r2.step_index == 1
    assert r2.causal_parent_hash == r1.leaf_hash

    summary = session.get_session_summary()
    assert summary["session_id"] == "stream-sess-1"
    assert summary["step_count"] == 2
    assert summary["intermediate_receipt_count"] == 2


def test_deliberation_provenance_groundedness():
    t0 = time.time()
    steps = [
        DeliberationStep(StepType.OBSERVATION, 0, "Account balance is 5.2 SOL", timestamp=t0),
        DeliberationStep(StepType.THOUGHT, 1, "Deciding to hedge perp exposure.", timestamp=t0 + 0.1),
        DeliberationStep(StepType.TOOL_CALL, 2, "place_order", metadata={"side": "short"}, timestamp=t0 + 0.2),
        DeliberationStep(StepType.TOOL_CALL, 3, "ungrounded_panic_close", timestamp=t0 + 0.3),
    ]

    records = DeliberationProvenanceTracker.audit_groundedness(steps, max_reasoning_gap_ms=5000.0)
    assert len(records) == 2

    # Step 2: grounded by preceding thought & observation
    assert records[0].step_index == 2
    assert records[0].grounded is True
    assert 1 in records[0].prior_thought_indices

    # Step 3: immediately follows tool call with no intermediate thought
    assert records[1].step_index == 3
    assert records[1].grounded is False
    assert len(records[1].warnings) > 0
