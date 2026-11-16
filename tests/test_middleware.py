import asyncio
import pytest
from agent_witness.middleware import async_witness_scope, witness_action, witness_scope
from agent_witness.models import StepType
from agent_witness.receipt import WitnessEngine


def test_sync_witness_action_decorator():
    engine = WitnessEngine(
        agent_id="test-agent",
        model_id="claude-3-7-sonnet",
        system_prompt="Test agent",
    )

    @witness_action(engine)
    def calculate_trade_size(balance: float, risk_pct: float) -> float:
        return balance * risk_pct

    size = calculate_trade_size(10000.0, risk_pct=0.02)
    assert size == 200.0

    # Must record 2 steps: TOOL_CALL and TOOL_RESULT
    assert len(engine.steps) == 2
    assert engine.steps[0].step_type == StepType.TOOL_CALL
    assert "calculate_trade_size" in engine.steps[0].content
    assert "10000.0" in engine.steps[0].content

    assert engine.steps[1].step_type == StepType.TOOL_RESULT
    assert "200.0" in engine.steps[1].content


def test_sync_witness_action_exception():
    engine = WitnessEngine(
        agent_id="test-agent",
        model_id="claude-3-7-sonnet",
        system_prompt="Test agent",
    )

    @witness_action(engine)
    def risky_operation():
        raise ValueError("Insufficient liquidity")

    with pytest.raises(ValueError, match="Insufficient liquidity"):
        risky_operation()

    assert len(engine.steps) == 2
    assert engine.steps[1].step_type == StepType.TOOL_RESULT
    assert "ERROR" in engine.steps[1].content
    assert "ValueError" in engine.steps[1].content


def test_async_witness_action_decorator():
    async def _run():
        engine = WitnessEngine(
            agent_id="async-agent",
            model_id="gpt-4o",
            system_prompt="Async test",
        )

        @witness_action(engine)
        async def async_fetch_oracle(symbol: str) -> dict:
            await asyncio.sleep(0.01)
            return {"symbol": symbol, "price": 93250.0}

        data = await async_fetch_oracle("BTC/USD")
        assert data["price"] == 93250.0

        assert len(engine.steps) == 2
        assert engine.steps[0].step_type == StepType.TOOL_CALL
        assert "async_fetch_oracle" in engine.steps[0].content
        assert engine.steps[1].step_type == StepType.TOOL_RESULT
        assert "93250.0" in engine.steps[1].content

    asyncio.run(_run())


def test_witness_scope_context_manager():
    engine = WitnessEngine("agent", "model", "prompt")

    with witness_scope(engine, scope_name="market_analysis"):
        engine.record_step(StepType.OBSERVATION, "Orderbook depth analyzed")

    assert len(engine.steps) == 3
    assert "Entering scope: market_analysis" in engine.steps[0].content
    assert "Orderbook depth analyzed" in engine.steps[1].content
    assert "Exiting scope: market_analysis" in engine.steps[2].content


def test_async_witness_scope_context_manager():
    async def _run():
        engine = WitnessEngine("agent", "model", "prompt")

        async with async_witness_scope(engine, scope_name="subsecond_deliberation"):
            await asyncio.sleep(0.01)
            engine.record_step(StepType.DECISION, "Execution confirmed")

        assert len(engine.steps) == 3
        assert "Entering async scope: subsecond_deliberation" in engine.steps[0].content
        assert "Exiting async scope: subsecond_deliberation" in engine.steps[2].content

    asyncio.run(_run())
