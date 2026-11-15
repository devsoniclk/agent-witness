import asyncio
import functools
import inspect
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Callable, Dict, Optional
from .models import StepType
from .receipt import WitnessEngine


def witness_action(
    engine: WitnessEngine,
    step_type: StepType = StepType.TOOL_CALL,
    capture_args: bool = True,
    capture_result: bool = True,
) -> Callable:
    """
    Decorator for agent tools and actions. Automatically records tool calls
    and tool results into the WitnessEngine session. Supports both sync and async functions.

    Example:
        @witness_action(engine)
        def transfer_funds(to_address: str, amount: int):
            ...

        @witness_action(engine)
        async def fetch_price(symbol: str):
            ...
    """

    def decorator(func: Callable) -> Callable:
        func_name = getattr(func, "__name__", "anonymous_action")

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                call_desc = f"{func_name}()"
                call_meta: Dict[str, Any] = {"function": func_name}

                if capture_args:
                    arg_str = ", ".join(
                        [str(a) for a in args] + [f"{k}={v}" for k, v in sorted(kwargs.items())]
                    )
                    call_desc = f"{func_name}({arg_str})"
                    call_meta["args"] = [str(a) for a in args]
                    call_meta["kwargs"] = {k: str(v) for k, v in kwargs.items()}

                engine.record_step(step_type, call_desc, metadata=call_meta)

                try:
                    res = await func(*args, **kwargs)
                    if capture_result:
                        res_desc = f"{func_name} -> {str(res)[:256]}"
                        engine.record_step(
                            StepType.TOOL_RESULT,
                            res_desc,
                            metadata={"function": func_name, "status": "success"},
                        )
                    return res
                except Exception as exc:
                    err_desc = f"{func_name} ERROR -> {type(exc).__name__}: {str(exc)[:256]}"
                    engine.record_step(
                        StepType.TOOL_RESULT,
                        err_desc,
                        metadata={"function": func_name, "status": "error", "error_type": type(exc).__name__},
                    )
                    raise

            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                call_desc = f"{func_name}()"
                call_meta: Dict[str, Any] = {"function": func_name}

                if capture_args:
                    arg_str = ", ".join(
                        [str(a) for a in args] + [f"{k}={v}" for k, v in sorted(kwargs.items())]
                    )
                    call_desc = f"{func_name}({arg_str})"
                    call_meta["args"] = [str(a) for a in args]
                    call_meta["kwargs"] = {k: str(v) for k, v in kwargs.items()}

                engine.record_step(step_type, call_desc, metadata=call_meta)

                try:
                    res = func(*args, **kwargs)
                    if capture_result:
                        res_desc = f"{func_name} -> {str(res)[:256]}"
                        engine.record_step(
                            StepType.TOOL_RESULT,
                            res_desc,
                            metadata={"function": func_name, "status": "success"},
                        )
                    return res
                except Exception as exc:
                    err_desc = f"{func_name} ERROR -> {type(exc).__name__}: {str(exc)[:256]}"
                    engine.record_step(
                        StepType.TOOL_RESULT,
                        err_desc,
                        metadata={"function": func_name, "status": "error", "error_type": type(exc).__name__},
                    )
                    raise

            return sync_wrapper

    return decorator


@contextmanager
def witness_scope(engine: WitnessEngine, scope_name: str = "deliberation"):
    """
    Synchronous context manager that records entry and exit steps in an agent workflow.
    """
    engine.record_step(StepType.THOUGHT, f"Entering scope: {scope_name}")
    try:
        yield
    finally:
        engine.record_step(StepType.THOUGHT, f"Exiting scope: {scope_name}")


@asynccontextmanager
async def async_witness_scope(engine: WitnessEngine, scope_name: str = "deliberation"):
    """
    Asynchronous context manager that records entry and exit steps in an async agent workflow.
    """
    engine.record_step(StepType.THOUGHT, f"Entering async scope: {scope_name}")
    try:
        yield
    finally:
        engine.record_step(StepType.THOUGHT, f"Exiting async scope: {scope_name}")
