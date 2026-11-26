import asyncio
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from pydantic import ValidationError

from mcp_agent_server.errors import ConfigurationError
from mcp_agent_server.guardrails.rate_limiting import RateDenial, RateLimiter, process_limiter
from mcp_agent_server.guardrails.security_settings import RateSettings


@pytest.mark.asyncio
async def test_burst_refill_rollback_and_clock() -> None:
    clock = [0.0]
    limiter = RateLimiter(
        RateSettings(
            connection_capacity=2, global_capacity=3, connection_refill=1, global_refill=1
        ),
        lambda: clock[0],
    )
    a, b = uuid4(), uuid4()
    await limiter.admit(a)
    await limiter.admit(a)
    with pytest.raises(RateDenial) as denied:
        await limiter.admit(a)
    assert "(connection)" in denied.value.public.message
    assert limiter._global.tokens == 1
    await limiter.admit(b)
    with pytest.raises(RateDenial) as denied:
        await limiter.admit(b)
    assert "(global)" in denied.value.public.message
    assert limiter._connections[b].tokens == 1
    clock[0] = -10
    with pytest.raises(RateDenial):
        await limiter.admit(a)
    clock[0] = 1
    await limiter.admit(a)
    assert limiter._connections[a].tokens == 0
    clock[0] = 100
    await limiter.admit(b)
    assert limiter._global.tokens == 2 and limiter._connections[b].tokens == 1


@pytest.mark.asyncio
async def test_async_and_multithread_atomicity() -> None:
    limiter = RateLimiter(RateSettings(global_capacity=7), lambda: 0)

    async def attempt() -> bool:
        try:
            await limiter.admit(uuid4())
            return True
        except RateDenial:
            return False

    assert sum(await asyncio.gather(*(attempt() for _ in range(50)))) == 7
    limiter = RateLimiter(RateSettings(global_capacity=7), lambda: 0)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: asyncio.run(attempt()), range(50)))
    assert sum(results) == 7 and limiter._global.tokens == 0
    print("concurrent_attempts=50 accepted=7 quota=7 remaining=0")


@pytest.mark.asyncio
async def test_bounded_retention_never_resets_underfilled_bucket() -> None:
    now = [0.0]
    limit = RateLimiter(
        RateSettings(
            max_connections=1, connection_capacity=2, connection_refill=0.001, retention=1
        ),
        lambda: now[0],
    )
    first = uuid4()
    await limit.admit(first)
    now[0] = 2
    with pytest.raises(RateDenial) as denied:
        await limit.admit(uuid4())
    assert "(connection capacity)" in denied.value.public.message
    assert len(limit._connections) == 1
    now[0] = 1001
    await limit.admit(uuid4())
    assert len(limit._connections) == 1 and first not in limit._connections


@pytest.mark.parametrize(
    "data",
    [
        {"global_capacity": 0},
        {"connection_capacity": -1},
        {"connection_refill": 0},
        {"global_refill": float("nan")},
        {"global_refill": float("inf")},
        {"retention": -1},
        {"max_connections": 100000},
    ],
)
def test_invalid_rates(data: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        RateSettings.model_validate(data)


def test_shared_process_configuration() -> None:
    defaults = RateSettings()
    assert process_limiter(defaults) is process_limiter(defaults)
    with pytest.raises(ConfigurationError):
        process_limiter(RateSettings(global_capacity=1))
    with pytest.raises(ValueError):
        RateLimiter(defaults, lambda: float("nan"))


@pytest.mark.asyncio
async def test_connection_concurrency_and_invalid_clock() -> None:
    now = [0.0]
    limiter = RateLimiter(RateSettings(connection_capacity=3, global_capacity=10), lambda: now[0])
    conn = uuid4()

    async def attempt() -> bool:
        try:
            await limiter.admit(conn)
            return True
        except RateDenial:
            return False

    assert sum(await asyncio.gather(*(attempt() for _ in range(50)))) == 3
    assert limiter._global.tokens == 7
    assert limiter._connections[conn].tokens == 0
    now[0] = float("nan")
    with pytest.raises(RateDenial) as denied:
        await limiter.admit(uuid4())
    assert "(clock)" in denied.value.public.message and limiter._global.tokens == 7
    print("same_connection_attempts=50 accepted=3 global_remaining=7")
