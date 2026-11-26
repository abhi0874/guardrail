from pathlib import Path

import pytest

from .support import check_stdio


@pytest.mark.asyncio
async def test_real_stdio_health(tmp_path: Path) -> None:
    await check_stdio(["-m", "mcp_agent_server"], tmp_path)
