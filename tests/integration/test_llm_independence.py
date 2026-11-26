import ast
import sys
from pathlib import Path

import pytest

import mcp_agent_server

from .support import check_stdio

# Instrument the child before the installed module's entry point. Any attempted access
# emits a non-JSON stderr line so the test fails even if a dependency swallows the error.
GUARDED_START = """
import importlib.abc
import os
import runpy
import socket
import sys

class BlockProviders(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        blocked = ('mcp_agent_server.llm', 'ollama', 'google.genai', 'google.generativeai')
        if any(fullname == p or fullname.startswith(p + '.') for p in blocked):
            print('Forbidden provider import', file=sys.stderr)
            raise ModuleNotFoundError('Provider access forbidden')
        return None

def offline(event, args):
    internet_socket = event == 'socket.__new__' and args[1] in (socket.AF_INET, socket.AF_INET6)
    if internet_socket or event in ('socket.connect', 'socket.getaddrinfo', 'socket.gethostbyname'):
        print('Forbidden network operation', file=sys.stderr)
        raise RuntimeError('Network unavailable')

sys.meta_path.insert(0, BlockProviders())
sys.addaudithook(offline)
for key in ('OLLAMA_MODEL', 'OLLAMA_HOST', 'GEMINI_API_KEY', 'GOOGLE_API_KEY'):
    assert key not in os.environ
runpy.run_module('mcp_agent_server', run_name='__main__', alter_sys=True)
"""


def test_import_boundary() -> None:
    package = Path(mcp_agent_server.__file__).parent
    for source in package.rglob("*.py"):
        for node in ast.walk(ast.parse(source.read_text())):
            if isinstance(node, ast.Import):
                names = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "") + "." + item.name for item in node.names]
            else:
                continue
            assert all("llm" not in name.split(".") for name in names), source.name


@pytest.mark.asyncio
async def test_stdio_with_provider_imports_and_network_blocked(tmp_path: Path) -> None:
    assert "mcp_agent_server.llm" not in sys.modules
    await check_stdio(["-c", GUARDED_START], tmp_path)
