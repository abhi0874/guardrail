#!/usr/bin/env bash
set -euo pipefail
export UV_OFFLINE=1 PYTHONDONTWRITEBYTECODE=1
export MYPYPATH="${PYTHONPATH:-}"
mkdir -p .cache/reports
uv lock --check
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy src tests
uv run --frozen pytest -q --junitxml=.cache/pytest.xml --cov-report=xml:.cache/coverage.xml
uv run --frozen python -m mcp_agent_server.agent demo

uv run --frozen python - <<'PYTHON'
import json
from pathlib import Path
from xml.etree import ElementTree as E
suite=E.parse('.cache/pytest.xml').getroot().find('testsuite')
coverage=E.parse('.cache/coverage.xml').getroot()
Path('.cache/reports/test-summary.json').write_text(json.dumps({
 'tests':int(suite.attrib['tests']), 'failures':int(suite.attrib['failures']),
 'errors':int(suite.attrib['errors']), 'skipped':int(suite.attrib['skipped']),
 'line_rate':float(coverage.attrib['line-rate'])
}))
PYTHON
