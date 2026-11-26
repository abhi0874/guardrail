# Agent Security Scanner

This package evaluates saved observations against a supplied authorization context. It includes the original rules, advisory judge interface, metrics, reporting types and read-only API response schemas. The MCP server has its own environment.

From this directory, install with `uv sync --frozen --python 3.11.15`. Run the following commands in the checkout.

```sh
uv run --frozen python -m agent_security_scanner
uv run --frozen python -m agent_security_scanner.detectors validate
uv run --frozen pytest -q
```

The four constructed examples demonstrate verdict semantics. The separate frozen benchmark has 55 development cases and 120 evaluation cases. Eight evaluation rows share exact detector inputs with development rows. The evaluator checks file hashes and split membership. It prints the full evaluation and the 112-row subset with no exact development-input matches. The wheel also contains the benchmark data and public JSON schemas.

See [detector methodology](DETECTOR-METHODOLOGY.md) for coverage and limitations. The reference application, external-target adapters, attack launcher and raw saved runs are excluded. The dashboard displays a reduced historical record that omits submitted payloads.
