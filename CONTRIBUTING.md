# Contributing

Use a topic branch and a pull request. For first-time contributions, useful starting points include a reproducible stdio example for a supported client, clearer installation troubleshooting, or a synthetic fixture that covers an identified gap. Open a discussion in an issue before making a broad interface or policy change.

## Local setup

- Use CPython 3.11.18, uv and Docker for MCP server work. Run `uv sync --frozen --python 3.11.18` and `uv run --frozen python -m mcp_agent_server.agent demo` from the repository root.
- Use a separate environment in `security-tests/scanner`. Run `uv sync --frozen --python 3.11.18`, `uv run --frozen pytest` and `uv run --frozen python -m agent_security_scanner.detectors validate`.
- Use Node 26 in `web`. Run `npm ci --ignore-scripts` and `npm run dev`. The recorded edition works with synthetic fixtures. Its tests use local services.

See [architecture](docs/ARCHITECTURE.md), [package interfaces](docs/DISTRIBUTION.md) and [verification commands](docs/VERIFICATION.md). Run the checks for the affected component and share the command, result and any limitations. For dependency or policy changes, explain the compatibility and security impact.

## Before opening a pull request

Describe the change, include relevant test evidence and update the docs for changed interfaces. Include provenance and applicable license notices for any bundled material. Use synthetic or anonymized data and keep credentials, account identifiers, private operations evidence and real third-party targets out of issues, commits and CI artifacts.

Follow the [code of conduct](CODE_OF_CONDUCT.md). Report suspected vulnerabilities through [private security reporting](SECURITY.md).
