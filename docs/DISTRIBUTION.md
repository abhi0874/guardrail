# Guardrail Python distributions

Guardrail provides a local, policy-controlled MCP server and a separate evaluator for saved synthetic observations. The hosted dashboard and account services have their own operational scope.

## Local quickstart

Use CPython 3.11 on Linux/amd64 for the qualified setup. The metadata accepts Python 3.11 and later. Newer Python versions, non-Linux wheel installs, other CPU architectures and PyPy are unverified. Windows, where the installed server relies on POSIX owner and permission checks, is outside the supported release scope. The examples use local synthetic data and need no provider account, external target or API key. The filenames below are the proposed release artifacts.

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install ./guardrail_mcp_server-0.1.0-py3-none-any.whl
python -m mcp_agent_server.agent demo
```

A stdio client launches `guardrail-mcp-server` as a subprocess. Use the full path to the executable in the client configuration if its process has a different PATH. The server writes MCP messages to stdout and logs to stderr. This example uses the official MCP Python SDK 2.3.0, installed with the server.

```python
import asyncio
import sys

from mcp import Client, StdioServerParameters


async def main():
    process = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_agent_server"],
    )
    async with Client(process) as client:
        print([tool.name for tool in (await client.list_tools()).tools])
        print((await client.call_tool("health", {})).structured_content)


asyncio.run(main())
```

Install the offline scanner in a separate virtual environment. Its JSON Schema dependency is pinned to a different version.

```sh
python3.11 -m venv .scanner-venv
. .scanner-venv/bin/activate
python -m pip install ./guardrail_offline_scanner-0.1.0-py3-none-any.whl
python -m agent_security_scanner
guardrail-offline-scanner validate
```

The benchmark is synthetic. Eight evaluation rows share exact detector inputs with development rows. The CLI reports the evaluation and the non-overlapping subset separately. These results do not establish accuracy against production targets.

## Supported interfaces

- **MCP server.** Local stdio, the console command and module entry point, and the six published tool schemas discoverable with `tools/list`. The initial compatibility target is MCP Python SDK 2.3.0 via real stdio. Other MCP hosts may be able to launch the same command. Codex, Claude Desktop, VS Code and other GUI or CLI hosts were outside this release test scope.
- **Policy.** The version 1 YAML schema and the bundled default policy. Put an operator-owned custom policy under `~/.guardrail/policies/` and select it with `MCP_AGENT_POLICY=policies/<file>.yaml`. The existing schema, path and approval checks apply.
- **Offline Scanner.** The demo module, `guardrail-offline-scanner validate`, its JSON report, and the distributed version 1 evidence schemas. It evaluates saved evidence locally.
- **Scope.** Use the repository for development and container validation. The Python archives exclude hosted account, password recovery, cloud-operator and dashboard code. Internal Python modules, private deployment configuration and non-stdio transports are outside the public compatibility contract.

## Dependencies and upgrades

The package metadata lists exact or bounded runtime requirements. The repository lockfiles pin the tested Python dependency graphs. The MCP SDK is pinned to 2.3.0 and the PostgreSQL client line is 3.3.9 to below 3.4. Local SQLite needs no PostgreSQL client libraries. If using the PostgreSQL storage backend, install a supported, security-patched system libpq before starting the server. On minimal Alpine, use the project container or build `psycopg[c]` against your system libpq so Psycopg can find it. The release does not install the Psycopg binary wheel. The Scanner requires jsonschema 4.23.0 and Pydantic 2.14.2. The optional Gemini extra requires a separately configured provider account and is unnecessary for the quickstart.

Both distributions start at 0.1.0 and version independently. Before 1.0, announce incompatible public interface changes in minor release notes. Reserve patch releases for backward-compatible fixes and compatible dependency updates. Review the notes, back up local state, then upgrade in fresh, separate environments and rerun the quickstart before switching applications. Installed servers store local state under the owner-only `~/.guardrail` directory. Existing repository-local state stays in its checkout. Copy no credentials or private recordings into issue reports.

The distribution names differ from the earlier source-build metadata. Existing module invocation names and MCP wire service names are preserved. Use a fresh environment to avoid conflicts with prior builds or other distributions using the same import names.

## Troubleshooting

- Run `python -m pip check` in the active environment and use its full executable path in your MCP client. Keep the server and Scanner in separate environments.
- Run `python -m mcp_agent_server.agent demo` to check stdio with synthetic data. Keep logs on stderr so the MCP client receives only protocol messages on stdout.
- Ensure the installed server's `~/.guardrail` is a real directory owned by the current user and accessible only by that user. Review and back up existing local state before correcting ownership or permissions. The server rejects symlinked state paths.
- For PostgreSQL, verify that the driver loads the system libpq and that the configured hostname matches the database certificate. Use a trusted CA and `sslmode=verify-full` for remote databases. The SQLite quickstart needs no libpq.
