# Architecture

| Component | Trust boundary |
| --- | --- |
| MCP server | Validates tool inputs, authorizes server-established principals, checks quotas and approvals, and records durable audit events. |
| Private MCP transport | Stdio or authenticated loopback HTTP. This surface is intended for trusted local clients. |
| Restricted cloud ingress | Serves a fixed operation set to provisioned grants. It has distinct credentials and independent request limits. |
| Offline demo | Uses a deterministic local provider and writes synthetic, bounded recordings. Playback does not dispatch tools. |
| Storage | SQLite supports local use. PostgreSQL deployments require verified TLS, least-privilege runtime grants and a separate migration role. |
| Agent Security Scanner | Passive rules classify effects in supplied observations. Separate MCP classifiers compare operator expectations with observed audit and receipt records. The server does not invoke these evaluators. |
| Dashboard | A Next.js application displays an integrity-checked projection of historical synthetic evidence. The optional loopback lab accepts four fixed cases. Account capabilities use a separate verified session. |

See [tool contracts](TOOLS.md), [authorization](AUTHORIZATION.md), [session controls](SESSION_SECURITY.md), and [deployment status](DEPLOYMENT_STATUS.md).
