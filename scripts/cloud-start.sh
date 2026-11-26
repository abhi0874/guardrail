#!/usr/bin/env sh
set -eu
# Production validation happens before binding either listener. No migrations here.
exec python -m mcp_agent_server.cloud
