FROM ghcr.io/astral-sh/uv:0.13.10@sha256:a3ea1357342c1a4bf9a0c53a3deb1b55379aefa037338d8113d5771efa01774f AS uv
FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3 AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./
COPY src ./src
RUN uv sync --frozen --no-dev --python /usr/local/bin/python

FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3 AS runtime
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --create-home app \
    && mkdir -p /app/.runtime/audit && chown -R app:app /app/.runtime \
    && chmod 700 /app/.runtime /app/.runtime/audit
WORKDIR /app
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
# Immutable source installation preserves the repository-relative policy/audit contract.
COPY --from=build /app/.venv ./.venv
COPY src ./src
COPY policies ./policies
COPY pyproject.toml LICENSE LICENSING.md ./
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "-m", "mcp_agent_server"]
