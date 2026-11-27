FROM ghcr.io/astral-sh/uv:0.13.10@sha256:a3ea1357342c1a4bf9a0c53a3deb1b55379aefa037338d8113d5771efa01774f AS uv
FROM python:3.11.18-alpine3.24@sha256:7fbad8e4652eae0186429a6f26cf5b23e27e8c6fd7ac4d0cfd7a6988cdeea1e1 AS python-base
# Use the system libpq so PostgreSQL and its TLS and Kerberos libraries receive Alpine updates.
RUN apk add --no-cache krb5-libs=1.22.3-r0 libcrypto3=3.5.9-r1 libssl3=3.5.9-r1 zlib=1.4-r0 libpq=18.7-r0 \
    && python -m pip uninstall --yes setuptools pip \
    && rm -rf /usr/local/lib/python3.11/ensurepip

FROM python-base AS adapter
COPY --from=uv /uv /usr/local/bin/uv
ADD --checksum=sha256:591fcbcb40e089235a7f096b9e887e71ccae78fd337aba198d918e33707c5e01 https://files.pythonhosted.org/packages/bc/2b/09dece13af82681cad81a70d21da76ecf37bc280a15693a3fe966751649f/psycopg_c-3.3.9.tar.gz /tmp/psycopg_c-3.3.9.tar.gz
COPY scripts/container-build-requirements.txt /build-requirements.txt
COPY scripts/build-psycopg-adapter.sh /build-adapter.sh
RUN sh /build-adapter.sh

FROM python-base AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./
COPY src ./src
COPY policies ./policies
COPY docs/DISTRIBUTION.md ./docs/DISTRIBUTION.md
RUN uv sync --frozen --no-dev --python /usr/local/bin/python

FROM python-base AS runtime
RUN addgroup -g 10001 app && adduser -D -u 10001 -G app app \
    && mkdir -p /app/.runtime/audit && chown -R app:app /app/.runtime \
    && chmod 700 /app/.runtime /app/.runtime/audit
WORKDIR /app
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
# Immutable source installation preserves the repository-relative policy/audit contract.
COPY --from=build /app/.venv ./.venv
COPY --from=adapter /adapter/ /app/.venv/lib/python3.11/site-packages/
COPY src ./src
COPY policies ./policies
COPY pyproject.toml LICENSE LICENSING.md ./
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "-m", "mcp_agent_server"]
