#!/bin/sh
set -eu
# Compile the locked adapter against Alpine's libpq. Discard the toolchain after this stage.
apk add --no-cache \
    binutils=2.45.1-r1 gcc=15.2.0-r5 gmp=6.3.0-r4 isl26=0.26-r2 \
    jansson=2.15.0-r0 libatomic=15.2.0-r5 libgcc=15.2.0-r5 libgcc-static=15.2.0-r5 \
    libgomp=15.2.0-r5 libpq-dev=18.7-r0 libstdc++=15.2.0-r5 mpc1=1.3.1-r1 \
    mpfr4=4.2.2-r0 musl-dev=1.2.6-r3 openssl-dev=3.5.9-r1 pkgconf=2.5.1-r0 zstd-libs=1.6.0-r1
uv venv --python /usr/local/bin/python /build-env
uv pip install --python /build-env/bin/python --only-binary :all: --require-hashes -r /build-requirements.txt
uv pip install --python /build-env/bin/python --no-build-isolation --no-deps --target /adapter /tmp/psycopg_c-3.3.9.tar.gz
