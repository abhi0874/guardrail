# Disposable PostgreSQL 17 test fixture. The default entrypoint uses the postgres user.
FROM postgres:17.12-alpine3.24@sha256:f9cf3e1f0066f0eb0c48707d864f0ac5941e9ff454a072077d97a4d278d07d73 AS postgres
RUN apk add --no-cache --upgrade libxml2=2.13.9-r5 libcrypto3=3.5.9-r1 libssl3=3.5.9-r1
# The fixture starts as postgres and never needs the root-only privilege switch.
RUN rm /usr/local/bin/gosu

FROM postgres AS build
# Pin the complete compiler transaction. Only the extension and its notice reach the final image.
RUN apk add --no-cache \
    binutils=2.45.1-r1 gcc=15.2.0-r5 gmp=6.3.0-r4 isl26=0.26-r2 \
    jansson=2.15.0-r0 libatomic=15.2.0-r5 libgcc-static=15.2.0-r5 libgomp=15.2.0-r5 \
    make=4.4.1-r4 mpc1=1.3.1-r1 mpfr4=4.2.2-r0 musl-dev=1.2.6-r3
ADD --checksum=sha256:cac0b10c360f05b2d521200105ba3697e773d4cd3731f5a915a7e37ebe0bea85 https://codeload.github.com/pgvector/pgvector/tar.gz/refs/tags/v0.8.7 /tmp/vector.tar.gz
WORKDIR /build
RUN tar -xzf /tmp/vector.tar.gz --strip-components=1 \
    && make OPTFLAGS="" with_llvm=no \
    && make install OPTFLAGS="" with_llvm=no DESTDIR=/out \
    && mkdir -p /out/usr/local/share/licenses/pgvector \
    && cp LICENSE /out/usr/local/share/licenses/pgvector/

FROM postgres
COPY --from=build /out/usr/local/lib/postgresql/vector.so /usr/local/lib/postgresql/
COPY --from=build /out/usr/local/share/postgresql/extension/ /usr/local/share/postgresql/extension/
COPY --from=build /out/usr/local/share/licenses/pgvector/ /usr/local/share/licenses/pgvector/
USER postgres
