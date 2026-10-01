FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk upgrade --no-cache \
    && apk add --no-cache bash git nodejs npm python3 \
    && npm install --global --prefix /opt/npm --no-audit --no-fund npm@11.19.1 \
    && /opt/npm/bin/npm install --prefix /opt/npm-patches --no-save \
        --ignore-scripts --no-audit --no-fund undici@6.28.1 brace-expansion@5.0.11 \
    && rm -rf /opt/npm/lib/node_modules/npm/node_modules/undici \
        /opt/npm/lib/node_modules/npm/node_modules/brace-expansion \
    && cp -R /opt/npm-patches/node_modules/undici \
        /opt/npm/lib/node_modules/npm/node_modules/undici \
    && cp -R /opt/npm-patches/node_modules/brace-expansion \
        /opt/npm/lib/node_modules/npm/node_modules/brace-expansion \
    && rm -rf /opt/npm-patches \
    && apk del npm \
    && addgroup -g 1000 validator \
    && adduser -D -u 1000 -G validator -h /home/validator validator \
    && install -d -m 0755 -o validator -g validator /workspace \
    && node --version \
    && /opt/npm/bin/npm --version \
    && python3 --version \
    && git --version

ENV HOME=/home/validator \
    LANG=C.UTF-8 \
    PATH=/opt/npm/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    SHELL=/bin/sh \
    TMPDIR=/tmp

USER validator:validator
WORKDIR /workspace
