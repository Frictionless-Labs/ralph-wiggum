FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS codex-installer

ARG CODEX_VERSION=0.145.0

RUN npm install --global --omit=dev --no-audit --no-fund "@openai/codex@${CODEX_VERSION}" \
    && codex --version \
    && native_binary="$(find /usr/local/lib/node_modules/@openai/codex -type f -path '*/bin/codex')" \
    && test -n "$native_binary" \
    && test "$(printf '%s\n' "$native_binary" | wc -l)" -eq 1 \
    && native_root="$(dirname "$(dirname "$native_binary")")" \
    && install --directory /tmp/codex-native \
    && cp -R "$native_root/." /tmp/codex-native/

FROM cgr.dev/chainguard/wolfi-base@sha256:824f77df45397eb954dfb963db255907ee8842e3446353ce93d688e5e862f51d AS helper-builder

RUN apk add --no-cache build-base linux-headers

COPY capcheck.c /tmp/capcheck.c
COPY netcheck.c /tmp/netcheck.c
RUN cc -static -O2 -Wall -Wextra -Werror /tmp/capcheck.c -o /tmp/ralph-capcheck \
    && cc -static -O2 -Wall -Wextra -Werror /tmp/netcheck.c -o /tmp/ralph-netcheck

FROM cgr.dev/chainguard/wolfi-base@sha256:824f77df45397eb954dfb963db255907ee8842e3446353ce93d688e5e862f51d

COPY --from=codex-installer /tmp/codex-native/ /opt/codex/
COPY --from=helper-builder /tmp/ralph-capcheck /usr/local/bin/ralph-capcheck
COPY --from=helper-builder /tmp/ralph-netcheck /usr/local/bin/ralph-netcheck

RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates \
    && ln -s /opt/codex/bin/codex /usr/local/bin/codex \
    && addgroup -g 1000 node \
    && adduser -D -u 1000 -G node -h /home/node node \
    && install -d -m 0755 -o node -g node /home/node/.codex /workspace \
    && codex --version

ENV HOME=/home/node \
    LANG=C.UTF-8 \
    SHELL=/bin/sh \
    TMPDIR=/tmp

USER node:node
WORKDIR /workspace
ENTRYPOINT ["codex"]
