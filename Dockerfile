FROM nimlang/nim:2.2.4-alpine AS builder

WORKDIR /src

RUN apk add --no-cache \
    gcc \
    musl-dev \
    openssl-dev \
    git

RUN nimble install -y \
    https://github.com/zystem/nim-yyjson \
    https://github.com/zystem/nim-promlite \
    https://github.com/zystem/nim-posixglob

COPY harbor_vulnerabilities_exporter.nim .

RUN nim c \
    -d:release \
    -d:ssl \
    --threads:on \
    --mm:orc \
    --out:/out/harbor-vulnerabilities-exporter \
    harbor_vulnerabilities_exporter.nim

FROM alpine:3.20

RUN apk add --no-cache ca-certificates curl

RUN mkdir -p /data && chown 65534:65534 /data

COPY --from=builder /out/harbor-vulnerabilities-exporter /usr/local/bin/harbor-vulnerabilities-exporter

USER 65534:65534

EXPOSE 9090

ENTRYPOINT ["/usr/local/bin/harbor-vulnerabilities-exporter"]
