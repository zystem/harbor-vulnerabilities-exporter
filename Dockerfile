FROM nimlang/nim:2.2.4-alpine AS builder

WORKDIR /src

RUN apk add --no-cache \
    gcc \
    musl-dev \
    openssl-dev \
    git

COPY harbor_vulnerabilities_exporter.nimble .
RUN nimble install -y --depsOnly

COPY src src
RUN nimble buildExporter && cp build/harbor-vulnerabilities-exporter /out/harbor-vulnerabilities-exporter

FROM alpine:3.20

RUN apk add --no-cache ca-certificates curl

RUN mkdir -p /data && chown 65534:65534 /data

COPY --from=builder /out/harbor-vulnerabilities-exporter /usr/local/bin/harbor-vulnerabilities-exporter

USER 65534:65534

EXPOSE 9090

ENTRYPOINT ["/usr/local/bin/harbor-vulnerabilities-exporter"]
