#!/bin/sh
set -eu

nim c -r -d:ssl --threads:on --mm:orc \
  --nimcache:build/nimcache \
  tests/t_exporter_core.nim

nim c -r --threads:on --mm:orc \
  --nimcache:build/nimcache \
  --out:build/generate-synthetic-harbor-cache \
  tools/generate_synthetic_harbor_cache.nim \
  --out:build/synthetic-harbor-cache \
  --projects:2 \
  --repositories:3 \
  --vulnerabilities:7 \
  --description-bytes:32 \
  --seed:1 \
  --clean

nim c --threads:on --mm:orc \
  --nimcache:build/nimcache \
  --out:build/serve-static-darkhttpd \
  tools/serve_static_darkhttpd.nim

./build/serve-static-darkhttpd build/synthetic-harbor-cache 127.0.0.1 18080 \
  > build/synthetic-harbor.log 2>&1 &
harbor_pid=$!
trap 'kill "$harbor_pid" 2>/dev/null || true' EXIT

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS http://127.0.0.1:18080/api/v2.0/projects.json >/dev/null; then
    break
  fi
  sleep 0.2
done

HARBOR_API_URL=http://127.0.0.1:18080/api/v2.0 \
HARBOR_STATIC_JSON_RESPONSES=1 \
nim c -r -d:ssl --threads:on --mm:orc \
  --nimcache:build/nimcache \
  tests/t_exporter_synthetic_harbor.nim
