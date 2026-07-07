#!/bin/sh
set -eu

nim c -d:release -d:ssl --threads:on --mm:orc \
  --nimcache:build/nimcache \
  --out:build/harbor-vulnerabilities-exporter \
  harbor_vulnerabilities_exporter.nim
