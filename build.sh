#!/bin/sh
set -eu

nim_paths=""
if [ -d ../nim-promlite/src ]; then
  nim_paths="$nim_paths --path:../nim-promlite/src"
fi
if [ -d ../nim-yyjson/src ]; then
  nim_paths="$nim_paths --path:../nim-yyjson/src"
fi
if [ -d ../nim-posixglob/src ]; then
  nim_paths="$nim_paths --path:../nim-posixglob/src"
fi

nim c -d:release -d:ssl --threads:on --mm:orc $nim_paths \
  --nimcache:build/nimcache \
  --out:build/harbor-vulnerabilities-exporter \
  harbor_vulnerabilities_exporter.nim
