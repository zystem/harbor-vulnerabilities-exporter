# Package
version       = "1.1.1"
author        = "Andrii Zagriadskyi"
description   = "Prometheus exporter for Harbor vulnerability reports"
license       = "MIT"

srcDir = "src"

bin = @["harbor_vulnerabilities_exporter"]

# Dependencies

requires "nim >= 2.2.0"
requires "yyjson == 1.0.0"
requires "promlite == 0.2.0"
requires "posixglob == 0.1.6"

# Tasks

task buildExporter, "Builds the release binary":
  mkDir "build"
  exec "nim c -d:release -d:ssl --threads:on --mm:orc --nimcache:build/nimcache --out:build/harbor-vulnerabilities-exporter src/harbor_vulnerabilities_exporter.nim"

task test, "Runs unit and synthetic Harbor integration tests":
  exec "nim c -r --threads:on --mm:orc --nimcache:build/nimcache tests/tester.nim"
