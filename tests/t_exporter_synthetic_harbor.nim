import std/[strutils, unittest]

import promlite

import ../harbor_vulnerabilities_exporter

proc countOccurrences(text, needle: string): int =
  var start = 0
  while true:
    let pos = text.find(needle, start)
    if pos < 0:
      break
    inc result
    start = pos + needle.len

suite "synthetic Harbor integration":
  test "collects vulnerabilities from static Harbor responses":
    var builder = initMetricsBuilder()
    builder.collectMetrics()

    let text = $builder
    check countOccurrences(text, "harbor_image_vulnerabilities{") == 7
    check "harbor_exporter_cache_ready 1" in text
    check "harbor_exporter_last_refresh_timestamp_seconds " in text
