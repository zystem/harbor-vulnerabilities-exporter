import std/[strutils, unittest]

import promlite
import yyjson

import ../src/harbor_vulnerabilities_exporter

suite "pattern matching":
  test "matches exact and wildcard patterns":
    check matchPattern("project-a", "project-a")
    check not matchPattern("project-a", "project-b")
    check matchPattern("project-a", "project-*")
    check matchPattern("project-a", "*-a")
    check matchPattern("project-a", "*ject*")
    check matchPattern("project-a", "pro*a")
    check matchPattern("project-a", "project-?")
    check matchPattern("project-a", "project-[abc]")
    check not matchPattern("project-aa", "project-?")

  test "matches any pattern":
    check matchesAny("repo/library/app", @["test/*", "repo/*"])
    check not matchesAny("repo/library/app", @["test/*", "other/*"])

  test "uses posixglob syntax for Harbor filters":
    check matchPattern("project-a", "project-[ab]")
    check not matchPattern("project-c", "project-[ab]")
    check matchPattern("project-c", "project-[!ab]")
    check matchPattern("repo/library/app", "repo/*/app")
    check matchPattern("repo/library/app", "repo*app")
    check matchPattern("repo-*", r"repo-\*")
    check not matchPattern("repo-abc", r"repo-\*")

suite "url normalization":
  test "keeps absolute vulnerability hrefs intact":
    let href = "https://harbor.example/api/v2.0/projects/p/repositories/r/artifacts/a/additions/vulnerabilities"
    check normalizeVulnerabilitiesHref("https://proxy.example/api/v2.0", href) == href

  test "joins relative Harbor hrefs with configured API base":
    let href = "/api/v2.0/projects/p/repositories/r/artifacts/a/additions/vulnerabilities"
    check normalizeVulnerabilitiesHref("https://harbor.example/api/v2.0/", href) ==
      "https://harbor.example/api/v2.0/projects/p/repositories/r/artifacts/a/additions/vulnerabilities"

suite "metric emission":
  test "writes escaped Prometheus labels through promlite":
    var doc = readJson("""
      {
        "id": "CVE-2026-1234",
        "package": "pkg\"name",
        "version": "1.0\\beta",
        "fix_version": "1.0.1",
        "severity": "High"
      }
    """)
    defer:
      doc.close()

    var builder = initMetricsBuilder()
    builder.writeMetricLine(doc.root(), "project-a", "repo-a")

    let text = $builder
    check "harbor_image_vulnerabilities" in text
    check "id=\"CVE-2026-1234\"" in text
    check "package=\"pkg\\\"name\"" in text
    check "version=\"1.0\\\\beta\"" in text
    check "project=\"project-a\"" in text
    check "repository=\"repo-a\"" in text
