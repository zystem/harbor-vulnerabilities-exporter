import mummy, mummy/routers
import std/[httpclient, json, os, strutils, sequtils, uri, base64, times, tables, locks]

const MetricsHeader = """
# HELP harbor_image_vulnerabilities Vulnerabilities found in the latest pushed image in every repository
# TYPE harbor_image_vulnerabilities gauge
"""

let harborApiUrl = getEnv("HARBOR_API_URL").strip(chars = {'/'})
let harborUsername = getEnv("HARBOR_USERNAME")
let harborPassword = getEnv("HARBOR_PASSWORD")
let exporterPort = parseInt(getEnv("EXPORTER_PORT", "8080"))
let refreshIntervalSeconds = parseInt(getEnv("REFRESH_INTERVAL_SECONDS", "600"))

let includeProjects =
  getEnv("INCLUDE_PROJECTS", "")
    .split(',')
    .mapIt(it.strip())
    .filterIt(it.len > 0)

let excludeProjects =
  getEnv("EXCLUDE_PROJECTS", "")
    .split(',')
    .mapIt(it.strip())
    .filterIt(it.len > 0)

let includeRepositories =
  getEnv("INCLUDE_REPOSITORIES", "")
    .split(',')
    .mapIt(it.strip())
    .filterIt(it.len > 0)

let excludeRepositories =
  getEnv("EXCLUDE_REPOSITORIES", "")
    .split(',')
    .mapIt(it.strip())
    .filterIt(it.len > 0)

var cacheLock: Lock
var metricsCache = MetricsHeader & "\nharbor_exporter_cache_ready 0\n"

initLock(cacheLock)

if harborApiUrl.len == 0:
  stderr.writeLine("HARBOR_API_URL env variable is required.")
  quit(2)

proc logInfo(msg: string) =
  echo now().format("yyyy-MM-dd HH:mm:ss','fff") & " - INFO - " & msg

proc logError(msg: string) =
  stderr.writeLine(now().format("yyyy-MM-dd HH:mm:ss','fff") & " - ERROR - " & msg)

proc matchPattern(value, pattern: string): bool =
  if pattern == "*":
    return true

  if not pattern.contains('*'):
    return value == pattern

  if pattern.startsWith('*') and pattern.endsWith('*'):
    let p = pattern[1 .. ^2]
    return value.contains(p)

  if pattern.startsWith('*'):
    return value.endsWith(pattern[1 .. ^1])

  if pattern.endsWith('*'):
    return value.startsWith(pattern[0 .. ^2])

  let parts = pattern.split('*')
  return value.startsWith(parts[0]) and
         value.endsWith(parts[^1])

proc matchesAny(value: string, patterns: seq[string]): bool =
  for pattern in patterns:
    if matchPattern(value, pattern):
      return true
  return false

proc shouldProcessProject(projectName: string): bool =
  if includeProjects.len > 0 and not matchesAny(projectName, includeProjects):
    logInfo("Project " & projectName & " does not match include rules. Skipping.")
    return false

  if matchesAny(projectName, excludeProjects):
    logInfo("Project " & projectName & " matches exclude rules. Skipping.")
    return false

  return true

proc shouldProcessRepository(repoName: string): bool =
  if includeRepositories.len > 0 and not matchesAny(repoName, includeRepositories):
    logInfo("Repository " & repoName & " does not match include rules. Skipping.")
    return false

  if matchesAny(repoName, excludeRepositories):
    logInfo("Repository " & repoName & " matches exclude rules. Skipping.")
    return false

  return true

proc authHeaders(): httpclient.HttpHeaders =
  result = httpclient.newHttpHeaders()
  if harborUsername.len > 0 and harborPassword.len > 0:
    result["Authorization"] = "Basic " & encode(harborUsername & ":" & harborPassword)

proc promEscape(s: string): string =
  result = s
  result = result.replace("\\", "\\\\")
  result = result.replace("\n", "\\n")
  result = result.replace("\"", "\\\"")

proc metricLine(v: JsonNode, project, repo: string): string =
  let labels = {
    "id": v{"id"}.getStr(""),
    "package": v{"package"}.getStr(""),
    "version": v{"version"}.getStr(""),
    "fix_version": v{"fix_version"}.getStr(""),
    "severity": v{"severity"}.getStr(""),
    "project": project,
    "repository": repo
  }.toTable

  var parts: seq[string] = @[]
  for k, val in labels:
    parts.add(k & "=\"" & promEscape(val) & "\"")

  return "harbor_image_vulnerabilities{" & parts.join(",") & "} 1"

proc httpGetJson(url: string): JsonNode =
  var client = httpclient.newHttpClient(headers = authHeaders())
  defer:
    client.close()

  return parseJson(client.getContent(url))

proc collectArtifact(artifact: JsonNode, fullRepoName: string): string =
  try:
    let parts = fullRepoName.split("/", maxsplit = 1)
    if parts.len != 2:
      return ""

    let project = parts[0]
    let repo = parts[1]

    var href = artifact{"addition_links"}{"vulnerabilities"}{"href"}.getStr("")
    if href.len == 0:
      return ""

    href = href.replace("/api/v2.0", "")
    let data = httpGetJson(harborApiUrl & href)

    if data.len == 0:
      return ""

    let firstKey = data.keys().toSeq()[0]
    let vulnerabilities = data[firstKey]{"vulnerabilities"}

    if vulnerabilities.kind != JArray or vulnerabilities.len == 0:
      logInfo("No vulnerabilities found for repository " & fullRepoName)
      return ""

    logInfo("Found vulnerabilities for repository " & fullRepoName)

    var lines: seq[string] = @[]
    for v in vulnerabilities:
      lines.add(metricLine(v, project, repo))

    return lines.join("\n")

  except CatchableError as e:
    logError("Error processing artifact " & fullRepoName & ": " & e.msg)
    return ""

proc processRepo(repo: JsonNode): string =
  let fullName = repo{"name"}.getStr("")

  try:
    if not shouldProcessRepository(fullName):
      return ""

    let parts = fullName.split("/", maxsplit = 1)
    if parts.len != 2:
      return ""

    let project = parts[0]
    let repository = parts[1].replace("/library", "")

    let encodedRepo = encodeUrl(encodeUrl(repository))
    let url = harborApiUrl & "/projects/" & encodeUrl(project) &
              "/repositories/" & encodedRepo &
              "/artifacts?page=1&page_size=0"

    let artifacts = httpGetJson(url)

    if artifacts.kind != JArray or artifacts.len == 0:
      logInfo("No artifacts found for repository " & fullName)
      return ""

    var latest = artifacts[0]
    for artifact in artifacts:
      if artifact{"push_time"}.getStr("") > latest{"push_time"}.getStr(""):
        latest = artifact

    logInfo("Found latest artifact for repository " & fullName & ":")
    return collectArtifact(latest, fullName)

  except CatchableError as e:
    logError("Error processing repository " & fullName & ": " & e.msg)
    return ""

proc processProject(project: JsonNode): string =
  try:
    let projectName = project{"name"}.getStr("")

    if not shouldProcessProject(projectName):
      return ""

    let url = harborApiUrl & "/projects/" & encodeUrl(projectName) &
              "/repositories?page=1&page_size=0"

    let repos = httpGetJson(url)
    if repos.kind != JArray:
      return ""

    var repoMetrics: seq[string] = @[]

    for repo in repos:
      let m = processRepo(repo)
      if m.len > 0:
        repoMetrics.add(m)

    return repoMetrics.join("\n")

  except CatchableError as e:
    logError("Error processing project: " & e.msg)
    return ""

proc collectMetrics(): string =
  let projects = httpGetJson(harborApiUrl & "/projects?page=1&page_size=0")
  if projects.kind != JArray:
    return MetricsHeader & "\nharbor_exporter_cache_ready 0\n"

  var projectMetrics: seq[string] = @[]

  for project in projects:
    let m = processProject(project)
    if m.len > 0:
      projectMetrics.add(m)

  var output: seq[string] = @[
    MetricsHeader.strip(),
    "# HELP harbor_exporter_cache_ready Whether the metrics cache was successfully refreshed",
    "# TYPE harbor_exporter_cache_ready gauge",
    "harbor_exporter_cache_ready 1",
    "# HELP harbor_exporter_last_refresh_timestamp_seconds Last successful metrics refresh timestamp",
    "# TYPE harbor_exporter_last_refresh_timestamp_seconds gauge",
    "harbor_exporter_last_refresh_timestamp_seconds " & $now().toTime().toUnix()
  ]

  output.add(projectMetrics)
  return output.join("\n") & "\n"

proc refreshMetrics() =
  logInfo("Refreshing metrics cache")

  try:
    let body = collectMetrics()

    acquire(cacheLock)
    try:
      metricsCache = body
    finally:
      release(cacheLock)

    logInfo("Metrics cache refreshed successfully")

  except CatchableError as e:
    logError("Metrics cache refresh failed: " & e.msg)

proc cachedMetrics(): string =
  acquire(cacheLock)
  try:
    return metricsCache
  finally:
    release(cacheLock)

proc refreshLoop() {.thread.} =
  {.cast(gcsafe).}:
    refreshMetrics()

  while true:
    sleep(refreshIntervalSeconds * 1000)
    {.cast(gcsafe).}:
      refreshMetrics()

proc metricsHandler(request: Request) {.gcsafe.} =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "text/plain; version=0.0.4"

  {.cast(gcsafe).}:
    request.respond(200, headers, cachedMetrics())

proc healthHandler(request: Request) {.gcsafe.} =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "text/plain"
  request.respond(200, headers, "ok\n")

proc notFoundHandler(request: Request) {.gcsafe.} =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "text/plain"
  request.respond(404, headers, "not found\n")

var router: Router
router.get("/metrics", metricsHandler)
router.get("/health", healthHandler)
router.get("/-/health", healthHandler)
router.get("/*", notFoundHandler)

var thread: Thread[void]
createThread(thread, refreshLoop)

let server = newServer(router)
logInfo("Starting HTTP server on 0.0.0.0:" & $exporterPort)
server.serve(Port(exporterPort))
