import mummy, mummy/routers
import std/[httpclient, os, strutils, sequtils, uri, base64, times]
import yyjson

const MetricsHeader = """
# HELP harbor_image_vulnerabilities Vulnerabilities found in the latest pushed image in every repository
# TYPE harbor_image_vulnerabilities gauge
"""

const EmptyMetrics = MetricsHeader & """
# HELP harbor_exporter_cache_ready Whether the metrics cache was successfully refreshed
# TYPE harbor_exporter_cache_ready gauge
harbor_exporter_cache_ready 0
"""

let harborApiUrl = getEnv("HARBOR_API_URL").strip(chars = {'/'})
let harborUsername = getEnv("HARBOR_USERNAME")
let harborPassword = getEnv("HARBOR_PASSWORD")

let exporterPort = parseInt(getEnv("EXPORTER_PORT", "9090"))
let bindAddress = getEnv("BIND_ADDRESS", "0.0.0.0")
let httpWorkerThreads = parseInt(getEnv("HTTP_WORKER_THREADS", "1"))

let refreshIntervalSeconds = parseInt(getEnv("REFRESH_INTERVAL_SECONDS", "600"))
let metricsFile = getEnv("METRICS_FILE", "/data/harbor-vulnerabilities-exporter.prom")

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

if harborApiUrl.len == 0:
  stderr.writeLine("HARBOR_API_URL env variable is required.")
  quit(2)

proc logInfo(msg: string) =
  echo now().format("yyyy-MM-dd HH:mm:ss','fff") & " - INFO - " & msg

proc logError(msg: string) =
  stderr.writeLine(now().format("yyyy-MM-dd HH:mm:ss','fff") & " - ERROR - " & msg)

proc currentRSSKb(): int =
  try:
    for line in lines("/proc/self/status"):
      if line.startsWith("VmRSS:"):
        return parseInt(line.splitWhitespace()[1])
  except CatchableError:
    discard
  return -1

proc logMem(stage: string) =
  let rss = currentRSSKb()
  if rss >= 0:
    logInfo(stage & " RSS=" & $rss & " KiB")

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
  return value.startsWith(parts[0]) and value.endsWith(parts[^1])

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

proc httpGetContent(url: string): string =
  var client = httpclient.newHttpClient(headers = authHeaders())
  defer:
    client.close()

  return client.getContent(url)

proc promEscape(s: string): string =
  result = s
  result = result.replace("\\", "\\\\")
  result = result.replace("\n", "\\n")
  result = result.replace("\"", "\\\"")

proc writeMetricLine(f: File, v: JsonVal, project, repo: string) =
  f.write("harbor_image_vulnerabilities{")
  f.write("id=\"" & promEscape(v.getStr("id")) & "\",")
  f.write("package=\"" & promEscape(v.getStr("package")) & "\",")
  f.write("version=\"" & promEscape(v.getStr("version")) & "\",")
  f.write("fix_version=\"" & promEscape(v.getStr("fix_version")) & "\",")
  f.write("severity=\"" & promEscape(v.getStr("severity")) & "\",")
  f.write("project=\"" & promEscape(project) & "\",")
  f.write("repository=\"" & promEscape(repo) & "\"")
  f.write("} 1\n")

proc normalizeVulnerabilitiesHref(href: string): string =
  var h = href
  h = h.replace("/api/v2.0", "")
  return harborApiUrl & h

proc writeMetricsHeader(f: File) =
  f.write(MetricsHeader.strip())
  f.write('\n')
  f.write("# HELP harbor_exporter_cache_ready Whether the metrics cache was successfully refreshed\n")
  f.write("# TYPE harbor_exporter_cache_ready gauge\n")
  f.write("harbor_exporter_cache_ready 1\n")
  f.write("# HELP harbor_exporter_last_refresh_timestamp_seconds Last successful metrics refresh timestamp\n")
  f.write("# TYPE harbor_exporter_last_refresh_timestamp_seconds gauge\n")
  f.write("harbor_exporter_last_refresh_timestamp_seconds ")
  f.write($now().toTime().toUnix())
  f.write('\n')

proc collectVulnerabilitiesToFile(f: File, artifact: JsonVal, fullRepoName: string) =
  try:
    let parts = fullRepoName.split("/", maxsplit = 1)
    if parts.len != 2:
      return

    let project = parts[0]
    let repo = parts[1]

    let href = artifact["addition_links"]["vulnerabilities"]["href"].str("")
    if href.len == 0:
      logInfo("No vulnerabilities addition link for repository " & fullRepoName)
      return

    let url = normalizeVulnerabilitiesHref(href)
    let body = httpGetContent(url)

    var doc = readJson(body)
    defer:
      doc.close()

    var count = 0
    for _, report in doc.root().pairs:
      let vulns = report["vulnerabilities"]
      if not vulns.isArray:
        continue

      for v in vulns.items:
        writeMetricLine(f, v, project, repo)
        inc count

    if count == 0:
      logInfo("No vulnerabilities found for repository " & fullRepoName)
    else:
      logInfo("Found vulnerabilities for repository " & fullRepoName & ": " & $count)

  except CatchableError as e:
    logError("Error processing artifact " & fullRepoName & ": " & e.msg)

proc processRepositoryToFile(f: File, repo: JsonVal) =
  let fullName = repo.getStr("name")
  if fullName.len == 0:
    return

  try:
    if not shouldProcessRepository(fullName):
      return

    let parts = fullName.split("/", maxsplit = 1)
    if parts.len != 2:
      logError("Repository name has unexpected format: " & fullName)
      return

    let project = parts[0]
    let repository = parts[1].replace("/library", "")

    let encodedRepo = encodeUrl(encodeUrl(repository))
    let url = harborApiUrl & "/projects/" & encodeUrl(project) &
              "/repositories/" & encodedRepo &
              "/artifacts?page=1&page_size=1&sort=-push_time"

    let body = httpGetContent(url)

    var doc = readJson(body)
    defer:
      doc.close()

    let artifacts = doc.root()
    if not artifacts.isArray or artifacts.len == 0:
      logInfo("No artifacts found for repository " & fullName)
      return

    let latest = block:
      var item: JsonVal
      for artifact in artifacts.items:
        item = artifact
        break
      item

    if latest.isNil:
      logInfo("No artifacts found for repository " & fullName)
      return

    logInfo("Found latest artifact for repository " & fullName & ":")
    collectVulnerabilitiesToFile(f, latest, fullName)

  except CatchableError as e:
    logError("Error processing repository " & fullName & ": " & e.msg)

proc processProjectToFile(f: File, project: JsonVal) =
  let projectName = project.getStr("name")
  if projectName.len == 0:
    return

  try:
    if not shouldProcessProject(projectName):
      return

    let url = harborApiUrl & "/projects/" & encodeUrl(projectName) &
              "/repositories?page=1&page_size=0"

    let body = httpGetContent(url)

    var doc = readJson(body)
    defer:
      doc.close()

    let repos = doc.root()
    if not repos.isArray:
      logError("Repositories response is not an array for project " & projectName)
      return

    logInfo("Processing project " & projectName & " repositories=" & $repos.len)
    logMem("before project " & projectName)

    for repo in repos.items:
      processRepositoryToFile(f, repo)

    f.flushFile()
    logMem("after project " & projectName)

  except CatchableError as e:
    logError("Error processing project " & projectName & ": " & e.msg)

proc replaceFileAtomic(src, dst: string) =
  if fileExists(dst):
    removeFile(dst)
  moveFile(src, dst)

proc refreshMetricsFile() =
  let dir = parentDir(metricsFile)
  if dir.len > 0:
    createDir(dir)

  let tmpFile = metricsFile & ".tmp." & $getCurrentProcessId()

  logInfo("Refreshing metrics file")
  logMem("refresh start")

  var f: File
  if not open(f, tmpFile, fmWrite):
    raise newException(IOError, "Cannot open metrics temp file: " & tmpFile)

  try:
    writeMetricsHeader(f)

    let body = httpGetContent(harborApiUrl & "/projects?page=1&page_size=0")

    var doc = readJson(body)
    defer:
      doc.close()

    let projects = doc.root()
    if not projects.isArray:
      raise newException(ValueError, "Projects response is not an array")

    logInfo("Projects count=" & $projects.len)
    logMem("after projects list")

    for project in projects.items:
      processProjectToFile(f, project)

    f.flushFile()

  finally:
    f.close()

  replaceFileAtomic(tmpFile, metricsFile)

  logInfo("Metrics file refreshed successfully: " & metricsFile)
  logMem("refresh done")

proc refreshLoop() {.thread.} =
  while true:
    {.cast(gcsafe).}:
      try:
        refreshMetricsFile()
      except CatchableError as e:
        logError("Metrics cache refresh failed: " & e.msg)

    sleep(refreshIntervalSeconds * 1000)

proc cachedMetricsFromFile(): string =
  if fileExists(metricsFile):
    return readFile(metricsFile)

  return EmptyMetrics

proc metricsHandler(request: Request) {.gcsafe.} =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "text/plain; version=0.0.4"

  {.cast(gcsafe).}:
    request.respond(200, headers, cachedMetricsFromFile())

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

let server = newServer(router, workerThreads = httpWorkerThreads)

logInfo(
  "Starting HTTP server on " & bindAddress & ":" & $exporterPort &
  " with " & $httpWorkerThreads & " worker thread(s)"
)

server.serve(Port(exporterPort), bindAddress)
