import std/[httpclient, os, strutils, uri, base64, times]
import posixglob
import promlite
import yyjson

let harborApiUrl = getEnv("HARBOR_API_URL").strip(chars = {'/'})
let harborUsername = getEnv("HARBOR_USERNAME")
let harborPassword = getEnv("HARBOR_PASSWORD")

let exporterPort = parseInt(getEnv("EXPORTER_PORT", "9090"))
let bindAddress = getEnv("BIND_ADDRESS", "0.0.0.0")

let refreshIntervalSeconds = parseInt(getEnv("REFRESH_INTERVAL_SECONDS", "600"))
let promliteDataDir = getEnv("PROM_LITE_DATA_DIR", "/data")
let harborStaticJsonResponses = getEnv("HARBOR_STATIC_JSON_RESPONSES", "") in ["1", "true", "yes"]

let includeProjects =
  parseGlobPatterns(getEnv("INCLUDE_PROJECTS", ""))

let excludeProjects =
  parseGlobPatterns(getEnv("EXCLUDE_PROJECTS", ""))

let includeRepositories =
  parseGlobPatterns(getEnv("INCLUDE_REPOSITORIES", ""))

let excludeRepositories =
  parseGlobPatterns(getEnv("EXCLUDE_REPOSITORIES", ""))

type RefreshStats = object
  projects: int
  repositories: int
  vulnerabilities: int
  errors: int

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

proc matchPattern*(value, pattern: string): bool =
  globMatch(pattern, value)

proc matchesAny*(value: string, patterns: seq[string]): bool =
  globMatchAny(patterns, value)

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

proc jsonResponseUrl(url: string): string =
  let queryPos = url.find('?')
  if queryPos >= 0:
    url[0 ..< queryPos] & ".json" & url[queryPos .. ^1]
  else:
    url & ".json"

proc httpGetContent(url: string): string =
  var client = httpclient.newHttpClient(headers = authHeaders())
  defer:
    client.close()

  try:
    return client.getContent(url)
  except CatchableError:
    if harborStaticJsonResponses:
      return client.getContent(jsonResponseUrl(url))
    raise

proc writeMetricLine*(m: var MetricsBuilder, v: JsonVal, project, repo: string) =
  m.gauge("harbor_image_vulnerabilities", 1, labels = {
    "id": v.getStr("id"),
    "package": v.getStr("package"),
    "version": v.getStr("version"),
    "fix_version": v.getStr("fix_version"),
    "severity": v.getStr("severity"),
    "project": project,
    "repository": repo
  })

proc normalizeVulnerabilitiesHref*(apiBase, href: string): string =
  if href.startsWith("http://") or href.startsWith("https://"):
    return href

  var h = href
  h = h.replace("/api/v2.0", "")
  return apiBase.strip(chars = {'/'}) & h

proc normalizeVulnerabilitiesHref(href: string): string =
  normalizeVulnerabilitiesHref(harborApiUrl, href)

proc collectVulnerabilities(m: var MetricsBuilder, artifact: JsonVal, fullRepoName: string): int =
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
        writeMetricLine(m, v, project, repo)
        inc count

    if count == 0:
      logInfo("No vulnerabilities found for repository " & fullRepoName)
    else:
      logInfo("Found vulnerabilities for repository " & fullRepoName & ": " & $count)

    return count

  except CatchableError as e:
    logError("Error processing artifact " & fullRepoName & ": " & e.msg)
    return 0

proc processRepository(m: var MetricsBuilder, repo: JsonVal, stats: var RefreshStats) =
  let fullName = repo.getStr("name")
  if fullName.len == 0:
    return

  try:
    if not shouldProcessRepository(fullName):
      return

    let parts = fullName.split("/", maxsplit = 1)
    if parts.len != 2:
      logError("Repository name has unexpected format: " & fullName)
      inc stats.errors
      return

    inc stats.repositories

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
    stats.vulnerabilities += collectVulnerabilities(m, latest, fullName)

  except CatchableError as e:
    logError("Error processing repository " & fullName & ": " & e.msg)
    inc stats.errors

proc processProject(m: var MetricsBuilder, project: JsonVal, stats: var RefreshStats) =
  let projectName = project.getStr("name")
  if projectName.len == 0:
    return

  try:
    if not shouldProcessProject(projectName):
      return

    inc stats.projects

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
      processRepository(m, repo, stats)

    logMem("after project " & projectName)

  except CatchableError as e:
    logError("Error processing project " & projectName & ": " & e.msg)
    inc stats.errors

proc collectMetrics*(m: var MetricsBuilder) {.gcsafe.} =
  {.cast(gcsafe).}:
    let refreshStarted = epochTime()
    var stats: RefreshStats

    logInfo("Refreshing metrics file")
    logMem("refresh start")

    m.help("harbor_image_vulnerabilities", "Vulnerabilities found in the latest pushed image in every repository")
    m.help("harbor_exporter_cache_ready", "Whether the metrics cache was successfully refreshed")
    m.gauge("harbor_exporter_cache_ready", 1)
    m.help("harbor_exporter_last_refresh_timestamp_seconds", "Last successful metrics refresh timestamp")
    m.gauge("harbor_exporter_last_refresh_timestamp_seconds", now().toTime().toUnix())
    m.help("harbor_exporter_refresh_duration_seconds", "Duration of the last metrics refresh")
    m.help("harbor_exporter_last_refresh_errors", "Errors seen during the last metrics refresh")
    m.help("harbor_exporter_projects_total", "Projects processed during the last metrics refresh")
    m.help("harbor_exporter_repositories_total", "Repositories processed during the last metrics refresh")
    m.help("harbor_exporter_vulnerabilities_total", "Vulnerabilities emitted during the last metrics refresh")

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
      processProject(m, project, stats)

    m.gauge("harbor_exporter_refresh_duration_seconds", epochTime() - refreshStarted)
    m.gauge("harbor_exporter_last_refresh_errors", stats.errors)
    m.gauge("harbor_exporter_projects_total", stats.projects)
    m.gauge("harbor_exporter_repositories_total", stats.repositories)
    m.gauge("harbor_exporter_vulnerabilities_total", stats.vulnerabilities)

    logInfo("Metrics file refreshed successfully")
    logMem("refresh done")

proc main() =
  if harborApiUrl.len == 0:
    stderr.writeLine("HARBOR_API_URL env variable is required.")
    quit(2)

  logInfo(
    "Starting HTTP server on " & bindAddress & ":" & $exporterPort
  )

  let exporter = newExporter(
    address = bindAddress,
    port = exporterPort,
    refreshIntervalSeconds = refreshIntervalSeconds,
    collector = collectMetrics,
    dataDir = promliteDataDir,
    metricsFileName = "metrics"
  )

  exporter.run()

when isMainModule:
  main()
