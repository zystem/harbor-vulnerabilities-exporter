import std/[os, random, strutils]

const
  Severities = ["Unknown", "Negligible", "Low", "Medium", "High", "Critical"]
  ReportKey = "application/vnd.security.vulnerability.report; version=1.1"
  DescriptionText =
    "Synthetic vulnerability description generated for local exporter tests. "

proc usage() =
  echo "usage: generate_synthetic_harbor_cache --out:DIR [--projects:N] [--repositories:N] [--vulnerabilities:N] [--description-bytes:N] [--seed:N] [--api-prefix:/api/v2.0] [--clean]"

proc argValue(name, defaultValue: string): string =
  let prefix = "--" & name & ":"
  for arg in commandLineParams():
    if arg.startsWith(prefix):
      return arg[prefix.len .. ^1]
  defaultValue

proc hasFlag(name: string): bool =
  let flag = "--" & name
  for arg in commandLineParams():
    if arg == flag:
      return true
  false

proc jsonEscape(value: string): string =
  result = newStringOfCap(value.len + 8)
  for ch in value:
    case ch
    of '\\': result.add("\\\\")
    of '"': result.add("\\\"")
    of '\n': result.add("\\n")
    of '\r': result.add("\\r")
    of '\t': result.add("\\t")
    else: result.add(ch)

proc quoted(value: string): string =
  "\"" & jsonEscape(value) & "\""

proc randChars(rng: var Rand, alphabet: string, count: int): string =
  result = newStringOfCap(count)
  for _ in 0 ..< count:
    result.add(alphabet[rand(rng, alphabet.high)])

proc randWord(rng: var Rand, prefix: string, minLen, maxLen: int): string =
  prefix & "-" & randChars(rng, "abcdefghijklmnopqrstuvwxyz0123456789", rand(rng, minLen .. maxLen))

proc sizedText(seed: string, size: int): string =
  if size <= 0:
    return ""
  result = newStringOfCap(size)
  while result.len < size:
    result.add(seed)
  result.setLen(size)

proc splitTotal(total, buckets: int): seq[int] =
  let base = total div buckets
  let rest = total mod buckets
  for i in 0 ..< buckets:
    result.add(base + ord(i < rest))

proc writeResponse(path, body: string) =
  let responsePath = path & ".json"
  createDir(parentDir(responsePath))
  writeFile(responsePath, body & "\n")

proc writeProjects(path: string, projects: openArray[string]) =
  var body = "["
  for i, project in projects:
    if i > 0:
      body.add(",")
    body.add("{\"name\":")
    body.add(quoted(project))
    body.add("}")
  body.add("]")
  writeResponse(path, body)

proc writeRepositories(path, project: string, repos: openArray[string]) =
  var body = "["
  for i, repo in repos:
    if i > 0:
      body.add(",")
    body.add("{\"name\":")
    body.add(quoted(project & "/" & repo))
    body.add("}")
  body.add("]")
  writeResponse(path, body)

proc writeArtifact(path, href, digest: string) =
  writeResponse(path,
    "[{\"digest\":" & quoted(digest) &
    ",\"tags\":[{\"name\":\"latest\"}],\"addition_links\":{\"vulnerabilities\":{\"href\":" &
    quoted(href) & ",\"absolute\":false}}}]")

proc writeVulnerabilityReport(path: string, rng: var Rand, count, descriptionBytes: int) =
  var body = "{\"" & ReportKey & "\":{\"vulnerabilities\":["
  for i in 0 ..< count:
    if i > 0:
      body.add(",")
    body.add("{\"id\":")
    body.add(quoted("CVE-" & $rand(rng, 2010 .. 2026) & "-" & $rand(rng, 1000 .. 999999)))
    body.add(",\"package\":")
    body.add(quoted(randWord(rng, "pkg", 5, 16)))
    body.add(",\"version\":")
    body.add(quoted($rand(rng, 0 .. 9) & "." & $rand(rng, 0 .. 30) & "." & $rand(rng, 0 .. 99)))
    body.add(",\"fix_version\":")
    body.add(quoted($rand(rng, 0 .. 9) & "." & $rand(rng, 0 .. 30) & "." & $rand(rng, 0 .. 99)))
    body.add(",\"severity\":")
    body.add(quoted(Severities[rand(rng, Severities.high)]))
    body.add(",\"description\":")
    body.add(quoted(sizedText(DescriptionText, descriptionBytes)))
    body.add("}")
  body.add("]}}")
  writeResponse(path, body)

when isMainModule:
  if hasFlag("help") or hasFlag("h"):
    usage()
    quit(0)

  let
    outDir = argValue("out", "build/synthetic-harbor-cache")
    projectsCount = parseInt(argValue("projects", "2"))
    repositoriesCount = parseInt(argValue("repositories", "3"))
    vulnerabilitiesCount = parseInt(argValue("vulnerabilities", "7"))
    descriptionBytes = parseInt(argValue("description-bytes", "64"))
    seed = parseInt(argValue("seed", "1"))
    apiPrefix = "/" & argValue("api-prefix", "/api/v2.0").strip(chars = {'/'})

  if projectsCount <= 0 or repositoriesCount <= 0:
    quit("projects and repositories must be positive", 2)
  if vulnerabilitiesCount < 0 or descriptionBytes < 0:
    quit("vulnerabilities and description-bytes must be non-negative", 2)

  if hasFlag("clean") and dirExists(outDir):
    removeDir(outDir)

  var rng = initRand(seed)
  let root = outDir / apiPrefix.strip(chars = {'/'})
  var projects: seq[string]
  for _ in 0 ..< projectsCount:
    projects.add(randWord(rng, "project", 6, 12))

  let reposPerProject = splitTotal(repositoriesCount, projectsCount)
  let vulnsPerRepo = splitTotal(vulnerabilitiesCount, repositoriesCount)
  writeProjects(root / "projects", projects)

  var repoIndex = 0
  var files = 1
  for projectIndex, project in projects:
    var repos: seq[string]
    for _ in 0 ..< reposPerProject[projectIndex]:
      repos.add(randWord(rng, "repo", 8, 18))

    writeRepositories(root / "projects" / project / "repositories", project, repos)
    inc files

    for repo in repos:
      let digest = "sha256-" & randChars(rng, "0123456789abcdef", 64)
      let artifactsPath = root / "projects" / project / "repositories" / repo / "artifacts"
      let vulnHref = apiPrefix & "/projects/" & project & "/repositories/" & repo &
        "/artifacts/" & digest & "/additions/vulnerabilities"

      writeArtifact(artifactsPath, vulnHref, digest)
      inc files

      writeVulnerabilityReport(
        root / "projects" / project / "repositories" / repo / "artifacts" / digest / "additions" / "vulnerabilities",
        rng,
        vulnsPerRepo[repoIndex],
        descriptionBytes
      )
      inc repoIndex
      inc files

  echo "synthetic harbor cache complete: projects=", projectsCount,
    " repositories=", repositoriesCount,
    " vulnerabilities=", vulnerabilitiesCount,
    " files=", files
