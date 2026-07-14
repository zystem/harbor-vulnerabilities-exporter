import std/[httpclient, os, osproc]

const
  BuildDir = "build"
  CacheDir = BuildDir / "synthetic-harbor-cache"
  ServerBin = BuildDir / "serve-static-darkhttpd"

proc run(command: string) =
  let code = execShellCmd(command)
  if code != 0:
    quit("command failed with exit code " & $code & ": " & command, code)

proc waitForSyntheticHarbor() =
  var client = newHttpClient()
  defer:
    client.close()

  for _ in 1 .. 10:
    try:
      discard client.getContent("http://127.0.0.1:18080/api/v2.0/projects.json")
      return
    except CatchableError:
      sleep(200)

  quit("synthetic Harbor server did not become ready", 1)

proc main() =
  createDir(BuildDir)

  run "nim c -r -d:ssl --threads:on --mm:orc --nimcache:build/nimcache tests/t_exporter_core.nim"
  run "nim c -r --threads:on --mm:orc --nimcache:build/nimcache --out:" &
    BuildDir / "generate-synthetic-harbor-cache tools/generate_synthetic_harbor_cache.nim" &
    " --out:" & CacheDir &
    " --projects:2 --repositories:3 --vulnerabilities:7 --description-bytes:32 --seed:1 --clean"
  run "nim c --threads:on --mm:orc --nimcache:build/nimcache --out:" & ServerBin &
    " tools/serve_static_darkhttpd.nim"

  let server = startProcess(
    ServerBin,
    args = [CacheDir, "127.0.0.1", "18080"],
    options = {poParentStreams}
  )
  defer:
    terminate(server)
    discard waitForExit(server)
    close(server)

  waitForSyntheticHarbor()
  putEnv("HARBOR_API_URL", "http://127.0.0.1:18080/api/v2.0")
  putEnv("HARBOR_STATIC_JSON_RESPONSES", "1")
  run "nim c -r -d:ssl --threads:on --mm:orc --nimcache:build/nimcache tests/t_exporter_synthetic_harbor.nim"

when isMainModule:
  main()
