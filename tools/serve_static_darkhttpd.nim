import std/[os, strutils]

import promlite

proc darkhttpdMain(argc: cint; argv: cstringArray): cint {.importc: "promlite_darkhttpd_main".}

when isMainModule:
  if paramCount() != 3:
    quit("usage: serve_static_darkhttpd ROOT ADDRESS PORT", 2)

  let
    root = paramStr(1)
    address = paramStr(2)
    port = paramStr(3)

  if not dirExists(root):
    quit("static root does not exist: " & root, 2)
  discard parseInt(port)

  var args = allocCStringArray([
    "darkhttpd",
    root,
    "--addr", address,
    "--port", port,
    "--no-listing",
    "--no-keepalive",
    "--default-mimetype", "application/json",
    "--header", "Cache-Control: no-store"
  ])
  let code = darkhttpdMain(12.cint, args)
  deallocCStringArray(args)
  quit(code)
