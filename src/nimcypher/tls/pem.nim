# PEM block extraction (RFC 7468 subset: CERTIFICATE blocks).
#
# SPDX-License-Identifier: BSD-2-Clause

import std/base64
import std/strutils

proc pemBlocks*(text: string, label = "CERTIFICATE"): seq[seq[byte]] =
  ## Decode all PEM blocks with the given label. Raises on bad base64.
  let beginMarker = "-----BEGIN " & label & "-----"
  let endMarker = "-----END " & label & "-----"
  var i = 0
  while true:
    let b = text.find(beginMarker, i)
    if b < 0: break
    let e = text.find(endMarker, b + beginMarker.len)
    if e < 0:
      raise newException(ValueError, "PEM: missing END line for " & label)
    var body = text[b + beginMarker.len ..< e]
    var clean = newStringOfCap(body.len)
    for c in body:
      if c notin {'\r', '\n', ' ', '\t'}:
        clean.add(c)
    result.add(cast[seq[byte]](decode(clean)))
    i = e + endMarker.len

proc pemParseFile*(path: string, label = "CERTIFICATE"): seq[seq[byte]] =
  pemBlocks(readFile(path), label)
