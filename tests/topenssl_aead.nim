# Live OpenSSL interop for the AEAD constructions: nimcypher vs libcrypto.
#
# `topenssl.nim` covers everything the `openssl enc` CLI can express, but
# that CLI rejects AEAD ciphers, so AES-GCM and ChaCha20-Poly1305 had no
# live cross-check (only the checked-in NIST/RFC vectors in `tgcm` /
# `tchacha20`). This suite drives libcrypto's EVP interface directly and
# exchanges real ciphertext and tags in both directions, for every size
# class that selects a different kernel path (wide 32-block, 8-block,
# pair, odd block, tail).
#
# libcrypto is resolved at runtime rather than through a compile-time
# `dynlib` name. On macOS `libcrypto.dylib` resolves to the system
# LibreSSL, which has no `EVP_chacha20_poly1305`; Homebrew's OpenSSL 3
# keg lives under /opt/homebrew (arm64) or /usr/local (x86_64) and is
# not on dyld's fallback path. We therefore try explicit keg paths,
# paths derived from the `openssl` binary on PATH (CI puts the keg's bin
# there), then bare sonames, and only accept a library that exports
# every symbol the suite uses — which LibreSSL does not.
#
# If no such library can be loaded the suite prints a note and passes
# trivially, unless NIMCYPHER_REQUIRE_OPENSSL=1 is set (as in CI), in
# which case it fails loudly — same convention as `topenssl.nim`.
# NIMCYPHER_OPENSSL_LIB overrides the search with an explicit path.

import std/dynlib
import std/options
import std/os
import std/random
import std/unittest

import nimcypher/utils
import nimcypher/algos/gcm as gcmAlgo
import nimcypher/tls/aead as tlsAead

type
  EvpCipher = pointer
  EvpCtx = pointer

  CtxNewFn = proc(): EvpCtx {.cdecl.}
  CtxFreeFn = proc(c: EvpCtx) {.cdecl.}
  CipherFn = proc(): EvpCipher {.cdecl.}
  InitFn = proc(c: EvpCtx, t: EvpCipher, impl, key, iv: pointer): cint {.cdecl.}
  UpdateFn = proc(c: EvpCtx, outd: pointer, outl: ptr cint,
                  ind: pointer, inl: cint): cint {.cdecl.}
  FinalFn = proc(c: EvpCtx, outd: pointer, outl: ptr cint): cint {.cdecl.}
  CtrlFn = proc(c: EvpCtx, typ: cint, arg: cint, p: pointer): cint {.cdecl.}

  EvpApi = object
    path: string
    ctxNew: CtxNewFn
    ctxFree: CtxFreeFn
    aes128Gcm: CipherFn
    aes256Gcm: CipherFn
    chacha20Poly1305: CipherFn
    encInit: InitFn
    encUpdate: UpdateFn
    encFinal: FinalFn
    decInit: InitFn
    decUpdate: UpdateFn
    decFinal: FinalFn
    ctrl: CtrlFn

var
  evp: EvpApi
  evpTried = false
  evpLoaded = false
  failedLoads: seq[string]

const
  EVP_CTRL_AEAD_GET_TAG = 0x10
  EVP_CTRL_AEAD_SET_TAG = 0x11

proc fetch[T](lib: LibHandle, name: string): T =
  try:
    let p = symAddr(lib, name.cstring)
    if p != nil:
      result = cast[T](p)
  except CatchableError:
    discard

proc libCandidates(): seq[string] =
  let override = getEnv("NIMCYPHER_OPENSSL_LIB")
  if override.len > 0:
    result.add override
  when defined(macosx):
    for dir in ["/opt/homebrew/opt/openssl@3/lib",
                "/usr/local/opt/openssl@3/lib",
                "/opt/homebrew/lib",
                "/usr/local/lib",
                "/opt/local/lib"]:
      result.add dir / "libcrypto.3.dylib"
      result.add dir / "libcrypto.dylib"
  elif defined(windows):
    result.add "libcrypto-3-x64.dll"
    result.add "libcrypto-1_1-x64.dll"
  else:
    result.add "libcrypto.so.3"
    result.add "libcrypto.so"
  # The `openssl` binary's keg is a reliable anchor for its libraries.
  # On macOS this is how the CI runners expose Homebrew's openssl@3:
  # /opt/homebrew/opt/openssl@3/bin/openssl -> ../lib/libcrypto.3.dylib.
  let exe = findExe("openssl")
  if exe.len > 0:
    let libDir = parentDir(exe) / ".." / "lib"
    when defined(macosx):
      result.add libDir / "libcrypto.3.dylib"
    elif not defined(windows):
      result.add libDir / "libcrypto.so.3"

proc loadCandidate(path: string): bool =
  # On macOS the system libcrypto is only in the dyld shared cache (no
  # file on disk) and dlopen()ing it aborts the process instead of
  # failing — Apple treats it as a restricted library. Requiring an
  # explicit path to exist on disk keeps us on Homebrew/MacPorts kegs,
  # which are real files; bare sonames (Linux) are not path-checked.
  if path.isAbsolute and not fileExists(path):
    failedLoads.add path & " (not found)"
    return false
  var lib: LibHandle
  try:
    lib = loadLib(path)
  except CatchableError:
    return false
  if lib == nil:
    return false

  var api: EvpApi
  var missing: seq[string]
  api.ctxNew = fetch[CtxNewFn](lib, "EVP_CIPHER_CTX_new")
  if api.ctxNew == nil: missing.add "EVP_CIPHER_CTX_new"
  api.ctxFree = fetch[CtxFreeFn](lib, "EVP_CIPHER_CTX_free")
  if api.ctxFree == nil: missing.add "EVP_CIPHER_CTX_free"
  api.aes128Gcm = fetch[CipherFn](lib, "EVP_aes_128_gcm")
  if api.aes128Gcm == nil: missing.add "EVP_aes_128_gcm"
  api.aes256Gcm = fetch[CipherFn](lib, "EVP_aes_256_gcm")
  if api.aes256Gcm == nil: missing.add "EVP_aes_256_gcm"
  api.chacha20Poly1305 = fetch[CipherFn](lib, "EVP_chacha20_poly1305")
  if api.chacha20Poly1305 == nil: missing.add "EVP_chacha20_poly1305"
  api.encInit = fetch[InitFn](lib, "EVP_EncryptInit_ex")
  if api.encInit == nil: missing.add "EVP_EncryptInit_ex"
  api.encUpdate = fetch[UpdateFn](lib, "EVP_EncryptUpdate")
  if api.encUpdate == nil: missing.add "EVP_EncryptUpdate"
  api.encFinal = fetch[FinalFn](lib, "EVP_EncryptFinal_ex")
  if api.encFinal == nil: missing.add "EVP_EncryptFinal_ex"
  api.decInit = fetch[InitFn](lib, "EVP_DecryptInit_ex")
  if api.decInit == nil: missing.add "EVP_DecryptInit_ex"
  api.decUpdate = fetch[UpdateFn](lib, "EVP_DecryptUpdate")
  if api.decUpdate == nil: missing.add "EVP_DecryptUpdate"
  api.decFinal = fetch[FinalFn](lib, "EVP_DecryptFinal_ex")
  if api.decFinal == nil: missing.add "EVP_DecryptFinal_ex"
  api.ctrl = fetch[CtrlFn](lib, "EVP_CIPHER_CTX_ctrl")
  if api.ctrl == nil: missing.add "EVP_CIPHER_CTX_ctrl"

  if missing.len > 0:
    unloadLib(lib)
    failedLoads.add path & " (missing " & $missing & ")"
    return false
  api.path = path
  evp = api
  true

proc loadEvp(): bool =
  if evpTried:
    return evpLoaded
  evpTried = true
  for path in libCandidates():
    if loadCandidate(path):
      evpLoaded = true
      echo "openssl AEAD interop: libcrypto = ", path
      return true
  false

proc osslSeal(cipher: EvpCipher, key, iv, pt, ad: openArray[byte]):
    (seq[byte], array[16, byte]) =
  let ctx = evp.ctxNew()
  doAssert ctx != nil
  defer: evp.ctxFree(ctx)
  doAssert evp.encInit(ctx, cipher, nil, unsafeAddr key[0],
                       unsafeAddr iv[0]) == 1
  var outl: cint = 0
  if ad.len > 0:
    # NB: for AAD OpenSSL reports the *input* length in outl, so it must
    # not be carried into the ciphertext length.
    doAssert evp.encUpdate(ctx, nil, addr outl, unsafeAddr ad[0],
                           ad.len.cint) == 1
  result[0] = newSeq[byte](pt.len + 16)
  var n = 0
  if pt.len > 0:
    doAssert evp.encUpdate(ctx, addr result[0][0], addr outl,
                           unsafeAddr pt[0], pt.len.cint) == 1
    n = outl.int
  doAssert evp.encFinal(ctx, addr result[0][n], addr outl) == 1
  n += outl.int
  result[0].setLen(n)
  doAssert evp.ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, addr result[1][0]) == 1

proc osslOpen(cipher: EvpCipher, key, iv, ct: openArray[byte],
              tag: array[16, byte], ad: openArray[byte]): Option[seq[byte]] =
  let ctx = evp.ctxNew()
  doAssert ctx != nil
  defer: evp.ctxFree(ctx)
  doAssert evp.decInit(ctx, cipher, nil, unsafeAddr key[0],
                       unsafeAddr iv[0]) == 1
  var outl: cint = 0
  if ad.len > 0:
    doAssert evp.decUpdate(ctx, nil, addr outl, unsafeAddr ad[0],
                           ad.len.cint) == 1
  var pt = newSeq[byte](ct.len + 16)
  var n = 0
  if ct.len > 0:
    doAssert evp.decUpdate(ctx, addr pt[0], addr outl,
                           unsafeAddr ct[0], ct.len.cint) == 1
    n = outl.int
  var t = tag
  doAssert evp.ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, addr t[0]) == 1
  let ok = evp.decFinal(ctx, addr pt[n], addr outl)
  if ok != 1:
    return none(seq[byte])
  n += outl.int
  pt.setLen(n)
  result = some(pt)

type EvpCipherId = enum
  ecAes128Gcm, ecAes256Gcm, ecChaCha20Poly1305

proc cipherFor(id: EvpCipherId): EvpCipher =
  case id
  of ecAes128Gcm: evp.aes128Gcm()
  of ecAes256Gcm: evp.aes256Gcm()
  of ecChaCha20Poly1305: evp.chacha20Poly1305()

proc unavailable(): bool =
  ## Returns true when libcrypto is missing; reports it according to the
  ## same policy as `topenssl.nim` (hard failure only when required).
  if loadEvp():
    return false
  if getEnv("NIMCYPHER_REQUIRE_OPENSSL") == "1":
    echo "tried: ", failedLoads
    check false
  else:
    echo "NOTE: no libcrypto with AEAD ciphers found; skipping live AEAD " &
         "interop (tried " & $failedLoads.len & " candidates)"
  true

const sizes = [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 257,
               511, 512, 513, 1023, 1024, 1025, 4096, 16384, 16385]

proc exercise(name: string, id: EvpCipherId, keyLen: int,
              nimSeal: proc(key, iv, pt, ad: openArray[byte]):
                (seq[byte], array[16, byte]) {.closure.},
              nimOpen: proc(key, iv, ct: openArray[byte],
                            tag: array[16, byte], ad: openArray[byte]):
                Option[seq[byte]] {.closure.}) =
  test name & ": nimcypher <-> openssl both directions, all sizes":
    if unavailable():
      return
    let cipher = cipherFor(id)
    check cipher != nil
    if cipher == nil:
      return
    randomize(0xAEAD)
    for aadLen in [0, 5]:
      for sz in sizes:
        var key = newSeq[byte](keyLen)
        var iv = newSeq[byte](12)
        for i in 0 ..< keyLen: key[i] = byte(rand(255))
        for i in 0 ..< 12: iv[i] = byte(rand(255))
        var pt = newSeq[byte](sz)
        for i in 0 ..< sz: pt[i] = byte(rand(255))
        var ad = newSeq[byte](aadLen)
        for i in 0 ..< aadLen: ad[i] = byte(rand(255))

        # nimcypher seal -> openssl open
        let (ctN, tagN) = nimSeal(key, iv, pt, ad)
        let back = osslOpen(cipher, key, iv, ctN, tagN, ad)
        check back.isSome
        if back.isSome:
          check back.get() == pt

        # openssl seal -> nimcypher open
        let (ctO, tagO) = osslSeal(cipher, key, iv, pt, ad)
        check ctO == ctN
        check tagO == tagN
        let openN = nimOpen(key, iv, ctO, tagO, ad)
        check openN.isSome
        if openN.isSome:
          check openN.get() == pt

        # tamper: both must reject
        if ctN.len > 0:
          var bad = ctN
          let bi = rand(ctN.len - 1)
          bad[bi] = bad[bi] xor 0x01
          check nimOpen(key, iv, bad, tagN, ad).isNone
          check osslOpen(cipher, key, iv, bad, tagN, ad).isNone
        var badTag = tagN
        badTag[0] = badTag[0] xor 0x01
        check nimOpen(key, iv, ctN, badTag, ad).isNone
        check osslOpen(cipher, key, iv, ctN, badTag, ad).isNone

suite "openssl AEAD interop":

  exercise("AES-128-GCM", ecAes128Gcm, 16,
    proc(key, iv, pt, ad: openArray[byte]): (seq[byte], array[16, byte]) =
      gcmAlgo.gcmLock(key, iv, pt, ad),
    proc(key, iv, ct: openArray[byte], tag: array[16, byte],
         ad: openArray[byte]): Option[seq[byte]] =
      gcmAlgo.gcmUnlock(key, iv, ct, tag, ad))

  exercise("AES-256-GCM", ecAes256Gcm, 32,
    proc(key, iv, pt, ad: openArray[byte]): (seq[byte], array[16, byte]) =
      gcmAlgo.gcmLock(key, iv, pt, ad),
    proc(key, iv, ct: openArray[byte], tag: array[16, byte],
         ad: openArray[byte]): Option[seq[byte]] =
      gcmAlgo.gcmUnlock(key, iv, ct, tag, ad))

  exercise("ChaCha20-Poly1305", ecChaCha20Poly1305, 32,
    proc(key, iv, pt, ad: openArray[byte]): (seq[byte], array[16, byte]) =
      tlsAead.chacha20Poly1305Seal(toArray[32](key), toArray[12](iv),
                                   pt, ad),
    proc(key, iv, ct: openArray[byte], tag: array[16, byte],
         ad: openArray[byte]): Option[seq[byte]] =
      tlsAead.chacha20Poly1305Open(toArray[32](key), toArray[12](iv),
                                   ct, tag, ad))

  test "AES-GCM session path matches one-shot and openssl":
    if not unavailable():
      randomize(0x5E55)
      for keyLen in [16, 32]:
        let cipher = cipherFor(
          if keyLen == 16: ecAes128Gcm else: ecAes256Gcm)
        var key = newSeq[byte](keyLen)
        var iv = newSeq[byte](12)
        for i in 0 ..< keyLen: key[i] = byte(rand(255))
        for i in 0 ..< 12: iv[i] = byte(rand(255))
        let sess = gcmAlgo.initGcmSession(key)
        for sz in [0, 16, 513, 16384]:
          var pt = newSeq[byte](sz)
          for i in 0 ..< sz: pt[i] = byte(rand(255))
          let ad = @[byte 0x17, 0x03, 0x03, 0x40, 0x00]
          let (ctS, tagS) = gcmAlgo.gcmLockWithSession(sess, iv, pt, ad)
          let (ctO, tagO) = osslSeal(cipher, key, iv, pt, ad)
          check ctS == ctO
          check tagS == tagO
          let openS = gcmAlgo.gcmUnlockWithSession(sess, iv, ctO, tagO, ad)
          check openS.isSome
          if openS.isSome:
            check openS.get() == pt
