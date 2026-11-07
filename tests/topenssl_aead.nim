# Live OpenSSL interop for the AEAD constructions: nimcypher vs libcrypto.
#
# `topenssl.nim` covers everything the `openssl enc` CLI can express, but
# that CLI rejects AEAD ciphers, so AES-GCM and ChaCha20-Poly1305 had no
# live cross-check (only the checked-in NIST/RFC vectors in `tgcm` /
# `tchacha20`). This suite drives libcrypto's EVP interface directly —
# the same dylib Nim's TLS stack links — and exchanges real ciphertext
# and tags in both directions, for every size class that selects a
# different kernel path (wide 32-block, 8-block, pair, odd block, tail).
#
# Requires libcrypto at runtime. If it cannot be loaded the suite prints
# a note and passes trivially, unless NIMCYPHER_REQUIRE_OPENSSL=1 is set
# (as in CI), in which case it fails loudly — same convention as
# `topenssl.nim`.

import std/options
import std/os
import std/random
import std/unittest

import std/openssl

import nimcypher/algos/common
import nimcypher/utils
import nimcypher/algos/gcm as gcmAlgo
import nimcypher/tls/enums
import nimcypher/tls/aead as tlsAead

type
  EVP_CIPHER = ptr object
  EVP_CIPHER_CTX = ptr object

{.push dynlib: DLLUtilName, cdecl, importc.}
proc EVP_CIPHER_CTX_new(): EVP_CIPHER_CTX
proc EVP_CIPHER_CTX_free(c: EVP_CIPHER_CTX)
proc EVP_aes_128_gcm(): EVP_CIPHER
proc EVP_aes_256_gcm(): EVP_CIPHER
proc EVP_chacha20_poly1305(): EVP_CIPHER
proc EVP_EncryptInit_ex(c: EVP_CIPHER_CTX, typ: EVP_CIPHER,
                        impl, key, iv: pointer): cint
proc EVP_EncryptUpdate(c: EVP_CIPHER_CTX, outd: pointer, outl: ptr cint,
                       ind: pointer, inl: cint): cint
proc EVP_EncryptFinal_ex(c: EVP_CIPHER_CTX, outd: pointer,
                         outl: ptr cint): cint
proc EVP_DecryptInit_ex(c: EVP_CIPHER_CTX, typ: EVP_CIPHER,
                        impl, key, iv: pointer): cint
proc EVP_DecryptUpdate(c: EVP_CIPHER_CTX, outd: pointer, outl: ptr cint,
                       ind: pointer, inl: cint): cint
proc EVP_DecryptFinal_ex(c: EVP_CIPHER_CTX, outd: pointer,
                         outl: ptr cint): cint
proc EVP_CIPHER_CTX_ctrl(c: EVP_CIPHER_CTX, typ: cint, arg: cint,
                         p: pointer): cint
{.pop.}

const
  EVP_CTRL_AEAD_GET_TAG = 0x10
  EVP_CTRL_AEAD_SET_TAG = 0x11

proc opensslAvailable(): bool =
  try:
    let c = EVP_CIPHER_CTX_new()
    if c == nil: return false
    EVP_CIPHER_CTX_free(c)
    true
  except CatchableError:
    false

proc osslSeal(cipher: EVP_CIPHER, key, iv, pt, ad: openArray[byte]):
    (seq[byte], array[16, byte]) =
  let ctx = EVP_CIPHER_CTX_new()
  doAssert ctx != nil
  defer: EVP_CIPHER_CTX_free(ctx)
  doAssert EVP_EncryptInit_ex(ctx, cipher, nil, unsafeAddr key[0],
                              unsafeAddr iv[0]) == 1
  var outl: cint = 0
  if ad.len > 0:
    # NB: for AAD OpenSSL reports the *input* length in outl, so it must
    # not be carried into the ciphertext length.
    doAssert EVP_EncryptUpdate(ctx, nil, addr outl, unsafeAddr ad[0],
                               ad.len.cint) == 1
  result[0] = newSeq[byte](pt.len + 16)
  var n = 0
  if pt.len > 0:
    doAssert EVP_EncryptUpdate(ctx, addr result[0][0], addr outl,
                               unsafeAddr pt[0], pt.len.cint) == 1
    n = outl.int
  doAssert EVP_EncryptFinal_ex(ctx, addr result[0][n], addr outl) == 1
  n += outl.int
  result[0].setLen(n)
  doAssert EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                               addr result[1][0]) == 1

proc osslOpen(cipher: EVP_CIPHER, key, iv, ct: openArray[byte],
              tag: array[16, byte], ad: openArray[byte]): Option[seq[byte]] =
  let ctx = EVP_CIPHER_CTX_new()
  doAssert ctx != nil
  defer: EVP_CIPHER_CTX_free(ctx)
  doAssert EVP_DecryptInit_ex(ctx, cipher, nil, unsafeAddr key[0],
                              unsafeAddr iv[0]) == 1
  var outl: cint = 0
  if ad.len > 0:
    doAssert EVP_DecryptUpdate(ctx, nil, addr outl, unsafeAddr ad[0],
                               ad.len.cint) == 1
  var pt = newSeq[byte](ct.len + 16)
  var n = 0
  if ct.len > 0:
    doAssert EVP_DecryptUpdate(ctx, addr pt[0], addr outl,
                               unsafeAddr ct[0], ct.len.cint) == 1
    n = outl.int
  var t = tag
  doAssert EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                               addr t[0]) == 1
  let ok = EVP_DecryptFinal_ex(ctx, addr pt[n], addr outl)
  if ok != 1:
    return none(seq[byte])
  n += outl.int
  pt.setLen(n)
  result = some(pt)

const sizes = [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 257,
               511, 512, 513, 1023, 1024, 1025, 4096, 16384, 16385]

proc exercise(name: string, cipher: EVP_CIPHER, keyLen: int,
              nimSeal: proc(key, iv, pt, ad: openArray[byte]):
                (seq[byte], array[16, byte]) {.closure.},
              nimOpen: proc(key, iv, ct: openArray[byte],
                            tag: array[16, byte], ad: openArray[byte]):
                Option[seq[byte]] {.closure.}) =
  test name & ": nimcypher <-> openssl both directions, all sizes":
    if not opensslAvailable():
      if getEnv("NIMCYPHER_REQUIRE_OPENSSL") == "1":
        check false # fail loudly in CI
      else:
        echo "NOTE: libcrypto not loadable; skipping live AEAD interop"
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

  exercise("AES-128-GCM", EVP_aes_128_gcm(), 16,
    proc(key, iv, pt, ad: openArray[byte]): (seq[byte], array[16, byte]) =
      gcmAlgo.gcmLock(key, iv, pt, ad),
    proc(key, iv, ct: openArray[byte], tag: array[16, byte],
         ad: openArray[byte]): Option[seq[byte]] =
      gcmAlgo.gcmUnlock(key, iv, ct, tag, ad))

  exercise("AES-256-GCM", EVP_aes_256_gcm(), 32,
    proc(key, iv, pt, ad: openArray[byte]): (seq[byte], array[16, byte]) =
      gcmAlgo.gcmLock(key, iv, pt, ad),
    proc(key, iv, ct: openArray[byte], tag: array[16, byte],
         ad: openArray[byte]): Option[seq[byte]] =
      gcmAlgo.gcmUnlock(key, iv, ct, tag, ad))

  exercise("ChaCha20-Poly1305", EVP_chacha20_poly1305(), 32,
    proc(key, iv, pt, ad: openArray[byte]): (seq[byte], array[16, byte]) =
      tlsAead.chacha20Poly1305Seal(toArray[32](key), toArray[12](iv),
                                   pt, ad),
    proc(key, iv, ct: openArray[byte], tag: array[16, byte],
         ad: openArray[byte]): Option[seq[byte]] =
      tlsAead.chacha20Poly1305Open(toArray[32](key), toArray[12](iv),
                                   ct, tag, ad))

  test "AES-GCM session path matches one-shot and openssl":
    if opensslAvailable():
      randomize(0x5E55)
      for keyLen in [16, 32]:
        let cipher = if keyLen == 16: EVP_aes_128_gcm() else: EVP_aes_256_gcm()
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
    else:
      echo "NOTE: libcrypto not loadable; skipping session interop"
