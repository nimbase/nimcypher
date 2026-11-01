# TLS AEAD: AES-GCM + RFC 8439 ChaCha20-Poly1305.
#
# AES-GCM reuses nimcypher's NIST-tested GCM construction. ChaCha20-Poly1305
# is the TLS single-shot variant (RFC 8439 S2.8), built from the existing
# IETF ChaCha20 + Poly1305 primitives -- distinct from Monocypher's
# XChaCha streaming AEAD in algos/aead.nim.
#
# SPDX-License-Identifier: BSD-2-Clause

import std/options

import nimcypher/algos/gcm as gcmAlgo
import nimcypher/algos/chacha20 as chachaAlgo
import nimcypher/algos/poly1305 as polyAlgo
import nimcypher/algos/common as commonAlgo

import ./enums

const
  TlsTagLen* = 16

func le64*(v: uint64): array[8, byte] =
  for i in 0 ..< 8:
    result[i] = byte((v shr (8 * i)) and 0xFF)

proc chacha20Poly1305Seal*(key: array[32, byte], nonce: array[12, byte],
                           plaintext, ad: openArray[byte]): (seq[byte],
    array[16, byte]) =
  ## RFC 8439 S2.8 AEAD encryption. Returns (ciphertext, tag).
  var zeroBlock: array[32, byte]
  let block0 = chachaAlgo.chacha20Ietf(zeroBlock, key, nonce, 0)
  var polyKey: array[32, byte]
  for i in 0 ..< 32: polyKey[i] = block0[i]
  let cipher = chachaAlgo.chacha20Ietf(plaintext, key, nonce, 1)
  var macData = newSeq[byte]()
  for b in ad: macData.add(b)
  let adPad = (16 - (ad.len mod 16)) mod 16
  for _ in 0 ..< adPad: macData.add(0)
  for b in cipher: macData.add(b)
  let ctPad = (16 - (cipher.len mod 16)) mod 16
  for _ in 0 ..< ctPad: macData.add(0)
  let aadLen = le64(uint64(ad.len))
  let ctLen = le64(uint64(cipher.len))
  for b in aadLen: macData.add(b)
  for b in ctLen: macData.add(b)
  var polyCtx: polyAlgo.Poly1305Context
  polyAlgo.initPoly1305(polyCtx, polyKey)
  polyAlgo.update(polyCtx, macData)
  let tag = polyAlgo.final(polyCtx)
  commonAlgo.wipe(polyKey)
  result = (cipher, tag)

proc chacha20Poly1305Open*(key: array[32, byte], nonce: array[12, byte],
                           ciphertext, tag: openArray[byte],
                           ad: openArray[byte] = []): Option[seq[byte]] =
  ## RFC 8439 S2.8 AEAD decryption. Returns none on tag mismatch.
  if tag.len != 16:
    return none(seq[byte])
  var zeroBlock: array[32, byte]
  let block0 = chachaAlgo.chacha20Ietf(zeroBlock, key, nonce, 0)
  var polyKey: array[32, byte]
  for i in 0 ..< 32: polyKey[i] = block0[i]
  var macData = newSeq[byte]()
  for b in ad: macData.add(b)
  let adPad = (16 - (ad.len mod 16)) mod 16
  for _ in 0 ..< adPad: macData.add(0)
  for b in ciphertext: macData.add(b)
  let ctPad = (16 - (ciphertext.len mod 16)) mod 16
  for _ in 0 ..< ctPad: macData.add(0)
  let aadLen = le64(uint64(ad.len))
  let ctLen = le64(uint64(ciphertext.len))
  for b in aadLen: macData.add(b)
  for b in ctLen: macData.add(b)
  var polyCtx: polyAlgo.Poly1305Context
  polyAlgo.initPoly1305(polyCtx, polyKey)
  polyAlgo.update(polyCtx, macData)
  let realTag = polyAlgo.final(polyCtx)
  commonAlgo.wipe(polyKey)
  if not commonAlgo.constantTimeEqual(tag, realTag):
    return none(seq[byte])
  result = some(chachaAlgo.chacha20Ietf(ciphertext, key, nonce, 1))

proc tlsSeal*(suite: CipherSuiteId, key, nonce: openArray[byte],
              plaintext, ad: openArray[byte]): (seq[byte], array[16, byte]) =
  ## Suite-dispatched AEAD seal. Key/nonce sizes checked per suite.
  case suite
  of TlsAes128GcmSha256:
    if key.len != 16 or nonce.len != 12:
      raise newException(ValueError, "AES-128-GCM needs 16-byte key, 12-byte nonce")
    result = gcmAlgo.gcmLock(key, nonce, plaintext, ad)
  of TlsAes256GcmSha384:
    if key.len != 32 or nonce.len != 12:
      raise newException(ValueError, "AES-256-GCM needs 32-byte key, 12-byte nonce")
    result = gcmAlgo.gcmLock(key, nonce, plaintext, ad)
  of TlsChacha20Poly1305Sha256:
    if key.len != 32 or nonce.len != 12:
      raise newException(ValueError, "ChaCha20-Poly1305 needs 32-byte key, 12-byte nonce")
    var k: array[32, byte]
    var n: array[12, byte]
    for i in 0 ..< 32: k[i] = key[i]
    for i in 0 ..< 12: n[i] = nonce[i]
    result = chacha20Poly1305Seal(k, n, plaintext, ad)
    commonAlgo.wipe(k)

proc tlsOpen*(suite: CipherSuiteId, key, nonce: openArray[byte],
              ciphertext, tag: openArray[byte],
              ad: openArray[byte] = []): Option[seq[byte]] =
  ## Suite-dispatched AEAD open. Returns none on authentication failure.
  case suite
  of TlsAes128GcmSha256:
    if key.len != 16 or nonce.len != 12:
      raise newException(ValueError, "AES-128-GCM needs 16-byte key, 12-byte nonce")
    result = gcmAlgo.gcmUnlock(key, nonce, ciphertext, tag, ad)
  of TlsAes256GcmSha384:
    if key.len != 32 or nonce.len != 12:
      raise newException(ValueError, "AES-256-GCM needs 32-byte key, 12-byte nonce")
    result = gcmAlgo.gcmUnlock(key, nonce, ciphertext, tag, ad)
  of TlsChacha20Poly1305Sha256:
    if key.len != 32 or nonce.len != 12:
      raise newException(ValueError, "ChaCha20-Poly1305 needs 32-byte key, 12-byte nonce")
    var k: array[32, byte]
    var n: array[12, byte]
    for i in 0 ..< 32: k[i] = key[i]
    for i in 0 ..< 12: n[i] = nonce[i]
    result = chacha20Poly1305Open(k, n, ciphertext, tag, ad)
    commonAlgo.wipe(k)
