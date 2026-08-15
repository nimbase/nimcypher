import std/unittest
import std/options

import nimcypher/algos/aead

import vectorutils
import vectors

test "aead_ietf vectors (XChaCha20-Poly1305 one-shot)":
  var i = 0
  while i < aeadIetfVectors.len:
    let key = hexToBytes(aeadIetfVectors[i]); inc i
    let nonce = hexToBytes(aeadIetfVectors[i]); inc i
    let ad = hexToBytes(aeadIetfVectors[i]); inc i
    let text = hexToBytes(aeadIetfVectors[i]); inc i
    let expected = hexToBytes(aeadIetfVectors[i]); inc i
    let expectedMac = expected[0 ..< 16]
    let expectedCt = expected[16 ..^ 1]
    let (ct, mac) = aeadLock(toArray[32](key), toArray[24](nonce), text, ad)
    check ct == expectedCt
    check mac == expectedMac
    # round-trip
    let unlocked = aeadUnlock(toArray[32](key), toArray[24](nonce), ct,
                              mac, ad)
    check unlocked.isSome
    check unlocked.get == text

test "aead_8439 vectors (IETF ChaCha20-Poly1305 streaming)":
  var i = 0
  while i < aead8439Vectors.len:
    let key = hexToBytes(aead8439Vectors[i]); inc i
    let nonce = hexToBytes(aead8439Vectors[i]); inc i
    let ad = hexToBytes(aead8439Vectors[i]); inc i
    let text = hexToBytes(aead8439Vectors[i]); inc i
    let expected = hexToBytes(aead8439Vectors[i]); inc i
    let expectedMac = expected[0 ..< 16]
    let expectedCt = expected[16 ..^ 1]
    var ctx: AeadContext
    initIetf(ctx, toArray[32](key), toArray[12](nonce))
    let (ct, mac) = write(ctx, text, ad)
    check ct == expectedCt
    check mac == expectedMac

test "aead round-trip with wrong mac fails":
  var key: array[32, byte]
  var nonce: array[24, byte]
  for j in 0 ..< 32: key[j] = byte(j)
  for j in 0 ..< 24: nonce[j] = byte(255 - j)
  let plain = @[byte 1, 2, 3, 4, 5, 6, 7, 8]
  let (ct, mac) = aeadLock(key, nonce, plain)
  # correct mac works
  let ok = aeadUnlock(key, nonce, ct, mac)
  check ok.isSome and ok.get == plain
  # corrupted mac fails
  var badMac = mac
  badMac[0] = badMac[0] xor 1
  let bad = aeadUnlock(key, nonce, ct, badMac)
  check bad.isNone

test "aead streaming round-trip across chunks":
  var key: array[32, byte]
  var nonce: array[24, byte]
  for j in 0 ..< 32: key[j] = byte(j)
  for j in 0 ..< 24: nonce[j] = byte(200 - j)
  var enc: AeadContext
  var dec: AeadContext
  initX(enc, key, nonce)
  initX(dec, key, nonce)
  var plain: seq[byte]
  var cipher: seq[byte]
  var macs: seq[array[16, byte]]
  for chunk in 0 ..< 10:
    var pt: seq[byte]
    for j in 0 ..< 8:
      pt.add(byte(chunk * 8 + j))
    plain.add(pt)
    let ad = @[byte(chunk)]
    let (ct, mac) = write(enc, pt, ad)
    cipher.add(ct)
    macs.add(mac)
    let back = read(dec, ct, mac, ad)
    check back.isSome
    check back.get == pt
  check cipher.len == plain.len
