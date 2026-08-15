import std/unittest

import nimcypher/algos/chacha20

import vectorutils
import vectors

test "chacha20 vectors":
  var i = 0
  while i < chacha20Vectors.len:
    let key = hexToBytes(chacha20Vectors[i]); inc i
    let nonce = hexToBytes(chacha20Vectors[i]); inc i
    let plain = hexToBytes(chacha20Vectors[i]); inc i
    let ctr = loadU64Le(hexToBytes(chacha20Vectors[i])); inc i
    let expected = hexToBytes(chacha20Vectors[i]); inc i
    let outBuf = chacha20(plain, toArray[32](key), toArray[8](nonce), ctr)
    check outBuf == expected

test "ietf chacha20 vectors":
  var i = 0
  while i < ietfChacha20Vectors.len:
    let key = hexToBytes(ietfChacha20Vectors[i]); inc i
    let nonce = hexToBytes(ietfChacha20Vectors[i]); inc i
    let plain = hexToBytes(ietfChacha20Vectors[i]); inc i
    let ctr = loadU32Le(hexToBytes(ietfChacha20Vectors[i])); inc i
    let expected = hexToBytes(ietfChacha20Vectors[i]); inc i
    let outBuf = chacha20Ietf(plain, toArray[32](key), toArray[12](nonce), ctr)
    check outBuf == expected

test "xchacha20 vectors":
  var i = 0
  while i < xchacha20Vectors.len:
    let key = hexToBytes(xchacha20Vectors[i]); inc i
    let nonce = hexToBytes(xchacha20Vectors[i]); inc i
    let plain = hexToBytes(xchacha20Vectors[i]); inc i
    let ctr = loadU64Le(hexToBytes(xchacha20Vectors[i])); inc i
    let expected = hexToBytes(xchacha20Vectors[i]); inc i
    let outBuf = chacha20X(plain, toArray[32](key), toArray[24](nonce), ctr)
    check outBuf == expected

test "hchacha20 vectors":
  var i = 0
  while i < hchacha20Vectors.len:
    let key = hexToBytes(hchacha20Vectors[i]); inc i
    let nonce = hexToBytes(hchacha20Vectors[i]); inc i
    let expected = hexToBytes(hchacha20Vectors[i]); inc i
    let outBuf = chacha20H(toArray[32](key), toArray[16](nonce))
    check outBuf == expected

test "streaming chacha20 == one-shot (all variants)":
  var data: seq[byte]
  for j in 0 ..< 300:
    data.add(byte(j * 13 + 1))
  var key: array[32, byte]
  for j in 0 ..< 32: key[j] = byte(j)

  # DJB
  var nonce8: array[8, byte]
  for j in 0 ..< 8: nonce8[j] = byte(j + 1)
  let whole8 = chacha20(data, key, nonce8)
  var ctx8: Chacha20Context
  initChacha20Djb(ctx8, key, nonce8)
  var streamed8: seq[byte]
  streamed8.add chacha20Encrypt(ctx8, data[0 ..< 64])
  streamed8.add chacha20Encrypt(ctx8, data[64 ..< 192])
  streamed8.add chacha20Encrypt(ctx8, data[192 ..^ 1])
  streamed8.add chacha20Final(ctx8)
  check streamed8 == whole8

  # IETF
  var nonce12: array[12, byte]
  for j in 0 ..< 12: nonce12[j] = byte(40 + j)
  let whole12 = chacha20Ietf(data, key, nonce12)
  var ctx12: Chacha20Context
  initChacha20Ietf(ctx12, key, nonce12)
  var streamed12: seq[byte]
  streamed12.add chacha20Encrypt(ctx12, data[0 ..< 16])
  streamed12.add chacha20Encrypt(ctx12, data[16 ..< 16 + 128])
  streamed12.add chacha20Encrypt(ctx12, data[16 + 128 ..^ 1])
  streamed12.add chacha20Final(ctx12)
  check streamed12 == whole12

  # XChaCha20
  var nonce24: array[24, byte]
  for j in 0 ..< 24: nonce24[j] = byte(80 + j)
  let whole24 = chacha20X(data, key, nonce24)
  var ctx24: Chacha20Context
  initChacha20X(ctx24, key, nonce24)
  var streamed24: seq[byte]
  streamed24.add chacha20Encrypt(ctx24, data[0 ..< 255])
  streamed24.add chacha20Encrypt(ctx24, data[255 ..^ 1])
  streamed24.add chacha20Final(ctx24)
  check streamed24 == whole24

  # streaming decrypts what it encrypted
  var ctxEnc: Chacha20Context
  initChacha20X(ctxEnc, key, nonce24)
  var ctxDec: Chacha20Context
  initChacha20X(ctxDec, key, nonce24)
  var cipher: seq[byte]
  cipher.add chacha20Encrypt(ctxEnc, data[0 ..< 100])
  cipher.add chacha20Encrypt(ctxEnc, data[100 ..^ 1])
  cipher.add chacha20Final(ctxEnc)
  var plain: seq[byte]
  plain.add chacha20Encrypt(ctxDec, cipher[0 ..< 100])
  plain.add chacha20Encrypt(ctxDec, cipher[100 ..^ 1])
  plain.add chacha20Final(ctxDec)
  check plain == data
