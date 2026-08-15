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
