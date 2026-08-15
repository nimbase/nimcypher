import std/unittest

import nimcypher/algos/poly1305

import vectorutils
import vectors

test "poly1305 vectors":
  var i = 0
  while i < poly1305Vectors.len:
    let key = hexToBytes(poly1305Vectors[i]); inc i
    let msg = hexToBytes(poly1305Vectors[i]); inc i
    let expected = hexToBytes(poly1305Vectors[i]); inc i
    let mac = poly1305(msg, toArray[32](key))
    check mac == expected

test "poly1305 incremental == one-shot":
  var keyArr: array[32, byte]
  for j in 0 ..< 32: keyArr[j] = byte(j)
  var ctx: Poly1305Context
  initPoly1305(ctx, keyArr)
  # authenticate the whole thing bit by bit
  var msg: seq[byte]
  for j in 0 ..< 16:
    msg.add(byte(j))
    update(ctx, @[byte(j)])
  let chunked = final(ctx)
  let whole = poly1305(msg, keyArr)
  check chunked == whole
