import std/unittest

import nimcypher/algos/common

test "wipe zeroes buffers":
  var buf: array[32, byte]
  for i in 0 ..< 32: buf[i] = byte(i)
  wipe(buf)
  check buf == default(array[32, byte])

  var seq = newSeq[byte](16)
  for i in 0 ..< 16: seq[i] = byte(255 - i)
  wipe(seq)
  check seq == newSeq[byte](16)

test "constantTimeEqual":
  var a: array[16, byte]
  var b: array[16, byte]
  for i in 0 ..< 16: a[i] = byte(i)
  for i in 0 ..< 16: b[i] = byte(i)
  check constantTimeEqual(a, b)
  b[7] = 0
  check not constantTimeEqual(a, b)

  var c: array[32, byte]
  var d: array[32, byte]
  for i in 0 ..< 32: c[i] = byte(i * 3)
  for i in 0 ..< 32: d[i] = byte(i * 3)
  check constantTimeEqual(c, d)
  d[31] = 1
  check not constantTimeEqual(c, d)

  var e: array[64, byte]
  var f: array[64, byte]
  for i in 0 ..< 64: e[i] = byte(i)
  for i in 0 ..< 64: f[i] = byte(i)
  check constantTimeEqual(e, f)
  e[63] = 0
  check not constantTimeEqual(e, f)

  # different lengths are never equal
  check not constantTimeEqual(a, c)
  # empty buffers are equal
  check constantTimeEqual(@[], @[])

test "verify16/32/64":
  var a: array[16, byte]
  var b: array[16, byte]
  for i in 0 ..< 16: a[i] = byte(i)
  for i in 0 ..< 16: b[i] = byte(i)
  check verify16(a, b)
  b[15] = 0
  check not verify16(a, b)

  var c: array[32, byte]
  var d: array[32, byte]
  for i in 0 ..< 32: c[i] = byte(i * 3)
  for i in 0 ..< 32: d[i] = byte(i * 3)
  check verify32(c, d)
  d[0] = 1
  check not verify32(c, d)

  var e: array[64, byte]
  var f: array[64, byte]
  for i in 0 ..< 64: e[i] = byte(i)
  for i in 0 ..< 64: f[i] = byte(i)
  check verify64(e, f)
  e[63] = 0
  check not verify64(e, f)
