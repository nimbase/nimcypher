# Arithmetic modulo L (the group order).
#
# Ported from `monocypher.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ../common

{.push checks: off.}

const
  L: array[8, uint32] = [
    0x5cf5d3ed'u32, 0x5812631a'u32, 0xa2f79cd6'u32, 0x14def9de'u32,
    0x00000000'u32, 0x00000000'u32, 0x00000000'u32, 0x10000000'u32,
  ]

# p = a*b + p
proc multiply*(p: var openArray[uint32], a, b: openArray[uint32]) =
  for i in 0 ..< 8:
    var carry: uint64 = 0
    for j in 0 ..< 8:
      carry += uint64(p[i + j]) + uint64(a[i]) * uint64(b[j])
      p[i + j] = uint32(carry)
      carry = carry shr 32
    p[i + 8] = uint32(carry)

proc isAboveL*(x: openArray[uint32]): int =
  # work with L directly in a 2's complement encoding
  var carry: uint64 = 1
  for i in 0 ..< 8:
    carry += uint64(x[i]) + (uint64(not L[i]) and 0xffffffff'u64)
    carry = carry shr 32
  result = int(carry) # 0 or 1

# Final reduction modulo L, by conditionally removing L.
# if x < l     , then r = x
# if l <= x < 2*l, then r = x-l
# otherwise the result will be wrong
proc removeL*(r: var openArray[uint32], x: openArray[uint32]) =
  var carry = uint64(isAboveL(x))
  let mask = not uint32(carry) + 1'u32 # carry == 0 or 1
  for i in 0 ..< 8:
    carry += uint64(x[i]) + (uint64(not L[i]) and uint64(mask))
    r[i] = uint32(carry)
    carry = carry shr 32

# Full reduction modulo L (Barrett reduction)
proc modL*(reduced: BytePtr, x: openArray[uint32]) =
  const
    r: array[9, uint32] = [
      0x0a2c131b'u32, 0xed9ce5a3'u32, 0x086329a7'u32, 0x2106215d'u32,
      0xffffffeb'u32, 0xffffffff'u32, 0xffffffff'u32, 0xffffffff'u32,
      0xf'u32,
    ]
  var xr: array[25, uint32]
  # xr = x * r
  for i in 0 ..< 9:
    var carry: uint64 = 0
    for j in 0 ..< 16:
      carry += uint64(xr[i + j]) + uint64(r[i]) * uint64(x[j])
      xr[i + j] = uint32(carry)
      carry = carry shr 32
    xr[i + 16] = uint32(carry)
  # xr = floor(xr / 2^512) * L
  for i in 0 ..< 8:
    xr[i] = 0
  for i in 0 ..< 8:
    var carry: uint64 = 0
    for j in 0 ..< (8 - i):
      carry += uint64(xr[i + j]) + uint64(xr[i + 16]) * uint64(L[j])
      xr[i + j] = uint32(carry)
      carry = carry shr 32
  # xr = x - xr
  var carry: uint64 = 1
  for i in 0 ..< 8:
    carry += uint64(x[i]) + (uint64(not xr[i]) and 0xffffffff'u64)
    xr[i] = uint32(carry)
    carry = carry shr 32
  # final reduction modulo L (conditional subtraction)
  removeL(xr.toOpenArray(0, 7), xr.toOpenArray(0, 7))
  store32LeBuf(reduced, xr.toOpenArray(0, 7), 8)
  wipe(xr)

# Montgomery reduction. Divides x by 2^256, reduces the result modulo L.
proc redc*(u: var openArray[uint32], x: openArray[uint32]) =
  const
    k: array[8, uint32] = [
      0x12547e1b'u32, 0xd2b51da3'u32, 0xfdba84ff'u32, 0xb1a206f2'u32,
      0xffa36bea'u32, 0x14e75438'u32, 0x6fe91836'u32, 0x9db6c6f2'u32,
    ]
  # s = x * k (modulo 2^256)
  var s: array[8, uint32]
  for i in 0 ..< 8:
    var carry: uint64 = 0
    for j in 0 ..< (8 - i):
      carry += uint64(s[i + j]) + uint64(x[i]) * uint64(k[j])
      s[i + j] = uint32(carry)
      carry = carry shr 32
  var t: array[16, uint32]
  multiply(t, s, L)
  # t = t + x
  var carry: uint64 = 0
  for i in 0 ..< 16:
    carry += uint64(t[i]) + uint64(x[i])
    t[i] = uint32(carry)
    carry = carry shr 32
  # u = (t / 2^256) % L
  removeL(u, t.toOpenArray(8, 15))
  wipe(s)
  wipe(t)

proc trimScalar*(outp: BytePtr, inp: BytePtr) =
  for i in 0 ..< 32:
    outp[i] = inp[i]
  outp[0] = outp[0] and 248
  outp[31] = outp[31] and 127
  outp[31] = outp[31] or 64

proc scalarBit*(s: BytePtr, i: int): int =
  if i < 0:
    return 0 # handle -1 for sliding windows
  result = int((s[i shr 3] shr (i and 7)) and 1)

# s + (x*L) % 8*L
# Guaranteed to fit in 256 bits iff s fits in 255 bits.
proc addXL*(s: BytePtr, x: byte) =
  let mod8 = uint64(x) and 7
  var carry: uint64 = 0
  for i in 0 ..< 8:
    carry = carry + uint64(load32Le(s + 4 * i)) + uint64(L[i]) * mod8
    store32Le(s + 4 * i, uint32(carry))
    carry = carry shr 32

# r = (a * b) + c (all modulo L)
proc mulAdd*(r: BytePtr, a, b, c: BytePtr) =
  var A: array[8, uint32]
  load32LeBuf(A.toOpenArray(0, 7), a, 8)
  var B: array[8, uint32]
  load32LeBuf(B.toOpenArray(0, 7), b, 8)
  var p: array[16, uint32]
  load32LeBuf(p.toOpenArray(0, 7), c, 8)
  for i in 8 ..< 16:
    p[i] = 0
  multiply(p, A, B)
  modL(r, p)
  wipe(p)
  wipe(A)
  wipe(B)

{.pop.}
