# Arithmetic modulo 2^255 - 19 (field elements).
#
# Ported from `monocypher.c` (Monocypher 4.0.3), originally taken from
# SUPERCOP's ref10 implementation.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ../common

{.push checks: off.}

type Fe* = array[10, int32]

# field constants
const
  feOne*: Fe = [int32 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  sqrtm1*: Fe = [
    -32595792, -7943725, 9377950, 3500415, 12389472,
    -272473, -25146209, -2005654, 326686, 11406482,
  ]
  d*: Fe = [
    -10913610, 13857413, -15372611, 6949391, 114729,
    -8787816, -6275908, -3247719, -18696448, -12055116,
  ]
  D2*: Fe = [
    -21827239, -5839606, -30745221, 13898782, 229458,
    15978800, -12551817, -6495438, 29715968, 9444199,
  ]
  lopX*: Fe = [
    21352778, 5345713, 4660180, -8347857, 24143090,
    14568123, 30185756, -12247770, -33528939, 8345319,
  ]
  lopY*: Fe = [
    -6952922, -1265500, 6862341, -7057498, -4037696,
    -5447722, 31680899, -15325402, -19365852, 1569102,
  ]
  ufactor*: Fe = [
    -1917299, 15887451, -18755900, -7000830, -24778944,
    544946, -16816446, 4011309, -653372, 10741468,
  ]
  A2*: Fe = [int32 12721188, 3529, 0, 0, 0, 0, 0, 0, 0, 0]

proc feZero*(h: var Fe) {.inline.} =
  for i in 0 ..< 10:
    h[i] = 0

proc feOneSet*(h: var Fe) {.inline.} =
  h[0] = 1
  for i in 1 ..< 10:
    h[i] = 0

proc feCopy*(h: var Fe, f: Fe) {.inline.} =
  for i in 0 ..< 10:
    h[i] = f[i]

proc feNeg*(h: var Fe, f: Fe) {.inline.} =
  for i in 0 ..< 10:
    h[i] = -f[i]

proc feAdd*(h: var Fe, f, g: Fe) {.inline.} =
  for i in 0 ..< 10:
    h[i] = f[i] + g[i]

proc feSub*(h: var Fe, f, g: Fe) {.inline.} =
  for i in 0 ..< 10:
    h[i] = f[i] - g[i]

proc feCswap*(f: var Fe, g: var Fe, b: int) {.inline.} =
  let mask = int32(-b)
  for i in 0 ..< 10:
    let x = (f[i] xor g[i]) and mask
    f[i] = f[i] xor x
    g[i] = g[i] xor x

proc feCcopy*(f: var Fe, g: Fe, b: int) {.inline.} =
  let mask = int32(-b)
  for i in 0 ..< 10:
    let x = (f[i] xor g[i]) and mask
    f[i] = f[i] xor x

# Signed carry propagation. `t0`..`t9` must be `var int64` locals and
# `h` a `var Fe`. See the C source for the full proof of bounds.
template carry() =
  var c: int64
  c = (t0 + (1'i64 shl 25)) shr 26
  t0 -= c * (1'i64 shl 26)
  t1 += c
  c = (t4 + (1'i64 shl 25)) shr 26
  t4 -= c * (1'i64 shl 26)
  t5 += c
  c = (t1 + (1'i64 shl 24)) shr 25
  t1 -= c * (1'i64 shl 25)
  t2 += c
  c = (t5 + (1'i64 shl 24)) shr 25
  t5 -= c * (1'i64 shl 25)
  t6 += c
  c = (t2 + (1'i64 shl 25)) shr 26
  t2 -= c * (1'i64 shl 26)
  t3 += c
  c = (t6 + (1'i64 shl 25)) shr 26
  t6 -= c * (1'i64 shl 26)
  t7 += c
  c = (t3 + (1'i64 shl 24)) shr 25
  t3 -= c * (1'i64 shl 25)
  t4 += c
  c = (t7 + (1'i64 shl 24)) shr 25
  t7 -= c * (1'i64 shl 25)
  t8 += c
  c = (t4 + (1'i64 shl 25)) shr 26
  t4 -= c * (1'i64 shl 26)
  t5 += c
  c = (t8 + (1'i64 shl 25)) shr 26
  t8 -= c * (1'i64 shl 26)
  t9 += c
  c = (t9 + (1'i64 shl 24)) shr 25
  t9 -= c * (1'i64 shl 25)
  t0 += c * 19
  c = (t0 + (1'i64 shl 25)) shr 26
  t0 -= c * (1'i64 shl 26)
  t1 += c
  h[0] = int32(t0); h[1] = int32(t1); h[2] = int32(t2); h[3] = int32(t3)
  h[4] = int32(t4); h[5] = int32(t5); h[6] = int32(t6); h[7] = int32(t7)
  h[8] = int32(t8); h[9] = int32(t9)

proc feFrombytesMask*(h: var Fe, s: BytePtr, nbMask: int) {.inline.} =
  let mask = 0xffffff'u32 shr nbMask
  var t0 = int64(load32Le(s))
  var t1 = int64(load24Le(s + 4)) shl 6
  var t2 = int64(load24Le(s + 7)) shl 5
  var t3 = int64(load24Le(s + 10)) shl 3
  var t4 = int64(load24Le(s + 13)) shl 2
  var t5 = int64(load32Le(s + 16))
  var t6 = int64(load24Le(s + 20)) shl 7
  var t7 = int64(load24Le(s + 23)) shl 5
  var t8 = int64(load24Le(s + 26)) shl 4
  var t9 = int64(load24Le(s + 29) and mask) shl 2
  carry()

proc feFrombytes*(h: var Fe, s: BytePtr) {.inline.} =
  feFrombytesMask(h, s, 1)

proc feTobytes*(s: BytePtr, h: Fe) =
  var t: array[10, int32]
  for i in 0 ..< 10:
    t[i] = h[i]
  var q = (19 * t[9] + (1 shl 24)) shr 25
  for i in 0 ..< 5:
    q += t[2 * i]
    q = q shr 26
    q += t[2 * i + 1]
    q = q shr 25
  q *= 19
  for i in 0 ..< 5:
    t[2 * i] += q
    q = t[2 * i] shr 26
    t[2 * i] -= q * (1 shl 26)
    t[2 * i + 1] += q
    q = t[2 * i + 1] shr 25
    t[2 * i + 1] -= q * (1 shl 25)
  store32Le(s, uint32(t[0]) or (uint32(t[1]) shl 26))
  store32Le(s + 4, uint32(t[1]) shr 6 or (uint32(t[2]) shl 19))
  store32Le(s + 8, uint32(t[2]) shr 13 or (uint32(t[3]) shl 13))
  store32Le(s + 12, uint32(t[3]) shr 19 or (uint32(t[4]) shl 6))
  store32Le(s + 16, uint32(t[5]) or (uint32(t[6]) shl 25))
  store32Le(s + 20, uint32(t[6]) shr 7 or (uint32(t[7]) shl 19))
  store32Le(s + 24, uint32(t[7]) shr 13 or (uint32(t[8]) shl 12))
  store32Le(s + 28, uint32(t[8]) shr 20 or (uint32(t[9]) shl 6))
  wipe(t)

proc feMulSmall*(h: var Fe, f: Fe, g: int32) {.inline.} =
  var t0 = int64(f[0]) * int64(g)
  var t1 = int64(f[1]) * int64(g)
  var t2 = int64(f[2]) * int64(g)
  var t3 = int64(f[3]) * int64(g)
  var t4 = int64(f[4]) * int64(g)
  var t5 = int64(f[5]) * int64(g)
  var t6 = int64(f[6]) * int64(g)
  var t7 = int64(f[7]) * int64(g)
  var t8 = int64(f[8]) * int64(g)
  var t9 = int64(f[9]) * int64(g)
  carry()

proc feMul*(h: var Fe, f, g: Fe) =
  let f0 = int64(f[0]); let f1 = int64(f[1]); let f2 = int64(f[2])
  let f3 = int64(f[3]); let f4 = int64(f[4]); let f5 = int64(f[5])
  let f6 = int64(f[6]); let f7 = int64(f[7]); let f8 = int64(f[8])
  let f9 = int64(f[9])
  let g0 = int64(g[0]); let g1 = int64(g[1]); let g2 = int64(g[2])
  let g3 = int64(g[3]); let g4 = int64(g[4]); let g5 = int64(g[5])
  let g6 = int64(g[6]); let g7 = int64(g[7]); let g8 = int64(g[8])
  let g9 = int64(g[9])
  let F1 = f1 * 2; let F3 = f3 * 2; let F5 = f5 * 2; let F7 = f7 * 2; let F9 = f9 * 2
  let G1 = g1 * 19; let G2 = g2 * 19; let G3 = g3 * 19
  let G4 = g4 * 19; let G5 = g5 * 19; let G6 = g6 * 19
  let G7 = g7 * 19; let G8 = g8 * 19; let G9 = g9 * 19
  var t0 = f0 * g0 + F1 * G9 + f2 * G8 + F3 * G7 + f4 * G6 +
           F5 * G5 + f6 * G4 + F7 * G3 + f8 * G2 + F9 * G1
  var t1 = f0 * g1 + f1 * g0 + f2 * G9 + f3 * G8 + f4 * G7 +
           f5 * G6 + f6 * G5 + f7 * G4 + f8 * G3 + f9 * G2
  var t2 = f0 * g2 + F1 * g1 + f2 * g0 + F3 * G9 + f4 * G8 +
           F5 * G7 + f6 * G6 + F7 * G5 + f8 * G4 + F9 * G3
  var t3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + f4 * G9 +
           f5 * G8 + f6 * G7 + f7 * G6 + f8 * G5 + f9 * G4
  var t4 = f0 * g4 + F1 * g3 + f2 * g2 + F3 * g1 + f4 * g0 +
           F5 * G9 + f6 * G8 + F7 * G7 + f8 * G6 + F9 * G5
  var t5 = f0 * g5 + f1 * g4 + f2 * g3 + f3 * g2 + f4 * g1 +
           f5 * g0 + f6 * G9 + f7 * G8 + f8 * G7 + f9 * G6
  var t6 = f0 * g6 + F1 * g5 + f2 * g4 + F3 * g3 + f4 * g2 +
           F5 * g1 + f6 * g0 + F7 * G9 + f8 * G8 + F9 * G7
  var t7 = f0 * g7 + f1 * g6 + f2 * g5 + f3 * g4 + f4 * g3 +
           f5 * g2 + f6 * g1 + f7 * g0 + f8 * G9 + f9 * G8
  var t8 = f0 * g8 + F1 * g7 + f2 * g6 + F3 * g5 + f4 * g4 +
           F5 * g3 + f6 * g2 + F7 * g1 + f8 * g0 + F9 * G9
  var t9 = f0 * g9 + f1 * g8 + f2 * g7 + f3 * g6 + f4 * g5 +
           f5 * g4 + f6 * g3 + f7 * g2 + f8 * g1 + f9 * g0
  carry()

proc feSq*(h: var Fe, f: Fe) =
  let f0 = int64(f[0]); let f1 = int64(f[1]); let f2 = int64(f[2])
  let f3 = int64(f[3]); let f4 = int64(f[4]); let f5 = int64(f[5])
  let f6 = int64(f[6]); let f7 = int64(f[7]); let f8 = int64(f[8])
  let f9 = int64(f[9])
  let f0_2 = f0 * 2; let f1_2 = f1 * 2; let f2_2 = f2 * 2; let f3_2 = f3 * 2
  let f4_2 = f4 * 2; let f5_2 = f5 * 2; let f6_2 = f6 * 2; let f7_2 = f7 * 2
  let f5_38 = f5 * 38; let f6_19 = f6 * 19; let f7_38 = f7 * 38
  let f8_19 = f8 * 19; let f9_38 = f9 * 38
  var t0 = f0 * f0 + f1_2 * f9_38 + f2_2 * f8_19 +
           f3_2 * f7_38 + f4_2 * f6_19 + f5 * f5_38
  var t1 = f0_2 * f1 + f2 * f9_38 + f3_2 * f8_19 +
           f4 * f7_38 + f5_2 * f6_19
  var t2 = f0_2 * f2 + f1_2 * f1 + f3_2 * f9_38 +
           f4_2 * f8_19 + f5_2 * f7_38 + f6 * f6_19
  var t3 = f0_2 * f3 + f1_2 * f2 + f4 * f9_38 +
           f5_2 * f8_19 + f6 * f7_38
  var t4 = f0_2 * f4 + f1_2 * f3_2 + f2 * f2 +
           f5_2 * f9_38 + f6_2 * f8_19 + f7 * f7_38
  var t5 = f0_2 * f5 + f1_2 * f4 + f2_2 * f3 +
           f6 * f9_38 + f7_2 * f8_19
  var t6 = f0_2 * f6 + f1_2 * f5_2 + f2_2 * f4 +
           f3_2 * f3 + f7_2 * f9_38 + f8 * f8_19
  var t7 = f0_2 * f7 + f1_2 * f6 + f2_2 * f5 +
           f3_2 * f4 + f8 * f9_38
  var t8 = f0_2 * f8 + f1_2 * f7_2 + f2_2 * f6 +
           f3_2 * f5_2 + f4 * f4 + f9 * f9_38
  var t9 = f0_2 * f9 + f1_2 * f8 + f2_2 * f7 +
           f3_2 * f6 + f4 * f5_2
  carry()

proc feIsOdd*(f: Fe): int {.inline.} =
  var s: array[32, byte]
  feTobytes(cast[BytePtr](unsafeAddr s[0]), f)
  result = int(s[0] and 1)
  wipe(s)

proc feIsEqual*(f, g: Fe): int {.inline.} =
  var fs, gs: array[32, byte]
  feTobytes(cast[BytePtr](unsafeAddr fs[0]), f)
  feTobytes(cast[BytePtr](unsafeAddr gs[0]), g)
  result = if constantTimeEqual(fs, gs): 1 else: 0
  wipe(fs)
  wipe(gs)

# Inverse square root. Returns 1 if x is a square, 0 otherwise.
# After the call:
#   isr = sqrt(1/x)        if x is a non-zero square.
#   isr = sqrt(sqrt(-1)/x) if x is not a square.
#   isr = 0                if x is zero.
proc invsqrt*(isr: var Fe, x: Fe): int =
  var t0, t1, t2: Fe
  feSq(t0, x)
  feSq(t1, t0)
  feSq(t1, t1)
  feMul(t1, x, t1)
  feMul(t0, t0, t1)
  feSq(t0, t0)
  feMul(t0, t1, t0)
  feSq(t1, t0)
  for i in 1 ..< 5:
    feSq(t1, t1)
  feMul(t0, t1, t0)
  feSq(t1, t0)
  for i in 1 ..< 10:
    feSq(t1, t1)
  feMul(t1, t1, t0)
  feSq(t2, t1)
  for i in 1 ..< 20:
    feSq(t2, t2)
  feMul(t1, t2, t1)
  feSq(t1, t1)
  for i in 1 ..< 10:
    feSq(t1, t1)
  feMul(t0, t1, t0)
  feSq(t1, t0)
  for i in 1 ..< 50:
    feSq(t1, t1)
  feMul(t1, t1, t0)
  feSq(t2, t1)
  for i in 1 ..< 100:
    feSq(t2, t2)
  feMul(t1, t2, t1)
  feSq(t1, t1)
  for i in 1 ..< 50:
    feSq(t1, t1)
  feMul(t0, t1, t0)
  feSq(t0, t0)
  for i in 1 ..< 2:
    feSq(t0, t0)
  feMul(t0, t0, x)

  # quartic = x^((p-1)/4)
  var quartic: Fe
  feSq(quartic, t0)
  feMul(quartic, quartic, x)

  var check: Fe
  feZero(check)
  let z0 = feIsEqual(x, check)
  feOneSet(check)
  let p1 = feIsEqual(quartic, check)
  feNeg(check, check)
  let m1 = feIsEqual(quartic, check)
  feNeg(check, sqrtm1)
  let ms = feIsEqual(quartic, check)

  # if quartic == -1 or sqrt(-1)
  # then  isr = x^((p-1)/4) * sqrt(-1)
  # else  isr = x^((p-1)/4)
  feMul(isr, t0, sqrtm1)
  feCcopy(isr, t0, 1 - (m1 or ms))

  wipe(t0)
  wipe(t1)
  wipe(t2)
  result = p1 or m1 or z0

proc feInvert*(outp: var Fe, x: Fe) =
  var tmp: Fe
  feSq(tmp, x)
  discard invsqrt(tmp, tmp)
  feSq(tmp, tmp)
  feMul(outp, tmp, x)
  wipe(tmp)

{.pop.}
