# AES-128/192/256 block cipher, constant-time bitsliced implementation.
#
# The core follows BearSSL's `aes_ct64` constant-time design (by Thomas
# Pornin, MIT licensed): the cipher state never touches lookup tables, the
# S-box is evaluated as the Boyar-Peralta boolean circuit, so every operation
# runs in time independent of the key and the data. The bitsliced
# representation processes four blocks per call; single-block calls replicate
# their input across the lanes.
#
# Modes on top: ECB, CBC, CTR (SP 800-38A, full 128-bit counter increment),
# CFB (128-bit segments), OFB, plus PKCS#7 padding helpers and streaming
# contexts shaped like the other NimCypher primitives.
#
# Optional AES-NI (amd64) and ARMv8 Crypto Extensions (arm64) kernels live in
# `./internal/aes_simd`; they are compiled only when
# `features.nimcypher.nimsimd` is defined (see nimcypher.nimble).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0; the ported
# circuits originate from BearSSL (MIT, copyright Thomas Pornin).

import ./common

when defined(features.nimcypher.nimsimd) and (defined(amd64) or defined(arm64)):
  import ./internal/aes_simd

{.push checks: off.}

const aesRcon = [0x01'u32, 0x02'u32, 0x04'u32, 0x08'u32, 0x10'u32,
                 0x20'u32, 0x40'u32, 0x80'u32, 0x1B'u32, 0x36'u32]

type
  AesContext* = object
    ## Expanded AES key schedule (constant-time bitsliced form).
    rounds*: int              # 10 (AES-128), 12 (AES-192) or 14 (AES-256)
    skey*: array[120, uint64] # expanded round keys, 8 words per round
    when defined(features.nimcypher.nimsimd) and (defined(amd64) or defined(arm64)):
      nrk*: array[240, byte]      # conventional schedule (hardware kernels)
      nrkInv*: array[240, byte]   # InvMixColumns form for decryption

# ---------------------------------------------------------------------------
# Bitsliced primitives (BearSSL aes_ct64).
#
# State: eight 64-bit words. Each word rank carries one byte position of the
# AES state; the 64 bits hold four blocks x eight bit ranks. `ortho`
# transposes bits between the "packed" and "sliced" views.
# ---------------------------------------------------------------------------

template swapN(cl, ch: uint64, s: int, x, y: uint64) =
  let a = x
  let b = y
  x = (a and cl) or ((b and cl) shl s)
  y = ((a and ch) shr s) or (b and ch)

proc ortho*(q: var array[8, uint64]) {.inline.} =
  ## Bit-transpose the eight words (pack <-> slice views).
  swapN(0x5555555555555555'u64, 0xAAAAAAAAAAAAAAAA'u64, 1, q[0], q[1])
  swapN(0x5555555555555555'u64, 0xAAAAAAAAAAAAAAAA'u64, 1, q[2], q[3])
  swapN(0x5555555555555555'u64, 0xAAAAAAAAAAAAAAAA'u64, 1, q[4], q[5])
  swapN(0x5555555555555555'u64, 0xAAAAAAAAAAAAAAAA'u64, 1, q[6], q[7])

  swapN(0x3333333333333333'u64, 0xCCCCCCCCCCCCCCCC'u64, 2, q[0], q[2])
  swapN(0x3333333333333333'u64, 0xCCCCCCCCCCCCCCCC'u64, 2, q[1], q[3])
  swapN(0x3333333333333333'u64, 0xCCCCCCCCCCCCCCCC'u64, 2, q[4], q[6])
  swapN(0x3333333333333333'u64, 0xCCCCCCCCCCCCCCCC'u64, 2, q[5], q[7])

  swapN(0x0F0F0F0F0F0F0F0F'u64, 0xF0F0F0F0F0F0F0F0'u64, 4, q[0], q[4])
  swapN(0x0F0F0F0F0F0F0F0F'u64, 0xF0F0F0F0F0F0F0F0'u64, 4, q[1], q[5])
  swapN(0x0F0F0F0F0F0F0F0F'u64, 0xF0F0F0F0F0F0F0F0'u64, 4, q[2], q[6])
  swapN(0x0F0F0F0F0F0F0F0F'u64, 0xF0F0F0F0F0F0F0F0'u64, 4, q[3], q[7])

proc interleaveIn*(q: var array[8, uint64], idx: int,
                   w0, w1, w2, w3: uint32) {.inline.} =
  ## Pack one block (four little-endian words) into lane group `idx`
  ## (words `idx` and `idx + 4`).
  var x0 = uint64(w0)
  var x1 = uint64(w1)
  var x2 = uint64(w2)
  var x3 = uint64(w3)
  x0 = x0 or (x0 shl 16)
  x1 = x1 or (x1 shl 16)
  x2 = x2 or (x2 shl 16)
  x3 = x3 or (x3 shl 16)
  x0 = x0 and 0x0000FFFF0000FFFF'u64
  x1 = x1 and 0x0000FFFF0000FFFF'u64
  x2 = x2 and 0x0000FFFF0000FFFF'u64
  x3 = x3 and 0x0000FFFF0000FFFF'u64
  x0 = x0 or (x0 shl 8)
  x1 = x1 or (x1 shl 8)
  x2 = x2 or (x2 shl 8)
  x3 = x3 or (x3 shl 8)
  x0 = x0 and 0x00FF00FF00FF00FF'u64
  x1 = x1 and 0x00FF00FF00FF00FF'u64
  x2 = x2 and 0x00FF00FF00FF00FF'u64
  x3 = x3 and 0x00FF00FF00FF00FF'u64
  q[idx] = x0 or (x2 shl 8)
  q[idx + 4] = x1 or (x3 shl 8)

proc interleaveOut*(w: var array[4, uint32], q0, q1: uint64) {.inline.} =
  ## Unpack lane group output back into four little-endian words.
  var x0 = q0 and 0x00FF00FF00FF00FF'u64
  var x1 = q1 and 0x00FF00FF00FF00FF'u64
  var x2 = (q0 shr 8) and 0x00FF00FF00FF00FF'u64
  var x3 = (q1 shr 8) and 0x00FF00FF00FF00FF'u64
  x0 = x0 or (x0 shr 8)
  x1 = x1 or (x1 shr 8)
  x2 = x2 or (x2 shr 8)
  x3 = x3 or (x3 shr 8)
  x0 = x0 and 0x0000FFFF0000FFFF'u64
  x1 = x1 and 0x0000FFFF0000FFFF'u64
  x2 = x2 and 0x0000FFFF0000FFFF'u64
  x3 = x3 and 0x0000FFFF0000FFFF'u64
  w[0] = uint32(x0) or uint32(x0 shr 16)
  w[1] = uint32(x1) or uint32(x1 shr 16)
  w[2] = uint32(x2) or uint32(x2 shr 16)
  w[3] = uint32(x3) or uint32(x3 shr 16)

proc bitsliceSbox*(q: var array[8, uint64]) =
  ## AES S-box as the Boyar-Peralta boolean circuit ("A new combinational
  ## logic minimization technique with applications to cryptology",
  ## https://eprint.iacr.org/2009/191.pdf). Inputs/outputs are numbered in
  ## "reverse" order (q[7] is the high bit, q[0] the low bit).
  let x0 = q[7]
  let x1 = q[6]
  let x2 = q[5]
  let x3 = q[4]
  let x4 = q[3]
  let x5 = q[2]
  let x6 = q[1]
  let x7 = q[0]

  # Top linear transformation.
  var y14 = x3 xor x5
  var y13 = x0 xor x6
  var y9 = x0 xor x3
  var y8 = x0 xor x5
  let t0 = x1 xor x2
  var y1 = t0 xor x7
  var y4 = y1 xor x3
  var y12 = y13 xor y14
  var y2 = y1 xor x0
  var y5 = y1 xor x6
  var y3 = y5 xor y8
  let t1 = x4 xor y12
  var y15 = t1 xor x5
  var y20 = t1 xor x1
  var y6 = y15 xor x7
  var y10 = y15 xor t0
  var y11 = y20 xor y9
  var y7 = x7 xor y11
  var y17 = y10 xor y11
  var y19 = y10 xor y8
  var y16 = t0 xor y11
  var y21 = y13 xor y16
  var y18 = x0 xor y16

  # Non-linear section.
  let t2 = y12 and y15
  let t3 = y3 and y6
  let t4 = t3 xor t2
  let t5 = y4 and x7
  let t6 = t5 xor t2
  let t7 = y13 and y16
  let t8 = y5 and y1
  let t9 = t8 xor t7
  let t10 = y2 and y7
  let t11 = t10 xor t7
  let t12 = y9 and y11
  let t13 = y14 and y17
  let t14 = t13 xor t12
  let t15 = y8 and y10
  let t16 = t15 xor t12
  let t17 = t4 xor t14
  let t18 = t6 xor t16
  let t19 = t9 xor t14
  let t20 = t11 xor t16
  let t21 = t17 xor y20
  let t22 = t18 xor y19
  let t23 = t19 xor y21
  let t24 = t20 xor y18

  let t25 = t21 xor t22
  let t26 = t21 and t23
  let t27 = t24 xor t26
  let t28 = t25 and t27
  let t29 = t28 xor t22
  let t30 = t23 xor t24
  let t31 = t22 xor t26
  let t32 = t31 and t30
  let t33 = t32 xor t24
  let t34 = t23 xor t33
  let t35 = t27 xor t33
  let t36 = t24 and t35
  let t37 = t36 xor t34
  let t38 = t27 xor t36
  let t39 = t29 and t38
  let t40 = t25 xor t39

  let t41 = t40 xor t37
  let t42 = t29 xor t33
  let t43 = t29 xor t40
  let t44 = t33 xor t37
  let t45 = t42 xor t41
  let z0 = t44 and y15
  let z1 = t37 and y6
  let z2 = t33 and x7
  let z3 = t43 and y16
  let z4 = t40 and y1
  let z5 = t29 and y7
  let z6 = t42 and y11
  let z7 = t45 and y17
  let z8 = t41 and y10
  let z9 = t44 and y12
  let z10 = t37 and y3
  let z11 = t33 and y4
  let z12 = t43 and y13
  let z13 = t40 and y5
  let z14 = t29 and y2
  let z15 = t42 and y9
  let z16 = t45 and y14
  let z17 = t41 and y8

  # Bottom linear transformation.
  let t46 = z15 xor z16
  let t47 = z10 xor z11
  let t48 = z5 xor z13
  let t49 = z9 xor z10
  let t50 = z2 xor z12
  let t51 = z2 xor z5
  let t52 = z7 xor z8
  let t53 = z0 xor z3
  let t54 = z6 xor z7
  let t55 = z16 xor z17
  let t56 = z12 xor t48
  let t57 = t50 xor t53
  let t58 = z4 xor t46
  let t59 = z3 xor t54
  let t60 = t46 xor t57
  let t61 = z14 xor t57
  let t62 = t52 xor t58
  let t63 = t49 xor t58
  let t64 = z4 xor t59
  let t65 = t61 xor t62
  let t66 = z1 xor t63
  let s0 = t59 xor t63
  let s6 = t56 xor (not t62)
  let s7 = t48 xor (not t60)
  let t67 = t64 xor t65
  let s3 = t53 xor t66
  let s4 = t51 xor t66
  let s5 = t47 xor t65
  let s1 = t64 xor (not s3)
  let s2 = t55 xor (not t67)

  q[7] = s0
  q[6] = s1
  q[5] = s2
  q[4] = s3
  q[3] = s4
  q[2] = s5
  q[1] = s6
  q[0] = s7

proc invBitsliceSbox*(q: var array[8, uint64]) =
  ## AES inverse S-box, derived from the forward circuit by the affine
  ## wrap-around trick.
  var v0 = not q[0]
  var v1 = not q[1]
  var v2 = q[2]
  var v3 = q[3]
  var v4 = q[4]
  var v5 = not q[5]
  var v6 = not q[6]
  var v7 = q[7]

  q[7] = v1 xor v4 xor v6
  q[6] = v0 xor v3 xor v5
  q[5] = v7 xor v2 xor v4
  q[4] = v6 xor v1 xor v3
  q[3] = v5 xor v0 xor v2
  q[2] = v4 xor v7 xor v1
  q[1] = v3 xor v6 xor v0
  q[0] = v2 xor v5 xor v7

  bitsliceSbox(q)

  v0 = not q[0]
  v1 = not q[1]
  v2 = q[2]
  v3 = q[3]
  v4 = q[4]
  v5 = not q[5]
  v6 = not q[6]
  v7 = q[7]

  q[7] = v1 xor v4 xor v6
  q[6] = v0 xor v3 xor v5
  q[5] = v7 xor v2 xor v4
  q[4] = v6 xor v1 xor v3
  q[3] = v5 xor v0 xor v2
  q[2] = v4 xor v7 xor v1
  q[1] = v3 xor v6 xor v0
  q[0] = v2 xor v5 xor v7

# ---------------------------------------------------------------------------
# Round function pieces.
# ---------------------------------------------------------------------------

template addRoundKey(q: var array[8, uint64], sk: array[120, uint64],
                     off: int) =
  q[0] = q[0] xor sk[off + 0]
  q[1] = q[1] xor sk[off + 1]
  q[2] = q[2] xor sk[off + 2]
  q[3] = q[3] xor sk[off + 3]
  q[4] = q[4] xor sk[off + 4]
  q[5] = q[5] xor sk[off + 5]
  q[6] = q[6] xor sk[off + 6]
  q[7] = q[7] xor sk[off + 7]

template shiftRows(q: var array[8, uint64]) =
  for i in 0 ..< 8:
    let x = q[i]
    q[i] = (x and 0x000000000000FFFF'u64) or
           ((x and 0x00000000FFF00000'u64) shr 4) or
           ((x and 0x00000000000F0000'u64) shl 12) or
           ((x and 0x0000FF0000000000'u64) shr 8) or
           ((x and 0x000000FF00000000'u64) shl 8) or
           ((x and 0xF000000000000000'u64) shr 12) or
           ((x and 0x0FFF000000000000'u64) shl 4)

template invShiftRows(q: var array[8, uint64]) =
  for i in 0 ..< 8:
    let x = q[i]
    q[i] = (x and 0x000000000000FFFF'u64) or
           ((x and 0x000000000FFF0000'u64) shl 4) or
           ((x and 0x00000000F0000000'u64) shr 12) or
           ((x and 0x000000FF00000000'u64) shl 8) or
           ((x and 0x0000FF0000000000'u64) shr 8) or
           ((x and 0x000F000000000000'u64) shl 12) or
           ((x and 0xFFF0000000000000'u64) shr 4)

template rotr32x(x: uint64): uint64 =
  (x shl 32) or (x shr 32)

template mixColumns(q: var array[8, uint64]) =
  let q0 = q[0]
  let q1 = q[1]
  let q2 = q[2]
  let q3 = q[3]
  let q4 = q[4]
  let q5 = q[5]
  let q6 = q[6]
  let q7 = q[7]
  let r0 = (q0 shr 16) or (q0 shl 48)
  let r1 = (q1 shr 16) or (q1 shl 48)
  let r2 = (q2 shr 16) or (q2 shl 48)
  let r3 = (q3 shr 16) or (q3 shl 48)
  let r4 = (q4 shr 16) or (q4 shl 48)
  let r5 = (q5 shr 16) or (q5 shl 48)
  let r6 = (q6 shr 16) or (q6 shl 48)
  let r7 = (q7 shr 16) or (q7 shl 48)

  q[0] = q7 xor r7 xor r0 xor rotr32x(q0 xor r0)
  q[1] = q0 xor r0 xor q7 xor r7 xor r1 xor rotr32x(q1 xor r1)
  q[2] = q1 xor r1 xor r2 xor rotr32x(q2 xor r2)
  q[3] = q2 xor r2 xor q7 xor r7 xor r3 xor rotr32x(q3 xor r3)
  q[4] = q3 xor r3 xor q7 xor r7 xor r4 xor rotr32x(q4 xor r4)
  q[5] = q4 xor r4 xor r5 xor rotr32x(q5 xor r5)
  q[6] = q5 xor r5 xor r6 xor rotr32x(q6 xor r6)
  q[7] = q6 xor r6 xor r7 xor rotr32x(q7 xor r7)

template invMixColumns(q: var array[8, uint64]) =
  let q0 = q[0]
  let q1 = q[1]
  let q2 = q[2]
  let q3 = q[3]
  let q4 = q[4]
  let q5 = q[5]
  let q6 = q[6]
  let q7 = q[7]
  let r0 = (q0 shr 16) or (q0 shl 48)
  let r1 = (q1 shr 16) or (q1 shl 48)
  let r2 = (q2 shr 16) or (q2 shl 48)
  let r3 = (q3 shr 16) or (q3 shl 48)
  let r4 = (q4 shr 16) or (q4 shl 48)
  let r5 = (q5 shr 16) or (q5 shl 48)
  let r6 = (q6 shr 16) or (q6 shl 48)
  let r7 = (q7 shr 16) or (q7 shl 48)

  q[0] = q5 xor q6 xor q7 xor r0 xor r5 xor r7 xor
         rotr32x(q0 xor q5 xor q6 xor r0 xor r5)
  q[1] = q0 xor q5 xor r0 xor r1 xor r5 xor r6 xor r7 xor
         rotr32x(q1 xor q5 xor q7 xor r1 xor r5 xor r6)
  q[2] = q0 xor q1 xor q6 xor r1 xor r2 xor r6 xor r7 xor
         rotr32x(q0 xor q2 xor q6 xor r2 xor r6 xor r7)
  q[3] = q0 xor q1 xor q2 xor q5 xor q6 xor r0 xor r2 xor r3 xor r5 xor
         rotr32x(q0 xor q1 xor q3 xor q5 xor q6 xor q7 xor r0 xor r3 xor r5 xor r7)
  q[4] = q1 xor q2 xor q3 xor q5 xor r1 xor r3 xor r4 xor r5 xor r6 xor r7 xor
         rotr32x(q1 xor q2 xor q4 xor q5 xor q7 xor r1 xor r4 xor r5 xor r6)
  q[5] = q2 xor q3 xor q4 xor q6 xor r2 xor r4 xor r5 xor r6 xor r7 xor
         rotr32x(q2 xor q3 xor q5 xor q6 xor r2 xor r5 xor r6 xor r7)
  q[6] = q3 xor q4 xor q5 xor q7 xor r3 xor r5 xor r6 xor r7 xor
         rotr32x(q3 xor q4 xor q6 xor q7 xor r3 xor r6 xor r7)
  q[7] = q4 xor q5 xor q6 xor r4 xor r6 xor r7 xor
         rotr32x(q4 xor q5 xor q7 xor r4 xor r7)

proc bitsliceEncryptScalar*(rounds: int, skey: array[120, uint64],
                            q: var array[8, uint64]) =
  ## Encrypt the bitsliced state in place (scalar reference kernel).
  addRoundKey(q, skey, 0)
  for u in 1 ..< rounds:
    bitsliceSbox(q)
    shiftRows(q)
    mixColumns(q)
    addRoundKey(q, skey, u shl 3)
  bitsliceSbox(q)
  shiftRows(q)
  addRoundKey(q, skey, rounds shl 3)

proc bitsliceDecryptScalar*(rounds: int, skey: array[120, uint64],
                            q: var array[8, uint64]) =
  ## Decrypt the bitsliced state in place (scalar reference kernel).
  addRoundKey(q, skey, rounds shl 3)
  var u = rounds - 1
  while u > 0:
    invShiftRows(q)
    invBitsliceSbox(q)
    addRoundKey(q, skey, u shl 3)
    invMixColumns(q)
    u -= 1
  invShiftRows(q)
  invBitsliceSbox(q)
  addRoundKey(q, skey, 0)

# ---------------------------------------------------------------------------
# Key schedule.
# ---------------------------------------------------------------------------

proc subWord(x: uint32): uint32 =
  ## Constant-time SubWord via the bitsliced S-box.
  var q: array[8, uint64]
  q[0] = uint64(x)
  ortho(q)
  bitsliceSbox(q)
  ortho(q)
  result = uint32(q[0])

proc keysched(compSkey: var array[30, uint64], convWords: var array[60, uint32],
              key: openArray[byte]): int =
  ## Compressed key schedule plus the conventional word layout; returns the
  ## number of rounds.
  let keyLen = key.len
  var rounds: int
  case keyLen
  of 16: rounds = 10
  of 24: rounds = 12
  of 32: rounds = 14
  else:
    raise newException(ValueError,
      "invalid AES key length: expected 16, 24 or 32 bytes, got " & $keyLen)
  let nk = keyLen shr 2
  let nkf = (rounds + 1) shl 2
  var skey: array[60, uint32]
  load32LeBuf(skey.toOpenArray(0, nk - 1),
              cast[BytePtr](unsafeAddr key[0]), nk)

  var tmp = skey[nk - 1]
  var i = nk
  var j = 0
  var k = 0
  while i < nkf:
    if j == 0:
      tmp = (tmp shl 24) or (tmp shr 8)
      tmp = subWord(tmp) xor aesRcon[k]
    elif nk > 6 and j == 4:
      tmp = subWord(tmp)
    tmp = tmp xor skey[i - nk]
    skey[i] = tmp
    j += 1
    if j == nk:
      j = 0
      k += 1
    i += 1

  for w in 0 ..< nkf:
    convWords[w] = skey[w]

  var ci = 0
  i = 0
  while i < nkf:
    var q: array[8, uint64]
    interleaveIn(q, 0, skey[i], skey[i + 1], skey[i + 2], skey[i + 3])
    q[1] = q[0]
    q[2] = q[0]
    q[3] = q[0]
    q[5] = q[4]
    q[6] = q[4]
    q[7] = q[4]
    ortho(q)
    compSkey[ci] = (q[0] and 0x1111111111111111'u64) or
                   (q[1] and 0x2222222222222222'u64) or
                   (q[2] and 0x4444444444444444'u64) or
                   (q[3] and 0x8888888888888888'u64)
    compSkey[ci + 1] = (q[4] and 0x1111111111111111'u64) or
                       (q[5] and 0x2222222222222222'u64) or
                       (q[6] and 0x4444444444444444'u64) or
                       (q[7] and 0x8888888888888888'u64)
    ci += 2
    i += 4
  result = rounds

proc expandSkey(skey: var array[120, uint64], rounds: int,
                compSkey: array[30, uint64]) =
  let n = (rounds + 1) shl 1
  var v = 0
  for u in 0 ..< n:
    var x0 = compSkey[u]
    var x1 = x0
    var x2 = x0
    var x3 = x0
    x0 = x0 and 0x1111111111111111'u64
    x1 = x1 and 0x2222222222222222'u64
    x2 = x2 and 0x4444444444444444'u64
    x3 = x3 and 0x8888888888888888'u64
    x1 = x1 shr 1
    x2 = x2 shr 2
    x3 = x3 shr 3
    skey[v + 0] = (x0 shl 4) - x0
    skey[v + 1] = (x1 shl 4) - x1
    skey[v + 2] = (x2 shl 4) - x2
    skey[v + 3] = (x3 shl 4) - x3
    v += 4

proc xtime(x: uint8): uint8 {.inline.} =
  byte((int(x) shl 1) xor ((int(x) shr 7) * 0x1b))

proc gmul(a, b: uint8): uint8 =
  var p = 0'u8
  var aa = a
  var bb = b
  while bb != 0:
    if (bb and 1) != 0:
      p = p xor aa
    aa = xtime(aa)
    bb = bb shr 1
  result = p

proc invMixColumn4(c: array[4, uint8]): array[4, uint8] =
  ## InvMixColumns of a single 4-byte state column
  ## (coefficients 0e, 0b, 0d, 09 rotated per row).
  result[0] = gmul(c[0], 14) xor gmul(c[1], 11) xor gmul(c[2], 13) xor
              gmul(c[3], 9)
  result[1] = gmul(c[1], 14) xor gmul(c[2], 11) xor gmul(c[3], 13) xor
              gmul(c[0], 9)
  result[2] = gmul(c[2], 14) xor gmul(c[3], 11) xor gmul(c[0], 13) xor
              gmul(c[1], 9)
  result[3] = gmul(c[3], 14) xor gmul(c[0], 11) xor gmul(c[1], 13) xor
              gmul(c[2], 9)

proc initAes*(ctx: var AesContext, key: openArray[byte]) =
  ## Expand `key` (16, 24 or 32 bytes) into a fresh AES context. Raises
  ## ValueError on any other key length.
  var compSkey: array[30, uint64]
  var convWords: array[60, uint32]
  ctx.rounds = keysched(compSkey, convWords, key)
  expandSkey(ctx.skey, ctx.rounds, compSkey)
  when defined(features.nimcypher.nimsimd) and (defined(amd64) or defined(arm64)):
    # conventional byte-image schedule for the hardware kernels. Schedule
    # words are loaded little-endian, so the spec byte order is the LE
    # image of each word.
    let nkf = (ctx.rounds + 1) * 4
    for i in 0 ..< nkf:
      let w = convWords[i]
      ctx.nrk[i * 4 + 0] = byte(w)
      ctx.nrk[i * 4 + 1] = byte(w shr 8)
      ctx.nrk[i * 4 + 2] = byte(w shr 16)
      ctx.nrk[i * 4 + 3] = byte(w shr 24)
    # equivalent inverse cipher: middle round keys get InvMixColumns
    for r in 1 ..< ctx.rounds:
      for col in 0 ..< 4:
        var c: array[4, uint8]
        for j in 0 ..< 4:
          c[j] = ctx.nrk[r * 16 + col * 4 + j]
        let m = invMixColumn4(c)
        for j in 0 ..< 4:
          ctx.nrkInv[r * 16 + col * 4 + j] = m[j]
    copyMem(addr ctx.nrkInv[0], addr ctx.nrk[0], 16)
    let last = ctx.rounds * 16
    copyMem(addr ctx.nrkInv[last], addr ctx.nrk[last], 16)
  wipe(compSkey)
  wipe(convWords)

proc initAes*(key: openArray[byte]): AesContext =
  initAes(result, key)

# ---------------------------------------------------------------------------
# Group (four-block) kernels. These are the units dispatched to the SIMD
# path when the feature is enabled; the scalar versions always stay compiled
# in as reference.
# ---------------------------------------------------------------------------

proc encryptGroupScalar*(ctx: AesContext, dst, src: BytePtr) {.inline.} =
  ## Encrypt four blocks (64 bytes) from `src` into `dst` (scalar kernel).
  var w: array[16, uint32]
  load32LeBuf(w.toOpenArray(0, 15), src, 16)
  var q: array[8, uint64]
  interleaveIn(q, 0, w[0], w[1], w[2], w[3])
  interleaveIn(q, 1, w[4], w[5], w[6], w[7])
  interleaveIn(q, 2, w[8], w[9], w[10], w[11])
  interleaveIn(q, 3, w[12], w[13], w[14], w[15])
  ortho(q)
  bitsliceEncryptScalar(ctx.rounds, ctx.skey, q)
  ortho(q)
  var outw: array[4, uint32]
  interleaveOut(outw, q[0], q[4])
  store32LeBuf(dst, outw.toOpenArray(0, 3), 4)
  interleaveOut(outw, q[1], q[5])
  store32LeBuf(dst + 16, outw.toOpenArray(0, 3), 4)
  interleaveOut(outw, q[2], q[6])
  store32LeBuf(dst + 32, outw.toOpenArray(0, 3), 4)
  interleaveOut(outw, q[3], q[7])
  store32LeBuf(dst + 48, outw.toOpenArray(0, 3), 4)

proc decryptGroupScalar*(ctx: AesContext, dst, src: BytePtr) {.inline.} =
  ## Decrypt four blocks (64 bytes) from `src` into `dst` (scalar kernel).
  var w: array[16, uint32]
  load32LeBuf(w.toOpenArray(0, 15), src, 16)
  var q: array[8, uint64]
  interleaveIn(q, 0, w[0], w[1], w[2], w[3])
  interleaveIn(q, 1, w[4], w[5], w[6], w[7])
  interleaveIn(q, 2, w[8], w[9], w[10], w[11])
  interleaveIn(q, 3, w[12], w[13], w[14], w[15])
  ortho(q)
  bitsliceDecryptScalar(ctx.rounds, ctx.skey, q)
  ortho(q)
  var outw: array[4, uint32]
  interleaveOut(outw, q[0], q[4])
  store32LeBuf(dst, outw.toOpenArray(0, 3), 4)
  interleaveOut(outw, q[1], q[5])
  store32LeBuf(dst + 16, outw.toOpenArray(0, 3), 4)
  interleaveOut(outw, q[2], q[6])
  store32LeBuf(dst + 32, outw.toOpenArray(0, 3), 4)
  interleaveOut(outw, q[3], q[7])
  store32LeBuf(dst + 48, outw.toOpenArray(0, 3), 4)

proc encryptBlocksScalar*(ctx: AesContext, dst, src: BytePtr, nb: int) =
  ## Scalar reference path: groups of four with replicated-lane tails.
  var off = 0
  var left = nb
  while left >= 4:
    encryptGroupScalar(ctx, dst + off * 16, src + off * 16)
    left -= 4
    off += 4
  if left > 0:
    var buf: array[128, byte]
    let tailBytes = left shl 4
    copyMem(addr buf[0], src + off * 16, tailBytes)
    var p = tailBytes
    while p < 64:
      copyMem(addr buf[p], addr buf[0], min(tailBytes, 64 - p))
      p += tailBytes
    encryptGroupScalar(ctx, cast[BytePtr](addr buf[64]),
                       cast[BytePtr](addr buf[0]))
    copyMem(dst + off * 16, addr buf[64], tailBytes)
    wipe(buf)

proc decryptBlocksScalar*(ctx: AesContext, dst, src: BytePtr, nb: int) =
  ## Scalar reference path (see `encryptBlocksScalar`).
  var off = 0
  var left = nb
  while left >= 4:
    decryptGroupScalar(ctx, dst + off * 16, src + off * 16)
    left -= 4
    off += 4
  if left > 0:
    var buf: array[128, byte]
    let tailBytes = left shl 4
    copyMem(addr buf[0], src + off * 16, tailBytes)
    var p = tailBytes
    while p < 64:
      copyMem(addr buf[p], addr buf[0], min(tailBytes, 64 - p))
      p += tailBytes
    decryptGroupScalar(ctx, cast[BytePtr](addr buf[64]),
                       cast[BytePtr](addr buf[0]))
    copyMem(dst + off * 16, addr buf[64], tailBytes)
    wipe(buf)

when defined(features.nimcypher.nimsimd) and (defined(amd64) or defined(arm64)):
  proc encryptBlocks*(ctx: AesContext, dst, src: BytePtr, nb: int) {.inline.} =
    ## Encrypt `nb` blocks; hardware batched kernel when enabled.
    encryptBlocksSimd(ctx.rounds, addr ctx.nrk[0], dst, src, nb)

  proc decryptBlocks*(ctx: AesContext, dst, src: BytePtr, nb: int) {.inline.} =
    ## Decrypt `nb` blocks; hardware batched kernel when enabled.
    decryptBlocksSimd(ctx.rounds, addr ctx.nrk[0], addr ctx.nrkInv[0],
                      dst, src, nb)
else:
  proc encryptBlocks*(ctx: AesContext, dst, src: BytePtr, nb: int) {.inline.} =
    encryptBlocksScalar(ctx, dst, src, nb)

  proc decryptBlocks*(ctx: AesContext, dst, src: BytePtr, nb: int) {.inline.} =
    decryptBlocksScalar(ctx, dst, src, nb)

proc encryptGroup*(ctx: AesContext, dst, src: BytePtr) {.inline.} =
  ## Encrypt exactly four blocks through the batched kernel.
  encryptBlocks(ctx, dst, src, 4)

proc decryptGroup*(ctx: AesContext, dst, src: BytePtr) {.inline.} =
  ## Decrypt exactly four blocks through the batched kernel.
  decryptBlocks(ctx, dst, src, 4)

# ---------------------------------------------------------------------------
# Block-level public API.
# ---------------------------------------------------------------------------

proc encryptBlock*(ctx: AesContext, dst: var array[16, byte],
                   src: array[16, byte]) =
  ## Encrypt one block. The input is replicated across all four lanes of the
  ## group kernel (into an internal scratch buffer), so timing does not
  ## depend on the data.
  var buf: array[128, byte]
  for i in 0 ..< 4:
    copyMem(addr buf[i * 16], unsafeAddr src[0], 16)
  encryptGroup(ctx, cast[BytePtr](addr buf[64]), cast[BytePtr](addr buf[0]))
  copyMem(addr dst[0], addr buf[64], 16)
  wipe(buf)

proc decryptBlock*(ctx: AesContext, dst: var array[16, byte],
                   src: array[16, byte]) =
  ## Decrypt one block (see `encryptBlock`).
  var buf: array[128, byte]
  for i in 0 ..< 4:
    copyMem(addr buf[i * 16], unsafeAddr src[0], 16)
  decryptGroup(ctx, cast[BytePtr](addr buf[64]), cast[BytePtr](addr buf[0]))
  copyMem(addr dst[0], addr buf[64], 16)
  wipe(buf)

# Raw pointer helpers used by the bulk modes below.

proc encryptBlockRaw*(ctx: AesContext, dst, src: BytePtr) =
  ## Single-block encryption through raw pointers (no allocation).
  var buf: array[128, byte]
  for i in 0 ..< 4:
    copyMem(addr buf[i * 16], src, 16)
  encryptGroup(ctx, cast[BytePtr](addr buf[64]), cast[BytePtr](addr buf[0]))
  copyMem(dst, addr buf[64], 16)
  wipe(buf)

proc decryptBlockRaw*(ctx: AesContext, dst, src: BytePtr) =
  ## Single-block decryption through raw pointers (no allocation).
  var buf: array[128, byte]
  for i in 0 ..< 4:
    copyMem(addr buf[i * 16], src, 16)
  decryptGroup(ctx, cast[BytePtr](addr buf[64]), cast[BytePtr](addr buf[0]))
  copyMem(dst, addr buf[64], 16)
  wipe(buf)

proc ecbProcess(ctx: AesContext, dst, src: BytePtr, size: int,
                encrypt: bool) =
  if size <= 0:
    return
  if (size and 15) != 0:
    raise newException(ValueError, "AES-ECB input must be a multiple of 16")
  let nbBlocks = size shr 4
  if nbBlocks > 0:
    if encrypt: encryptBlocks(ctx, dst, src, nbBlocks)
    else: decryptBlocks(ctx, dst, src, nbBlocks)

proc ecbEncrypt*(ctx: AesContext, data: openArray[byte]): seq[byte] =
  ## ECB encryption of whole blocks (`data.len` must be a multiple of 16).
  result = newSeqUninit[byte](data.len)
  if data.len > 0:
    ecbProcess(ctx, cast[BytePtr](unsafeAddr result[0]),
               cast[BytePtr](unsafeAddr data[0]), data.len, true)

proc ecbDecrypt*(ctx: AesContext, data: openArray[byte]): seq[byte] =
  ## ECB decryption of whole blocks (`data.len` must be a multiple of 16).
  result = newSeqUninit[byte](data.len)
  if data.len > 0:
    ecbProcess(ctx, cast[BytePtr](unsafeAddr result[0]),
               cast[BytePtr](unsafeAddr data[0]), data.len, false)

proc cbcEncryptOne*(ctx: AesContext, iv: array[16, byte],
                    data: openArray[byte]): seq[byte] =
  ## CBC encryption of whole blocks. CBC chaining is inherently serial, so
  # this runs one lane-group per block (the SIMD kernel keeps it fast).
  if (data.len and 15) != 0:
    raise newException(ValueError, "AES-CBC input must be a multiple of 16")
  result = newSeqUninit[byte](data.len)
  if data.len == 0:
    return
  var prev = iv
  var blockIn: array[16, byte]
  var rp = cast[BytePtr](unsafeAddr result[0])
  var sp = cast[BytePtr](unsafeAddr data[0])
  for _ in 0 ..< data.len shr 4:
    for i in 0 ..< 16:
      blockIn[i] = sp[i] xor prev[i]
    encryptBlockRaw(ctx, rp, cast[BytePtr](addr blockIn[0]))
    copyMem(addr prev[0], rp, 16)
    sp = sp + 16
    rp = rp + 16
  wipe(prev)
  wipe(blockIn)

proc cbcDecryptOne*(ctx: AesContext, iv: array[16, byte],
                    data: openArray[byte]): seq[byte] =
  ## CBC decryption of whole blocks (parallelizable, done in groups of 4).
  if (data.len and 15) != 0:
    raise newException(ValueError, "AES-CBC input must be a multiple of 16")
  result = newSeqUninit[byte](data.len)
  if data.len == 0:
    return
  var prev = iv
  var rp = cast[BytePtr](unsafeAddr result[0])
  var sp = cast[BytePtr](unsafeAddr data[0])
  let size = data.len
  # bulk-decrypt everything, then chain against the ciphertext
  decryptBlocks(ctx, rp, sp, size shr 4)
  let nbBlocks = size shr 4
  for b in 0 ..< nbBlocks:
    let base = b shl 4
    for i in 0 ..< 16:
      rp[base + i] = rp[base + i] xor prev[i]
    copyMem(addr prev[0], sp + base, 16)
  wipe(prev)

proc ctrIncrement*(counter: var array[16, byte]) =
  # Full 128-bit big-endian increment (SP 800-38A).
  var carry = 1
  var i = 15
  while i >= 0 and carry != 0:
    let v = int(counter[i]) + carry
    counter[i] = byte(v and 0xff)
    carry = v shr 8
    i -= 1

proc ctrXorInto*(ctx: AesContext, counter: var array[16, byte],
                 dst, src: BytePtr, size: int) =
  ## XOR `size` bytes at `src` with the AES-CTR keystream derived from
  ## `counter` (advanced as blocks are consumed). In-place variant of CTR.
  var cp = src
  var dp = dst
  var remaining = size
  const ctrChunkBlocks = 32
  while remaining > 0:
    var ks: array[ctrChunkBlocks * 16, byte]
    var cbs: array[ctrChunkBlocks * 16, byte]
    let nbBlocks = min(remaining + 15, ctrChunkBlocks * 16) shr 4
    for b in 0 ..< nbBlocks:
      copyMem(addr cbs[b * 16], addr counter[0], 16)
      ctrIncrement(counter)
    encryptBlocks(ctx, cast[BytePtr](addr ks[0]),
                  cast[BytePtr](addr cbs[0]), nbBlocks)
    let take = min(remaining, nbBlocks shl 4)
    for i in 0 ..< take:
      dp[i] = cp[i] xor ks[i]
    dp = dp + take
    cp = cp + take
    remaining -= take
    wipe(ks)
    wipe(cbs)

proc ctrCryptOne*(ctx: AesContext, counter: array[16, byte],
                  data: openArray[byte]): seq[byte] =
  ## AES-CTR encryption/decryption (identical operation). The whole 128-bit
  ## counter is incremented big-endian after each block.
  result = newSeqUninit[byte](data.len)
  if data.len == 0:
    return
  var ctr = counter
  ctrXorInto(ctx, ctr, cast[BytePtr](unsafeAddr result[0]),
             cast[BytePtr](unsafeAddr data[0]), data.len)
  wipe(ctr)

proc ofbXorInto*(ctx: AesContext, iv: var array[16, byte],
                 dst, src: BytePtr, size: int) =
  ## OFB keystream XOR (encryption == decryption). `iv` carries the feedback
  ## state between calls.
  var cp = src
  var dp = dst
  var remaining = size
  while remaining > 0:
    var ks: array[16, byte]
    encryptBlockRaw(ctx, cast[BytePtr](addr ks[0]), cast[BytePtr](addr iv[0]))
    let take = min(remaining, 16)
    for i in 0 ..< take:
      dp[i] = cp[i] xor ks[i]
    copyMem(addr iv[0], addr ks[0], 16)
    dp = dp + take
    cp = cp + take
    remaining -= take
    wipe(ks)

proc ofbCryptOne*(ctx: AesContext, iv: array[16, byte],
                  data: openArray[byte]): seq[byte] =
  ## AES-OFB encryption/decryption (identical operation).
  result = newSeqUninit[byte](data.len)
  if data.len == 0:
    return
  var state = iv
  ofbXorInto(ctx, state, cast[BytePtr](unsafeAddr result[0]),
             cast[BytePtr](unsafeAddr data[0]), data.len)
  wipe(state)

proc cfbEncryptInto*(ctx: AesContext, iv: var array[16, byte],
                     dst, src: BytePtr, size: int) =
  ## CFB (128-bit segments) encryption. `iv` carries the feedback state.
  var cp = src
  var dp = dst
  var remaining = size
  while remaining > 0:
    var ks: array[16, byte]
    encryptBlockRaw(ctx, cast[BytePtr](addr ks[0]), cast[BytePtr](addr iv[0]))
    let take = min(remaining, 16)
    for i in 0 ..< take:
      dp[i] = cp[i] xor ks[i]
    copyMem(addr iv[0], dp, 16)
    dp = dp + take
    cp = cp + take
    remaining -= take
    wipe(ks)

proc cfbDecryptInto*(ctx: AesContext, iv: var array[16, byte],
                     dst, src: BytePtr, size: int) =
  ## CFB (128-bit segments) decryption. `iv` carries the feedback state.
  var cp = src
  var dp = dst
  var remaining = size
  while remaining > 0:
    var ks: array[16, byte]
    var ct: array[16, byte]
    encryptBlockRaw(ctx, cast[BytePtr](addr ks[0]), cast[BytePtr](addr iv[0]))
    let take = min(remaining, 16)
    copyMem(addr ct[0], cp, 16)
    for i in 0 ..< take:
      dp[i] = cp[i] xor ks[i]
    copyMem(addr iv[0], addr ct[0], 16)
    dp = dp + take
    cp = cp + take
    remaining -= take
    wipe(ks)
    wipe(ct)

proc cfbEncryptOne*(ctx: AesContext, iv: array[16, byte],
                    data: openArray[byte]): seq[byte] =
  ## AES-CFB (CFB128) encryption.
  result = newSeqUninit[byte](data.len)
  if data.len == 0:
    return
  var state = iv
  cfbEncryptInto(ctx, state, cast[BytePtr](unsafeAddr result[0]),
                 cast[BytePtr](unsafeAddr data[0]), data.len)
  wipe(state)

proc cfbDecryptOne*(ctx: AesContext, iv: array[16, byte],
                    data: openArray[byte]): seq[byte] =
  ## AES-CFB (CFB128) decryption.
  result = newSeqUninit[byte](data.len)
  if data.len == 0:
    return
  var state = iv
  cfbDecryptInto(ctx, state, cast[BytePtr](unsafeAddr result[0]),
                 cast[BytePtr](unsafeAddr data[0]), data.len)
  wipe(state)

# ---------------------------------------------------------------------------
# PKCS#7 padding.
# ---------------------------------------------------------------------------

proc pkcs7Pad*(data: openArray[byte], blockSize: int = 16): seq[byte] =
  ## Pad `data` to a multiple of `blockSize` with PKCS#7 padding
  ## (a full block of padding is added to aligned input).
  if blockSize < 1 or blockSize > 255:
    raise newException(ValueError, "invalid PKCS#7 block size")
  let padLen = blockSize - (data.len mod blockSize)
  result = newSeqOfCap[byte](data.len + padLen)
  for b in data:
    result.add(b)
  for _ in 0 ..< padLen:
    result.add(byte(padLen))

proc pkcs7Unpad*(data: openArray[byte], blockSize: int = 16): seq[byte] =
  ## Validate and strip PKCS#7 padding. Raises ValueError on invalid padding.
  if blockSize < 1 or blockSize > 255:
    raise newException(ValueError, "invalid PKCS#7 block size")
  if data.len == 0 or (data.len mod blockSize) != 0:
    raise newException(ValueError,
      "PKCS#7 input must be a non-empty multiple of the block size")
  let n = data.len
  let padLen = int(data[n - 1])
  var ok = int(padLen >= 1 and padLen <= blockSize)
  # scan exactly `blockSize` bytes regardless of the claimed length, so the
  # running time does not depend on the data and no out-of-bounds read can
  # happen for bogus lengths.
  var acc = 0
  for i in 0 ..< blockSize:
    let within = int(i < padLen)
    acc = acc or ((int(data[n - 1 - i]) xor padLen) and within)
  ok = ok and int(acc == 0)
  if ok == 0:
    raise newException(ValueError, "invalid PKCS#7 padding")
  result = newSeqUninit[byte](n - padLen)
  copyMem(addr result[0], unsafeAddr data[0], n - padLen)

# ---------------------------------------------------------------------------
# Streaming contexts.
#
# CTR and OFB can emit any chunk length directly (their keystream advances
# bit-granular through the buffer). CFB-128 feeds back whole ciphertext
# blocks, so both CFB streams buffer an incomplete trailing block exactly
# like the ChaCha20 streaming extension does.
# ---------------------------------------------------------------------------

type
  AesCtrStream* = object
    ## Streaming AES-CTR context (encryption == decryption).
    ctx: AesContext
    counter: array[16, byte]
    buf: array[16, byte]
    used: int

  AesOfbStream* = object
    ## Streaming AES-OFB context (encryption == decryption).
    ctx: AesContext
    iv: array[16, byte]
    buf: array[16, byte]
    used: int

  AesCfbEncStream* = object
    ## Streaming AES-CFB (CFB128) encryption context.
    ctx: AesContext
    iv: array[16, byte]       # feedback source (last complete ciphertext block)
    buf: array[16, byte]      # current keystream block
    used: int                 # keystream bytes consumed in this block
    ct: array[16, byte]       # ciphertext bytes of the current block

  AesCfbDecStream* = object
    ## Streaming AES-CFB (CFB128) decryption context.
    ctx: AesContext
    iv: array[16, byte]
    buf: array[16, byte]
    used: int
    ct: array[16, byte]

proc initAesCtr*(ctx: var AesCtrStream, key: openArray[byte],
                 counterBlock: array[16, byte]) =
  ## Initialize a streaming AES-CTR context. The whole counter block is
  ## incremented big-endian per 16-byte keystream block.
  initAes(ctx.ctx, key)
  ctx.counter = counterBlock
  ctx.used = 16 # force keystream generation on the first update
  wipe(ctx.buf)

proc initAesOfb*(ctx: var AesOfbStream, key: openArray[byte],
                 iv: array[16, byte]) =
  ## Initialize a streaming AES-OFB context.
  initAes(ctx.ctx, key)
  ctx.iv = iv
  ctx.used = 16 # force keystream generation on the first update
  wipe(ctx.buf)

proc initAesCfbEnc*(ctx: var AesCfbEncStream, key: openArray[byte],
                    iv: array[16, byte]) =
  ## Initialize a streaming AES-CFB encryption context.
  initAes(ctx.ctx, key)
  ctx.iv = iv
  encryptBlockRaw(ctx.ctx, cast[BytePtr](addr ctx.buf[0]),
                  cast[BytePtr](addr ctx.iv[0]))
  ctx.used = 0

proc initAesCfbDec*(ctx: var AesCfbDecStream, key: openArray[byte],
                    iv: array[16, byte]) =
  ## Initialize a streaming AES-CFB decryption context.
  initAes(ctx.ctx, key)
  ctx.iv = iv
  encryptBlockRaw(ctx.ctx, cast[BytePtr](addr ctx.buf[0]),
                  cast[BytePtr](addr ctx.iv[0]))
  ctx.used = 0

proc aesCtrUpdate*(s: var AesCtrStream, data: openArray[byte]): seq[byte] =
  ## Encrypt or decrypt the next chunk (identical operation).
  result = newSeqUninit[byte](data.len)
  var di = 0
  while di < data.len:
    if s.used == 16:
      encryptBlockRaw(s.ctx, cast[BytePtr](addr s.buf[0]),
                      cast[BytePtr](addr s.counter[0]))
      ctrIncrement(s.counter)
      s.used = 0
    let take = min(16 - s.used, data.len - di)
    for i in 0 ..< take:
      result[di + i] = data[di + i] xor s.buf[s.used + i]
    s.used += take
    di += take

proc aesOfbUpdate*(s: var AesOfbStream, data: openArray[byte]): seq[byte] =
  ## Encrypt or decrypt the next chunk (identical operation).
  result = newSeqUninit[byte](data.len)
  var di = 0
  while di < data.len:
    if s.used == 16:
      encryptBlockRaw(s.ctx, cast[BytePtr](addr s.buf[0]),
                      cast[BytePtr](addr s.iv[0]))
      copyMem(addr s.iv[0], addr s.buf[0], 16)
      s.used = 0
    let take = min(16 - s.used, data.len - di)
    for i in 0 ..< take:
      result[di + i] = data[di + i] xor s.buf[s.used + i]
    s.used += take
    di += take

proc aesCfbEncryptUpdate*(s: var AesCfbEncStream,
                          data: openArray[byte]): seq[byte] =
  ## Encrypt the next chunk. The concatenated output equals the one-shot
  ## CFB encryption over the concatenated input regardless of chunking.
  result = newSeqUninit[byte](data.len)
  var di = 0
  while di < data.len:
    if s.used == 16:
      copyMem(addr s.iv[0], addr s.ct[0], 16)
      encryptBlockRaw(s.ctx, cast[BytePtr](addr s.buf[0]),
                      cast[BytePtr](addr s.iv[0]))
      s.used = 0
    let take = min(16 - s.used, data.len - di)
    for i in 0 ..< take:
      let c = data[di + i] xor s.buf[s.used + i]
      result[di + i] = c
      s.ct[s.used + i] = c
    s.used += take
    di += take

proc aesCfbDecryptUpdate*(s: var AesCfbDecStream,
                          data: openArray[byte]): seq[byte] =
  ## Decrypt the next chunk.
  result = newSeqUninit[byte](data.len)
  var di = 0
  while di < data.len:
    if s.used == 16:
      copyMem(addr s.iv[0], addr s.ct[0], 16)
      encryptBlockRaw(s.ctx, cast[BytePtr](addr s.buf[0]),
                      cast[BytePtr](addr s.iv[0]))
      s.used = 0
    let take = min(16 - s.used, data.len - di)
    for i in 0 ..< take:
      let c = data[di + i]
      result[di + i] = c xor s.buf[s.used + i]
      s.ct[s.used + i] = c
    s.used += take
    di += take

{.pop.}
