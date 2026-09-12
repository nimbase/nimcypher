# Montgomery modular exponentiation on 64-bit limbs.
#
# 64-bit limbs halve the limb count (and loop trip counts) versus the 32-bit
# default in `internal/montgomery`, but the win only materializes with a
# single-instruction 64x64->128-bit multiply: with portable 32-bit-half
# splitting it costs the same number of narrow multiplies, so there is no
# portable speedup to be had. Hence this module is selected only when
# `features.nimcypher.nimsimd` is defined on amd64, where MULX (BMI2) yields
# lo+hi in one instruction through `nimsimd/bmi2` (works on GCC, Clang and
# MSVC alike -- no raw asm in this tier). Other configurations keep the
# 32-bit default; a portable splitting fallback covers nimsimd builds on
# non-amd64 for correctness until dedicated kernels land.
#
# The carry handling uses an exact 3-word (c0, c1, c2) accumulator with
# wrap-checked adds, so it is correct regardless of global overflow checks.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import std/bitops
import std/options

import bigints

when defined(features.nimcypher.nimsimd) and defined(amd64):
  when not defined(vcc):
    {.passC: "-mbmi2".}
  import nimsimd/bmi2

{.push checks: off.}

const mont64Window* = 5

# ---------------------------------------------------------------------------
# Wide multiply: lo = a*b mod 2^64, hi = floor(a*b / 2^64)
# ---------------------------------------------------------------------------

when defined(features.nimcypher.nimsimd) and defined(amd64):
  proc mulWide(a, b: uint64, hi: var uint64): uint64 {.inline.} =
    ## Single MULX instruction (BMI2): no flags touched, best scheduling.
    mulx_u64(a, b, addr hi)
else:
  proc mulWide(a, b: uint64, hi: var uint64): uint64 {.inline.} =
    ## Portable 32-bit-half splitting. Same narrow-mult count as 32-bit
    ## limbs: correctness fallback only, not a speedup.
    const mask = 0xFFFF_FFFF'u64
    let a0 = a and mask
    let a1 = a shr 32
    let b0 = b and mask
    let b1 = b shr 32
    let u = a0 * b0
    let v1 = a0 * b1
    let v2 = a1 * b0
    let w = a1 * b1
    let sLo = v1 + v2
    let sHi = if sLo < v1: 1'u64 else: 0'u64
    let t = (sLo and mask) shl 32
    let lo = u + t
    let c1 = if lo < u: 1'u64 else: 0'u64
    # Partial sums below never exceed the true high word (< 2^64), so the
    # plain adds cannot wrap: every term is non-negative.
    hi = (sLo shr 32) + (sHi shl 32) + w + c1
    lo

# ---------------------------------------------------------------------------
# Limb helpers (little-endian seq[uint64])
# ---------------------------------------------------------------------------

proc trimLimbs64*(a: var seq[uint64]) =
  var n = a.len
  while n > 1 and a[n - 1] == 0'u64:
    dec n
  if n != a.len:
    a.setLen(n)

proc cmpLimbs64*(a, b: openArray[uint64]): int =
  var ia = a.len
  while ia > 0 and a[ia - 1] == 0'u64:
    dec ia
  var ib = b.len
  while ib > 0 and b[ib - 1] == 0'u64:
    dec ib
  if ia != ib:
    return (if ia > ib: 1 else: -1)
  for i in countdown(ia - 1, 0):
    if a[i] != b[i]:
      return (if a[i] > b[i]: 1 else: -1)
  0

proc subLimbs64InPlace*(a: var seq[uint64], b: openArray[uint64]) =
  ## `a -= b`, requires `a >= b`.
  var borrow: uint64 = 0
  for i in 0 ..< a.len:
    let limb = if i < b.len: b[i] else: 0'u64
    if limb == 0xFFFF_FFFF_FFFF_FFFF'u64 and borrow == 1'u64:
      # True subtrahend is 2^64: `a[i]` keeps its value, borrow stays set.
      borrow = 1'u64
    else:
      let bi = limb + borrow # cannot wrap here (limb != MAX or borrow == 0)
      borrow = (if a[i] < bi: 1'u64 else: 0'u64)
      a[i] = a[i] - bi

proc testBitLimbs64*(limbs: openArray[uint64], idx: int): bool {.inline.} =
  let w = idx shr 6
  if w >= limbs.len:
    return false
  (limbs[w] and (1'u64 shl (idx and 63))) != 0'u64

proc bitLenLimbs64*(limbs: openArray[uint64]): int =
  var top = limbs.len - 1
  while top > 0 and limbs[top] == 0'u64:
    dec top
  if limbs[top] == 0'u64:
    return 0
  top * 64 + (64 - countLeadingZeroBits(limbs[top]))

# ---------------------------------------------------------------------------
# Schoolbook multiply + Montgomery reduction (SOS form, 64-bit limbs)
# ---------------------------------------------------------------------------

proc mulLimbs64(a, b: openArray[uint64], t: var seq[uint64]) =
  ## `t += a * b`. Caller zeroes `t` first; `t` needs `a.len + b.len + 2`.
  for i in 0 ..< a.len:
    let ai = a[i]
    if ai == 0:
      continue
    var c0, c1, c2: uint64 = 0
    for j in 0 ..< b.len:
      var hi: uint64
      let lo = mulWide(ai, b[j], hi)
      var o = c0
      c0 += t[i + j]
      c1 += (if c0 < o: 1'u64 else: 0'u64)
      o = c0
      c0 += lo
      c1 += (if c0 < o: 1'u64 else: 0'u64)
      o = c1
      c1 += hi
      c2 += (if c1 < o: 1'u64 else: 0'u64)
      t[i + j] = c0
      c0 = c1
      c1 = c2
      c2 = 0
    # Remaining carry is tiny (c0 arbitrary, c1 <= ~2): propagate.
    var p = i + b.len
    var cc = c0
    while cc != 0:
      let o = t[p]
      t[p] += cc
      cc = (if t[p] < o: 1'u64 else: 0'u64)
      inc p
    cc = c1
    while cc != 0:
      let o = t[p]
      t[p] += cc
      cc = (if t[p] < o: 1'u64 else: 0'u64)
      inc p

proc montN0_64*(n: openArray[uint64]): uint64 =
  ## `n0 = -n^(-1) mod 2^64`. Requires odd `n`. The products intentionally
  ## wrap modulo 2^64 (this module compiles with `checks: off`, and
  ## wrapping is exactly the Newton iteration over Z/2^64Z).
  var x = 1'u64 # n^(-1) mod 2 (exact: n is odd)
  for _ in 0 ..< 6: # Newton doubles the bits: 1 -> 64
    x = x * (2'u64 - n[0] * x)
  0'u64 - x

proc montReduce64(t: var seq[uint64], k: int, n: openArray[uint64],
                  n0: uint64) =
  ## In-place REDC: `t = t / B^k mod n` with `B = 2^64`. `t` holds at least
  ## `2k + 2` limbs with value `< n * B^k`. Result lands in `t[k .. 2k]`.
  for i in 0 ..< k:
    let m = t[i] * n0 # low 64 bits only -- exactly what REDC needs
    if m == 0:
      continue
    var c0, c1, c2: uint64 = 0
    for j in 0 ..< k:
      var hi: uint64
      let lo = mulWide(m, n[j], hi)
      var o = c0
      c0 += t[i + j]
      c1 += (if c0 < o: 1'u64 else: 0'u64)
      o = c0
      c0 += lo
      c1 += (if c0 < o: 1'u64 else: 0'u64)
      o = c1
      c1 += hi
      c2 += (if c1 < o: 1'u64 else: 0'u64)
      t[i + j] = c0
      c0 = c1
      c1 = c2
      c2 = 0
    var p = i + k
    var cc = c0
    while cc != 0:
      let o = t[p]
      t[p] += cc
      cc = (if t[p] < o: 1'u64 else: 0'u64)
      inc p
    cc = c1
    while cc != 0:
      let o = t[p]
      t[p] += cc
      cc = (if t[p] < o: 1'u64 else: 0'u64)
      inc p

proc montMul64(a, b, n: openArray[uint64], n0: uint64,
               t: var seq[uint64]): seq[uint64] =
  ## Montgomery product: returns `a * b / R mod n` with `R = B^k`,
  ## `k = n.len`. Inputs must be `< n`. Output is `< n`.
  let k = n.len
  for i in 0 ..< 2 * k + 2:
    t[i] = 0'u64
  mulLimbs64(a, b, t)
  montReduce64(t, k, n, n0)
  result = newSeq[uint64](k + 1)
  for i in 0 ..< k + 1:
    result[i] = t[k + i]
  trimLimbs64(result)
  if cmpLimbs64(result, n) >= 0:
    subLimbs64InPlace(result, n)
    trimLimbs64(result)

# ---------------------------------------------------------------------------
# BigInt boundary conversion
# ---------------------------------------------------------------------------

let mask32Big64 = initBigInt(0xFFFF_FFFF'u32)

proc bigToLimbs64*(x: BigInt): seq[uint64] =
  ## Two guarded 32-bit steps per limb: `bigints.shr` fails when the shift
  ## erases all limbs (`setLen(-1)`), so never shift an empty value.
  if x == initBigInt(0):
    return @[0'u64]
  var v = x
  result = @[]
  while v != initBigInt(0):
    let lo = uint64(toInt[uint32](v and mask32Big64).get)
    v = v shr 32
    var hi = 0'u64
    if v != initBigInt(0):
      hi = uint64(toInt[uint32](v and mask32Big64).get)
      v = v shr 32
    result.add(lo or (hi shl 32))

proc limbsToBig64*(a: openArray[uint64]): BigInt =
  var s = newSeq[uint32]((a.len * 2) + 1)
  for i in 0 ..< a.len:
    s[2 * i] = uint32(a[i] and 0xFFFF_FFFF'u64)
    s[2 * i + 1] = uint32(a[i] shr 32)
  initBigInt(s) # normalizes away leading zeros

proc padTo64*(limbs: seq[uint64], k: int): seq[uint64] =
  result = newSeq[uint64](k)
  let n = min(limbs.len, k)
  for i in 0 ..< n:
    result[i] = limbs[i]

# ---------------------------------------------------------------------------
# Binary extended GCD inverse (HAC 14.61), 64-bit limbs
# ---------------------------------------------------------------------------

proc isZero64(a: openArray[uint64]): bool =
  for w in a:
    if w != 0'u64:
      return false
  true

proc shr1_64(a: var seq[uint64]) =
  var carry = 0'u64
  for i in countdown(a.high, 0):
    let newCarry = (a[i] and 1'u64) shl 63
    a[i] = (a[i] shr 1) or carry
    carry = newCarry
  trimLimbs64(a)

proc addLimbs64(a, b: openArray[uint64]): seq[uint64] =
  ## Sum with an extra top limb; exact via wrap-checked adds.
  result = newSeq[uint64](max(a.len, b.len) + 1)
  var c = 0'u64
  for i in 0 ..< result.len - 1:
    let av = if i < a.len: a[i] else: 0'u64
    let bv = if i < b.len: b[i] else: 0'u64
    var s = av
    var w = 0'u64
    var o = s
    s += bv
    w += (if s < o: 1'u64 else: 0'u64)
    o = s
    s += c
    w += (if s < o: 1'u64 else: 0'u64)
    result[i] = s
    c = w # <= 2: `w += 1` above can never wrap it
  result[^1] = c
  trimLimbs64(result)

proc subMod64(a, b, n: seq[uint64]): seq[uint64] =
  ## `(a - b) mod n`. Requires `a, b < n`.
  if cmpLimbs64(a, b) >= 0:
    result = a
    subLimbs64InPlace(result, b)
  else:
    result = addLimbs64(a, n) # < 2n
    subLimbs64InPlace(result, b) # < n (since a < b)
  trimLimbs64(result)

proc halfMod64(a, n: seq[uint64]): seq[uint64] =
  ## `a/2` if even else `(a+n)/2`. Requires `a < n`, `n` odd; result `< n`.
  if (a[0] and 1'u64) == 0'u64:
    result = a
    shr1_64(result)
  else:
    result = addLimbs64(a, n) # even (odd + odd), < 2n
    shr1_64(result) # < n

proc fastInvmod*(a, modulus: BigInt): BigInt =
  ## `a^(-1) mod modulus` via binary extended GCD (HAC 14.61) on 64-bit
  ## limbs: only shifts, adds and subtracts, no divisions. Pure Nim,
  ## portable, ~4x faster than `bigints.invmod` at RSA sizes, so it is used
  ## unconditionally (no feature flag). Variable-time like all bigint code
  ## here -- in RSA it inverts the random blinding factor, which is the
  ## standard practice (cf. OpenSSL). Mirrors `bigints.invmod` errors;
  ## even moduli fall back to `bigints.invmod`.
  if modulus == initBigInt(1):
    return initBigInt(0)
  if a == initBigInt(0):
    raise newException(DivByZeroDefect, "0 has no modular inverse")
  var am = a mod modulus
  if am == initBigInt(0):
    raise newException(ValueError, $a & " has no modular inverse modulo " &
      $modulus)
  if am < initBigInt(0):
    am += modulus
  if (modulus and initBigInt(1)) == initBigInt(0):
    return invmod(a, modulus)
  let m = bigToLimbs64(modulus)
  var u = bigToLimbs64(am)
  var v = m
  var x1 = @[1'u64]
  var x2 = @[0'u64]
  while u != @[1'u64] and v != @[1'u64]:
    if isZero64(u) or isZero64(v):
      raise newException(ValueError, $a & " has no modular inverse modulo " &
        $modulus)
    while (u[0] and 1'u64) == 0'u64:
      shr1_64(u)
      x1 = halfMod64(x1, m)
    while (v[0] and 1'u64) == 0'u64:
      shr1_64(v)
      x2 = halfMod64(x2, m)
    if cmpLimbs64(u, v) >= 0:
      var uu = u
      subLimbs64InPlace(uu, v)
      trimLimbs64(uu)
      u = uu
      x1 = subMod64(x1, x2, m)
    else:
      var vv = v
      subLimbs64InPlace(vv, u)
      trimLimbs64(vv)
      v = vv
      x2 = subMod64(x2, x1, m)
  if u == @[1'u64]:
    limbsToBig64(x1)
  else:
    limbsToBig64(x2)

# ---------------------------------------------------------------------------
# Sliding-window exponentiation
# ---------------------------------------------------------------------------

proc montPowWindowed64(baseL, expL, n: seq[uint64], n0: uint64,
                       r2mod: seq[uint64], t: var seq[uint64]): seq[uint64] =
  ## `baseL^expL mod n`, all values `< n`, `n` odd with `n.len = k`.
  ## `r2mod = R^2 mod n`, `t` is scratch with `2k + 2` limbs.
  let k = n.len
  let tableSize = 1 shl (mont64Window - 1) # odd powers 1,3,..,2^w - 1
  let baseR = montMul64(baseL, r2mod, n, n0, t)
  let oneR = montMul64(padTo64(@[1'u64], k), r2mod, n, n0, t)
  let g2 = montMul64(baseR, baseR, n, n0, t)
  var tab = newSeq[seq[uint64]](tableSize)
  tab[0] = baseR
  for i in 1 ..< tableSize:
    tab[i] = montMul64(tab[i - 1], g2, n, n0, t)
  var acc = oneR
  var i = bitLenLimbs64(expL) - 1
  while i >= 0:
    if not testBitLimbs64(expL, i):
      acc = montMul64(acc, acc, n, n0, t)
      dec i
    else:
      var l = min(mont64Window, i + 1)
      var win: uint64 = 0
      for j in 0 ..< l:
        if testBitLimbs64(expL, i - j):
          win = win or (1'u64 shl (l - 1 - j))
      while (win and 1'u64) == 0'u64: # shrink to odd window
        dec l
        win = win shr 1
      for _ in 0 ..< l:
        acc = montMul64(acc, acc, n, n0, t)
      acc = montMul64(acc, tab[int((win - 1) shr 1)], n, n0, t)
      i -= l
  # out of Montgomery domain: acc * 1
  montMul64(acc, padTo64(@[1'u64], k), n, n0, t)

proc fastPowmod64*(base, exp, modulus: BigInt): BigInt =
  ## `base^exp mod modulus` via 64-bit-limb Montgomery sliding-window
  ## exponentiation. Falls back to `bigints.powmod` for even moduli.
  if modulus == initBigInt(1):
    return initBigInt(0)
  if exp == initBigInt(0):
    return initBigInt(1)
  var b = base mod modulus
  if b == initBigInt(0):
    return initBigInt(0)
  if b < initBigInt(0):
    b += modulus
  if (modulus and initBigInt(1)) == initBigInt(0):
    return powmod(base, exp, modulus) # even modulus: no Montgomery inverse
  let n = bigToLimbs64(modulus)
  let k = n.len
  let baseL = padTo64(bigToLimbs64(b), k)
  let expL = bigToLimbs64(exp)
  let n0 = montN0_64(n)
  # R^2 mod n via one bigints op (single shift + single division);
  # negligible next to the ~1000 multiplies of the exponentiation itself.
  let r2mod = padTo64(bigToLimbs64((initBigInt(1) shl (128 * k)) mod modulus), k)
  var t = newSeq[uint64](2 * k + 2)
  limbsToBig64(montPowWindowed64(baseL, expL, n, n0, r2mod, t))

{.pop.}
