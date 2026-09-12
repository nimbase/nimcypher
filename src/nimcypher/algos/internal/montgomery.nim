# Montgomery modular exponentiation on 32-bit limbs (pure Nim).
#
# `pkg/bigints` `powmod` is binary square-and-multiply with a full division
# per multiply. For RSA-sized moduli (>= 512 bits) that division dominates:
# on RSA-2048 it accounts for ~96% of a sign operation. This module replaces
# it with Montgomery arithmetic (CIOS form, every division becomes two
# multiplications) plus a left-to-right sliding window (w = 5), cutting the
# multiply count by ~2x on top. This is the portable default tier;
# `internal/montgomery64` selects 64-bit limbs + MULX when built with
# `-d:features.nimcypher.nimsimd` on amd64 (see `fastPowmod` below).
#
# Boundary conversion BigInt <-> limbs happens once per call; the hot loop
# works on `seq[uint32]` little-endian limbs with `uint64` accumulators, so
# it compiles to plain MUL/ADD chains on every backend (no SIMD needed and
# none used: a single RSA exponentiation is a sequential carry chain that
# does not vectorize).
#
# Scope: odd moduli only (RSA moduli always are). Even moduli fall back to
# `bigints.powmod` in `fastPowmod`.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import std/bitops
import std/options

import bigints

when defined(features.nimcypher.nimsimd) and defined(amd64):
  import ./montgomery64

{.push checks: off.}

const montWindow = 5

# ---------------------------------------------------------------------------
# Limb helpers (little-endian seq[uint32])
# ---------------------------------------------------------------------------

proc trimLimbs(a: var seq[uint32]) =
  var n = a.len
  while n > 1 and a[n - 1] == 0'u32:
    dec n
  if n != a.len:
    a.setLen(n)

proc cmpLimbs(a, b: openArray[uint32]): int =
  var ia = a.len
  while ia > 0 and a[ia - 1] == 0'u32:
    dec ia
  var ib = b.len
  while ib > 0 and b[ib - 1] == 0'u32:
    dec ib
  if ia != ib:
    return (if ia > ib: 1 else: -1)
  for i in countdown(ia - 1, 0):
    if a[i] != b[i]:
      return (if a[i] > b[i]: 1 else: -1)
  0

proc subLimbsInPlace(a: var seq[uint32], b: openArray[uint32]) =
  ## `a -= b`, requires `a >= b`.
  var borrow: uint64 = 0
  for i in 0 ..< a.len:
    let bi = (if i < b.len: uint64(b[i]) else: 0'u64) + borrow
    borrow = (if uint64(a[i]) < bi: 1'u64 else: 0'u64)
    a[i] = uint32((uint64(a[i]) - bi) and 0xFFFF_FFFF'u64)

proc testBitLimbs(limbs: openArray[uint32], idx: int): bool {.inline.} =
  let w = idx shr 5
  if w >= limbs.len:
    return false
  (limbs[w] and (1'u32 shl (idx and 31))) != 0'u32

proc bitLenLimbs(limbs: openArray[uint32]): int =
  var top = limbs.len - 1
  while top > 0 and limbs[top] == 0'u32:
    dec top
  if limbs[top] == 0'u32:
    return 0
  top * 32 + (32 - countLeadingZeroBits(limbs[top]))

# ---------------------------------------------------------------------------
# Schoolbook multiply + Montgomery reduction (SOS form)
# ---------------------------------------------------------------------------

proc mulLimbs(a, b: openArray[uint32], t: var seq[uint32]) =
  ## `t += a * b`. Caller zeroes `t` first; `t` needs `a.len + b.len + 1` limbs.
  for i in 0 ..< a.len:
    let ai = uint64(a[i])
    if ai == 0:
      continue
    var c: uint64 = 0
    for j in 0 ..< b.len:
      c += uint64(t[i + j]) + ai * uint64(b[j])
      t[i + j] = uint32(c and 0xFFFF_FFFF'u64)
      c = c shr 32
    var p = i + b.len
    while c != 0:
      c += uint64(t[p])
      t[p] = uint32(c and 0xFFFF_FFFF'u64)
      c = c shr 32
      inc p

proc montN0(n: openArray[uint32]): uint32 =
  ## `n0 = -n^(-1) mod 2^32`. Requires odd `n` (`n[0]` odd).
  let n0 = uint64(n[0])
  var x = 1'u64 # n^(-1) mod 2 (exact: n is odd)
  for _ in 0 ..< 5: # Newton doubles the bits: 1 -> 64
    x = (x * (2'u64 - (n0 * x and 0xFFFF_FFFF'u64))) and 0xFFFF_FFFF'u64
  uint32((0'u64 - x) and 0xFFFF_FFFF'u64)

proc montReduce(t: var seq[uint32], k: int, n: openArray[uint32],
                n0: uint32) =
  ## In-place REDC: `t = t / B^k mod n` with `B = 2^32`. `t` holds at least
  ## `2k + 1` limbs with value `< n * B^k`. Result lands in `t[k .. 2k]`.
  for i in 0 ..< k:
    let m = uint32((uint64(t[i]) * uint64(n0)) and 0xFFFF_FFFF'u64)
    if m == 0:
      continue
    var c: uint64 = 0
    for j in 0 ..< k:
      c += uint64(t[i + j]) + uint64(m) * uint64(n[j])
      t[i + j] = uint32(c and 0xFFFF_FFFF'u64)
      c = c shr 32
    var p = i + k
    while c != 0:
      c += uint64(t[p])
      t[p] = uint32(c and 0xFFFF_FFFF'u64)
      c = c shr 32
      inc p

proc montMul(a, b, n: openArray[uint32], n0: uint32,
             t: var seq[uint32]): seq[uint32] =
  ## Montgomery product: returns `a * b / R mod n` with `R = B^k`,
  ## `k = n.len`. Inputs must be `< n`. Output is `< n`.
  let k = n.len
  for i in 0 ..< 2 * k + 1:
    t[i] = 0'u32
  mulLimbs(a, b, t)
  montReduce(t, k, n, n0)
  result = newSeq[uint32](k + 1)
  for i in 0 ..< k + 1:
    result[i] = t[k + i]
  trimLimbs(result)
  if cmpLimbs(result, n) >= 0:
    subLimbsInPlace(result, n)
    trimLimbs(result)

# ---------------------------------------------------------------------------
# BigInt boundary conversion
# ---------------------------------------------------------------------------

let mask32Big = initBigInt(0xFFFF_FFFF'u32)

proc bigToLimbs(x: BigInt): seq[uint32] =
  if x == initBigInt(0):
    return @[0'u32]
  var v = x
  result = @[]
  while v != initBigInt(0):
    result.add(toInt[uint32](v and mask32Big).get)
    v = v shr 32

proc limbsToBig(a: openArray[uint32]): BigInt =
  var s = newSeq[uint32](a.len)
  for i in 0 ..< a.len:
    s[i] = a[i]
  initBigInt(s)

proc padTo(limbs: seq[uint32], k: int): seq[uint32] =
  result = newSeq[uint32](k)
  let n = min(limbs.len, k)
  for i in 0 ..< n:
    result[i] = limbs[i]

# ---------------------------------------------------------------------------
# Sliding-window exponentiation
# ---------------------------------------------------------------------------

proc montPowWindowed(baseL, expL, n: seq[uint32], n0: uint32,
                     r2mod: seq[uint32], t: var seq[uint32]): seq[uint32] =
  ## `baseL^expL mod n`, all values `< n`, `n` odd with `n.len = k`.
  ## `r2mod = R^2 mod n`, `t` is scratch with `2k + 2` limbs.
  let k = n.len
  let tableSize = 1 shl (montWindow - 1) # odd powers 1,3,..,2^w - 1
  let baseR = montMul(baseL, r2mod, n, n0, t)
  let oneR = montMul(padTo(@[1'u32], k), r2mod, n, n0, t)
  let g2 = montMul(baseR, baseR, n, n0, t)
  var tab = newSeq[seq[uint32]](tableSize)
  tab[0] = baseR
  for i in 1 ..< tableSize:
    tab[i] = montMul(tab[i - 1], g2, n, n0, t)
  var acc = oneR
  var i = bitLenLimbs(expL) - 1
  while i >= 0:
    if not testBitLimbs(expL, i):
      acc = montMul(acc, acc, n, n0, t)
      dec i
    else:
      var l = min(montWindow, i + 1)
      var win: uint32 = 0
      for j in 0 ..< l:
        if testBitLimbs(expL, i - j):
          win = win or (1'u32 shl (l - 1 - j))
      while (win and 1'u32) == 0'u32: # shrink to odd window
        dec l
        win = win shr 1
      for _ in 0 ..< l:
        acc = montMul(acc, acc, n, n0, t)
      acc = montMul(acc, tab[(win - 1) shr 1], n, n0, t)
      i -= l
  # out of Montgomery domain: acc * 1
  montMul(acc, padTo(@[1'u32], k), n, n0, t)

proc fastPowmod32*(base, exp, modulus: BigInt): BigInt =
  ## `base^exp mod modulus` via 32-bit-limb Montgomery sliding-window
  ## exponentiation. Pure Nim, portable default. Falls back to
  ## `bigints.powmod` for even moduli.
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
  let n = bigToLimbs(modulus)
  let k = n.len
  let baseL = padTo(bigToLimbs(b), k)
  let expL = bigToLimbs(exp)
  let n0 = montN0(n)
  # R^2 mod n via one bigints op (single shift + single division);
  # negligible next to the ~1000 multiplies of the exponentiation itself.
  let r2mod = padTo(bigToLimbs((initBigInt(1) shl (64 * k)) mod modulus), k)
  var t = newSeq[uint32](2 * k + 2)
  limbsToBig(montPowWindowed(baseL, expL, n, n0, r2mod, t))

proc fastPowmod*(base, exp, modulus: BigInt): BigInt =
  ## Tier dispatch, all differential-tested against `bigints.powmod`:
  ## 64-bit limbs + MULX when built with `-d:features.nimcypher.nimsimd`
  ## on amd64 (needs BMI2), portable 32-bit limbs otherwise. The default
  ## build is pure Nim with no ISA requirements.
  ## NOTE: a dual-chain ADCX/ADOX tier was prototyped and abandoned --
  ## splitting lo/hi words into CF/OF chains forces a merge pass, and the
  ## merge (or any folded 3-addend form, which needs 2-bit carries --
  ## concrete counterexample A=lo=H=B-1,CF=1: true carry 2, chains yield
  ## 1) eats the parallel gain (measured 1.53ms vs 0.98ms Tier 2 on a
  ## 1024-bit exp). Instruction-level parallelism here is spent; the next
  ## lever is algorithmic (dedicated squaring), not narrower carries.
  when defined(features.nimcypher.nimsimd) and defined(amd64):
    fastPowmod64(base, exp, modulus)
  else:
    fastPowmod32(base, exp, modulus)

{.pop.}
