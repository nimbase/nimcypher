# ECDSA + ECDH over NIST P-256/P-384/P-521 and secp256k1.
#
# Pure Nim on `pkg/bigints`. Affine coordinates with `invmod`; simple
# double-and-add scalar multiplication (variable-time). Signatures use
# deterministic nonces per RFC 6979 (HMAC-SHA of the curve hash).
# Randomness (keygen) from `std/sysrand`.
#
# JOSE mapping (RFC 7518): ES256 = P-256/SHA-256, ES384 = P-384/SHA-384,
# ES512 = P-521/SHA-512, ES256K = secp256k1/SHA-256. JWS format is the
# fixed-width concatenation R || S (each of coordLen bytes).
#
# Curve parameters cross-checked against `openssl ecparam -param_enc
# explicit` output (OpenSSL 3.6.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import std/strutils

import bigints

import ./common
import ./bigint_ext
import ./sha256 as sha256Algo
import ./sha384 as sha384Algo
import ./sha512 as sha512Algo

{.push checks: off.}

type
  EcCurve* = enum
    ## Supported curves. `P521` is the JWA `P-521` curve (ES512).
    P256, P384, P521, Secp256k1

  EcHash* = enum
    ehSha256, ehSha384, ehSha512

  CurveParams* = object
    p*, a*, b*: BigInt
    gx*, gy*: BigInt
    n*: BigInt
    h*: int
    coordLen*: int ## field-element byte length
    orderLen*: int ## order byte length
    hash*: EcHash

  EcPoint* = object
    x*, y*: BigInt
    inf*: bool

  EcPrivateKey* = object
    curve*: EcCurve
    d*: BigInt ## in [1, n-1]

  EcPublicKey* = object
    curve*: EcCurve
    x*, y*: BigInt

# ---------------------------------------------------------------------------
# Hex parsing + curve table
# ---------------------------------------------------------------------------

proc hexToBigInt(s: string): BigInt =
  var hex = s
  if hex.len mod 2 == 1:
    hex = "0" & hex
  var bytes = newSeq[byte](hex.len div 2)
  const digits = "0123456789ABCDEF"
  for i in 0 ..< bytes.len:
    let hi = digits.find(hex[2 * i].toUpperAscii)
    let lo = digits.find(hex[2 * i + 1].toUpperAscii)
    if hi < 0 or lo < 0:
      raise newException(ValueError, "invalid hex in curve constant")
    bytes[i] = byte(hi * 16 + lo)
  fromBytesBE(bytes)

proc curveParams*(c: EcCurve): CurveParams =
  case c
  of P256:
    result.p = hexToBigInt("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")
    result.a = hexToBigInt("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC")
    result.b = hexToBigInt("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")
    result.gx = hexToBigInt("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")
    result.gy = hexToBigInt("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
    result.n = hexToBigInt("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
    result.h = 1
    result.coordLen = 32
    result.orderLen = 32
    result.hash = ehSha256
  of P384:
    result.p = hexToBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF")
    result.a = hexToBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC")
    result.b = hexToBigInt("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF")
    result.gx = hexToBigInt("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7")
    result.gy = hexToBigInt("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F")
    result.n = hexToBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973")
    result.h = 1
    result.coordLen = 48
    result.orderLen = 48
    result.hash = ehSha384
  of P521:
    result.p = hexToBigInt("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
    result.a = hexToBigInt("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC")
    result.b = hexToBigInt("51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00")
    # Generator is the 04 || X(66) || Y(66) uncompressed point; X and Y
    # below are the two 66-byte halves of that blob (verified against
    # `openssl ecparam -param_enc explicit` output).
    result.gx = hexToBigInt("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66")
    result.gy = hexToBigInt("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650")
    result.n = hexToBigInt("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409")
    result.h = 1
    result.coordLen = 66
    result.orderLen = 66
    result.hash = ehSha512
  of Secp256k1:
    result.p = hexToBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
    result.a = initBigInt(0)
    result.b = initBigInt(7)
    result.gx = hexToBigInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    result.gy = hexToBigInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
    result.n = hexToBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
    result.h = 1
    result.coordLen = 32
    result.orderLen = 32
    result.hash = ehSha256

# ---------------------------------------------------------------------------
# Field + point arithmetic (affine, variable-time)
# ---------------------------------------------------------------------------

proc fmod(cp: CurveParams, x: BigInt): BigInt =
  var r = x mod cp.p
  if r < initBigInt(0): r += cp.p
  r

proc pointAtInfinity*(): EcPoint =
  EcPoint(inf: true, x: initBigInt(0), y: initBigInt(0))

proc isOnCurve*(cp: CurveParams, pt: EcPoint): bool =
  if pt.inf: return true
  let lhs = fmod(cp, pt.y * pt.y)
  let rhs = fmod(cp, pt.x * pt.x * pt.x + cp.a * pt.x + cp.b)
  lhs == rhs

proc pointDouble(cp: CurveParams, pt: EcPoint): EcPoint =
  if pt.inf: return pt
  if pt.y == initBigInt(0): return pointAtInfinity()
  # lambda = (3x^2 + a) / (2y)
  let three = initBigInt(3)
  let two = initBigInt(2)
  let num = fmod(cp, three * pt.x * pt.x + cp.a)
  let den = fmod(cp, two * pt.y)
  let lam = fmod(cp, num * invmod(den, cp.p))
  let x3 = fmod(cp, lam * lam - pt.x - pt.x)
  let y3 = fmod(cp, lam * (pt.x - x3) - pt.y)
  EcPoint(x: x3, y: y3, inf: false)

proc pointAdd*(cp: CurveParams, p1, p2: EcPoint): EcPoint =
  if p1.inf: return p2
  if p2.inf: return p1
  if p1.x == p2.x:
    if fmod(cp, p1.y + p2.y) == initBigInt(0):
      return pointAtInfinity()
    # P == Q -> doubling (also covers y == 0 -> infinity inside)
    return pointDouble(cp, p1)
  let num = fmod(cp, p2.y - p1.y)
  let den = fmod(cp, p2.x - p1.x)
  let lam = fmod(cp, num * invmod(den, cp.p))
  let x3 = fmod(cp, lam * lam - p1.x - p2.x)
  let y3 = fmod(cp, lam * (p1.x - x3) - p1.y)
  EcPoint(x: x3, y: y3, inf: false)

# ---------------------------------------------------------------------------
# Jacobian coordinates for scalar multiplication.
#
# Affine formulas need one `invmod` per add/double; Jacobian defers the
# single inversion to the final affine conversion, which is ~50x faster
# with `pkg/bigints`. Variable-time (like the rest of this module).
# ---------------------------------------------------------------------------

type
  JacPoint = object
    x*, y*, z*: BigInt # infinity iff z == 0

proc toJacobian(pt: EcPoint): JacPoint =
  if pt.inf:
    JacPoint(x: initBigInt(0), y: initBigInt(0), z: initBigInt(0))
  else:
    JacPoint(x: pt.x, y: pt.y, z: initBigInt(1))

proc jacDouble(cp: CurveParams, p: JacPoint): JacPoint =
  if p.z == initBigInt(0): return p
  if p.y == initBigInt(0):
    return JacPoint(x: initBigInt(0), y: initBigInt(0), z: initBigInt(0))
  # S = 4*X*Y^2; M = 3*X^2 + a*Z^4
  let y2 = fmod(cp, p.y * p.y)
  let s = fmod(cp, initBigInt(4) * p.x * y2)
  let z2 = fmod(cp, p.z * p.z)
  let m = fmod(cp, initBigInt(3) * p.x * p.x + cp.a * z2 * z2)
  let x3 = fmod(cp, m * m - initBigInt(2) * s)
  let y4 = fmod(cp, y2 * y2)
  let y3 = fmod(cp, m * (s - x3) - initBigInt(8) * y4)
  let z3 = fmod(cp, initBigInt(2) * p.y * p.z)
  JacPoint(x: x3, y: y3, z: z3)

proc jacAddMixed(cp: CurveParams, j: JacPoint, a: EcPoint): JacPoint =
  ## Add a Jacobian point and an affine point.
  if j.z == initBigInt(0):
    return toJacobian(a)
  if a.inf: return j
  # U2 = X2*Z1^2; S2 = Y2*Z1^3; U1 = X1; S1 = Y1
  let z1sq = fmod(cp, j.z * j.z)
  let u2 = fmod(cp, a.x * z1sq)
  let s2 = fmod(cp, a.y * z1sq * j.z)
  let h = fmod(cp, u2 - j.x)
  let r = fmod(cp, s2 - j.y)
  if h == initBigInt(0):
    if r == initBigInt(0):
      return jacDouble(cp, j)
    return JacPoint(x: initBigInt(0), y: initBigInt(0), z: initBigInt(0))
  let h2 = fmod(cp, h * h)
  let h3 = fmod(cp, h2 * h)
  let u1h2 = fmod(cp, j.x * h2)
  let x3 = fmod(cp, r * r - h3 - initBigInt(2) * u1h2)
  let y3 = fmod(cp, r * (u1h2 - x3) - j.y * h3)
  let z3 = fmod(cp, h * j.z)
  JacPoint(x: x3, y: y3, z: z3)

proc jacToAffine(cp: CurveParams, p: JacPoint): EcPoint =
  if p.z == initBigInt(0):
    return pointAtInfinity()
  let zi = invmod(p.z, cp.p)
  let z2 = fmod(cp, zi * zi)
  let z3 = fmod(cp, z2 * zi)
  EcPoint(x: fmod(cp, p.x * z2), y: fmod(cp, p.y * z3), inf: false)

proc pointMul*(cp: CurveParams, scalar: BigInt, pt: EcPoint): EcPoint =
  ## Double-and-add over a Jacobian accumulator, MSB first.
  ## `scalar` should already be reduced. Variable-time.
  if pt.inf: return pt
  if scalar == initBigInt(0): return pointAtInfinity()
  let nbits = bitLen(scalar)
  let two = initBigInt(2)
  let zero = initBigInt(0)
  var acc = JacPoint(x: zero, y: zero, z: zero)
  for i in countdown(nbits - 1, 0):
    acc = jacDouble(cp, acc)
    if ((scalar shr Natural(i)) mod two) != zero:
      acc = jacAddMixed(cp, acc, pt)
  jacToAffine(cp, acc)

proc generator*(cp: CurveParams): EcPoint =
  EcPoint(x: cp.gx, y: cp.gy, inf: false)

# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

proc generateKeyPair*(curve: EcCurve): (EcPrivateKey, EcPublicKey) =
  ## Generate a fresh key pair with an OS-random secret in [1, n-1].
  let cp = curveParams(curve)
  let d = randomBigIntBelow(cp.n)
  let q = pointMul(cp, d, generator(cp))
  if q.inf:
    raise newException(ValueError, "generated point at infinity, retry")
  if not isOnCurve(cp, q):
    raise newException(ValueError, "generated point off curve")
  (EcPrivateKey(curve: curve, d: d), EcPublicKey(curve: curve, x: q.x, y: q.y))

proc publicKeyFromPrivate*(priv: EcPrivateKey): EcPublicKey =
  let cp = curveParams(priv.curve)
  if priv.d <= initBigInt(0) or priv.d >= cp.n:
    raise newException(ValueError, "private scalar out of range")
  let q = pointMul(cp, priv.d, generator(cp))
  EcPublicKey(curve: priv.curve, x: q.x, y: q.y)

proc validatePublicKey*(pub: EcPublicKey): bool =
  let cp = curveParams(pub.curve)
  if pub.x < initBigInt(0) or pub.x >= cp.p: return false
  if pub.y < initBigInt(0) or pub.y >= cp.p: return false
  let pt = EcPoint(x: pub.x, y: pub.y, inf: false)
  if not isOnCurve(cp, pt): return false
  # Subgroup check: all built-in curves have cofactor h == 1 (prime order),
  # so on-curve already implies subgroup membership. The n*Q check only
  # runs for hypothetical h != 1 curves.
  if cp.h != 1:
    let chk = pointMul(cp, cp.n, pt)
    if not chk.inf: return false
  result = true

proc bitAt(x: BigInt, i, nbits: int): bool =
  ## Bit `i` of `x` (0 when `i` is past the cached bit length).
  if i < 0 or i >= nbits: return false
  ((x shr Natural(i)) mod initBigInt(2)) != initBigInt(0)

proc pointMulJoint*(cp: CurveParams, k1: BigInt, p1: EcPoint,
                    k2: BigInt, p2: EcPoint): EcPoint =
  ## Shamir's trick: k1*P1 + k2*P2 in a single double-and-add chain.
  ## Used by verify (u1*G + u2*Q); ~40% cheaper than two `pointMul`s.
  if p1.inf and p2.inf: return pointAtInfinity()
  if k1 == initBigInt(0): return pointMul(cp, k2, p2)
  if k2 == initBigInt(0): return pointMul(cp, k1, p1)
  let n1 = bitLen(k1)
  let n2 = bitLen(k2)
  let top = max(n1, n2)
  let zero = initBigInt(0)
  var acc = JacPoint(x: zero, y: zero, z: zero)
  for i in countdown(top - 1, 0):
    acc = jacDouble(cp, acc)
    if bitAt(k1, i, n1):
      acc = jacAddMixed(cp, acc, p1)
    if bitAt(k2, i, n2):
      acc = jacAddMixed(cp, acc, p2)
  jacToAffine(cp, acc)

# ---------------------------------------------------------------------------
# Hashing + RFC 6979 deterministic nonce
# ---------------------------------------------------------------------------

proc curveHashLen(cp: CurveParams): int =
  case cp.hash
  of ehSha256: 32
  of ehSha384: 48
  of ehSha512: 64

proc hashMsg(cp: CurveParams, msg: openArray[byte]): seq[byte] =
  case cp.hash
  of ehSha256:
    let d = sha256Algo.sha256(msg)
    result = newSeq[byte](32)
    for i in 0 ..< 32: result[i] = d[i]
  of ehSha384:
    let d = sha384Algo.sha384(msg)
    result = newSeq[byte](48)
    for i in 0 ..< 48: result[i] = d[i]
  of ehSha512:
    let d = sha512Algo.sha512(msg)
    result = newSeq[byte](64)
    for i in 0 ..< 64: result[i] = d[i]

proc hmacForCurve(cp: CurveParams, key, msg: openArray[byte]): seq[byte] =
  case cp.hash
  of ehSha256:
    let m = sha256Algo.sha256Hmac(key, msg)
    result = newSeq[byte](32)
    for i in 0 ..< 32: result[i] = m[i]
  of ehSha384:
    let m = sha384Algo.sha384Hmac(key, msg)
    result = newSeq[byte](48)
    for i in 0 ..< 48: result[i] = m[i]
  of ehSha512:
    let m = sha512Algo.sha512Hmac(key, msg)
    result = newSeq[byte](64)
    for i in 0 ..< 64: result[i] = m[i]

proc bits2int(cp: CurveParams, hashBytes: openArray[byte]): BigInt =
  ## Truncate (leftmost) when hash is longer than the order, per SEC1.
  let nbits = bitLen(cp.n)
  var x = fromBytesBE(hashBytes)
  let hbits = hashBytes.len * 8
  if hbits > nbits:
    x = x shr Natural(hbits - nbits)
  x

proc rfc6979(cp: CurveParams, privOctets, h1Octets: openArray[byte]): BigInt =
  ## RFC 6979 §3.2 HMAC_DRBG deterministic nonce in [1, n-1].
  let hlen = curveHashLen(cp)
  var v = newSeq[byte](hlen)
  for i in 0 ..< hlen: v[i] = 0x01
  var k = newSeq[byte](hlen)
  for i in 0 ..< hlen: k[i] = 0x00
  var tmp = newSeq[byte](v.len + 1 + privOctets.len + h1Octets.len)
  for i in 0 ..< v.len: tmp[i] = v[i]
  tmp[v.len] = 0x00
  for i in 0 ..< privOctets.len: tmp[v.len + 1 + i] = privOctets[i]
  for i in 0 ..< h1Octets.len: tmp[v.len + 1 + privOctets.len + i] = h1Octets[i]
  k = hmacForCurve(cp, k, tmp)
  v = hmacForCurve(cp, k, v)
  # second round with 0x01
  for i in 0 ..< v.len: tmp[i] = v[i]
  tmp[v.len] = 0x01
  for i in 0 ..< privOctets.len: tmp[v.len + 1 + i] = privOctets[i]
  for i in 0 ..< h1Octets.len: tmp[v.len + 1 + privOctets.len + i] = h1Octets[i]
  k = hmacForCurve(cp, k, tmp)
  v = hmacForCurve(cp, k, v)
  wipe(tmp)
  let orderLen = cp.orderLen
  while true:
    var t: seq[byte] = @[]
    while t.len < orderLen:
      v = hmacForCurve(cp, k, v)
      t.add(v)
    var candBytes = newSeq[byte](orderLen)
    for i in 0 ..< orderLen: candBytes[i] = t[i]
    let cand = bits2int(cp, candBytes)
    wipe(candBytes)
    if cand >= initBigInt(1) and cand < cp.n:
      wipe(v); wipe(k)
      return cand
    # retry: K = HMAC(K, V || 0x00), V = HMAC(K, V)
    var rk = newSeq[byte](v.len + 1)
    for i in 0 ..< v.len: rk[i] = v[i]
    rk[v.len] = 0x00
    k = hmacForCurve(cp, k, rk)
    v = hmacForCurve(cp, k, v)
    wipe(rk)

# ---------------------------------------------------------------------------
# ECDSA sign / verify (JWS R||S format)
# ---------------------------------------------------------------------------

proc sign*(priv: EcPrivateKey, msg: openArray[byte]): seq[byte] =
  ## ECDSA sign with RFC 6979 nonce. Returns R || S (coordLen each).
  let cp = curveParams(priv.curve)
  if priv.d <= initBigInt(0) or priv.d >= cp.n:
    raise newException(ValueError, "private scalar out of range")
  let h = hashMsg(cp, msg)
  var e = bits2int(cp, h)
  if e >= cp.n: e = e mod cp.n
  let privOct = toBytesBE(priv.d, cp.orderLen)
  # bits2octets(h1) = (e mod n) as orderLen octets
  let h1Oct = toBytesBE(e mod cp.n, cp.orderLen)
  let kk = rfc6979(cp, privOct, h1Oct)
  let kp = pointMul(cp, kk, generator(cp))
  if kp.inf:
    raise newException(ValueError, "nonce produced point at infinity")
  let r = kp.x mod cp.n
  if r == initBigInt(0):
    raise newException(ValueError, "nonce produced r = 0, retry")
  let kInv = invmod(kk, cp.n)
  let s = (kInv * (e + r * priv.d)) mod cp.n
  if s == initBigInt(0):
    raise newException(ValueError, "signature s = 0, retry")
  result = newSeq[byte](2 * cp.coordLen)
  let rb = toBytesBE(r, cp.coordLen)
  let sb = toBytesBE(s, cp.coordLen)
  for i in 0 ..< cp.coordLen: result[i] = rb[i]
  for i in 0 ..< cp.coordLen: result[cp.coordLen + i] = sb[i]

proc verify*(pub: EcPublicKey, msg: openArray[byte],
             sig: openArray[byte]): bool =
  ## ECDSA verify over a JWS R || S signature. False on any failure.
  let cp = curveParams(pub.curve)
  if sig.len != 2 * cp.coordLen:
    return false
  if not validatePublicKey(pub):
    return false
  var rb = newSeq[byte](cp.coordLen)
  var sb = newSeq[byte](cp.coordLen)
  for i in 0 ..< cp.coordLen: rb[i] = sig[i]
  for i in 0 ..< cp.coordLen: sb[i] = sig[cp.coordLen + i]
  let r = fromBytesBE(rb)
  let s = fromBytesBE(sb)
  let one = initBigInt(1)
  if r < one or r >= cp.n or s < one or s >= cp.n:
    return false
  let h = hashMsg(cp, msg)
  var e = bits2int(cp, h)
  if e >= cp.n: e = e mod cp.n
  let w =
    try: invmod(s, cp.n)
    except ValueError: return false
  let u1 = (e * w) mod cp.n
  let u2 = (r * w) mod cp.n
  let g = generator(cp)
  let q = EcPoint(x: pub.x, y: pub.y, inf: false)
  let pt = pointMulJoint(cp, u1, g, u2, q)
  if pt.inf:
    return false
  result = (pt.x mod cp.n) == r

# ---------------------------------------------------------------------------
# ECDH (for ECDH-ES): x-coordinate of d*Q as coordLen bytes
# ---------------------------------------------------------------------------

proc ecdh*(priv: EcPrivateKey, peer: EcPublicKey): seq[byte] =
  ## ECDH shared secret Z = x(d*Q) as coordLen big-endian bytes.
  ## Raises on curve mismatch, invalid peer, or infinity result.
  if priv.curve != peer.curve:
    raise newException(ValueError, "curve mismatch for ECDH")
  let cp = curveParams(priv.curve)
  if priv.d <= initBigInt(0) or priv.d >= cp.n:
    raise newException(ValueError, "private scalar out of range")
  if not validatePublicKey(peer):
    raise newException(ValueError, "invalid peer public key")
  let q = EcPoint(x: peer.x, y: peer.y, inf: false)
  let shared = pointMul(cp, priv.d, q)
  if shared.inf:
    raise newException(ValueError, "ECDH produced point at infinity")
  result = toBytesBE(shared.x mod cp.p, cp.coordLen)

proc wipe*(key: var EcPrivateKey) =
  ## Best-effort wipe (drops the limb reference; see `rsa.wipe` for limits).
  ## Call explicitly when done with the key; no auto-destroy hook is
  ## installed (BigInt limbs live in managed seqs).
  key.d = initBigInt(0)

{.pop.}
