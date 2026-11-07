# Private key import: PKCS#1, PKCS#8 (unencrypted), SEC1 (RFC 8017/5958/5915).
#
# Covers what a TLS server needs: RSA (two-prime), NIST P-256/P-384/P-521
# and secp256k1 EC, Ed25519 and X25519 (RFC 8410). Encrypted PKCS#8,
# multi-prime RSA, and explicit-curve parameters are rejected.
#
# SPDX-License-Identifier: BSD-2-Clause

import bigints

import nimcypher/algos/bigint_ext as bigintExt
import nimcypher/algos/rsa as rsaAlgo
import nimcypher/algos/ecdsa as ecdsaAlgo
import nimcypher/sign as edsa
import nimcypher/utils

import ./asn1
import ./codec
import ./pem
import ./x509

type
  PrivKeyKind* = enum
    pkRsa
    pkEc
    pkEd25519
    pkX25519

  PrivateKey* = object
    case kind*: PrivKeyKind
    of pkRsa:
      rsa*: rsaAlgo.RsaPrivateKey
    of pkEc:
      ec*: ecdsaAlgo.EcPrivateKey
    of pkEd25519:
      edSecret*: array[64, byte]
      edPub*: array[32, byte]
    of pkX25519:
      xSeed*: array[32, byte]

const
  OidRsaEncryption = "1.2.840.113549.1.1.1"
  OidEcPublicKey = "1.2.840.10045.2.1"
  OidEd25519 = "1.3.101.112"
  OidX25519 = "1.3.101.110"
  OidP256 = "1.2.840.10045.3.1.7"
  OidP384 = "1.3.132.0.34"
  OidP521 = "1.3.132.0.35"
  OidSecp256k1 = "1.3.132.0.10"

func ecCurveOfOid*(oid: string): ecdsaAlgo.EcCurve =
  case oid
  of OidP256: ecdsaAlgo.P256
  of OidP384: ecdsaAlgo.P384
  of OidP521: ecdsaAlgo.P521
  of OidSecp256k1: ecdsaAlgo.Secp256k1
  else: raise newException(ValueError, "unsupported EC curve " & oid)

proc rsaPrivateFromParts*(nB, eB, dB, pB, qB: openArray[byte]): rsaAlgo.RsaPrivateKey =
  ## Build + consistency-check an RSA key from big-endian parts.
  ## CRT values are recomputed, never trusted from the encoding.
  let n = bigintExt.fromBytesBE(nB)
  let e = bigintExt.fromBytesBE(eB)
  let d = bigintExt.fromBytesBE(dB)
  let p = bigintExt.fromBytesBE(pB)
  let q = bigintExt.fromBytesBE(qB)
  let one = bigintExt.initBigInt(1)
  if p * q != n:
    raise newException(ValueError, "RSA p*q != n")
  if e <= one or d <= one:
    raise newException(ValueError, "RSA bad exponent")
  let pm1 = p - one
  let qm1 = q - one
  let dp = d mod pm1
  let dq = d mod qm1
  let qinv = invmod(q, p)
  rsaAlgo.RsaPrivateKey(n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq,
                        qinv: qinv, k: bigintExt.byteLen(n))

proc parseRsaPkcs1*(der: openArray[byte]): rsaAlgo.RsaPrivateKey =
  var r = initReader(der)
  let top = r.readTlv()
  r.expectEmpty()
  top.expectTag(0x30, "RSAPrivateKey")
  let f = top.children
  if f.len < 9:
    raise newException(ValueError, "RSAPrivateKey too short")
  if f[0].tag != byte(ord(tInteger)) or f[0].content != @[byte 0]:
    raise newException(ValueError, "only two-prime RSA supported")
  rsaPrivateFromParts(f[1].asIntegerBytes, f[2].asIntegerBytes,
                      f[3].asIntegerBytes, f[4].asIntegerBytes,
                      f[5].asIntegerBytes)

proc parseEcSec1*(der: openArray[byte]): ecdsaAlgo.EcPrivateKey =
  var r = initReader(der)
  let top = r.readTlv()
  r.expectEmpty()
  top.expectTag(0x30, "ECPrivateKey")
  var versionOk = false
  var privBytes: seq[byte]
  var havePriv = false
  var curve: ecdsaAlgo.EcCurve
  var haveCurve = false
  var pubBytes: seq[byte]
  for f in top.children:
    if f.tag == byte(ord(tInteger)):
      if f.content != @[byte 1]:
        raise newException(ValueError, "bad ECPrivateKey version")
      versionOk = true
    elif f.tag == byte(ord(tOctetString)):
      privBytes = f.asOctetString()
      havePriv = true
    elif f.tag == 0xA0: # parameters [0] EXPLICIT
      var ir = initReader(f.content)
      let oid = ir.readTlv()
      ir.expectEmpty()
      curve = ecCurveOfOid(oidToString(oid.asOid))
      haveCurve = true
    elif f.tag == 0xA1: # publicKey [1] EXPLICIT, optional
      var ir = initReader(f.content)
      let bs = ir.readTlv()
      ir.expectEmpty()
      pubBytes = bs.asBitString().data
    else:
      raise newException(ValueError, "unexpected ECPrivateKey field")
  if not (versionOk and havePriv and haveCurve):
    raise newException(ValueError, "ECPrivateKey missing fields")
  let cp = ecdsaAlgo.curveParams(curve)
  if privBytes.len != cp.orderLen:
    raise newException(ValueError, "EC private scalar wrong length")
  let d = bigintExt.fromBytesBE(privBytes)
  if d <= bigintExt.initBigInt(1) or d >= cp.n:
    raise newException(ValueError, "EC private scalar out of range")
  let priv = ecdsaAlgo.EcPrivateKey(curve: curve, d: d)
  let pub = ecdsaAlgo.publicKeyFromPrivate(priv)
  if pubBytes.len > 0:
    # Cross-check the embedded public key when present.
    if pubBytes.len != 1 + 2 * cp.coordLen or pubBytes[0] != 0x04:
      raise newException(ValueError, "bad SEC1 public key encoding")
    let x = bigintExt.fromBytesBE(pubBytes.toOpenArray(1, cp.coordLen))
    let y = bigintExt.fromBytesBE(
      pubBytes.toOpenArray(1 + cp.coordLen, pubBytes.len - 1))
    if x != pub.x or y != pub.y:
      raise newException(ValueError, "SEC1 public key mismatch")
  priv

proc rawSeedFromPkcs8Octets*(inner: openArray[byte],
                             what: string): array[32, byte] =
  ## RFC 8410 wraps the 32-byte seed in an inner OCTET STRING, but some
  ## encoders store it bare. Accept both.
  var seed = @(inner.toOpenArray(0, inner.high))
  if seed.len != 32:
    var r = initReader(inner)
    let o = r.readTlv()
    r.expectEmpty()
    seed = o.asOctetString()
    if seed.len != 32:
      raise newException(ValueError, "bad " & what & " seed length")
  for i in 0 ..< 32: result[i] = seed[i]

proc parseEcSec1Implied*(sec1der: openArray[byte],
                          curve: ecdsaAlgo.EcCurve): ecdsaAlgo.EcPrivateKey =
  ## SEC1 without optional parameters (curve implied by outer PKCS#8).
  var r = initReader(sec1der)
  let top = r.readTlv()
  r.expectEmpty()
  top.expectTag(0x30, "ECPrivateKey")
  var versionOk = false
  var privBytes: seq[byte]
  for f in top.children:
    if f.tag == byte(ord(tInteger)):
      if f.content != @[byte 1]:
        raise newException(ValueError, "bad ECPrivateKey version")
      versionOk = true
    elif f.tag == byte(ord(tOctetString)):
      privBytes = f.asOctetString()
    elif f.tag == 0xA1:
      discard # optional public key; verified by caller if needed
    else:
      raise newException(ValueError, "unexpected ECPrivateKey field")
  if not versionOk or privBytes.len == 0:
    raise newException(ValueError, "ECPrivateKey missing fields")
  let cp = ecdsaAlgo.curveParams(curve)
  if privBytes.len != cp.orderLen:
    raise newException(ValueError, "EC private scalar wrong length")
  let d = bigintExt.fromBytesBE(privBytes)
  if d <= bigintExt.initBigInt(1) or d >= cp.n:
    raise newException(ValueError, "EC private scalar out of range")
  ecdsaAlgo.EcPrivateKey(curve: curve, d: d)

proc parsePkcs8*(der: openArray[byte]): PrivateKey =
  var r = initReader(der)
  let top = r.readTlv()
  r.expectEmpty()
  top.expectTag(0x30, "PrivateKeyInfo")
  let f = top.children
  if f.len < 3 or f.len > 4:
    raise newException(ValueError, "bad PrivateKeyInfo")
  if f[0].tag != byte(ord(tInteger)) or f[0].content != @[byte 0]:
    raise newException(ValueError, "bad PrivateKeyInfo version")
  let aiKids = f[1].children
  if aiKids.len == 0 or aiKids.len > 2:
    raise newException(ValueError, "bad PKCS#8 algorithm")
  let algOid = oidToString(aiKids[0].asOid)
  let inner = f[2].asOctetString()
  case algOid
  of OidRsaEncryption:
    result = PrivateKey(kind: pkRsa, rsa: parseRsaPkcs1(inner))
  of OidEcPublicKey:
    if aiKids.len != 2:
      raise newException(ValueError, "PKCS#8 EC params missing")
    let curve = ecCurveOfOid(oidToString(aiKids[1].asOid))
    var sec1r = initReader(inner)
    let sec1 = sec1r.readTlv()
    sec1r.expectEmpty()
    # Re-parse as SEC1 with the curve implied by PKCS#8 params.
    if sec1.tag != 0x30:
      raise newException(ValueError, "bad SEC1 wrapper")
    # Inject parameters [0] if the inner SEC1 omits them (RFC 5915
    # allows omission inside PKCS#8 since the curve is already known).
    var hasParams = false
    for c in sec1.children:
      if c.tag == 0xA0: hasParams = true
    if hasParams:
      result = PrivateKey(kind: pkEc, ec: parseEcSec1(inner))
    else:
      result = PrivateKey(kind: pkEc, ec: parseEcSec1Implied(inner, curve))
  of OidEd25519:
    let seed = rawSeedFromPkcs8Octets(inner, "Ed25519")
    let kp = edsa.generateSigningKeyPair(toArray[32](seed))
    result = PrivateKey(kind: pkEd25519, edSecret: kp.secretKey.data,
                        edPub: kp.publicKey)
  of OidX25519:
    let seed = rawSeedFromPkcs8Octets(inner, "X25519")
    result = PrivateKey(kind: pkX25519, xSeed: seed)
  else:
    raise newException(ValueError, "unsupported PKCS#8 algorithm " & algOid)

proc loadPrivateKeyDer*(der: openArray[byte]): PrivateKey =
  ## Dispatch PKCS#8 ("PRIVATE KEY") vs PKCS#1 ("RSA PRIVATE KEY") vs
  ## SEC1 ("EC PRIVATE KEY") by structure.
  var r = initReader(der)
  let top = r.readTlv()
  r.expectEmpty()
  top.expectTag(0x30, "private key")
  let f = top.children
  if f.len >= 3 and f[0].tag == byte(ord(tInteger)) and
      f[1].tag == 0x30:
    # PKCS#8: INTEGER version, SEQUENCE algorithm, OCTET STRING key.
    return parsePkcs8(der)
  if f.len >= 9 and f[0].tag == byte(ord(tInteger)):
    return PrivateKey(kind: pkRsa, rsa: parseRsaPkcs1(der))
  # SEC1 ECPrivateKey: INTEGER(1), OCTET STRING, [0] params, ...
  return PrivateKey(kind: pkEc, ec: parseEcSec1(der))

proc loadPrivateKeyPem*(pemText: string): PrivateKey =
  ## Accept "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY" blocks.
  for label in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"]:
    let blocks = pemBlocks(pemText, label)
    if blocks.len > 0:
      if blocks.len > 1:
        raise newException(ValueError, "multiple PEM blocks")
      return loadPrivateKeyDer(blocks[0])
  raise newException(ValueError, "no private key PEM block found")

proc privateKeyMatchesSpki*(key: PrivateKey, spki: PublicKeyInfo): bool =
  ## Check a private key owns a certificate SPKI (server startup check).
  case key.kind
  of pkRsa:
    if spki.kind != skRsa: return false
    let pub = rsaAlgo.publicKey(key.rsa)
    pub.n == rsaPubKey(spki).n and pub.e == rsaPubKey(spki).e
  of pkEc:
    if spki.kind != skEc: return false
    let pub = ecdsaAlgo.publicKeyFromPrivate(key.ec)
    let sp = ecPubKey(spki)
    pub.curve == sp.curve and pub.x == sp.x and pub.y == sp.y
  of pkEd25519:
    spki.kind == skEd25519 and key.edPub == spki.edKey
  of pkX25519:
    false # agreement-only key, never a TLS identity
