# X.509 certificate parsing + signature verification (RFC 5280 profile).
#
# Fresh implementation from the RFCs. Signature checks dispatch to the
# existing nimcypher RSA/ECDSA/Ed25519 primitives. Out of scope for v1:
# CRL/OCSP, name constraints, policy mappings, non-Z timezones,
# explicit-curve parameters, DSA keys, SHA-1/MD5 signatures.
#
# SPDX-License-Identifier: BSD-2-Clause

import std/times

import nimcypher/algos/bigint_ext as bigintExt
import nimcypher/algos/rsa as rsaAlgo
import nimcypher/algos/ecdsa as ecdsaAlgo
import nimcypher/sign as edsa

import ./asn1
import ./codec

type
  CertSigAlg* = enum
    saRsaPkcs1Sha256
    saRsaPkcs1Sha384
    saRsaPkcs1Sha512
    saRsaPssSha256
    saRsaPssSha384
    saRsaPssSha512
    saEcdsaSha256
    saEcdsaSha384
    saEcdsaSha512
    saEd25519

  SpkiKind* = enum
    skRsa
    skEc
    skEd25519

  PublicKeyInfo* = object
    case kind*: SpkiKind
    of skRsa:
      nBytes*, eBytes*: seq[byte]
    of skEc:
      curve*: ecdsaAlgo.EcCurve
      point*: seq[byte]
    of skEd25519:
      edKey*: array[32, byte]

  TbsCertificate* = object
    raw*: seq[byte]
    version*: int
    serial*: seq[byte]
    sigAlg*: CertSigAlg
    issuerDer*: seq[byte]
    issuerCn*: string
    notBefore*, notAfter*: int64
    subjectDer*: seq[byte]
    subjectCn*: string
    spki*: PublicKeyInfo
    isCa*: bool
    pathLen*: int  # -1 when absent
    keyUsage*: uint16
    hasKeyUsage*: bool
    sanDns*: seq[string]
    hasEku*: bool
    ekuServerAuth*: bool

  Certificate* = object
    tbs*: TbsCertificate
    sigAlg*: CertSigAlg
    signature*: seq[byte]

const
  OidRsaEncryption = "1.2.840.113549.1.1.1"
  OidSha256Rsa = "1.2.840.113549.1.1.11"
  OidSha384Rsa = "1.2.840.113549.1.1.12"
  OidSha512Rsa = "1.2.840.113549.1.1.13"
  OidRsaSsaPss = "1.2.840.113549.1.1.10"
  OidEcdsaSha256 = "1.2.840.10045.4.3.2"
  OidEcdsaSha384 = "1.2.840.10045.4.3.3"
  OidEcdsaSha512 = "1.2.840.10045.4.3.4"
  OidEd25519 = "1.3.101.112"
  OidEcPublicKey = "1.2.840.10045.2.1"
  OidP256 = "1.2.840.10045.3.1.7"
  OidP384 = "1.3.132.0.34"
  OidP521 = "1.3.132.0.35"
  OidBasicConstraints = "2.5.29.19"
  OidKeyUsage = "2.5.29.15"
  OidSubjectAltName = "2.5.29.17"
  OidExtKeyUsage = "2.5.29.37"
  OidServerAuth = "1.3.6.1.5.5.7.3.1"
  OidCommonName = "2.5.4.3"
  OidSha256 = "2.16.840.1.101.3.4.2.1"
  OidSha384 = "2.16.840.1.101.3.4.2.2"
  OidSha512 = "2.16.840.1.101.3.4.2.3"
  OidMgf1 = "1.2.840.113549.1.1.8"

func rsaHashOf*(alg: CertSigAlg): rsaAlgo.RsaHash =
  case alg
  of saRsaPkcs1Sha256, saRsaPssSha256: rsaAlgo.rhSha256
  of saRsaPkcs1Sha384, saRsaPssSha384: rsaAlgo.rhSha384
  of saRsaPkcs1Sha512, saRsaPssSha512: rsaAlgo.rhSha512
  else: raise newException(ValueError, "not an RSA signature algorithm")

func curveOfOid*(oid: string): ecdsaAlgo.EcCurve =
  case oid
  of OidP256: ecdsaAlgo.P256
  of OidP384: ecdsaAlgo.P384
  of OidP521: ecdsaAlgo.P521
  else: raise newException(ValueError, "unsupported EC curve " & oid)

func coordLenOf*(c: ecdsaAlgo.EcCurve): int =
  case c
  of ecdsaAlgo.P256: 32
  of ecdsaAlgo.P384: 48
  of ecdsaAlgo.P521: 66
  of ecdsaAlgo.Secp256k1: 32

# --- time ---

func daysFromCivil(y, m, d: int64): int64 =
  var y = y
  if m <= 2: y -= 1
  let era = (if y >= 0: y else: y - 399) div 400
  let yoe = y - era * 400
  let mp = (m + 9) mod 12
  let doy = (153 * mp + 2) div 5 + d - 1
  let doe = yoe * 365 + yoe div 4 - yoe div 100 + doy
  era * 146097 + doe - 719468

proc parseCertTime*(n: Asn1Node): int64 =
  var s = newString(n.content.len)
  for i, b in n.content: s[i] = char(b)
  var year, mon, day, hour, minu, sec: int64
  if n.tag == byte(ord(tUtcTime)):
    if s.len != 13 or s[^1] != 'Z':
      raise newException(ValueError, "bad UTCTime (want YYMMDDHHMMSSZ)")
    var yy = 0
    for c in s[0 ..< 2]: yy = yy * 10 + (ord(c) - ord('0'))
    year = if yy >= 50: 1900 + yy else: 2000 + yy
    mon = 0; for c in s[2 ..< 4]: mon = mon * 10 + (ord(c) - ord('0'))
    day = 0; for c in s[4 ..< 6]: day = day * 10 + (ord(c) - ord('0'))
    hour = 0; for c in s[6 ..< 8]: hour = hour * 10 + (ord(c) - ord('0'))
    minu = 0; for c in s[8 ..< 10]: minu = minu * 10 + (ord(c) - ord('0'))
    sec = 0; for c in s[10 ..< 12]: sec = sec * 10 + (ord(c) - ord('0'))
  elif n.tag == byte(ord(tGeneralizedTime)):
    if s.len != 15 or s[^1] != 'Z':
      raise newException(ValueError, "bad GeneralizedTime (want YYYYMMDDHHMMSSZ)")
    year = 0; for c in s[0 ..< 4]: year = year * 10 + (ord(c) - ord('0'))
    mon = 0; for c in s[4 ..< 6]: mon = mon * 10 + (ord(c) - ord('0'))
    day = 0; for c in s[6 ..< 8]: day = day * 10 + (ord(c) - ord('0'))
    hour = 0; for c in s[8 ..< 10]: hour = hour * 10 + (ord(c) - ord('0'))
    minu = 0; for c in s[10 ..< 12]: minu = minu * 10 + (ord(c) - ord('0'))
    sec = 0; for c in s[12 ..< 14]: sec = sec * 10 + (ord(c) - ord('0'))
  else:
    raise newException(ValueError, "certificate time must be UTCTime/GeneralizedTime")
  if mon < 1 or mon > 12 or day < 1 or day > 31 or hour > 23 or
      minu > 59 or sec > 60:
    raise newException(ValueError, "certificate time out of range")
  daysFromCivil(year, mon, day) * 86400 + hour * 3600 + minu * 60 + sec

# --- names ---

proc commonName*(nameDer: openArray[byte]): string =
  var r = initReader(nameDer)
  let top = r.readTlv()
  if top.tag != 0x30:
    raise newException(ValueError, "Name is not a SEQUENCE")
  for rdn in top.children:
    if rdn.tag != 0x31:
      raise newException(ValueError, "RDN is not a SET")
    for atv in rdn.children:
      let parts = atv.children
      if parts.len != 2: continue
      if oidToString(parts[0].asOid) == OidCommonName and
          isStringTag(parts[1].tag):
        result = newString(parts[1].content.len)
        for i, b in parts[1].content: result[i] = char(b)

# --- algorithm identifiers ---

proc parsePssHash*(params: Asn1Node): CertSigAlg =
  # RSASSA-PSS-params; requires MGF1 with the same hash, trailerField 1,
  # and saltLength == hashLen (what nimcypher's PSS verify enforces).
  var hashOid = ""
  var saltLen = -1
  for f in params.children:
    if not f.constructed or f.content.len == 0: continue
    let tagNo = f.tag and 0x1F
    var inner = initReader(f.content)
    let node = inner.readTlv()
    inner.expectEmpty()
    case tagNo
    of 0: # hashAlgorithm
      let seqKids = node.children
      if seqKids.len == 0:
        raise newException(ValueError, "PSS: bad hashAlgorithm")
      hashOid = oidToString(seqKids[0].asOid)
    of 1: # maskGenAlgorithm, must be MGF1(same hash)
      let seqKids = node.children
      if seqKids.len == 0 or oidToString(seqKids[0].asOid) != OidMgf1:
        raise newException(ValueError, "PSS: only MGF1 supported")
      if seqKids.len > 1:
        let mgfKids = seqKids[1].children
        if mgfKids.len == 0 or oidToString(mgfKids[0].asOid) != hashOid and
            hashOid != "":
          raise newException(ValueError, "PSS: MGF1 hash mismatch")
    of 2: # saltLength
      if node.tag != byte(ord(tInteger)):
        raise newException(ValueError, "PSS: bad saltLength")
      saltLen = 0
      for b in node.asIntegerBytes: saltLen = saltLen * 256 + int(b)
    of 3: # trailerField, must be 1
      if node.tag != byte(ord(tInteger)):
        raise newException(ValueError, "PSS: bad trailerField")
      var v = 0
      for b in node.asIntegerBytes: v = v * 256 + int(b)
      if v != 1:
        raise newException(ValueError, "PSS: trailerField must be 1")
    else: discard
  let hlen = case hashOid
    of OidSha256: 32
    of OidSha384: 48
    of OidSha512: 64
    else: raise newException(ValueError, "PSS: unsupported hash " & hashOid)
  if saltLen != -1 and saltLen != hlen:
    raise newException(ValueError, "PSS: saltLength must equal hashLen")
  case hashOid
  of OidSha256: saRsaPssSha256
  of OidSha384: saRsaPssSha384
  else: saRsaPssSha512

proc parseSigAlg*(ai: Asn1Node): CertSigAlg =
  let kids = ai.children
  if kids.len == 0 or kids.len > 2:
    raise newException(ValueError, "bad AlgorithmIdentifier")
  let oid = oidToString(kids[0].asOid)
  case oid
  of OidSha256Rsa: saRsaPkcs1Sha256
  of OidSha384Rsa: saRsaPkcs1Sha384
  of OidSha512Rsa: saRsaPkcs1Sha512
  of OidEcdsaSha256: saEcdsaSha256
  of OidEcdsaSha384: saEcdsaSha384
  of OidEcdsaSha512: saEcdsaSha512
  of OidEd25519: saEd25519
  of OidRsaSsaPss:
    if kids.len != 2:
      raise newException(ValueError, "PSS params missing")
    parsePssHash(kids[1])
  else: raise newException(ValueError, "unsupported signature algorithm " & oid)

# --- subject public keys ---

proc parseSpki*(n: Asn1Node): PublicKeyInfo =
  let kids = n.children
  if kids.len != 2:
    raise newException(ValueError, "bad SubjectPublicKeyInfo")
  let aiKids = kids[0].children
  if aiKids.len == 0 or aiKids.len > 2:
    raise newException(ValueError, "bad SPKI algorithm")
  let oid = oidToString(aiKids[0].asOid)
  let (keyBytes, _) = kids[1].asBitString()
  case oid
  of OidRsaEncryption:
    var kr = initReader(keyBytes)
    let seq = kr.readTlv()
    seq.expectTag(0x30, "RSAPublicKey")
    kr.expectEmpty()
    let parts = seq.children
    if parts.len != 2:
      raise newException(ValueError, "bad RSAPublicKey")
    result = PublicKeyInfo(kind: skRsa, nBytes: parts[0].asIntegerBytes,
                           eBytes: parts[1].asIntegerBytes)
  of OidEcPublicKey:
    if aiKids.len != 2:
      raise newException(ValueError, "EC params missing")
    let curve = curveOfOid(oidToString(aiKids[1].asOid))
    if keyBytes.len != 1 + 2 * coordLenOf(curve) or keyBytes[0] != 0x04:
      raise newException(ValueError, "only uncompressed EC points supported")
    result = PublicKeyInfo(kind: skEc, curve: curve, point: keyBytes)
  of OidEd25519:
    if keyBytes.len != 32:
      raise newException(ValueError, "bad Ed25519 key")
    var k: array[32, byte]
    for i in 0 ..< 32: k[i] = keyBytes[i]
    result = PublicKeyInfo(kind: skEd25519, edKey: k)
  else: raise newException(ValueError, "unsupported public key algorithm " & oid)

# --- extensions ---

proc parseExtensions*(extDer: openArray[byte], tbs: var TbsCertificate) =
  var r = initReader(extDer)
  let outer = r.readTlv()
  r.expectEmpty()
  if outer.tag != 0x30:
    raise newException(ValueError, "extensions is not a SEQUENCE")
  for ext in outer.children:
    let parts = ext.children
    if parts.len < 2 or parts.len > 3:
      raise newException(ValueError, "bad Extension")
    let oid = oidToString(parts[0].asOid)
    let valueNode = parts[^1]
    if valueNode.tag != byte(ord(tOctetString)):
      raise newException(ValueError, "Extension value is not OCTET STRING")
    let inner = valueNode.asOctetString()
    case oid
    of OidBasicConstraints:
      var ir = initReader(inner)
      let seq = ir.readTlv()
      seq.expectTag(0x30, "BasicConstraints")
      ir.expectEmpty()
      for f in seq.children:
        if f.tag == 0x01:
          if f.content.len != 1:
            raise newException(ValueError, "bad cA boolean")
          tbs.isCa = f.content[0] != 0
        elif f.tag == byte(ord(tInteger)):
          var v = 0
          for b in f.asIntegerBytes: v = v * 256 + int(b)
          tbs.pathLen = v
    of OidKeyUsage:
      var ir = initReader(inner)
      let bs = ir.readTlv()
      ir.expectEmpty()
      if bs.tag != byte(ord(tBitString)) or bs.content.len < 1 or
          bs.content.len > 3:
        raise newException(ValueError, "bad KeyUsage")
      let unused = int(bs.content[0])
      var bits: uint16 = 0
      for i in 1 ..< bs.content.len:
        for bit in 0 ..< 8:
          if (bs.content[i] and byte(0x80 shr bit)) != 0:
            let pos = (i - 1) * 8 + bit
            if pos < 16:
              bits = bits or (uint16(1) shl (15 - pos))
      tbs.keyUsage = bits
      tbs.hasKeyUsage = true
      discard unused
    of OidSubjectAltName:
      var ir = initReader(inner)
      let seq = ir.readTlv()
      seq.expectTag(0x30, "SubjectAltName")
      ir.expectEmpty()
      for gn in seq.children:
        if gn.tag == 0x82: # dNSName IA5String
          var s = newString(gn.content.len)
          for i, b in gn.content: s[i] = char(b)
          tbs.sanDns.add(s)
    of OidExtKeyUsage:
      var ir = initReader(inner)
      let seq = ir.readTlv()
      seq.expectTag(0x30, "ExtKeyUsage")
      ir.expectEmpty()
      tbs.hasEku = true
      for eku in seq.children:
        if oidToString(eku.asOid) == OidServerAuth:
          tbs.ekuServerAuth = true
    else: discard # ignore unknown extensions

# --- top level ---

proc parseTbs*(tbsNode: Asn1Node, raw: seq[byte]): TbsCertificate =
  result = TbsCertificate(pathLen: -1)
  result.raw = raw
  let f = tbsNode.children
  if f.len < 6:
    raise newException(ValueError, "TBSCertificate too short")
  var i = 0
  if f[0].tag == 0xA0: # version [0] EXPLICIT
    var vr = initReader(f[0].content)
    let v = vr.readTlv()
    vr.expectEmpty()
    if v.tag != byte(ord(tInteger)) or v.content.len != 1:
      raise newException(ValueError, "bad version")
    result.version = int(v.content[0]) + 1
    i = 1
  else:
    result.version = 1
  if f.len < i + 6:
    raise newException(ValueError, "TBSCertificate too short")
  result.serial = f[i].asIntegerBytes; inc i
  result.sigAlg = parseSigAlg(f[i]); inc i
  result.issuerDer = encodeTlv(f[i].tag, f[i].content)
  result.issuerCn = commonName(result.issuerDer); inc i
  let validity = f[i].children; inc i
  if validity.len != 2:
    raise newException(ValueError, "bad Validity")
  result.notBefore = parseCertTime(validity[0])
  result.notAfter = parseCertTime(validity[1])
  result.subjectDer = encodeTlv(f[i].tag, f[i].content)
  result.subjectCn = commonName(result.subjectDer); inc i
  result.spki = parseSpki(f[i]); inc i
  # Optional [1] issuerUniqueID / [2] subjectUniqueID are rejected (v1);
  # extensions [3] EXPLICIT come last when present.
  for j in i ..< f.len:
    if f[j].tag == 0xA3:
      parseExtensions(f[j].content, result)
    elif f[j].tag in [0xA1'u8, 0xA2'u8]:
      raise newException(ValueError, "unique identifiers unsupported")
    else:
      raise newException(ValueError, "unexpected TBSCertificate field")

proc parseCertificate*(der: openArray[byte]): Certificate =
  var r = initReader(der)
  let top = r.readTlv()
  r.expectEmpty()
  top.expectTag(0x30, "Certificate")
  let f = top.children
  if f.len != 3:
    raise newException(ValueError, "Certificate must have 3 fields")
  let tbsRaw = encodeTlv(f[0].tag, f[0].content)
  if f[0].tag != 0x30:
    raise newException(ValueError, "tbsCertificate is not a SEQUENCE")
  result.tbs = parseTbs(f[0], tbsRaw)
  result.sigAlg = parseSigAlg(f[1])
  let (sigBytes, unused) = f[2].asBitString()
  if unused != 0:
    raise newException(ValueError, "signature BIT STRING has padding")
  result.signature = sigBytes

# --- signature verification ---

proc rsaPubKey*(info: PublicKeyInfo): rsaAlgo.RsaPublicKey =
  if info.kind != skRsa:
    raise newException(ValueError, "not an RSA key")
  let n = bigintExt.fromBytesBE(info.nBytes)
  let e = bigintExt.fromBytesBE(info.eBytes)
  rsaAlgo.RsaPublicKey(n: n, e: e, k: bigintExt.byteLen(n))

proc ecPubKey*(info: PublicKeyInfo): ecdsaAlgo.EcPublicKey =
  if info.kind != skEc:
    raise newException(ValueError, "not an EC key")
  let coordLen = coordLenOf(info.curve)
  let x = bigintExt.fromBytesBE(info.point.toOpenArray(1, coordLen))
  let y = bigintExt.fromBytesBE(
    info.point.toOpenArray(1 + coordLen, 1 + 2 * coordLen - 1))
  ecdsaAlgo.EcPublicKey(curve: info.curve, x: x, y: y)

proc rawToDerEcdsaSig*(raw: openArray[byte], coordLen: int): seq[byte] =
  ## Encode R||S as DER SEQUENCE { INTEGER r, INTEGER s } (minimal form).
  if raw.len != 2 * coordLen:
    raise newException(ValueError, "bad raw ECDSA signature length")
  var body: seq[byte]
  for k in 0 ..< 2:
    let seg = @(raw.toOpenArray(k * coordLen, (k + 1) * coordLen - 1))
    var start = 0
    while start < seg.len and seg[start] == 0: inc start
    var mag: seq[byte]
    if start < seg.len:
      for b in seg.toOpenArray(start, seg.high): mag.add(b)
    else:
      mag = @[byte 0]
    var enc: seq[byte]
    if (mag[0] and 0x80) != 0: enc.add(byte 0)
    for b in mag: enc.add(b)
    body.add(encodeTlv(byte(ord(tInteger)), enc))
  encodeTlv(0x30, body)

proc derToRawEcdsaSig*(der: openArray[byte], coordLen: int): seq[byte] =
  var r = initReader(der)
  let seq = r.readTlv()
  r.expectEmpty()
  seq.expectTag(0x30, "ECDSA-Sig-Value")
  let parts = seq.children
  if parts.len != 2:
    raise newException(ValueError, "bad ECDSA-Sig-Value")
  result = newSeq[byte](2 * coordLen)
  for k in 0 ..< 2:
    let v = parts[k].asIntegerBytes
    if v.len > coordLen:
      raise newException(ValueError, "ECDSA r/s too large")
    for i in 0 ..< v.len:
      result[k * coordLen + (coordLen - v.len) + i] = v[i]

proc verifyCertSignature*(cert: Certificate,
                          issuerKey: PublicKeyInfo): bool =
  ## Verify `cert`'s signature with the issuer's public key. The outer
  ## signatureAlgorithm must agree with the TBSCertificate's (RFC 5280).
  if cert.sigAlg != cert.tbs.sigAlg:
    return false
  case cert.sigAlg
  of saRsaPkcs1Sha256, saRsaPkcs1Sha384, saRsaPkcs1Sha512:
    if issuerKey.kind != skRsa: return false
    rsaAlgo.pkcs1v15Verify(rsaPubKey(issuerKey), rsaHashOf(cert.sigAlg),
                           cert.tbs.raw, cert.signature)
  of saRsaPssSha256, saRsaPssSha384, saRsaPssSha512:
    if issuerKey.kind != skRsa: return false
    rsaAlgo.pssVerify(rsaPubKey(issuerKey), rsaHashOf(cert.sigAlg),
                       cert.tbs.raw, cert.signature)
  of saEcdsaSha256, saEcdsaSha384, saEcdsaSha512:
    if issuerKey.kind != skEc: return false
    let curve = issuerKey.curve
    # Standard pairings only (RFC 5480 / JWS).
    if (cert.sigAlg == saEcdsaSha256 and curve != ecdsaAlgo.P256) or
        (cert.sigAlg == saEcdsaSha384 and curve != ecdsaAlgo.P384) or
        (cert.sigAlg == saEcdsaSha512 and curve != ecdsaAlgo.P521):
      return false
    let raw =
      try: derToRawEcdsaSig(cert.signature, coordLenOf(curve))
      except ValueError: return false
    ecdsaAlgo.verify(ecPubKey(issuerKey), cert.tbs.raw, raw)
  of saEd25519:
    if issuerKey.kind != skEd25519: return false
    if cert.signature.len != 64: return false
    var sig: array[64, byte]
    for i in 0 ..< 64: sig[i] = cert.signature[i]
    edsa.verify(issuerKey.edKey, cert.tbs.raw, sig)
