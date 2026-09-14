# Live OpenSSL interop tests: nimcypher vs the system `openssl` CLI.
#
# Each case runs in both directions (nimcypher output checked by openssl and
# vice versa) over keys generated fresh by openssl at test time. This
# complements the checked-in static vectors in `trsa`/`tecdsa` and the live
# C-Monocypher FFI suite in `tinterop`.
#
# Requires the `openssl` binary on PATH. If it is missing the suite prints a
# note and passes trivially, unless `NIMCYPHER_REQUIRE_OPENSSL=1` is set (as
# done in CI), in which case it fails loudly.
#
# Notes on coverage:
# - AES-GCM is intentionally absent: `openssl enc` rejects AEAD ciphers and
#   GCM is already pinned by NIST vectors in `tgcm`.
# - RSA/ECDSA keys come from openssl; parsing uses the stable `-text` output
#   (colon-separated hex blocks), avoiding any DER/PEM parsing.
# - ChaCha20 uses `openssl enc -chacha20` with a 128-bit IV laid out as
#   LE-u32 block counter || 96-bit nonce (verified against RFC 8439 vectors
#   during development); the test pins counter = 0.

import std/os
import std/osproc
import std/streams
import std/strutils
import std/unittest

import bigints
import nimcypher/utils
import nimcypher/algos/bigint_ext
import nimcypher/algos/rsa as rsaAlgo
import nimcypher/algos/ecdsa as ecdsaAlgo
import nimcypher/algos/aes
import nimcypher/algos/sha1 as sha1Algo
import nimcypher/algos/sha256 as sha256Algo
import nimcypher/algos/sha384 as sha384Algo
import nimcypher/algos/sha512 as sha512Algo
import nimcypher/hashes/md5 as md5Algo
import nimcypher/algos/chacha20
import nimcypher/algos/x25519
import nimcypher/algos/ed25519

proc hexToBytes(s: string): seq[byte] =
  doAssert s.len mod 2 == 0
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

let requireOssl = getEnv("NIMCYPHER_REQUIRE_OPENSSL") == "1"
let osslBin = findExe("openssl")

if osslBin == "":
  if requireOssl:
    raise newException(OSError,
      "openssl not found on PATH but NIMCYPHER_REQUIRE_OPENSSL=1")
  echo "SKIP topenssl: openssl binary not found on PATH"

var workDir = ""
if osslBin != "":
  workDir = getTempDir() / ("nimcypher-ossl-" & $getCurrentProcessId())
  createDir(workDir)

proc wp(name: string): string = workDir / name

proc osslOut(args: varargs[string]): string =
  ## Run `openssl`, return stdout, raising on nonzero exit.
  let p = startProcess(osslBin, args = @args,
                       options = {poUsePath, poStdErrToStdOut})
  result = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    raise newException(OSError,
      "openssl " & (@args).join(" ") & " failed (" & $code & "): " & result)

proc ossl(args: varargs[string]) =
  ## Run `openssl`, discarding stdout, raising on nonzero exit.
  discard osslOut(args)

proc writeBin(name: string, data: openArray[byte]) =
  var s = newString(data.len)
  for i in 0 ..< data.len: s[i] = char(data[i])
  writeFile(wp(name), s)

proc writeBin(name: string, data: string) = writeFile(wp(name), data)

proc readBin(name: string): seq[byte] =
  let s = readFile(wp(name))
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len: result[i] = byte(s[i])

proc toHexBytes(data: openArray[byte]): string =
  const digits = "0123456789abcdef"
  result = newStringOfCap(data.len * 2)
  for b in data:
    result.add(digits[int(b) shr 4])
    result.add(digits[int(b) and 15])

proc sameBytes(a, b: openArray[byte]): bool =
  if a.len != b.len: return false
  for i in 0 ..< a.len:
    if a[i] != b[i]: return false
  true

proc parseColonHex(lines: seq[string], start: int): (seq[byte], int) =
  ## Collect `aa:bb:...` lines from `start`; returns (bytes, firstUnusedIdx).
  var hex = ""
  var i = start
  while i < lines.len:
    let t = lines[i].strip()
    if t.len == 0:
      inc i
      continue
    var ok = t.len > 0
    for c in t:
      if c notin {'0' .. '9', 'a' .. 'f', 'A' .. 'F', ':', ' '}:
        ok = false
        break
    if not ok or ':' notin t:
      break
    for c in t:
      if c != ':' and c != ' ': hex.add(c)
    inc i
  (hexToBytes(hex), i)

proc textBlocks(textOut: string): seq[(string, seq[byte])] =
  ## Split `openssl ... -text` output into (label, bytes) blocks.
  let lines = textOut.splitLines()
  var i = 0
  while i < lines.len:
    let t = lines[i].strip()
    if t.endsWith(":") and
        t[0 ..< ^1].allCharsInSet({'a' .. 'z', 'A' .. 'Z', '0' .. '9', '-', '_', ' '}):
      let label = t[0 ..< ^1].strip()
      if label in ["modulus", "privateExponent", "prime1", "prime2",
                   "priv", "pub"]:
        let (bytes, next) = parseColonHex(lines, i + 1)
        result.add((label, bytes))
        i = next
        continue
    inc i

proc textField(textOut, label: string): seq[byte] =
  for (l, b) in textBlocks(textOut):
    if l == label: return b
  raise newException(ValueError, "label not found in openssl -text: " & label)

proc textInt(textOut, label: string): int =
  ## Parse e.g. "publicExponent: 65537 (0x10001)".
  for line in textOut.splitLines():
    let t = line.strip()
    if t.startsWith(label & ":"):
      return parseInt(t[label.len + 1 .. ^1].strip().split(' ')[0])
  raise newException(ValueError, "int label not found: " & label)

# DER helpers for ECDSA signatures (openssl dgst speaks DER, we speak R||S).

proc derLen(n: int): seq[byte] =
  if n < 128: @[byte(n)]
  elif n < 256: @[byte(0x81), byte(n)]
  else: @[byte(0x82), byte(n shr 8), byte(n and 0xFF)]

proc derInt(x: openArray[byte]): seq[byte] =
  var i = 0
  while i < x.len - 1 and x[i] == 0: inc i
  var body = @(x.toOpenArray(i, x.len - 1))
  if (body[0] and 0x80) != 0:
    body.insert(byte(0), 0)
  result = @[byte(0x02)] & derLen(body.len) & body

proc ecSigToDer(sig: openArray[byte], coordLen: int): seq[byte] =
  doAssert sig.len == 2 * coordLen
  let body = derInt(sig.toOpenArray(0, coordLen - 1)) &
             derInt(sig.toOpenArray(coordLen, sig.len - 1))
  @[byte(0x30)] & derLen(body.len) & body

proc readDerLen(d: openArray[byte], pos: var int): int =
  let b0 = int(d[pos]); inc pos
  if (b0 and 0x80) == 0: return b0
  let n = b0 and 0x7F
  doAssert n in {1, 2}
  result = 0
  for _ in 0 ..< n:
    result = (result shl 8) or int(d[pos]); inc pos

proc derToEcSig(der: openArray[byte], coordLen: int): seq[byte] =
  var pos = 0
  doAssert der[pos] == 0x30; inc pos
  discard readDerLen(der, pos)
  result = newSeq[byte](2 * coordLen)
  for half in 0 ..< 2:
    doAssert der[pos] == 0x02; inc pos
    let ln = readDerLen(der, pos)
    var v = @(der.toOpenArray(pos, pos + ln - 1)); pos += ln
    while v.len > 0 and v[0] == 0: v.delete(0)
    doAssert v.len <= coordLen
    let off = half * coordLen + (coordLen - v.len)
    for i in 0 ..< v.len: result[off + i] = v[i]

# ---------------------------------------------------------------------------
# Suites (only registered when openssl exists)
# ---------------------------------------------------------------------------

const interopMsg = "nimcypher openssl interop message"

proc rsaKeyFromPem(pemName: string): (RsaPrivateKey, RsaPublicKey) =
  let t = osslOut("rsa", "-in", wp(pemName), "-noout", "-text")
  let priv = rsaAlgo.rsaPrivateKey(fromBytesBE(textField(t, "modulus")),
    initBigInt(textInt(t, "publicExponent")),
    fromBytesBE(textField(t, "privateExponent")),
    fromBytesBE(textField(t, "prime1")),
    fromBytesBE(textField(t, "prime2")))
  (priv, rsaAlgo.publicKey(priv))

proc ecKeyFromPem(pemName: string, curve: EcCurve,
                  coordLen: int): (EcPrivateKey, EcPublicKey) =
  let t = osslOut("ec", "-in", wp(pemName), "-noout", "-text")
  let point = textField(t, "pub")
  doAssert point.len == 1 + 2 * coordLen and point[0] == 0x04
  let priv = EcPrivateKey(curve: curve, d: fromBytesBE(textField(t, "priv")))
  let pub = EcPublicKey(curve: curve,
    x: fromBytesBE(point.toOpenArray(1, coordLen)),
    y: fromBytesBE(point.toOpenArray(coordLen + 1, 2 * coordLen)))
  (priv, pub)

proc rawKeyOf(pemName: string, label: string): array[32, byte] =
  let b = textField(osslOut("pkey", "-in", wp(pemName), "-noout", "-text"),
                    label)
  doAssert b.len == 32
  toArray[32](b)

if osslBin != "":

  suite "openssl RSA PKCS#1 v1.5":
    var priv: RsaPrivateKey
    var pub: RsaPublicKey

    setup:
      ossl("genrsa", "-out", wp("rsa.pem"), "1024")
      ossl("rsa", "-in", wp("rsa.pem"), "-pubout", "-out", wp("rsa_pub.pem"))
      (priv, pub) = rsaKeyFromPem("rsa.pem")

    test "openssl signs, nimcypher verifies":
      writeBin("msg.bin", interopMsg)
      ossl("dgst", "-sha256", "-sign", wp("rsa.pem"),
           "-out", wp("v15_ossl.sig"), wp("msg.bin"))
      let sig = readBin("v15_ossl.sig")
      check sig.len == priv.k
      check rsaAlgo.pkcs1v15Verify(pub, rhSha256, toBytes(interopMsg), sig)
      var bad = sig
      bad[10] = bad[10] xor 1
      check not rsaAlgo.pkcs1v15Verify(pub, rhSha256, toBytes(interopMsg), bad)

    test "nimcypher signs, openssl verifies":
      writeBin("msg.bin", interopMsg)
      let sig = rsaAlgo.pkcs1v15Sign(priv, rhSha256, toBytes(interopMsg))
      writeBin("v15_nim.sig", sig)
      ossl("dgst", "-sha256", "-verify", wp("rsa_pub.pem"),
           "-signature", wp("v15_nim.sig"), wp("msg.bin"))

  suite "openssl RSA PSS":
    var priv: RsaPrivateKey
    var pub: RsaPublicKey

    setup:
      ossl("genrsa", "-out", wp("rsaP.pem"), "1024")
      ossl("rsa", "-in", wp("rsaP.pem"), "-pubout", "-out", wp("rsaP_pub.pem"))
      (priv, pub) = rsaKeyFromPem("rsaP.pem")

    test "openssl signs digest, nimcypher verifies message":
      # pkeyutl signs a pre-hashed digest; saltLen = hashLen per JWA.
      let digest = sha256Algo.sha256(toBytes(interopMsg))
      writeBin("dig.bin", digest)
      ossl("pkeyutl", "-sign", "-inkey", wp("rsaP.pem"),
           "-pkeyopt", "digest:sha256",
           "-pkeyopt", "rsa_padding_mode:pss",
           "-pkeyopt", "rsa_pss_saltlen:32",
           "-pkeyopt", "rsa_mgf1_md:sha256",
           "-in", wp("dig.bin"), "-out", wp("pss_ossl.sig"))
      let sig = readBin("pss_ossl.sig")
      check rsaAlgo.pssVerify(pub, rhSha256, toBytes(interopMsg), sig)

    test "nimcypher signs, openssl verifies digest":
      let sig = rsaAlgo.pssSign(priv, rhSha256, toBytes(interopMsg))
      let digest = sha256Algo.sha256(toBytes(interopMsg))
      writeBin("dig2.bin", digest)
      writeBin("pss_nim.sig", sig)
      ossl("pkeyutl", "-verify", "-pubin", "-inkey", wp("rsaP_pub.pem"),
           "-pkeyopt", "digest:sha256",
           "-pkeyopt", "rsa_padding_mode:pss",
           "-pkeyopt", "rsa_pss_saltlen:32",
           "-pkeyopt", "rsa_mgf1_md:sha256",
           "-in", wp("dig2.bin"), "-sigfile", wp("pss_nim.sig"))

  suite "openssl RSA OAEP":
    var priv: RsaPrivateKey
    var pub: RsaPublicKey

    setup:
      ossl("genrsa", "-out", wp("rsaO.pem"), "1024")
      ossl("rsa", "-in", wp("rsaO.pem"), "-pubout", "-out", wp("rsaO_pub.pem"))
      (priv, pub) = rsaKeyFromPem("rsaO.pem")

    test "openssl encrypts, nimcypher decrypts":
      writeBin("pt.bin", interopMsg)
      ossl("pkeyutl", "-encrypt", "-pubin", "-inkey", wp("rsaO_pub.pem"),
           "-pkeyopt", "rsa_padding_mode:oaep",
           "-pkeyopt", "rsa_oaep_md:sha256",
           "-pkeyopt", "rsa_mgf1_md:sha256",
           "-in", wp("pt.bin"), "-out", wp("oaep_ossl.bin"))
      let pt = rsaAlgo.oaepDecrypt(priv, rhSha256, readBin("oaep_ossl.bin"))
      check sameBytes(pt, toBytes(interopMsg))

    test "nimcypher encrypts, openssl decrypts":
      let ct = rsaAlgo.oaepEncrypt(pub, rhSha256, toBytes(interopMsg))
      writeBin("oaep_nim.bin", ct)
      ossl("pkeyutl", "-decrypt", "-inkey", wp("rsaO.pem"),
           "-pkeyopt", "rsa_padding_mode:oaep",
           "-pkeyopt", "rsa_oaep_md:sha256",
           "-pkeyopt", "rsa_mgf1_md:sha256",
           "-in", wp("oaep_nim.bin"), "-out", wp("oaep_rt.bin"))
      check sameBytes(readBin("oaep_rt.bin"), toBytes(interopMsg))

  suite "openssl ECDSA":
    test "P-256 / SHA-256 roundtrip":
      ossl("ecparam", "-name", "prime256v1", "-genkey", "-noout",
           "-out", wp("ec256.pem"))
      ossl("ec", "-in", wp("ec256.pem"), "-pubout", "-out", wp("ec256_pub.pem"))
      let (priv, pub) = ecKeyFromPem("ec256.pem", P256, 32)
      check ecdsaAlgo.validatePublicKey(pub)
      writeBin("msg.bin", interopMsg)
      # openssl -> nim
      ossl("dgst", "-sha256", "-sign", wp("ec256.pem"),
           "-out", wp("ec256_ossl.sig"), wp("msg.bin"))
      let rawOssl = derToEcSig(readBin("ec256_ossl.sig"), 32)
      check ecdsaAlgo.verify(pub, toBytes(interopMsg), rawOssl)
      # nim -> openssl
      let rawNim = ecdsaAlgo.sign(priv, toBytes(interopMsg))
      check rawNim.len == 64
      writeBin("ec256_nim.sig", ecSigToDer(rawNim, 32))
      ossl("dgst", "-sha256", "-verify", wp("ec256_pub.pem"),
           "-signature", wp("ec256_nim.sig"), wp("msg.bin"))

    test "P-384 / SHA-384 roundtrip":
      ossl("ecparam", "-name", "secp384r1", "-genkey", "-noout",
           "-out", wp("ec384.pem"))
      ossl("ec", "-in", wp("ec384.pem"), "-pubout", "-out", wp("ec384_pub.pem"))
      let (priv, pub) = ecKeyFromPem("ec384.pem", P384, 48)
      check ecdsaAlgo.validatePublicKey(pub)
      writeBin("msg.bin", interopMsg)
      ossl("dgst", "-sha384", "-sign", wp("ec384.pem"),
           "-out", wp("ec384_ossl.sig"), wp("msg.bin"))
      check ecdsaAlgo.verify(pub, toBytes(interopMsg),
                             derToEcSig(readBin("ec384_ossl.sig"), 48))
      let rawNim = ecdsaAlgo.sign(priv, toBytes(interopMsg))
      writeBin("ec384_nim.sig", ecSigToDer(rawNim, 48))
      ossl("dgst", "-sha384", "-verify", wp("ec384_pub.pem"),
           "-signature", wp("ec384_nim.sig"), wp("msg.bin"))

    test "secp256k1 / SHA-256 roundtrip":
      ossl("ecparam", "-name", "secp256k1", "-genkey", "-noout",
           "-out", wp("eck.pem"))
      ossl("ec", "-in", wp("eck.pem"), "-pubout", "-out", wp("eck_pub.pem"))
      let (priv, pub) = ecKeyFromPem("eck.pem", Secp256k1, 32)
      check ecdsaAlgo.validatePublicKey(pub)
      writeBin("msg.bin", interopMsg)
      ossl("dgst", "-sha256", "-sign", wp("eck.pem"),
           "-out", wp("eck_ossl.sig"), wp("msg.bin"))
      check ecdsaAlgo.verify(pub, toBytes(interopMsg),
                             derToEcSig(readBin("eck_ossl.sig"), 32))
      let rawNim = ecdsaAlgo.sign(priv, toBytes(interopMsg))
      writeBin("eck_nim.sig", ecSigToDer(rawNim, 32))
      ossl("dgst", "-sha256", "-verify", wp("eck_pub.pem"),
           "-signature", wp("eck_nim.sig"), wp("msg.bin"))

  suite "openssl AES":
    const key128 = "2b7e151628aed2a6abf7158809cf4f3c"
    const key256 = key128 & "2b7e151628aed2a6abf7158809cf4f3c"
    const ivHex = "000102030405060708090a0b0c0d0e0f"
    const ptHex = "6bc1bee22e409f96e93d7e117393172a" &
                  "ae2d8a571e03ac9c9eb76fac45af8e51" &
                  "30c81c46a35ce411e5fbc1191a0a52ef" &
                  "f69f2445df4f9b17ad2b417be66c3710"

    test "AES-128-CBC both directions":
      let pt = hexToBytes(ptHex)
      writeBin("aes_pt.bin", pt)
      ossl("enc", "-e", "-aes-128-cbc", "-nopad", "-K", key128, "-iv", ivHex,
           "-in", wp("aes_pt.bin"), "-out", wp("aes_cbc_ossl.bin"))
      let ctx = initAes(hexToBytes(key128))
      check sameBytes(cbcDecryptOne(ctx, toArray[16](hexToBytes(ivHex)),
                                    readBin("aes_cbc_ossl.bin")), pt)
      let ctNim = cbcEncryptOne(ctx, toArray[16](hexToBytes(ivHex)), pt)
      writeBin("aes_cbc_nim.bin", ctNim)
      ossl("enc", "-d", "-aes-128-cbc", "-nopad", "-K", key128, "-iv", ivHex,
           "-in", wp("aes_cbc_nim.bin"), "-out", wp("aes_cbc_rt.bin"))
      check sameBytes(readBin("aes_cbc_rt.bin"), pt)

    test "AES-256-CBC both directions":
      let pt = hexToBytes(ptHex)
      writeBin("aes_pt.bin", pt)
      ossl("enc", "-e", "-aes-256-cbc", "-nopad", "-K", key256, "-iv", ivHex,
           "-in", wp("aes_pt.bin"), "-out", wp("aes256_ossl.bin"))
      let ctx = initAes(hexToBytes(key256))
      check sameBytes(cbcDecryptOne(ctx, toArray[16](hexToBytes(ivHex)),
                                    readBin("aes256_ossl.bin")), pt)
      writeBin("aes256_nim.bin",
               cbcEncryptOne(ctx, toArray[16](hexToBytes(ivHex)), pt))
      ossl("enc", "-d", "-aes-256-cbc", "-nopad", "-K", key256, "-iv", ivHex,
           "-in", wp("aes256_nim.bin"), "-out", wp("aes256_rt.bin"))
      check sameBytes(readBin("aes256_rt.bin"), pt)

    test "AES-128-CTR both directions":
      let pt = hexToBytes(ptHex)
      writeBin("aes_pt.bin", pt)
      ossl("enc", "-e", "-aes-128-ctr", "-nopad", "-K", key128, "-iv", ivHex,
           "-in", wp("aes_pt.bin"), "-out", wp("aes_ctr_ossl.bin"))
      let ctx = initAes(hexToBytes(key128))
      check sameBytes(ctrCryptOne(ctx, toArray[16](hexToBytes(ivHex)),
                                  readBin("aes_ctr_ossl.bin")), pt)
      writeBin("aes_ctr_nim.bin",
               ctrCryptOne(ctx, toArray[16](hexToBytes(ivHex)), pt))
      ossl("enc", "-d", "-aes-128-ctr", "-nopad", "-K", key128, "-iv", ivHex,
           "-in", wp("aes_ctr_nim.bin"), "-out", wp("aes_ctr_rt.bin"))
      check sameBytes(readBin("aes_ctr_rt.bin"), pt)

    test "AES-128-ECB both directions":
      let pt = hexToBytes(ptHex)
      writeBin("aes_pt.bin", pt)
      ossl("enc", "-e", "-aes-128-ecb", "-nopad", "-K", key128,
           "-in", wp("aes_pt.bin"), "-out", wp("aes_ecb_ossl.bin"))
      let ctx = initAes(hexToBytes(key128))
      check sameBytes(ecbDecrypt(ctx, readBin("aes_ecb_ossl.bin")), pt)
      writeBin("aes_ecb_nim.bin", ecbEncrypt(ctx, pt))
      ossl("enc", "-d", "-aes-128-ecb", "-nopad", "-K", key128,
           "-in", wp("aes_ecb_nim.bin"), "-out", wp("aes_ecb_rt.bin"))
      check sameBytes(readBin("aes_ecb_rt.bin"), pt)

  suite "openssl digests":
    test "SHA-1/256/384/512 match":
      writeBin("msg.bin", interopMsg)
      let msg = toBytes(interopMsg)
      ossl("dgst", "-sha1", "-binary", "-out", wp("d1.bin"), wp("msg.bin"))
      ossl("dgst", "-sha256", "-binary", "-out", wp("d256.bin"), wp("msg.bin"))
      ossl("dgst", "-sha384", "-binary", "-out", wp("d384.bin"), wp("msg.bin"))
      ossl("dgst", "-sha512", "-binary", "-out", wp("d512.bin"), wp("msg.bin"))
      check sameBytes(@(sha1Algo.sha1(msg)), readBin("d1.bin"))
      check sameBytes(@(sha256Algo.sha256(msg)), readBin("d256.bin"))
      let h384 = sha384Algo.sha384(msg)
      check sameBytes(h384.toOpenArray(0, 47), readBin("d384.bin"))
      check sameBytes(@(sha512Algo.sha512(msg)), readBin("d512.bin"))

    test "HMAC-SHA-256 matches":
      writeBin("msg.bin", interopMsg)
      ossl("dgst", "-sha256", "-hmac", "testkey123", "-binary",
           "-out", wp("hm.bin"), wp("msg.bin"))
      check sameBytes(@(sha256Algo.sha256Hmac(toBytes("testkey123"),
                                             toBytes(interopMsg))),
                      readBin("hm.bin"))

    test "MD5 matches":
      writeBin("msg.bin", interopMsg)
      let msg = toBytes(interopMsg)
      ossl("dgst", "-md5", "-binary", "-out", wp("dmd5.bin"), wp("msg.bin"))
      check sameBytes(@(md5Algo.md5(msg)), readBin("dmd5.bin"))

    test "HMAC-MD5 matches":
      writeBin("msg.bin", interopMsg)
      ossl("dgst", "-md5", "-hmac", "testkey123", "-binary",
           "-out", wp("hmd5.bin"), wp("msg.bin"))
      check sameBytes(@(md5Algo.md5Hmac(toBytes("testkey123"),
                                       toBytes(interopMsg))),
                      readBin("hmd5.bin"))

  suite "openssl ChaCha20":
    test "IETF ChaCha20 both directions (counter 0)":
      let key = hexToBytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      let nonce = hexToBytes("000000000000004a00000000")
      # openssl IV = LE-u32 counter (0) || 96-bit nonce
      let ivHex = "00000000" & toHexBytes(nonce)
      var pt = newSeq[byte](114)
      for i in 0 ..< pt.len: pt[i] = byte(i * 7 + 1)
      writeBin("cc_pt.bin", pt)
      ossl("enc", "-e", "-chacha20", "-nopad",
           "-K", toHexBytes(key), "-iv", ivHex,
           "-in", wp("cc_pt.bin"), "-out", wp("cc_ossl.bin"))
      let ctOssl = readBin("cc_ossl.bin")
      check sameBytes(chacha20Ietf(pt, toArray[32](key), toArray[12](nonce), 0),
                      ctOssl)
      let ctNim = chacha20Ietf(pt, toArray[32](key), toArray[12](nonce), 0)
      writeBin("cc_nim.bin", ctNim)
      ossl("enc", "-d", "-chacha20", "-nopad",
           "-K", toHexBytes(key), "-iv", ivHex,
           "-in", wp("cc_nim.bin"), "-out", wp("cc_rt.bin"))
      check sameBytes(readBin("cc_rt.bin"), pt)

  suite "openssl X25519":
    test "shared secrets agree both directions":
      ossl("genpkey", "-algorithm", "X25519", "-out", wp("xa.pem"))
      ossl("genpkey", "-algorithm", "X25519", "-out", wp("xb.pem"))
      ossl("pkey", "-in", wp("xa.pem"), "-pubout", "-out", wp("xa_pub.pem"))
      ossl("pkey", "-in", wp("xb.pem"), "-pubout", "-out", wp("xb_pub.pem"))
      let skA = rawKeyOf("xa.pem", "priv")
      let pkA = rawKeyOf("xa.pem", "pub")
      let skB = rawKeyOf("xb.pem", "priv")
      let pkB = rawKeyOf("xb.pem", "pub")
      # our pubkeys match openssl's
      check x25519PublicKey(skA) == pkA
      check x25519PublicKey(skB) == pkB
      # openssl derives, nim agrees
      ossl("pkeyutl", "-derive", "-inkey", wp("xa.pem"),
           "-peerkey", wp("xb_pub.pem"), "-out", wp("sx_ab.bin"))
      ossl("pkeyutl", "-derive", "-inkey", wp("xb.pem"),
           "-peerkey", wp("xa_pub.pem"), "-out", wp("sx_ba.bin"))
      let sAB = readBin("sx_ab.bin")
      let sBA = readBin("sx_ba.bin")
      check sameBytes(sAB, sBA)
      check sameBytes(@(x25519(skA, pkB)), sAB)
      check sameBytes(@(x25519(skB, pkA)), sAB)

  suite "openssl Ed25519":
    test "keypair, sign and verify cross-checked":
      ossl("genpkey", "-algorithm", "Ed25519", "-out", wp("ed.pem"))
      ossl("pkey", "-in", wp("ed.pem"), "-pubout", "-out", wp("ed_pub.pem"))
      let seed = rawKeyOf("ed.pem", "priv")
      let (skN, pkN) = ed25519KeyPair(seed)
      check pkN == rawKeyOf("ed.pem", "pub")
      writeBin("msg.bin", interopMsg)
      # openssl -> nim
      ossl("pkeyutl", "-sign", "-inkey", wp("ed.pem"),
           "-rawin", "-in", wp("msg.bin"), "-out", wp("ed_ossl.sig"))
      check ed25519Check(toArray[64](readBin("ed_ossl.sig")), pkN,
                         toBytes(interopMsg))
      # nim -> openssl
      let sigN = ed25519Sign(toBytes(interopMsg), skN)
      writeBin("ed_nim.sig", sigN)
      ossl("pkeyutl", "-verify", "-pubin", "-inkey", wp("ed_pub.pem"),
           "-rawin", "-in", wp("msg.bin"), "-sigfile", wp("ed_nim.sig"))

if osslBin != "":
  removeDir(workDir)
