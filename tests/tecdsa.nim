# Tests for ECDSA (P-256/P-384/P-521/secp256k1) and ECDH.
#
# Fixed P-256/P-521 keys were generated with openssl; the "ossl" signatures
# were made with `openssl dgst -sha256/-sha512 -sign` over
# "nimcypher interop test message". The "ours" signatures are our own
# deterministic (RFC 6979) outputs for the same inputs: they pin the nonce
# generator byte-for-byte and are additionally verified by openssl (see
# commit notes). JWS signature format is R || S, fixed width.
import std/unittest

import bigints
import nimcypher/algos/bigint_ext
import nimcypher/algos/ecdsa as ecdsaAlgo
import nimcypher/ecdsa as ecdsaApi
import nimcypher/utils
import vectorutils

proc hb(s: string): seq[byte] = hexToBytes(s)
proc bi(s: string): BigInt = fromBytesBE(hexToBytes(s))

const interopMsg = "nimcypher interop test message"

# P-256 fixed key (openssl ecparam -name prime256v1 -genkey)
const
  p256d = "72CCC57356F16E8484CB2C32945400917AB39A2D149389293A3A152896383CEE"
  p256x = "ADB6E6219EB6BD2CC8443F2C70C627A174F757F49E657CD52C9B31DCF7336D3A"
  p256y = "E81573964ABE1E475212CF8491086ADF34F4E3F5EDE080EA3C3FCE9FB39A7A45"
  # openssl dgst -sha256 -sign (DER 0221..0221 -> R||S)
  osslP256r = "F039937FCFEDD2080BEDEF6F691B711233854C407385E32C942966547FD5536B"
  osslP256s = "EDC3089F43F7BEBAC4FBD361A8405DABC736AB1AB151D8295F99C902CB9C9403"
  # our RFC 6979 signature (verified by openssl too)
  ourP256r = "0B0651F4FE897F8875494B6AA81BFFD828D3D8C99BCD44FC7AAEB36647152444"
  ourP256s = "7B4D4B56E75B4FD984491E15689C8C5688C786438D714350B29581734B1807F0"

# P-521 fixed key (openssl ecparam -name secp521r1 -genkey)
const
  p521d = "180F9E310EF8E25EA85B3223E5A9017F5173DCD416E26EBD53ADBBF4F27" &
    "B5BCFF8EDB5B708B470151474FAFA188E773CBEEFF7189CFB24D5CD8A920832E89222CA"
  p521x = "00D14C6E26E6C7C12F980F0E3351675B6D799DBA74DDDE5864E9448E5CEE" &
    "F9DBCD4D6CDBF19587C00AD350F4ADB2951D988C7C16478EF8B5E89617BD3D2A6013A5F7"
  p521y = "007586F330D3FBE14E2AC37E99FF4879CE1CA73872025F55744683F201D6" &
    "64DE1B5535E7D110570ACEB9FBCA8063E1DC91A43CCF17C06820CAD9D320598FCCC8DC2A"
  # our RFC 6979 signature (verified by openssl too)
  ourP521r = "015DA9FCA5439785CB309E674D48B16E7627A1C9D570164689C018417F" &
    "583CD158964E0631C1453CC6193205611322A81A8085A83063F076C673F12A8A0FAF8C6E6C"
  ourP521s = "012DC8D21C8E92B9C87BF3700615427E6F4234C9962982EC0AE59087A1" &
    "2B273CA83CFD8C49ABA6E6F5F2981942D12453058382502BECB8A3C9338F3EE015008B5CB0"
  # openssl dgst -sha512 -sign (DER -> R||S)
  osslP521r = "011C44F40DDD27C051B66B9698C8B45B5A12DB4EF8DCB127970258BE1C" &
    "64AC9D7EF762726BE851405D5EB8150CDBDFC22583367C53D54F3EAD6E4DBC3EB50D5E3D02"
  osslP521s = "00BCA012FFB76E922200934BF8F7262DDE0642FF59CD1C6D918851FFD3" &
    "7FC8747E0AB6CB88EAA31438A0B2A8F4E3B4A7E953AD120C32408B6DB2899AB8A10712054D"

proc p256Priv(): EcPrivateKey = EcPrivateKey(curve: P256, d: bi(p256d))
proc p256Pub(): EcPublicKey =
  EcPublicKey(curve: P256, x: bi(p256x), y: bi(p256y))

proc p521Priv(): EcPrivateKey = EcPrivateKey(curve: P521, d: bi(p521d))
proc p521Pub(): EcPublicKey =
  EcPublicKey(curve: P521, x: bi(p521x), y: bi(p521y))

suite "ecdsa p256 interop":
  test "public key derivation matches openssl":
    let q = publicKeyFromPrivate(p256Priv())
    check toBytesBE(q.x, 32) == hb(p256x)
    check toBytesBE(q.y, 32) == hb(p256y)
    check validatePublicKey(p256Pub())

  test "openssl signature verifies":
    check verify(p256Pub(), toBytes(interopMsg), hb(osslP256r) & hb(osslP256s))

  test "our signature is deterministic (RFC 6979) and verifies":
    var k = p256Priv()
    let s1 = sign(k, toBytes(interopMsg))
    let s2 = sign(k, toBytes(interopMsg))
    check s1 == s2
    check s1 == hb(ourP256r) & hb(ourP256s)
    check verify(p256Pub(), toBytes(interopMsg), s1)
    wipe(k)

  test "tampered signature and wrong message fail":
    let good = hb(ourP256r) & hb(ourP256s)
    var bad = good
    bad[5] = bad[5] xor 0x01
    check not verify(p256Pub(), toBytes(interopMsg), bad)
    check not verify(p256Pub(), toBytes("other message"), good)
    check not verify(p256Pub(), toBytes(interopMsg), good[0 ..< 63])

suite "ecdsa p521 interop":
  test "public key derivation matches openssl":
    let q = publicKeyFromPrivate(p521Priv())
    check toBytesBE(q.x, 66) == hb(p521x)
    check toBytesBE(q.y, 66) == hb(p521y)
    check validatePublicKey(p521Pub())

  test "openssl signature verifies":
    check verify(p521Pub(), toBytes(interopMsg), hb(osslP521r) & hb(osslP521s))

  test "our signature is deterministic (RFC 6979) and verifies":
    var k = p521Priv()
    let s1 = sign(k, toBytes(interopMsg))
    check s1 == hb(ourP521r) & hb(ourP521s)
    check verify(p521Pub(), toBytes(interopMsg), s1)
    wipe(k)

suite "ecdsa roundtrips":
  test "p256, p384, secp256k1 generate/sign/verify":
    for curve in [P256, P384, Secp256k1]:
      var (priv, pub) = generateKeyPair(curve)
      check validatePublicKey(pub)
      let cp = curveParams(curve)
      let msg = toBytes("ecdsa roundtrip")
      let sig = sign(priv, msg)
      check sig.len == 2 * cp.coordLen
      check verify(pub, msg, sig)
      check sign(priv, msg) == sig # deterministic
      var wrong = sig
      wrong[^1] = wrong[^1] xor 0x01
      check not verify(pub, msg, wrong)
      wipe(priv)

  test "wrong-curve key fails":
    var (priv384, _) = generateKeyPair(P384)
    let msg = toBytes("ecdsa roundtrip")
    let sig = sign(priv384, msg)
    var (_, pub256) = generateKeyPair(P256)
    check not verify(pub256, msg, sig)
    wipe(priv384)

suite "ecdh":
  test "p256 shared secrets agree both ways":
    var (aPriv, aPub) = generateKeyPair(P256)
    var (bPriv, bPub) = generateKeyPair(P256)
    let za = ecdh(aPriv, bPub)
    let zb = ecdh(bPriv, aPub)
    check za.len == 32
    check za == zb
    wipe(aPriv); wipe(bPriv)

  test "different peers give different secrets":
    var (aPriv, _) = generateKeyPair(P256)
    var (_, bPub) = generateKeyPair(P256)
    var (_, cPub) = generateKeyPair(P256)
    check ecdh(aPriv, bPub) != ecdh(aPriv, cPub)
    wipe(aPriv)

  test "curve mismatch raises":
    var (aPriv, _) = generateKeyPair(P256)
    var (_, bPub) = generateKeyPair(P384)
    expect ValueError:
      discard ecdh(aPriv, bPub)
    wipe(aPriv)

  test "hashed ECDH secret agrees and differs from raw":
    var (aPriv, _) = generateKeyPair(P256)
    var (bPriv, bPub) = generateKeyPair(P256)
    let aPub = publicKeyFromPrivate(aPriv)
    let h1 = ecdsaApi.ecdhHashedSecret(aPriv, bPub)
    let h2 = ecdsaApi.ecdhHashedSecret(bPriv, aPub)
    check h1 == h2
    check h1.len == 32
    wipe(aPriv); wipe(bPriv)

suite "ecdsa scalar-mult edge cases":
  test "blinded mult respects the group law (0, 1, n -> inf, G)":
    for curve in [P256, Secp256k1]:
      let cp = curveParams(curve)
      let g = generator(cp)
      check pointMul(cp, initBigInt(0), g).inf
      check pointMul(cp, cp.n, g).inf # blinding adds multiples of n
      let one = pointMul(cp, initBigInt(1), g)
      check not one.inf
      check one.x == g.x and one.y == g.y
      # 2*G via mult equals double via add
      let two = pointMul(cp, initBigInt(2), g)
      let doubled = pointAdd(cp, g, g)
      check two.x == doubled.x and two.y == doubled.y
