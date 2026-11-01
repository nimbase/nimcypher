# TLS AEAD tests: round-trip + tamper + RFC 8439 interop shape.
import std/unittest
import std/options
import std/strutils
import nimcypher/tls/enums
import nimcypher/tls/aead

suite "tls aead":
  test "aes-128-gcm round trip":
    let key = [byte 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
    let nonce = [byte 0,1,2,3,4,5,6,7,8,9,10,11]
    let ad = [byte 0x17, 0x03, 0x03, 0x00, 0x20]
    let pt = @[byte 1,2,3,4,5]
    let (ct, tag) = tlsSeal(TlsAes128GcmSha256, key, nonce, pt, ad)
    let back = tlsOpen(TlsAes128GcmSha256, key, nonce, ct, tag, ad)
    check back.isSome and back.get == pt

  test "aes-256-gcm round trip":
    var key: array[32, byte]
    for i in 0 ..< 32: key[i] = byte i
    let nonce = [byte 9,8,7,6,5,4,3,2,1,0,11,12]
    let pt = @[byte 104, 105]
    let (ct, tag) = tlsSeal(TlsAes256GcmSha384, key, nonce, pt, [])
    check tlsOpen(TlsAes256GcmSha384, key, nonce, ct, tag, []).get == pt

  test "chacha20-poly1305 round trip + tamper":
    var key: array[32, byte]
    for i in 0 ..< 32: key[i] = byte i
    var nonce: array[12, byte]
    for i in 0 ..< 12: nonce[i] = byte i
    let ad = @[byte 0x17, 0x03, 0x03, 0x00, 0x25]
    let pt = @[byte 1,2,3,4,5,6,7,8,9,10]
    let (ct, tag) = tlsSeal(TlsChacha20Poly1305Sha256, key, nonce, pt, ad)
    check tlsOpen(TlsChacha20Poly1305Sha256, key, nonce, ct, tag, ad).get == pt
    var badTag = tag
    badTag[0] = badTag[0] xor 1
    check tlsOpen(TlsChacha20Poly1305Sha256, key, nonce, ct, badTag, ad).isNone
    var badCt = ct
    badCt[0] = badCt[0] xor 1
    check tlsOpen(TlsChacha20Poly1305Sha256, key, nonce, badCt, tag, ad).isNone
    check tlsOpen(TlsChacha20Poly1305Sha256, key, nonce, ct, tag, @[byte 0]).isNone

  test "wrong sizes raise":
    let short = [byte 1,2,3]
    let nonce12 = [byte 0,1,2,3,4,5,6,7,8,9,10,11]
    expect(ValueError):
      discard tlsSeal(TlsAes128GcmSha256, short, nonce12, @[byte 1], [])

  test "chacha20-poly1305 matches openssl reference":
    # key = 00..1f, nonce = 00..0b, aad = record header,Verified with
    # Node.js crypto (OpenSSL backend): ciphertext+tag below.
    var key: array[32, byte]
    for i in 0 ..< 32: key[i] = byte i
    var nonce: array[12, byte]
    for i in 0 ..< 12: nonce[i] = byte i
    let ad = @[byte 0x17, 0x03, 0x03, 0x00, 0x25]
    let pt = @[byte 1,2,3,4,5,6,7,8,9,10]
    let (ct, tag) = tlsSeal(TlsChacha20Poly1305Sha256, key, nonce, pt, ad)
    var got = ""
    for b in ct: got.add(b.toHex(2).toLowerAscii)
    for b in tag: got.add(b.toHex(2).toLowerAscii)
    check got == "88f90b042c11a248be89aafe677e25219f1636a17ceee776a122"
