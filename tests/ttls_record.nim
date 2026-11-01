# TLS record layer tests: seal/open symmetry, nonce sequencing, tamper.
import std/unittest
import nimcypher/tls/enums
import nimcypher/tls/record

suite "tls record":
  test "gcm record round trip both directions":
    var ck: array[16, byte]
    var sk: array[16, byte]
    for i in 0 ..< 16:
      ck[i] = byte i
      sk[i] = byte (0x80 + i)
    var civ: array[12, byte]
    var siv: array[12, byte]
    for i in 0 ..< 12:
      civ[i] = byte i
      siv[i] = byte (0x40 + i)
    var cSend = initTrafficKeys(TlsAes128GcmSha256, ck, civ)
    var sRecv = initTrafficKeys(TlsAes128GcmSha256, ck, civ)
    let pkt = cSend.sealRecord(@[byte 104, 105], ctHandshake)
    check cSend.seqNum == 1
    let (content, itype) = sRecv.openRecord(pkt)
    check content == @[byte 104, 105]
    check itype == ctHandshake
    check sRecv.seqNum == 1
    # wrong sequence fails
    expect(ValueError):
      discard sRecv.openRecord(pkt)

  test "chacha record round trip":
    var key: array[32, byte]
    for i in 0 ..< 32: key[i] = byte (i * 3)
    var iv: array[12, byte]
    for i in 0 ..< 12: iv[i] = byte i
    var a = initTrafficKeys(TlsChacha20Poly1305Sha256, key, iv)
    var b = initTrafficKeys(TlsChacha20Poly1305Sha256, key, iv)
    let pkt = a.sealRecord(@[byte 1,2,3], ctApplicationData)
    let (content, itype) = b.openRecord(pkt)
    check content == @[byte 1,2,3]
    check itype == ctApplicationData

  test "tampered record fails":
    var key: array[16, byte]
    for i in 0 ..< 16: key[i] = byte i
    var iv: array[12, byte]
    var a = initTrafficKeys(TlsAes128GcmSha256, key, iv)
    var b = initTrafficKeys(TlsAes128GcmSha256, key, iv)
    var pkt = a.sealRecord(@[byte 9], ctAlert)
    pkt[^1] = pkt[^1] xor 1
    expect(ValueError):
      discard b.openRecord(pkt)
