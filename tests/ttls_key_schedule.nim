# Key-schedule vectors (AES_128_GCM_SHA256 path).
# Cross-checked against OpenSSL output via the rustls test suite (factual
# vectors, implementation is fresh from RFC 8446 S7).
import std/unittest
import std/strutils
import nimcypher/tls/enums
import nimcypher/tls/key_schedule

proc hb(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2*i .. 2*i+1]))

suite "tls13 key schedule (sha256 suite)":
  test "handshake + application secrets match vectors":
    let h = thSha256
    let hsStart = hb("ec147a06dea3c8846c02b2238e41bddc9d89f9aea17b5efd4d7482af75881c0a")
    let hsFull = hb("751a3d4a14dfabeb68e92ca5918e2408b9bcb0748982ec9c3230ac30bbeb23e2")
    let ecdhe = hb("e7b8fef8903b520cb9a18971b69dd45dca53ce2f12bf3bef9315e31271df4b40")

    let early = earlySecretNoPsk(h)
    let hs = toHandshakeSecret(h, early, ecdhe)

    let (cHts, sHts) = handshakeTrafficSecrets(h, hs, hsStart)
    check cHts == hb("617b35076b9d0e08cf731d94a86614784109ef255551921dd46e040135cf46ab")
    check sHts == hb("fcf7dfe64fa2c04f6235387f434e01422336d9c039de6847a0b9ddcf29a88759")

    let (ck, civ) = deriveTrafficKeys(h, cHts, 16, 12)
    check ck == hb("62d0dd00f69619d3b8193ab4a09585a7")
    check civ == hb("fff75df5ad35d5cb3c53f3a9")
    let (sk, siv) = deriveTrafficKeys(h, sHts, 16, 12)
    check sk == hb("0467f316a805b8c497ee67047bbcbc54")
    check siv == hb("de83a73e9d814b04c48b7809")

    let master = toMasterSecret(h, hs)
    let (cAts, sAts, _, _) = applicationTrafficSecrets(h, master, hsFull)
    check cAts == hb("c14a6d7976d8102b5a0c9951493fee87dcaff82c24cab214e8be71a8206dbda5")
    check sAts == hb("2c907738d3f83702d1e4598f4848531d9f9365491b9f7f52c822290d4c232192")
    let (cak, caiv) = deriveTrafficKeys(h, cAts, 16, 12)
    check cak == hb("cc9f5f980b5f10306cbad7be98d7572e")
    check caiv == hb("b80929e8d02c70f61162ed6b")
    let (sak, saiv) = deriveTrafficKeys(h, sAts, 16, 12)
    check sak == hb("0cb29562d8d88f48b02cbfbed7e62bb3")
    check saiv == hb("0db28f988586a1b7e4d5c69c")

  test "expand-label encoding":
    # HkdfLabel for Length=32, Label="derived", empty context.
    let info = hkdfLabelBytes(32, "derived", [])
    check info[0] == byte 0x00
    check info[1] == byte 0x20
    # "tls13 derived" is 13 bytes
    check info[2] == byte 13

  test "finished verify data is deterministic":
    let h = thSha256
    let base = hb("617b35076b9d0e08cf731d94a86614784109ef255551921dd46e040135cf46ab")
    let th = hb("ec147a06dea3c8846c02b2238e41bddc9d89f9aea17b5efd4d7482af75881c0a")
    let fk = finishedKey(h, base)
    check fk.len == 32
    let vd = finishedVerifyData(h, fk, th)
    check vd.len == 32
    check vd == finishedVerifyData(h, fk, th)
