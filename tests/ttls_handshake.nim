# Handshake codec round-trip tests.
import std/unittest
import nimcypher/tls/enums
import nimcypher/tls/handshake

suite "tls handshake codec":
  test "clienthello round trip":
    var rnd: array[32, byte]
    for i in 0 ..< 32: rnd[i] = byte i
    var kex = newSeq[byte](32)
    for i in 0 ..< 32: kex[i] = byte (0xA0 + i)
    let ch = ClientHello(
      random: rnd,
      sessionId: @[byte 1, 2, 3],
      cipherSuites: @[TlsAes128GcmSha256, TlsChacha20Poly1305Sha256],
      extensions: @[
        extServerName("example.com"),
        extAlpn(["h2", "http/1.1"]),
        extSupportedGroups([ngX25519, ngSecp256r1]),
        extSignatureAlgorithms([ssEcdsaSecp256r1Sha256, ssEd25519,
                                ssRsaPssRsaeSha256]),
        extSupportedVersionsClient([uint16(ord(Tls13))]),
        extKeyShareClient([KeyShareEntry(group: ngX25519, keyExchange: kex)])])
    let wire = encodeClientHello(ch)
    let back = decodeClientHello(wire)
    check back.random == rnd
    check back.sessionId == @[byte 1, 2, 3]
    check back.cipherSuites == @[TlsAes128GcmSha256, TlsChacha20Poly1305Sha256]
    check back.serverName == "example.com"
    check back.alpn == @["h2", "http/1.1"]
    check back.groups == @[ngX25519, ngSecp256r1]
    check back.versions == @[uint16(ord(Tls13))]
    check back.keyShares.len == 1
    check back.keyShares[0].group == ngX25519
    check back.keyShares[0].keyExchange == kex

  test "serverhello round trip + hrr":
    var rnd: array[32, byte]
    for i in 0 ..< 32: rnd[i] = byte (0xF0 + i)
    var kex = @[byte 9, 9, 9]
    let sh = ServerHello(
      random: rnd,
      sessionIdEcho: @[byte 7],
      cipherSuite: TlsAes128GcmSha256,
      extensions: @[extSupportedVersionsServer(uint16(ord(Tls13))),
                    extKeyShareServer(KeyShareEntry(group: ngX25519,
                                                    keyExchange: kex))])
    let wire = encodeServerHello(sh)
    let back = decodeServerHello(wire)
    check back.cipherSuite == TlsAes128GcmSha256
    check back.serverVersion == uint16(ord(Tls13))
    check back.hasKeyShare
    check back.keyShare.keyExchange == kex
    check not back.isRetryRequest
    # HRR marker
    var hrr = sh
    hrr.random = HrrRandom
    check decodeServerHello(encodeServerHello(hrr)).isRetryRequest

  test "certificate + verify + finished round trip":
    let cert = CertificateMsg(requestContext: @[],
      entries: @[CertificateEntry(certData: @[byte 1,2,3,4],
                                  extensions: @[])])
    let back = decodeCertificate(encodeCertificate(cert))
    check back.entries.len == 1
    check back.entries[0].certData == @[byte 1,2,3,4]
    let cv = CertificateVerifyMsg(algorithm: ssEd25519,
                                  signature: @[byte 5, 6, 7])
    check decodeCertificateVerify(encodeCertificateVerify(cv)).signature ==
      @[byte 5, 6, 7]
    var vd = newSeq[byte](32)
    for i in 0 ..< 32: vd[i] = byte i
    check decodeFinished(encodeFinished(vd), 32) == vd
    expect(ValueError):
      discard decodeFinished(encodeFinished(vd), 48)

  test "truncated hello raises":
    expect(ValueError):
      discard decodeClientHello(@[byte 1, 0, 0, 1, 0])
