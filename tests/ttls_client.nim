# Client unit tests: flight shape, reassembly, failure paths.
# No network; live handshake is covered by ttls_interop.
import std/unittest
import nimcypher/tls/enums
import nimcypher/tls/codec
import nimcypher/tls/record
import nimcypher/tls/handshake
import nimcypher/tls/config
import nimcypher/tls/client

suite "tls client units":
  test "initial flight is ClientHello + CCS":
    var cfg = defaultClientConfig()
    var conn = newClientConn(cfg, "example.com")
    let flight = conn.takeOutbox()
    check flight.len > 6
    # First record: handshake, version 0303.
    check flight[0] == byte(ord(ctHandshake))
    check flight[1] == 0x03 and flight[2] == 0x03
    let reclen = (int(flight[3]) shl 8) or int(flight[4])
    var r = initReader(flight.toOpenArray(5, 5 + reclen - 1))
    check HandshakeType(r.readByte()) == htClientHello
    let bodyLen = r.readUint24()
    let body = r.readBytes(bodyLen)
    let ch = decodeClientHello(
      @[byte(ord(htClientHello))] & flight[5+1 ..< 5+4] & body)
    check ch.serverName == "example.com"
    check ch.cipherSuites == cfg.suites
    check ch.keyShares.len == 1
    check ch.versions == @[uint16(ord(Tls13))]
    # Tail is a CCS record.
    check isCcsRecord(flight[^6 .. ^1])

  test "no SNI for IP literals":
    var cfg = defaultClientConfig()
    var conn = newClientConn(cfg, "127.0.0.1")
    let flight = conn.takeOutbox()
    let reclen = (int(flight[3]) shl 8) or int(flight[4])
    var r = initReader(flight.toOpenArray(5, 5 + reclen - 1))
    discard r.readByte()
    let ch = decodeClientHello(
      @[byte(ord(htClientHello))] & flight[5+1 ..< 5+4] &
      r.readBytes(r.readUint24()))
    check ch.serverName == ""

  test "garbage record fails with alert":
    var cfg = defaultClientConfig()
    var conn = newClientConn(cfg, "example.com")
    discard conn.takeOutbox()
    conn.feed(@[byte 99, 3, 3, 0, 1, 0])
    check conn.failed
    check conn.takeOutbox().len > 0 # fatal alert queued

  test "truncated record waits, wrong message fails":
    var cfg = defaultClientConfig()
    var conn = newClientConn(cfg, "example.com")
    discard conn.takeOutbox()
    conn.feed(@[byte 22, 3, 3, 0])
    check not conn.failed # incomplete header: no progress, no failure
    # Complete record carrying a ClientHello where ServerHello is expected.
    conn.feed(@[byte 10, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
    check conn.failed # unexpected handshake message -> alert

  test "cert verify content shape":
    var th = newSeq[byte](32)
    for i in 0 ..< 32: th[i] = byte i
    let c = certVerifyContent(true, th)
    check c.len == 64 + len("TLS 1.3, server CertificateVerify") + 1 + 32
    for i in 0 ..< 64: check c[i] == 0x20
    check c[64] == byte('T')

  test "handshake buffer reassembly":
    var b = HandshakeBuffer()
    let msg = encodeFinished(@[byte 1, 2, 3])
    b.feed(msg.toOpenArray(0, 1))
    let (f1, _, _) = b.popMessage()
    check not f1
    b.feed(msg.toOpenArray(2, msg.high))
    let (f2, t2, raw2) = b.popMessage()
    check f2 and t2 == htFinished and raw2 == msg
