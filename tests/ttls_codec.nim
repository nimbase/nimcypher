# Round-trip tests for the TLS presentation-language codec.
import std/unittest
import nimcypher/tls/codec

suite "tls codec":
  test "u16/u24 round trip":
    var buf: seq[byte] = @[]
    buf.writeUint16(0x0304'u16)
    buf.writeUint24(0x010203)
    check buf == @[byte 0x03, 0x04, 0x01, 0x02, 0x03]
    var r = initReader(buf)
    check r.readUint16() == 0x0304'u16
    check r.readUint24() == 0x010203
    r.expectEmpty()

  test "opaque vectors round trip":
    var buf: seq[byte] = @[]
    buf.writeOpaque8([byte 1, 2, 3])
    buf.writeOpaque16([byte 4, 5])
    buf.writeOpaque24([byte 6])
    var r = initReader(buf)
    check r.readOpaque8() == @[byte 1, 2, 3]
    check r.readOpaque16() == @[byte 4, 5]
    check r.readOpaque24() == @[byte 6]
    r.expectEmpty()

  test "truncation raises":
    var r = initReader([byte 0x01])
    expect(ValueError):
      discard r.readUint16()
