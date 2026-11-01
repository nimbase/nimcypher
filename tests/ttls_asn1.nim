# ASN.1 DER reader tests with hand-encoded vectors.
import std/unittest
import nimcypher/tls/codec
import nimcypher/tls/asn1

suite "der reader":
  test "integer + oid + sequence":
    # SEQUENCE { INTEGER 0x0100, OID 1.2.840.113549.1.1.11 }
    let der = @[byte 0x30, 0x0F,
      0x02, 0x02, 0x01, 0x00,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]
    let top = parseDer(der)
    check top.tag == 0x30
    let kids = top.children
    check kids.len == 2
    check kids[0].asIntegerBytes == @[byte 0x01, 0x00]
    check oidToString(kids[1].asOid) == "1.2.840.113549.1.1.11"

  test "bit string + octet string + null":
    let der = @[byte 0x30, 0x0A,
      0x03, 0x02, 0x00, 0xA0,
      0x04, 0x02, 0xDE, 0xAD,
      0x05, 0x00]
    let kids = parseDer(der).children
    let (bits, unused) = kids[0].asBitString
    check unused == 0 and bits == @[byte 0xA0]
    check kids[1].asOctetString == @[byte 0xDE, 0xAD]
    check kids[2].tag == 0x05

  test "rejects indefinite + trailing + negative":
    expect(ValueError):
      discard parseDer(@[byte 0x30, 0x80, 0x00, 0x00])
    expect(ValueError):
      discard parseDer(@[byte 0x02, 0x01, 0x05, 0xFF])
    expect(ValueError):
      discard parseDer(@[byte 0x02, 0x01, 0xFF]).asIntegerBytes
    expect(ValueError):
      discard parseDer(@[byte 0x06, 0x02, 0x2A, 0x86]).asOid

  test "padded positive integer strips one zero":
    # INTEGER 0x0080FF (high bit set -> one pad byte) -> 80 FF
    check parseDer(@[byte 0x02, 0x03, 0x00, 0x80, 0xFF]).asIntegerBytes ==
      @[byte 0x80, 0xFF]
    # INTEGER 0x00 -> single zero
    check parseDer(@[byte 0x02, 0x01, 0x00]).asIntegerBytes == @[byte 0x00]
    # Non-minimal two pad bytes rejected
    expect(ValueError):
      discard parseDer(@[byte 0x02, 0x03, 0x00, 0x00, 0x01]).asIntegerBytes
