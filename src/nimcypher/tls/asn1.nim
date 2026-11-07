# Minimal ASN.1 DER reader for X.509 (RFC 5280 profile).
#
# Supports the subset TLS certificates use: SEQUENCE, SET, INTEGER
# (positive, arbitrary size), OID, NULL, BOOLEAN, ENUMERATED,
# BIT STRING, OCTET STRING, PrintableString/UTF8String/IA5String/
# TeletexString/BMPString, UTCTime/GeneralizedTime. Rejects indefinite
# lengths and trailing data at each level.
#
# SPDX-License-Identifier: BSD-2-Clause

import ./codec

type
  Asn1Tag* = enum
    tBoolean = 0x01
    tInteger = 0x02
    tBitString = 0x03
    tOctetString = 0x04
    tNull = 0x05
    tOid = 0x06
    tEnumerated = 0x0A
    tUtf8String = 0x0C
    tSequence = 0x30
    tSet = 0x31
    tPrintableString = 0x13
    tTeletexString = 0x14
    tIa5String = 0x16
    tUtcTime = 0x17
    tGeneralizedTime = 0x18
    tBmpString = 0x1E

  Asn1Node* = object
    tag*: byte
    constructed*: bool
    content*: seq[byte]  # value bytes (for constructed: nested TLVs)

proc readTlv*(r: var TlsReader): Asn1Node =
  let tagByte = r.readByte()
  let constructed = (tagByte and 0x20) != 0
  let tagNum = tagByte and 0x1F
  if tagNum == 0x1F:
    raise newException(ValueError, "DER: high-tag form unsupported")
  let firstLen = r.readByte()
  var length: int
  if (firstLen and 0x80) == 0:
    length = int(firstLen)
  else:
    let n = int(firstLen and 0x7F)
    if n == 0 or n > 4:
      raise newException(ValueError, "DER: bad length octets")
    length = 0
    for _ in 0 ..< n:
      let b = r.readByte()
      if length == 0 and b == 0:
        raise newException(ValueError, "DER: non-minimal length")
      length = (length shl 8) or int(b)
    if length < 128:
      raise newException(ValueError, "DER: non-minimal long length")
  result.tag = tagByte
  result.constructed = constructed
  result.content = r.readBytes(length)

proc parseDer*(data: openArray[byte]): Asn1Node =
  var r = initReader(data)
  result = r.readTlv()
  r.expectEmpty()

proc children*(n: Asn1Node): seq[Asn1Node] =
  if not n.constructed:
    raise newException(ValueError, "DER: not constructed")
  var r = initReader(n.content)
  while r.remaining > 0:
    result.add(r.readTlv())
  r.expectEmpty()

proc expectTag*(n: Asn1Node, tag: byte, what: string) =
  if n.tag != tag:
    raise newException(ValueError, "DER: expected " & what)

proc asIntegerBytes*(n: Asn1Node): seq[byte] =
  ## Unsigned big-endian bytes of a non-negative INTEGER. Minimal DER
  ## carries at most one leading zero pad (iff the value's high bit is
  ## set); anything else is rejected.
  n.expectTag(byte(ord(tInteger)), "INTEGER")
  if n.content.len == 0:
    raise newException(ValueError, "DER: empty INTEGER")
  if (n.content[0] and 0x80) != 0:
    raise newException(ValueError, "DER: negative INTEGER unsupported")
  if n.content.len > 1 and n.content[0] == 0:
    if (n.content[1] and 0x80) == 0:
      raise newException(ValueError, "DER: non-minimal INTEGER")
    return n.content[1 .. ^1]
  n.content

proc asOid*(n: Asn1Node): seq[uint64] =
  n.expectTag(byte(ord(tOid)), "OID")
  if n.content.len == 0:
    raise newException(ValueError, "DER: empty OID")
  let first = uint64(n.content[0])
  result.add(first div 40)
  result.add(first mod 40)
  var v: uint64 = 0
  var started = false
  for i in 1 ..< n.content.len:
    let b = n.content[i]
    v = (v shl 7) or uint64(b and 0x7F)
    if v > high(uint64) shr 7 and (b and 0x80) != 0:
      raise newException(ValueError, "DER: OID arc overflow")
    if (b and 0x80) == 0:
      result.add(v)
      v = 0
      started = false
    else:
      started = true
  if started:
    raise newException(ValueError, "DER: truncated OID")

proc asBitString*(n: Asn1Node): tuple[data: seq[byte], unusedBits: int] =
  n.expectTag(byte(ord(tBitString)), "BIT STRING")
  if n.content.len == 0:
    raise newException(ValueError, "DER: empty BIT STRING")
  let unused = int(n.content[0])
  if unused < 0 or unused > 7:
    raise newException(ValueError, "DER: bad BIT STRING padding")
  if n.content.len == 1 and unused != 0:
    raise newException(ValueError, "DER: bad BIT STRING")
  (n.content[1 .. ^1], unused)

proc asOctetString*(n: Asn1Node): seq[byte] =
  n.expectTag(byte(ord(tOctetString)), "OCTET STRING")
  n.content

func oidToString*(arcs: openArray[uint64]): string =
  for i, a in arcs:
    if i > 0: result.add('.')
    result.add($a)

func isStringTag*(tag: byte): bool =
  tag in [byte(ord(tUtf8String)), byte(ord(tPrintableString)),
           byte(ord(tTeletexString)), byte(ord(tIa5String)),
           byte(ord(tBmpString))]

proc encodeLength*(length: int): seq[byte] =
  if length < 0:
    raise newException(ValueError, "DER: negative length")
  if length < 128:
    result = @[byte(length)]
  else:
    var tmp: seq[byte]
    var v = length
    while v > 0:
      tmp.add(byte(v and 0xFF))
      v = v shr 8
    result = @[byte(0x80 or tmp.len)]
    for i in countdown(tmp.high, 0): result.add(tmp[i])

proc encodeTlv*(tag: byte, content: openArray[byte]): seq[byte] =
  ## Re-encode a TLV in minimal DER form. Round-trips DER input exactly,
  ## which is what certificate signature verification relies on.
  result = @[tag]
  for b in encodeLength(content.len): result.add(b)
  for b in content: result.add(b)
