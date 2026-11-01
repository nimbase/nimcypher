# TLS presentation-language codec (RFC 8446 S3).
#
# Fresh implementation from the RFC; boundaries inspired by rustls
# msgs/codec.rs with no code copied.
#
# SPDX-License-Identifier: BSD-2-Clause

type
  TlsReader* = object
    buf*: seq[byte]
    pos*: int

func initReader*(data: openArray[byte]): TlsReader =
  result.buf = @(data.toOpenArray(0, data.high))
  result.pos = 0

func remaining*(r: TlsReader): int {.inline.} =
  r.buf.len - r.pos

func readByte*(r: var TlsReader): byte =
  if r.pos >= r.buf.len:
    raise newException(ValueError, "TLS codec: truncated uint8")
  result = r.buf[r.pos]
  inc r.pos

func readUint16*(r: var TlsReader): uint16 =
  let hi = readByte(r)
  let lo = readByte(r)
  (uint16(hi) shl 8) or uint16(lo)

func readUint24*(r: var TlsReader): int =
  let a = readByte(r)
  let b = readByte(r)
  let c = readByte(r)
  (int(a) shl 16) or (int(b) shl 8) or int(c)

func readBytes*(r: var TlsReader, n: int): seq[byte] =
  if n < 0 or r.pos + n > r.buf.len:
    raise newException(ValueError, "TLS codec: truncated opaque[" & $n & "]")
  result = r.buf[r.pos ..< r.pos + n]
  r.pos += n

func readOpaque8*(r: var TlsReader): seq[byte] =
  let n = int(readByte(r))
  readBytes(r, n)

func readOpaque16*(r: var TlsReader): seq[byte] =
  let n = int(readUint16(r))
  readBytes(r, n)

func readOpaque24*(r: var TlsReader): seq[byte] =
  let n = readUint24(r)
  readBytes(r, n)

func expectEmpty*(r: TlsReader) =
  if r.remaining != 0:
    raise newException(ValueError, "TLS codec: trailing bytes")

# --- writers (append to seq) ---

proc writeByte*(dst: var seq[byte], v: byte) {.inline.} =
  dst.add(v)

proc writeUint16*(dst: var seq[byte], v: uint16) {.inline.} =
  dst.add(byte(v shr 8))
  dst.add(byte(v and 0xFF))

proc writeUint24*(dst: var seq[byte], v: int) {.inline.} =
  if v < 0 or v > 0xFFFFFF:
    raise newException(ValueError, "TLS codec: uint24 out of range")
  dst.add(byte(v shr 16))
  dst.add(byte((v shr 8) and 0xFF))
  dst.add(byte(v and 0xFF))

proc writeOpaque8*(dst: var seq[byte], data: openArray[byte]) =
  if data.len > 255:
    raise newException(ValueError, "TLS codec: opaque8 too long")
  dst.add(byte(data.len))
  for b in data: dst.add(b)

proc writeOpaque16*(dst: var seq[byte], data: openArray[byte]) =
  if data.len > 0xFFFF:
    raise newException(ValueError, "TLS codec: opaque16 too long")
  writeUint16(dst, uint16(data.len))
  for b in data: dst.add(b)

proc writeOpaque24*(dst: var seq[byte], data: openArray[byte]) =
  if data.len > 0xFFFFFF:
    raise newException(ValueError, "TLS codec: opaque24 too long")
  writeUint24(dst, data.len)
  for b in data: dst.add(b)
