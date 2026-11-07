# TLS 1.3 handshake message codec (RFC 8446 S4).
#
# Fresh implementation from the RFC wire format. Covers the messages a
# TLS 1.3 client + server exchange in v1: ClientHello, ServerHello
# (incl. HelloRetryRequest detection), EncryptedExtensions, Certificate,
# CertificateVerify, Finished. PSK/HRR-cookie flows and post-handshake
# auth are out of scope for v1.
#
# SPDX-License-Identifier: BSD-2-Clause

import ./enums
import ./codec

const
  # RFC 8446 S4.1.3: fixed HRR random marker.
  HrrRandom*: array[32, byte] = [
    0xCF'u8, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C]

type
  KeyShareEntry* = object
    group*: NamedGroup
    keyExchange*: seq[byte]

  ClientHello* = object
    random*: array[32, byte]
    sessionId*: seq[byte]
    cipherSuites*: seq[CipherSuiteId]
    extensions*: seq[Extension]
    # Parsed views of the key extensions we send/accept in v1:
    serverName*: string
    alpn*: seq[string]
    groups*: seq[NamedGroup]
    sigSchemes*: seq[SignatureScheme]
    versions*: seq[uint16]
    keyShares*: seq[KeyShareEntry]

  Extension* = object
    extType*: uint16
    data*: seq[byte]

  ServerHello* = object
    random*: array[32, byte]
    sessionIdEcho*: seq[byte]
    cipherSuite*: CipherSuiteId
    extensions*: seq[Extension]
    isRetryRequest*: bool
    serverVersion*: uint16
    keyShare*: KeyShareEntry
    hasKeyShare*: bool
    hrrSelectedGroup*: NamedGroup
    hasHrrGroup*: bool

  CertificateEntry* = object
    certData*: seq[byte]
    extensions*: seq[byte]

  CertificateMsg* = object
    requestContext*: seq[byte]
    entries*: seq[CertificateEntry]

  CertificateVerifyMsg* = object
    algorithm*: SignatureScheme
    signature*: seq[byte]

func bytesToString(b: openArray[byte]): string =
  result = newString(b.len)
  for i, x in b: result[i] = char(x)

func stringToBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

# --- extension builders (client) ---

proc extServerName*(hostname: string): Extension =
  var inner: seq[byte]
  let hb = stringToBytes(hostname)
  var entry: seq[byte]
  entry.writeByte(byte(0)) # host_name
  entry.writeOpaque16(hb)
  inner.writeOpaque16(entry)
  result.extType = uint16(ord(extServerName))
  result.data = inner

proc extSupportedGroups*(groups: openArray[NamedGroup]): Extension =
  var inner: seq[byte]
  var list: seq[byte]
  for g in groups: list.writeUint16(uint16(ord(g)))
  inner.writeOpaque16(list)
  result.extType = uint16(ord(extSupportedGroups))
  result.data = inner

proc extSignatureAlgorithms*(schemes: openArray[SignatureScheme]): Extension =
  var inner: seq[byte]
  var list: seq[byte]
  for s in schemes: list.writeUint16(uint16(ord(s)))
  inner.writeOpaque16(list)
  result.extType = uint16(ord(extSignatureAlgorithms))
  result.data = inner

proc extAlpn*(protocols: openArray[string]): Extension =
  var inner: seq[byte]
  var list: seq[byte]
  for p in protocols:
    list.writeOpaque8(stringToBytes(p))
  inner.writeOpaque16(list)
  result.extType = uint16(ord(extAlpn))
  result.data = inner

proc extSupportedVersionsClient*(versions: openArray[uint16]): Extension =
  var inner: seq[byte]
  var list: seq[byte]
  for v in versions: list.writeUint16(v)
  inner.writeByte(byte(list.len))
  for b in list: inner.add(b)
  result.extType = uint16(ord(extSupportedVersions))
  result.data = inner

proc extKeyShareClient*(shares: openArray[KeyShareEntry]): Extension =
  var inner: seq[byte]
  var list: seq[byte]
  for s in shares:
    list.writeUint16(uint16(ord(s.group)))
    list.writeOpaque16(s.keyExchange)
  inner.writeOpaque16(list)
  result.extType = uint16(ord(extKeyShare))
  result.data = inner

proc extSupportedVersionsServer*(selected: uint16): Extension =
  var inner: seq[byte]
  inner.writeUint16(selected)
  result.extType = uint16(ord(extSupportedVersions))
  result.data = inner

proc extKeyShareServer*(share: KeyShareEntry): Extension =
  var inner: seq[byte]
  inner.writeUint16(uint16(ord(share.group)))
  inner.writeOpaque16(share.keyExchange)
  result.extType = uint16(ord(extKeyShare))
  result.data = inner

# --- message framing ---

proc wrapHandshake*(msgType: HandshakeType, body: openArray[byte]): seq[byte] =
  result = @[byte(ord(msgType))]
  result.writeUint24(body.len)
  for b in body: result.add(b)

proc encodeClientHello*(ch: ClientHello): seq[byte] =
  var body: seq[byte]
  body.writeUint16(uint16(ord(Tls12))) # legacy_version
  for b in ch.random: body.add(b)
  body.writeOpaque8(ch.sessionId)
  var cs: seq[byte]
  for s in ch.cipherSuites: cs.writeUint16(uint16(ord(s)))
  body.writeOpaque16(cs)
  body.writeOpaque8([byte 0]) # null compression only
  var exts: seq[byte]
  for e in ch.extensions:
    exts.writeUint16(e.extType)
    exts.writeOpaque16(e.data)
  body.writeOpaque16(exts)
  wrapHandshake(htClientHello, body)

proc decodeClientHello*(msg: openArray[byte]): ClientHello =
  var r = initReader(msg)
  if HandshakeType(r.readByte()) != htClientHello:
    raise newException(ValueError, "not a ClientHello")
  let bodyLen = r.readUint24()
  let body = r.readBytes(bodyLen)
  r.expectEmpty()
  var b = initReader(body)
  if b.readUint16() != uint16(ord(Tls12)):
    raise newException(ValueError, "ClientHello legacy_version must be 0x0303")
  for i in 0 ..< 32: result.random[i] = b.readByte()
  result.sessionId = b.readOpaque8()
  let csBytes = b.readOpaque16()
  var c = initReader(csBytes)
  while c.remaining > 0:
    result.cipherSuites.add(CipherSuiteId(c.readUint16()))
  let comp = b.readOpaque8()
  if comp.len != 1 or comp[0] != 0:
    raise newException(ValueError, "ClientHello must offer null compression")
  let extBytes = b.readOpaque16()
  b.expectEmpty()
  var e = initReader(extBytes)
  while e.remaining > 0:
    let t = e.readUint16()
    let d = e.readOpaque16()
    result.extensions.add(Extension(extType: t, data: d))
    case t
    of uint16(ord(extServerName)):
      var er = initReader(d)
      let lst = er.readOpaque16()
      var lr = initReader(lst)
      if lr.remaining > 0 and lr.readByte() == 0:
        result.serverName = bytesToString(lr.readOpaque16())
    of uint16(ord(extAlpn)):
      var er = initReader(d)
      let lst = er.readOpaque16()
      var lr = initReader(lst)
      while lr.remaining > 0:
        result.alpn.add(bytesToString(lr.readOpaque8()))
    of uint16(ord(extSupportedGroups)):
      var er = initReader(d)
      let lst = er.readOpaque16()
      var lr = initReader(lst)
      while lr.remaining > 0:
        result.groups.add(NamedGroup(lr.readUint16()))
    of uint16(ord(extSignatureAlgorithms)):
      var er = initReader(d)
      let lst = er.readOpaque16()
      var lr = initReader(lst)
      while lr.remaining > 0:
        result.sigSchemes.add(SignatureScheme(lr.readUint16()))
    of uint16(ord(extSupportedVersions)):
      var er = initReader(d)
      let n = int(er.readByte())
      let vb = er.readBytes(n)
      var vr = initReader(vb)
      while vr.remaining > 0:
        result.versions.add(vr.readUint16())
    of uint16(ord(extKeyShare)):
      var er = initReader(d)
      let lst = er.readOpaque16()
      var lr = initReader(lst)
      while lr.remaining > 0:
        let g = NamedGroup(lr.readUint16())
        let ke = lr.readOpaque16()
        result.keyShares.add(KeyShareEntry(group: g, keyExchange: ke))
    else: discard

proc encodeServerHello*(sh: ServerHello): seq[byte] =
  var body: seq[byte]
  body.writeUint16(uint16(ord(Tls12)))
  for b in sh.random: body.add(b)
  body.writeOpaque8(sh.sessionIdEcho)
  body.writeUint16(uint16(ord(sh.cipherSuite)))
  body.writeByte(byte(0))
  var exts: seq[byte]
  for e in sh.extensions:
    exts.writeUint16(e.extType)
    exts.writeOpaque16(e.data)
  body.writeOpaque16(exts)
  wrapHandshake(htServerHello, body)

proc decodeServerHello*(msg: openArray[byte]): ServerHello =
  var r = initReader(msg)
  if HandshakeType(r.readByte()) != htServerHello:
    raise newException(ValueError, "not a ServerHello")
  let bodyLen = r.readUint24()
  let body = r.readBytes(bodyLen)
  r.expectEmpty()
  var b = initReader(body)
  if b.readUint16() != uint16(ord(Tls12)):
    raise newException(ValueError, "ServerHello legacy_version must be 0x0303")
  for i in 0 ..< 32: result.random[i] = b.readByte()
  result.isRetryRequest = result.random == HrrRandom
  result.sessionIdEcho = b.readOpaque8()
  result.cipherSuite = CipherSuiteId(b.readUint16())
  if b.readByte() != 0:
    raise newException(ValueError, "ServerHello compression must be 0")
  let extBytes = b.readOpaque16()
  b.expectEmpty()
  var e = initReader(extBytes)
  while e.remaining > 0:
    let t = e.readUint16()
    let d = e.readOpaque16()
    result.extensions.add(Extension(extType: t, data: d))
    if t == uint16(ord(extSupportedVersions)) and d.len == 2:
      result.serverVersion = (uint16(d[0]) shl 8) or uint16(d[1])
    if t == uint16(ord(extKeyShare)):
      if d.len == 2:
        # HelloRetryRequest form: bare selected_group (RFC 8446 S4.1.4).
        result.hrrSelectedGroup =
          NamedGroup((uint16(d[0]) shl 8) or uint16(d[1]))
        result.hasHrrGroup = true
      else:
        var kr = initReader(d)
        result.keyShare = KeyShareEntry(group: NamedGroup(kr.readUint16()),
                                        keyExchange: kr.readOpaque16())
        kr.expectEmpty()
        result.hasKeyShare = true

# --- post-ServerHello messages (all handshake-wrapped) ---

proc encodeEncryptedExtensions*(exts: openArray[Extension]): seq[byte] =
  var body: seq[byte]
  var list: seq[byte]
  for e in exts:
    list.writeUint16(e.extType)
    list.writeOpaque16(e.data)
  body.writeOpaque16(list)
  wrapHandshake(htEncryptedExtensions, body)

proc decodeEncryptedExtensions*(msg: openArray[byte]): seq[Extension] =
  var r = initReader(msg)
  if HandshakeType(r.readByte()) != htEncryptedExtensions:
    raise newException(ValueError, "not EncryptedExtensions")
  let body = r.readBytes(r.readUint24())
  r.expectEmpty()
  var b = initReader(body)
  let list = b.readOpaque16()
  b.expectEmpty()
  var lr = initReader(list)
  while lr.remaining > 0:
    result.add(Extension(extType: lr.readUint16(), data: lr.readOpaque16()))

proc encodeCertificate*(cert: CertificateMsg): seq[byte] =
  var body: seq[byte]
  body.writeOpaque8(cert.requestContext)
  var list: seq[byte]
  for e in cert.entries:
    var entry: seq[byte]
    entry.writeOpaque24(e.certData)
    entry.writeOpaque16(e.extensions)
    for b in entry: list.add(b)
  body.writeOpaque24(list)
  wrapHandshake(htCertificate, body)

proc decodeCertificate*(msg: openArray[byte]): CertificateMsg =
  var r = initReader(msg)
  if HandshakeType(r.readByte()) != htCertificate:
    raise newException(ValueError, "not a Certificate")
  let body = r.readBytes(r.readUint24())
  r.expectEmpty()
  var b = initReader(body)
  result.requestContext = b.readOpaque8()
  let list = b.readOpaque24()
  b.expectEmpty()
  var lr = initReader(list)
  while lr.remaining > 0:
    let certData = lr.readOpaque24()
    let exts = lr.readOpaque16()
    result.entries.add(CertificateEntry(certData: certData, extensions: exts))

proc encodeCertificateVerify*(cv: CertificateVerifyMsg): seq[byte] =
  var body: seq[byte]
  body.writeUint16(uint16(ord(cv.algorithm)))
  body.writeOpaque16(cv.signature)
  wrapHandshake(htCertificateVerify, body)

proc decodeCertificateVerify*(msg: openArray[byte]): CertificateVerifyMsg =
  var r = initReader(msg)
  if HandshakeType(r.readByte()) != htCertificateVerify:
    raise newException(ValueError, "not a CertificateVerify")
  let body = r.readBytes(r.readUint24())
  r.expectEmpty()
  var b = initReader(body)
  result.algorithm = SignatureScheme(b.readUint16())
  result.signature = b.readOpaque16()
  b.expectEmpty()

proc encodeFinished*(verifyData: openArray[byte]): seq[byte] =
  var body: seq[byte]
  for b in verifyData: body.add(b)
  wrapHandshake(htFinished, body)

proc decodeFinished*(msg: openArray[byte], hashLen: int): seq[byte] =
  var r = initReader(msg)
  if HandshakeType(r.readByte()) != htFinished:
    raise newException(ValueError, "not a Finished")
  let body = r.readBytes(r.readUint24())
  r.expectEmpty()
  if body.len != hashLen:
    raise newException(ValueError, "Finished length mismatch")
  body

# --- transcript helpers ---

type
  HandshakeBuffer* = object
    data*: seq[byte]

proc feed*(b: var HandshakeBuffer, chunk: openArray[byte]) =
  for x in chunk: b.data.add(x)

proc pending*(b: HandshakeBuffer): int {.inline.} =
  b.data.len

proc popMessage*(b: var HandshakeBuffer): tuple[found: bool,
    msgType: HandshakeType, raw: seq[byte]] =
  ## Remove and return one complete handshake message (header + body).
  if b.data.len < 4:
    return (false, htClientHello, @[])
  let bodyLen = (int(b.data[1]) shl 16) or (int(b.data[2]) shl 8) or
    int(b.data[3])
  if b.data.len < 4 + bodyLen:
    return (false, htClientHello, @[])
  let raw = b.data[0 ..< 4 + bodyLen]
  b.data = b.data[4 + bodyLen .. ^1]
  (true, HandshakeType(raw[0]), raw)

proc wrapMessageHash*(helloHash: openArray[byte]): seq[byte] =
  ## Synthetic message_hash replacing ClientHello1 in the transcript
  ## after HelloRetryRequest (RFC 8446 S4.4.1).
  result = @[byte(ord(htMessageHash))]
  result.writeUint24(helloHash.len)
  for b in helloHash: result.add(b)

proc certVerifyContent*(forServer: bool,
                        transcriptHash: openArray[byte]): seq[byte] =
  ## 64 spaces + context string + 0x00 + transcript hash (RFC 8446 S4.4.3).
  ## `forServer` selects the "server CertificateVerify" context (server
  ## sending CV, or anyone verifying one); false selects the client one.
  result = newSeq[byte](64)
  for i in 0 ..< 64: result[i] = 0x20
  let ctxStr = if forServer: "TLS 1.3, server CertificateVerify"
               else: "TLS 1.3, client CertificateVerify"
  for c in ctxStr: result.add(byte(c))
  result.add(byte(0))
  for b in transcriptHash: result.add(b)
