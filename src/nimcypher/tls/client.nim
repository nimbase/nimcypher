# TLS 1.3 client handshake (RFC 8446, ECDHE, no PSK).
#
# I/O-decoupled state machine in the rustls style: the application moves
# bytes between a TCP socket and `feed` / `takeOutbox`. Covers the full
# handshake through Finished, HelloRetryRequest (group switch + cookie
# echo), certificate validation, and KeyUpdate in the traffic phase.
# No client authentication, no resumption, no early data in v1.
#
# SPDX-License-Identifier: BSD-2-Clause

import std/options
import std/times

import nimcypher/algos/x25519 as x25519Algo
import nimcypher/algos/ecdsa as ecdsaAlgo
import nimcypher/algos/bigint_ext as bigintExt
import nimcypher/algos/common as commonAlgo
import nimcypher/algos/rsa as rsaAlgo
import nimcypher/sign as edsa
import nimcypher/utils

import ./enums
import ./codec
import ./key_schedule
import ./record
import ./handshake
import ./x509
import ./verify
import ./config

type
  ClientState* = enum
    csExpectServerHello
    csExpectEncryptedExtensions
    csExpectCertificate
    csExpectCertificateVerify
    csExpectFinished
    csTraffic
    csClosed
    csFailed

  TlsClientConn* = object
    config*: ClientConfig
    hostname*: string
    state*: ClientState
    failAlert*: AlertDescription
    failReason*: string
    outbox*: seq[byte]
    recvBuf*: seq[byte]
    appIncoming*: seq[byte]
    transcript*: seq[byte]
    hsBuf*: HandshakeBuffer
    suite*: CipherSuiteId
    hash*: TlsHash
    group*: NamedGroup
    clientRandom*: array[32, byte]
    sessionId*: seq[byte]
    xSecret*: array[32, byte]
    hasXSecret*: bool
    ecPriv*: ecdsaAlgo.EcPrivateKey
    hasEcPriv*: bool
    earlySecret*: seq[byte]
    handshakeSecret*: seq[byte]
    clientHsSecret*: seq[byte]
    serverHsSecret*: seq[byte]
    sendHsKeys*: TlsTrafficKeys
    recvHsKeys*: TlsTrafficKeys
    hasHsKeys*: bool
    sendAppKeys*: TlsTrafficKeys
    recvAppKeys*: TlsTrafficKeys
    alpnSelected*: string
    leafKey*: PublicKeyInfo
    leafSigAlg*: CertSigAlg
    hasLeaf*: bool
    ch1raw*: seq[byte]
    hrrSeen*: bool
    hrrRaw*: seq[byte]
    cookie*: seq[byte]

func failed*(c: TlsClientConn): bool {.inline.} =
  c.state == csFailed

func established*(c: TlsClientConn): bool {.inline.} =
  c.state == csTraffic

proc takeOutbox*(c: var TlsClientConn): seq[byte] =
  result = c.outbox
  c.outbox = @[]

proc readApp*(c: var TlsClientConn): seq[byte] =
  result = c.appIncoming
  c.appIncoming = @[]

proc failConn(c: var TlsClientConn, desc: AlertDescription, msg: string) =
  if c.state == csFailed: return
  c.failAlert = desc
  c.failReason = msg
  if c.state == csTraffic:
    try: c.outbox.add(c.sendAppKeys.sealRecord(
      [byte(2), byte(ord(desc))], ctAlert))
    except ValueError: discard
  elif c.hasHsKeys:
    try: c.outbox.add(c.sendHsKeys.sealRecord(
      [byte(2), byte(ord(desc))], ctAlert))
    except ValueError: discard
  else:
    c.outbox.add(sealAlertFatal(desc))
  c.state = csFailed

# --- ephemeral key shares ---

func isIpLiteral(host: string): bool =
  if host == "": return true
  var dots = 0
  var v4 = true
  for c in host:
    if c == '.': inc dots
    elif c == ':': return true # IPv6
    elif c notin {'0' .. '9'}: v4 = false
  v4 and dots == 3

proc genShare(c: var TlsClientConn, group: NamedGroup): KeyShareEntry =
  case group
  of ngX25519:
    c.xSecret = randomBytes[32]()
    c.hasXSecret = true
    c.hasEcPriv = false
    KeyShareEntry(group: group,
                  keyExchange: @(x25519Algo.x25519PublicKey(c.xSecret)))
  of ngSecp256r1, ngSecp384r1, ngSecp521r1:
    let curve = case group
      of ngSecp256r1: ecdsaAlgo.P256
      of ngSecp384r1: ecdsaAlgo.P384
      else: ecdsaAlgo.P521
    let (priv, pub) = ecdsaAlgo.generateKeyPair(curve)
    c.ecPriv = priv
    c.hasEcPriv = true
    c.hasXSecret = false
    let cp = ecdsaAlgo.curveParams(curve)
    let xb = bigintExt.toBytesBE(pub.x, cp.coordLen)
    let yb = bigintExt.toBytesBE(pub.y, cp.coordLen)
    var point = @[byte 0x04]
    for b in xb: point.add(b)
    for b in yb: point.add(b)
    KeyShareEntry(group: group, keyExchange: point)
  else:
    raise newException(ValueError, "unsupported group for key share")

proc ecdhShared(c: TlsClientConn, group: NamedGroup,
                peerBytes: openArray[byte]): seq[byte] =
  case group
  of ngX25519:
    if not c.hasXSecret or peerBytes.len != 32:
      raise newException(ValueError, "bad X25519 share")
    var peer: array[32, byte]
    for i in 0 ..< 32: peer[i] = peerBytes[i]
    result = @(x25519Algo.x25519(c.xSecret, peer))
  of ngSecp256r1, ngSecp384r1, ngSecp521r1:
    if not c.hasEcPriv:
      raise newException(ValueError, "no EC ephemeral for group")
    let curve = c.ecPriv.curve
    let cp = ecdsaAlgo.curveParams(curve)
    if peerBytes.len != 1 + 2 * cp.coordLen or peerBytes[0] != 0x04:
      raise newException(ValueError, "bad EC share encoding")
    let x = bigintExt.fromBytesBE(
      peerBytes.toOpenArray(1, cp.coordLen))
    let y = bigintExt.fromBytesBE(
      peerBytes.toOpenArray(1 + cp.coordLen, peerBytes.len - 1))
    let peer = ecdsaAlgo.EcPublicKey(curve: curve, x: x, y: y)
    if not ecdsaAlgo.validatePublicKey(peer):
      raise newException(ValueError, "peer share off curve")
    result = ecdsaAlgo.ecdh(c.ecPriv, peer)
  else:
    raise newException(ValueError, "unsupported group")

# --- ClientHello ---

proc buildClientHello(c: var TlsClientConn, group: NamedGroup,
                      share: KeyShareEntry): seq[byte] =
  var exts: seq[Extension]
  if not isIpLiteral(c.hostname):
    exts.add(extServerName(c.hostname))
  exts.add(extSupportedGroups(c.config.groups))
  exts.add(extSignatureAlgorithms(c.config.sigSchemes))
  if c.config.alpn.len > 0:
    exts.add(extAlpn(c.config.alpn))
  exts.add(extSupportedVersionsClient([uint16(ord(Tls13))]))
  exts.add(extKeyShareClient([share]))
  if c.cookie.len > 0:
    exts.add(Extension(extType: uint16(ord(extCookie)), data: c.cookie))
  let ch = ClientHello(random: c.clientRandom, sessionId: c.sessionId,
                       cipherSuites: c.config.suites, extensions: exts)
  encodeClientHello(ch)

proc sendHelloFlight(c: var TlsClientConn) =
  let share = genShare(c, c.group)
  let chMsg = buildClientHello(c, c.group, share)
  if not c.hrrSeen:
    c.ch1raw = chMsg
  c.outbox.add(encodePlaintext(ctHandshake, chMsg))
  c.outbox.add(sealCcs()) # middlebox compat (RFC 8446 D.4)

proc newClientConn*(config: ClientConfig, hostname: string): TlsClientConn =
  if hostname == "":
    raise newException(ValueError, "hostname required")
  if config.suites.len == 0 or config.groups.len == 0:
    raise newException(ValueError, "empty suites/groups")
  result = TlsClientConn(config: config, hostname: hostname,
                         state: csExpectServerHello)
  result.group = config.groups[0]
  result.clientRandom = randomBytes[32]()
  result.sessionId = @(randomBytes[32]())
  result.sendHelloFlight()

# --- server messages ---

proc deriveHandshake(c: var TlsClientConn, shRaw: openArray[byte],
                     serverShare: KeyShareEntry) =
  let shared = c.ecdhShared(serverShare.group, serverShare.keyExchange)
  c.transcript.add(shRaw)
  let helloHash = hashData(c.hash, c.transcript)
  c.handshakeSecret = toHandshakeSecret(c.hash, c.earlySecret, shared)
  let (cHs, sHs) = handshakeTrafficSecrets(c.hash, c.handshakeSecret,
                                           helloHash)
  c.clientHsSecret = cHs
  c.serverHsSecret = sHs
  c.sendHsKeys = initTrafficKeysFromSecret(c.suite, cHs)
  c.recvHsKeys = initTrafficKeysFromSecret(c.suite, sHs)
  c.hasHsKeys = true

proc onServerHello(c: var TlsClientConn, raw: seq[byte]) =
  let sh = decodeServerHello(raw)
  if sh.isRetryRequest:
    if c.hrrSeen:
      c.failConn(adIllegalParameter, "second HelloRetryRequest")
      return
    c.hrrSeen = true
    c.hrrRaw = raw
    if sh.serverVersion != 0 and
        sh.serverVersion != uint16(ord(Tls13)):
      c.failConn(adProtocolVersion, "HRR wrong version")
      return
    # Adopt the server's suite now: the transcript hash follows it.
    if CipherSuiteId(sh.cipherSuite) notin c.config.suites:
      c.failConn(adHandshakeFailure, "HRR picked unconfigured suite")
      return
    c.suite = sh.cipherSuite
    c.hash = hashOfSuite(c.suite)
    var newGroup = c.group
    var haveGroup = false
    if sh.hasHrrGroup:
      newGroup = sh.hrrSelectedGroup
      haveGroup = true
      if newGroup notin c.config.groups:
        c.failConn(adHandshakeFailure, "HRR selected unsupported group")
        return
      if newGroup == c.group:
        c.failConn(adIllegalParameter, "HRR did not change group")
        return
    for e in sh.extensions:
      if e.extType == uint16(ord(extCookie)):
        c.cookie = e.data
    if not haveGroup and c.cookie.len == 0:
      c.failConn(adIllegalParameter, "HRR without group or cookie")
      return
    c.group = newGroup
    # Transcript: message_hash(Hash(CH1)) || HRR || CH2 (S4.4.1).
    let h1 = hashData(c.hash, c.ch1raw)
    c.transcript = wrapMessageHash(h1)
    c.transcript.add(c.hrrRaw)
    let share = genShare(c, c.group)
    let ch2 = buildClientHello(c, c.group, share)
    c.transcript.add(ch2)
    c.outbox.add(encodePlaintext(ctHandshake, ch2))
    c.outbox.add(sealCcs())
    return
  # Normal ServerHello.
  if sh.serverVersion != uint16(ord(Tls13)):
    c.failConn(adProtocolVersion, "server did not negotiate TLS 1.3")
    return
  if CipherSuiteId(sh.cipherSuite) notin c.config.suites:
    c.failConn(adHandshakeFailure, "server picked unconfigured suite")
    return
  if sh.sessionIdEcho != c.sessionId:
    c.failConn(adIllegalParameter, "session id echo mismatch")
    return
  if not sh.hasKeyShare or sh.keyShare.group notin c.config.groups:
    c.failConn(adHandshakeFailure, "bad server key share")
    return
  c.suite = sh.cipherSuite
  c.hash = hashOfSuite(c.suite)
  c.earlySecret = earlySecretNoPsk(c.hash)
  if not c.hrrSeen:
    # Transcript opens with ClientHello. After HelloRetryRequest it is
    # already message_hash || HRR || CH2 (S4.4.1), so do not touch it.
    c.transcript.add(c.ch1raw)
  try:
    c.deriveHandshake(raw, sh.keyShare)
  except ValueError as e:
    c.failConn(adHandshakeFailure, "key exchange failed: " & e.msg)
    return
  c.state = csExpectEncryptedExtensions

proc onEncryptedExtensions(c: var TlsClientConn, raw: seq[byte]) =
  let exts =
    try: decodeEncryptedExtensions(raw)
    except ValueError as e:
      c.failConn(adDecodeError, "bad EncryptedExtensions: " & e.msg)
      return
  for e in exts:
    if e.extType == uint16(ord(extAlpn)):
      var r = initReader(e.data)
      var alpn: seq[string]
      try:
        let list = r.readOpaque16()
        r.expectEmpty()
        var lr = initReader(list)
        while lr.remaining > 0:
          var s = lr.readOpaque8()
          var str = newString(s.len)
          for i, b in s: str[i] = char(b)
          alpn.add(str)
      except ValueError:
        c.failConn(adDecodeError, "bad ALPN extension")
        return
      if alpn.len != 1 or alpn[0] notin c.config.alpn:
        c.failConn(adIllegalParameter, "ALPN mismatch")
        return
      c.alpnSelected = alpn[0]
  c.transcript.add(raw)
  c.state = csExpectCertificate

proc onCertificate(c: var TlsClientConn, raw: seq[byte]) =
  let certMsg =
    try: decodeCertificate(raw)
    except ValueError as e:
      c.failConn(adDecodeError, "bad Certificate: " & e.msg)
      return
  if certMsg.entries.len == 0:
    c.failConn(adHandshakeFailure, "server sent no certificate")
    return
  var intermediates: seq[seq[byte]]
  for i in 1 ..< certMsg.entries.len:
    intermediates.add(certMsg.entries[i].certData)
  let ok =
    try:
      verifyChain(certMsg.entries[0].certData, intermediates,
                  c.config.roots, c.hostname)
    except ValueError as e:
      c.failConn(adBadCertificate, "cert parse: " & e.msg)
      return
  if not ok:
    c.failConn(adBadCertificate, "certificate validation failed")
    return
  let leaf =
    try: parseCertificate(certMsg.entries[0].certData)
    except ValueError as e:
      c.failConn(adBadCertificate, "leaf parse: " & e.msg)
      return
  c.leafKey = leaf.tbs.spki
  c.leafSigAlg = leaf.sigAlg
  c.hasLeaf = true
  c.transcript.add(raw)
  c.state = csExpectCertificateVerify

proc verifyServerCv(c: var TlsClientConn, cv: CertificateVerifyMsg) =
  let content = certVerifyContent(true, hashData(c.hash, c.transcript))
  case c.leafKey.kind
  of skRsa:
    if cv.algorithm notin [ssRsaPssRsaeSha256, ssRsaPssRsaeSha384,
                           ssRsaPssRsaeSha512]:
      c.failConn(adHandshakeFailure, "server CV must be RSA-PSS")
      return
    let h = case cv.algorithm
      of ssRsaPssRsaeSha256: rsaAlgo.rhSha256
      of ssRsaPssRsaeSha384: rsaAlgo.rhSha384
      else: rsaAlgo.rhSha512
    if not rsaAlgo.pssVerify(rsaPubKey(c.leafKey), h, content,
                             cv.signature):
      c.failConn(adDecryptError, "CertificateVerify failed")
  of skEc:
    let curve = c.leafKey.curve
    let want = case curve
      of ecdsaAlgo.P256: ssEcdsaSecp256r1Sha256
      of ecdsaAlgo.P384: ssEcdsaSecp384r1Sha384
      of ecdsaAlgo.P521: ssEcdsaSecp521r1Sha512
      else:
        c.failConn(adHandshakeFailure, "unsupported CV curve")
        return
    if cv.algorithm != want:
      c.failConn(adHandshakeFailure, "CertificateVerify alg mismatch")
      return
    let raw =
      try: derToRawEcdsaSig(cv.signature, coordLenOf(curve))
      except ValueError:
        c.failConn(adDecryptError, "bad CV signature encoding")
        return
    if not ecdsaAlgo.verify(ecPubKey(c.leafKey), content, raw):
      c.failConn(adDecryptError, "CertificateVerify failed")
  of skEd25519:
    if cv.algorithm != ssEd25519 or cv.signature.len != 64:
      c.failConn(adHandshakeFailure, "bad Ed25519 CertificateVerify")
      return
    var sig: array[64, byte]
    for i in 0 ..< 64: sig[i] = cv.signature[i]
    if not edsa.verify(c.leafKey.edKey, content, sig):
      c.failConn(adDecryptError, "CertificateVerify failed")

proc onCertificateVerify(c: var TlsClientConn, raw: seq[byte]) =
  if not c.hasLeaf:
    c.failConn(adUnexpectedMessage, "CertificateVerify without Certificate")
    return
  let cv =
    try: decodeCertificateVerify(raw)
    except ValueError as e:
      c.failConn(adDecodeError, "bad CertificateVerify: " & e.msg)
      return
  c.verifyServerCv(cv)
  if c.state == csFailed: return
  c.transcript.add(raw)
  c.state = csExpectFinished

proc onFinished(c: var TlsClientConn, raw: seq[byte]) =
  let vd =
    try: decodeFinished(raw, c.hash.hashLen)
    except ValueError as e:
      c.failConn(adDecodeError, "bad Finished: " & e.msg)
      return
  let fkServer = finishedKey(c.hash, c.serverHsSecret)
  let thash = hashData(c.hash, c.transcript)
  let expect = finishedVerifyData(c.hash, fkServer, thash)
  if expect.len != vd.len or
      not commonAlgo.constantTimeEqual(expect, vd):
    c.failConn(adDecryptError, "Finished verify failed")
    return
  c.transcript.add(raw)
  # Application secrets (transcript through server Finished).
  let master = toMasterSecret(c.hash, c.handshakeSecret)
  let (cApp, sApp, _, _) = applicationTrafficSecrets(
    c.hash, master, hashData(c.hash, c.transcript))
  c.recvAppKeys = initTrafficKeysFromSecret(c.suite, sApp)
  # Our Finished goes out under the client handshake keys.
  let cHsCopy = c.clientHsSecret
  let thCopy = hashData(c.hash, c.transcript)
  let ourVd = finishedVerifyData(c.hash, finishedKey(c.hash, cHsCopy),
                                 thCopy)
  let finMsg = encodeFinished(ourVd)
  c.transcript.add(finMsg)
  try:
    c.outbox.add(c.sendHsKeys.sealRecord(finMsg, ctHandshake))
  except ValueError as e:
    c.failConn(adInternalError, "seal failed: " & e.msg)
    return
  c.sendAppKeys = initTrafficKeysFromSecret(c.suite, cApp)
  c.state = csTraffic

# --- record loop ---

proc onHandshakeMsg(c: var TlsClientConn, msgType: HandshakeType,
                    raw: seq[byte]) =
  case c.state
  of csExpectServerHello:
    if msgType != htServerHello:
      c.failConn(adUnexpectedMessage, "expected ServerHello")
    else: c.onServerHello(raw)
  of csExpectEncryptedExtensions:
    if msgType != htEncryptedExtensions:
      c.failConn(adUnexpectedMessage, "expected EncryptedExtensions")
    else: c.onEncryptedExtensions(raw)
  of csExpectCertificate:
    if msgType == htCertificateRequest:
      c.failConn(adHandshakeFailure, "client auth unsupported")
    elif msgType != htCertificate:
      c.failConn(adUnexpectedMessage, "expected Certificate")
    else: c.onCertificate(raw)
  of csExpectCertificateVerify:
    if msgType != htCertificateVerify:
      c.failConn(adUnexpectedMessage, "expected CertificateVerify")
    else: c.onCertificateVerify(raw)
  of csExpectFinished:
    if msgType != htFinished:
      c.failConn(adUnexpectedMessage, "expected Finished")
    else: c.onFinished(raw)
  of csTraffic:
    # Post-handshake: ignore tickets, handle KeyUpdate.
    if msgType == htNewSessionTicket:
      discard
    elif msgType == htKeyUpdate:
      if raw.len != 5 or raw[4] notin [0'u8, 1'u8]:
        c.failConn(adDecodeError, "bad KeyUpdate")
        return
      c.recvAppKeys.ratchet()
      if raw[4] == 1:
        let kuMsg = @[byte(ord(htKeyUpdate)), 0, 0, 1, 0]
        try:
          c.outbox.add(c.sendAppKeys.sealRecord(kuMsg, ctHandshake))
        except ValueError as e:
          c.failConn(adInternalError, "seal failed: " & e.msg)
          return
        c.sendAppKeys.ratchet()
    else:
      c.failConn(adUnexpectedMessage, "unexpected post-handshake message")
  of csClosed, csFailed:
    discard

proc onProtectedRecord(c: var TlsClientConn, packet: seq[byte]) =
  if not c.hasHsKeys:
    c.failConn(adUnexpectedMessage, "protected record before ServerHello")
    return
  let useApp = c.state == csTraffic
  let content =
    try:
      if useApp: c.recvAppKeys.openRecord(packet)
      else: c.recvHsKeys.openRecord(packet)
    except ValueError:
      c.failConn(adBadRecordMac, "record auth failed")
      return
  case content.innerType
  of ctHandshake:
    c.hsBuf.feed(content.content)
  of ctApplicationData:
    if c.state != csTraffic:
      c.failConn(adUnexpectedMessage, "early application data")
      return
    for b in content.content: c.appIncoming.add(b)
  of ctAlert:
    if content.content.len != 2:
      c.failConn(adDecodeError, "bad alert")
      return
    if content.content[0] == 1 and content.content[1] == 0:
      c.state = csClosed # peer close_notify
    else:
      c.failConn(adHandshakeFailure,
        "peer alert " & $content.content[1])
  else:
    c.failConn(adUnexpectedMessage, "bad inner content type")

proc processRecords(c: var TlsClientConn) =
  while c.recvBuf.len >= 5 and c.state != csFailed:
    let outer = c.recvBuf[0]
    let reclen = (int(c.recvBuf[3]) shl 8) or int(c.recvBuf[4])
    if reclen > TlsMaxFragment + TlsMaxRecordOverhead:
      c.failConn(adRecordOverflow, "record overflow")
      return
    if c.recvBuf.len < 5 + reclen:
      return
    let packet = c.recvBuf[0 ..< 5 + reclen]
    c.recvBuf = c.recvBuf[5 + reclen .. ^1]
    case outer
    of byte(ord(ctChangeCipherSpec)):
      if not isCcsRecord(packet):
        c.failConn(adUnexpectedMessage, "bad ChangeCipherSpec")
    of byte(ord(ctAlert)):
      if c.recvBuf.len == 0 and packet.len == 7 and packet[5] == 1 and
          packet[6] == 0:
        c.state = csClosed # plaintext close_notify
      else:
        c.failConn(adHandshakeFailure,
          "plaintext peer alert")
    of byte(ord(ctHandshake)):
      if c.hasHsKeys:
        c.failConn(adUnexpectedMessage,
          "plaintext handshake after ServerHello")
        return
      c.hsBuf.feed(packet.toOpenArray(5, packet.high))
    of byte(ord(ctApplicationData)):
      c.onProtectedRecord(packet)
    else:
      c.failConn(adIllegalParameter, "bad outer content type")
    # Drain complete handshake messages after every record: later
    # records in the same flight may need the keys they install
    # (ServerHello precedes handshake-protected traffic).
    while c.state != csFailed:
      let (found, msgType, raw) = c.hsBuf.popMessage()
      if not found: break
      c.onHandshakeMsg(msgType, raw)

proc feed*(c: var TlsClientConn, chunk: openArray[byte]) =
  ## Deliver network bytes. Queues outbound data in `outbox`,
  ## application data in `appIncoming`.
  if c.state in [csFailed, csClosed]: return
  for b in chunk: c.recvBuf.add(b)
  try:
    c.processRecords()
  except ValueError as e:
    c.failConn(adDecodeError, "decode: " & e.msg)

# --- traffic API ---

proc encryptApp*(c: var TlsClientConn, data: openArray[byte]) =
  if c.state != csTraffic:
    raise newException(ValueError, "handshake not complete")
  var i = 0
  while i < data.len:
    let n = min(data.len - i, TlsMaxFragment)
    c.outbox.add(c.sendAppKeys.sealRecord(
      data.toOpenArray(i, i + n - 1), ctApplicationData))
    i += n

proc encryptApp*(c: var TlsClientConn, data: string) =
  encryptApp(c, toBytes(data))

proc sendCloseNotify*(c: var TlsClientConn) =
  if c.state != csTraffic: return
  c.outbox.add(c.sendAppKeys.sealRecord([byte 1, byte 0], ctAlert))
  c.state = csClosed
