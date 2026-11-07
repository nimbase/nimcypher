# TLS 1.3 server handshake (RFC 8446, ECDHE, no client auth).
#
# I/O-decoupled like the client: bytes in via `feed`, bytes out via
# `takeOutbox`. Handles group-switch HelloRetryRequest, negotiates
# suite/group/ALPN, validates the private key owns the leaf, and signs
# CertificateVerify with RSA-PSS / ECDSA / Ed25519. No resumption
# tickets are issued in v1; KeyUpdate and close_notify are handled.
#
# SPDX-License-Identifier: BSD-2-Clause

import nimcypher/algos/bigint_ext as bigintExt
import nimcypher/algos/x25519 as x25519Algo
import nimcypher/algos/ecdsa as ecdsaAlgo
import nimcypher/algos/rsa as rsaAlgo
import nimcypher/algos/common as commonAlgo
import nimcypher/sign as edsa
import nimcypher/utils

import ./enums
import ./codec
import ./key_schedule
import ./record
import ./handshake
import ./x509
import ./pem
import ./keys
import ./config

type
  ServerState* = enum
    ssExpectClientHello
    ssExpectSecondHello
    ssExpectFinished
    ssTraffic
    ssClosed
    ssFailed

  TlsServerConn* = object
    config*: ServerConfig
    leafDer*: seq[byte]
    leaf*: Certificate
    chainTail*: seq[seq[byte]]
    key*: PrivateKey
    state*: ServerState
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
    xSecret*: array[32, byte]
    hasXSecret*: bool
    ecPriv*: ecdsaAlgo.EcPrivateKey
    hasEcPriv*: bool
    serverRandom*: array[32, byte]
    sessionEcho*: seq[byte]
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
    sni*: string
    ch1raw*: seq[byte]
    hrrSent*: bool
    cvScheme*: SignatureScheme

func failed*(c: TlsServerConn): bool {.inline.} =
  c.state == ssFailed

func established*(c: TlsServerConn): bool {.inline.} =
  c.state == ssTraffic

proc takeOutbox*(c: var TlsServerConn): seq[byte] =
  result = c.outbox
  c.outbox = @[]

proc readApp*(c: var TlsServerConn): seq[byte] =
  result = c.appIncoming
  c.appIncoming = @[]

proc failConn(c: var TlsServerConn, desc: AlertDescription, msg: string) =
  if c.state == ssFailed: return
  c.failAlert = desc
  c.failReason = msg
  if c.state == ssTraffic:
    try: c.outbox.add(c.sendAppKeys.sealRecord(
      [byte(2), byte(ord(desc))], ctAlert))
    except ValueError: discard
  elif c.hasHsKeys:
    try: c.outbox.add(c.sendHsKeys.sealRecord(
      [byte(2), byte(ord(desc))], ctAlert))
    except ValueError: discard
  else:
    c.outbox.add(sealAlertFatal(desc))
  c.state = ssFailed

proc newServerConn*(config: ServerConfig, chainPem: string,
                    key: PrivateKey): TlsServerConn =
  ## `chainPem` holds leaf + intermediates (leaf first). The key must
  ## own the leaf SPKI or construction raises.
  let blocks = pemBlocks(chainPem)
  if blocks.len == 0:
    raise newException(ValueError, "server chain is empty")
  result = TlsServerConn(config: config, state: ssExpectClientHello)
  result.leaf = parseCertificate(blocks[0])
  result.leafDer = blocks[0]
  for i in 1 ..< blocks.len:
    discard parseCertificate(blocks[i]) # validate chain DER early
    result.chainTail.add(blocks[i])
  if key.kind == pkX25519:
    raise newException(ValueError, "X25519 is not a signature key")
  if not privateKeyMatchesSpki(key, result.leaf.tbs.spki):
    raise newException(ValueError, "private key does not match leaf")
  result.key = key

# --- ephemeral ---

proc genShare(c: var TlsServerConn, group: NamedGroup): KeyShareEntry =
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

proc ecdhShared(c: TlsServerConn, group: NamedGroup,
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
    let cp = ecdsaAlgo.curveParams(c.ecPriv.curve)
    if peerBytes.len != 1 + 2 * cp.coordLen or peerBytes[0] != 0x04:
      raise newException(ValueError, "bad EC share encoding")
    let x = bigintExt.fromBytesBE(
      peerBytes.toOpenArray(1, cp.coordLen))
    let y = bigintExt.fromBytesBE(
      peerBytes.toOpenArray(1 + cp.coordLen, peerBytes.len - 1))
    let peer = ecdsaAlgo.EcPublicKey(curve: c.ecPriv.curve, x: x, y: y)
    if not ecdsaAlgo.validatePublicKey(peer):
      raise newException(ValueError, "peer share off curve")
    result = ecdsaAlgo.ecdh(c.ecPriv, peer)
  else:
    raise newException(ValueError, "unsupported group")

# --- CertificateVerify signing ---

proc pickCvScheme(c: TlsServerConn, offered: openArray[SignatureScheme],
                  h: TlsHash): SignatureScheme =
  let have = @(offered.toOpenArray(0, offered.high))
  case c.key.kind
  of pkRsa:
    let want = case h
      of thSha256: ssRsaPssRsaeSha256
      of thSha384: ssRsaPssRsaeSha384
    if want in have: return want
    for s in [ssRsaPssRsaeSha256, ssRsaPssRsaeSha384, ssRsaPssRsaeSha512]:
      if s in have: return s
  of pkEc:
    let want = case c.key.ec.curve
      of ecdsaAlgo.P256: ssEcdsaSecp256r1Sha256
      of ecdsaAlgo.P384: ssEcdsaSecp384r1Sha384
      of ecdsaAlgo.P521: ssEcdsaSecp521r1Sha512
      else:
        raise newException(ValueError, "unsupported CV curve")
    if want in have: return want
  of pkEd25519:
    if ssEd25519 in have: return ssEd25519
  of pkX25519:
    discard
  raise newException(ValueError, "no mutually supported signature scheme")

proc signCv(c: TlsServerConn, scheme: SignatureScheme,
            content: openArray[byte]): seq[byte] =
  case c.key.kind
  of pkRsa:
    let h = case scheme
      of ssRsaPssRsaeSha256: rsaAlgo.rhSha256
      of ssRsaPssRsaeSha384: rsaAlgo.rhSha384
      of ssRsaPssRsaeSha512: rsaAlgo.rhSha512
      else: raise newException(ValueError, "bad RSA CV scheme")
    rsaAlgo.pssSign(c.key.rsa, h, content)
  of pkEc:
    let raw = ecdsaAlgo.sign(c.key.ec, content)
    rawToDerEcdsaSig(raw, coordLenOf(c.key.ec.curve))
  of pkEd25519:
    @(edsa.sign(c.key.edSecret, content))
  of pkX25519:
    raise newException(ValueError, "X25519 cannot sign")

# --- flight ---

proc sendFlight(c: var TlsServerConn, share: KeyShareEntry) =
  ## ServerHello (plaintext) + CCS + EE/Cert/CV/Finished (protected).
  let selVer = extSupportedVersionsServer(uint16(ord(Tls13)))
  let selKs = extKeyShareServer(share)
  let sh = ServerHello(random: c.serverRandom, sessionIdEcho: c.sessionEcho,
                       cipherSuite: c.suite,
                       extensions: @[selVer, selKs])
  let shMsg = encodeServerHello(sh)
  c.transcript.add(shMsg)
  c.outbox.add(encodePlaintext(ctHandshake, shMsg))
  c.outbox.add(sealCcs())
  let helloHash = hashData(c.hash, c.transcript)
  let (cHs, sHs) = handshakeTrafficSecrets(c.hash, c.handshakeSecret,
                                           helloHash)
  c.clientHsSecret = cHs
  c.serverHsSecret = sHs
  c.sendHsKeys = initTrafficKeysFromSecret(c.suite, sHs)
  c.recvHsKeys = initTrafficKeysFromSecret(c.suite, cHs)
  c.hasHsKeys = true
  # EncryptedExtensions.
  var eeExts: seq[Extension]
  if c.alpnSelected != "":
    var inner: seq[byte]
    var list: seq[byte]
    list.writeOpaque8(toBytes(c.alpnSelected))
    inner.writeOpaque16(list)
    eeExts.add(Extension(extType: uint16(ord(extAlpn)), data: inner))
  let eeMsg = encodeEncryptedExtensions(eeExts)
  c.transcript.add(eeMsg)
  c.outbox.add(c.sendHsKeys.sealRecord(eeMsg, ctHandshake))
  # Certificate.
  var entries = @[CertificateEntry(certData: c.leafDer, extensions: @[])]
  for d in c.chainTail:
    entries.add(CertificateEntry(certData: d, extensions: @[]))
  let certMsg = encodeCertificate(
    CertificateMsg(requestContext: @[], entries: entries))
  c.transcript.add(certMsg)
  c.outbox.add(c.sendHsKeys.sealRecord(certMsg, ctHandshake))
  # CertificateVerify.
  let cvContent = certVerifyContent(true, hashData(c.hash, c.transcript))
  let cvSig = c.signCv(c.cvScheme, cvContent)
  let cvMsg = encodeCertificateVerify(
    CertificateVerifyMsg(algorithm: c.cvScheme, signature: cvSig))
  c.transcript.add(cvMsg)
  c.outbox.add(c.sendHsKeys.sealRecord(cvMsg, ctHandshake))
  # Finished.
  let sFk = finishedKey(c.hash, c.serverHsSecret)
  let sTh = hashData(c.hash, c.transcript)
  let vd = finishedVerifyData(c.hash, sFk, sTh)
  let finMsg = encodeFinished(vd)
  c.transcript.add(finMsg)
  c.outbox.add(c.sendHsKeys.sealRecord(finMsg, ctHandshake))
  # Application keys: client Finished arrives under client app keys.
  let master = toMasterSecret(c.hash, c.handshakeSecret)
  let (cApp, sApp, _, _) = applicationTrafficSecrets(
    c.hash, master, hashData(c.hash, c.transcript))
  c.recvAppKeys = initTrafficKeysFromSecret(c.suite, cApp)
  c.sendAppKeys = initTrafficKeysFromSecret(c.suite, sApp)
  c.state = ssExpectFinished

proc sendRetryRequest(c: var TlsServerConn, ch: ClientHello,
                      selected: NamedGroup) =
  var hrr = HrrRandom
  let sh = ServerHello(random: hrr, sessionIdEcho: ch.sessionId,
                       cipherSuite: c.suite,
                       extensions: @[
                         extSupportedVersionsServer(uint16(ord(Tls13))),
                         Extension(extType: uint16(ord(extKeyShare)),
                                   data: block:
                                     var d: seq[byte]
                                     d.writeUint16(uint16(ord(selected)))
                                     d)])
  let hrrMsg = encodeServerHello(sh)
  c.outbox.add(encodePlaintext(ctHandshake, hrrMsg))
  c.outbox.add(sealCcs())
  # Transcript resets to message_hash(Hash(CH1)) || HRR (S4.4.1);
  # CH2 is appended when it arrives.
  c.transcript = wrapMessageHash(hashData(c.hash, c.ch1raw))
  c.transcript.add(hrrMsg)

# --- ClientHello processing ---

proc negotiate(c: var TlsServerConn, ch: ClientHello, raw: seq[byte]) =
  if uint16(ord(Tls13)) notin ch.versions:
    c.failConn(adProtocolVersion, "client did not offer TLS 1.3")
    return
  var suite = TlsAes128GcmSha256
  var haveSuite = false
  for s in c.config.suites:
    if s in ch.cipherSuites:
      suite = s
      haveSuite = true
      break
  if not haveSuite:
    c.failConn(adHandshakeFailure, "no shared cipher suite")
    return
  if ch.sigSchemes.len == 0:
    c.failConn(adMissingExtension, "no signature_algorithms")
    return
  c.suite = suite
  c.hash = hashOfSuite(suite)
  c.sessionEcho = ch.sessionId
  c.sni = ch.serverName
  # ALPN: first client protocol we also offer.
  for p in ch.alpn:
    if p in c.config.alpn:
      c.alpnSelected = p
      break
  # Group: server preference among the client's groups.
  var selected = ngX25519
  var haveGroup = false
  for g in c.config.groups:
    if g in ch.groups:
      selected = g
      haveGroup = true
      break
  if not haveGroup:
    c.failConn(adHandshakeFailure, "no shared group")
    return
  var share = KeyShareEntry(group: selected, keyExchange: @[])
  var haveShare = false
  for ks in ch.keyShares:
    if ks.group == selected:
      share = ks
      haveShare = true
      break
  if not haveShare:
    # Ask for a usable share (S4.1.4).
    c.group = selected
    c.sendRetryRequest(ch, selected)
    c.hrrSent = true
    c.state = ssExpectSecondHello
    return
  c.group = selected
  let eph = c.genShare(selected)
  let shared =
    try: c.ecdhShared(selected, share.keyExchange)
    except ValueError as e:
      c.failConn(adIllegalParameter, "bad key share: " & e.msg)
      return
  try:
    c.cvScheme = c.pickCvScheme(ch.sigSchemes, c.hash)
  except ValueError as e:
    c.failConn(adHandshakeFailure, "no shared signature scheme: " & e.msg)
    return
  c.earlySecret = earlySecretNoPsk(c.hash)
  c.handshakeSecret = toHandshakeSecret(c.hash, c.earlySecret, shared)
  c.transcript.add(raw)
  c.sendFlight(eph)

proc onClientHello(c: var TlsServerConn, raw: seq[byte]) =
  let ch =
    try: decodeClientHello(raw)
    except ValueError as e:
      c.failConn(adDecodeError, "bad ClientHello: " & e.msg)
      return
  if c.state == ssExpectSecondHello:
    # CH2 after HRR: must carry a share for the selected group.
    if not c.hrrSent:
      c.failConn(adUnexpectedMessage, "unexpected second ClientHello")
      return
    c.transcript.add(raw)
    var share = KeyShareEntry(group: c.group, keyExchange: @[])
    var haveShare = false
    for ks in ch.keyShares:
      if ks.group == c.group:
        share = ks
        haveShare = true
        break
    if not haveShare:
      c.failConn(adIllegalParameter, "HRR share missing")
      return
    if ch.cipherSuites.len == 0:
      c.failConn(adIllegalParameter, "empty second ClientHello")
      return
    let eph = c.genShare(c.group)
    let shared =
      try: c.ecdhShared(c.group, share.keyExchange)
      except ValueError as e:
        c.failConn(adIllegalParameter, "bad key share: " & e.msg)
        return
    try:
      c.cvScheme = c.pickCvScheme(ch.sigSchemes, c.hash)
    except ValueError as e:
      c.failConn(adHandshakeFailure, "no shared signature scheme: " & e.msg)
      return
    c.earlySecret = earlySecretNoPsk(c.hash)
    c.handshakeSecret = toHandshakeSecret(c.hash, c.earlySecret, shared)
    c.sendFlight(eph)
    return
  # First flight.
  if ch.cipherSuites.len == 0:
    c.failConn(adIllegalParameter, "empty ClientHello")
    return
  c.ch1raw = raw
  c.serverRandom = randomBytes[32]()
  c.negotiate(ch, raw)

# --- record loop ---

proc onHandshakeMsg(c: var TlsServerConn, msgType: HandshakeType,
                    raw: seq[byte]) =
  case c.state
  of ssExpectClientHello, ssExpectSecondHello:
    if msgType != htClientHello:
      c.failConn(adUnexpectedMessage, "expected ClientHello")
    else: c.onClientHello(raw)
  of ssExpectFinished:
    if msgType != htFinished:
      c.failConn(adUnexpectedMessage, "expected Finished")
      return
    let vd =
      try: decodeFinished(raw, c.hash.hashLen)
      except ValueError as e:
        c.failConn(adDecodeError, "bad Finished: " & e.msg)
        return
    let fk = finishedKey(c.hash, c.clientHsSecret)
    let th = hashData(c.hash, c.transcript)
    let expect = finishedVerifyData(c.hash, fk, th)
    if expect.len != vd.len or
        not commonAlgo.constantTimeEqual(expect, vd):
      c.failConn(adDecryptError, "Finished verify failed")
      return
    c.transcript.add(raw)
    c.state = ssTraffic
  of ssTraffic:
    if msgType == htNewSessionTicket:
      c.failConn(adUnexpectedMessage, "unexpected ticket")
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
  of ssClosed, ssFailed:
    discard

proc onProtectedRecord(c: var TlsServerConn, packet: seq[byte]) =
  if not c.hasHsKeys:
    c.failConn(adUnexpectedMessage, "protected record before keys")
    return
  let useApp = c.state in [ssTraffic, ssClosed]
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
    if c.state != ssTraffic:
      c.failConn(adUnexpectedMessage, "early application data")
      return
    for b in content.content: c.appIncoming.add(b)
  of ctAlert:
    if content.content.len != 2:
      c.failConn(adDecodeError, "bad alert")
      return
    if content.content[0] == 1 and content.content[1] == 0:
      c.state = ssClosed
    else:
      c.failConn(adHandshakeFailure,
        "peer alert " & $content.content[1])
  else:
    c.failConn(adUnexpectedMessage, "bad inner content type")

proc processRecords(c: var TlsServerConn) =
  while c.recvBuf.len >= 5 and c.state != ssFailed:
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
      c.failConn(adHandshakeFailure, "plaintext peer alert")
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
    # Drain after every record: Finished processing installs the
    # traffic state that later records in the flight may need.
    while c.state != ssFailed:
      let (found, msgType, raw) = c.hsBuf.popMessage()
      if not found: break
      c.onHandshakeMsg(msgType, raw)

proc feed*(c: var TlsServerConn, chunk: openArray[byte]) =
  ## Deliver network bytes. Outbound data accumulates in `outbox`,
  ## application data in `appIncoming`.
  if c.state in [ssFailed, ssClosed]: return
  for b in chunk: c.recvBuf.add(b)
  try:
    c.processRecords()
  except ValueError as e:
    c.failConn(adDecodeError, "decode: " & e.msg)

# --- traffic API ---

proc encryptApp*(c: var TlsServerConn, data: openArray[byte]) =
  if c.state != ssTraffic:
    raise newException(ValueError, "handshake not complete")
  var i = 0
  while i < data.len:
    let n = min(data.len - i, TlsMaxFragment)
    c.outbox.add(c.sendAppKeys.sealRecord(
      data.toOpenArray(i, i + n - 1), ctApplicationData))
    i += n

proc encryptApp*(c: var TlsServerConn, data: string) =
  encryptApp(c, toBytes(data))

proc sendCloseNotify*(c: var TlsServerConn) =
  if c.state != ssTraffic: return
  c.outbox.add(c.sendAppKeys.sealRecord([byte 1, byte 0], ctAlert))
  c.state = ssClosed
