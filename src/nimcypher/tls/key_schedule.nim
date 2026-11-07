# TLS 1.3 key schedule (RFC 8446 S7).
#
# Fresh implementation over nimcypher's HKDF/SHA-2 primitives; sequence
# follows RFC 8446 (and rustls tls13/key_schedule.rs as a behavioral
# reference) with no code copied.
#
# SPDX-License-Identifier: BSD-2-Clause

import nimcypher/algos/sha256 as sha256Algo
import nimcypher/algos/sha384 as sha384Algo
import nimcypher/algos/hkdf as hkdfAlgo
import nimcypher/algos/common as commonAlgo

import ./enums
import ./codec

type
  TlsHash* = enum
    thSha256
    thSha384

func hashOfSuite*(s: CipherSuiteId): TlsHash =
  case s
  of TlsAes128GcmSha256, TlsChacha20Poly1305Sha256: thSha256
  of TlsAes256GcmSha384: thSha384

func hashLen*(h: TlsHash): int =
  case h
  of thSha256: 32
  of thSha384: 48

func hashData*(h: TlsHash, data: openArray[byte]): seq[byte] =
  case h
  of thSha256:
    let d = sha256Algo.sha256(data)
    result = newSeq[byte](32)
    for i in 0 ..< 32: result[i] = d[i]
  of thSha384:
    let d = sha384Algo.sha384(data)
    result = newSeq[byte](48)
    for i in 0 ..< 48: result[i] = d[i]

func zeros*(n: int): seq[byte] =
  result = newSeq[byte](n)

proc hkdfExtract*(h: TlsHash, salt, ikm: openArray[byte]): seq[byte] =
  ## HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM). Empty salt means
  ## HashLen zeroes (RFC 8446 S7.1, RFC 5869 S2.2).
  var s: seq[byte]
  if salt.len == 0:
    s = zeros(h.hashLen)
  else:
    s = @salt
  case h
  of thSha256:
    let prk = sha256Algo.sha256Hmac(s, ikm)
    result = newSeq[byte](32)
    for i in 0 ..< 32: result[i] = prk[i]
  of thSha384:
    let prk = sha384Algo.sha384Hmac(s, ikm)
    result = newSeq[byte](48)
    for i in 0 ..< 48: result[i] = prk[i]
  commonAlgo.wipe(s)

proc hkdfExpand*(h: TlsHash, prk, info: openArray[byte],
                 okmLen: int): seq[byte] =
  case h
  of thSha256:
    hkdfAlgo.sha256HkdfExpand(prk, info, okmLen)
  of thSha384:
    hkdfAlgo.sha384HkdfExpand(prk, info, okmLen)

proc hkdfLabelBytes*(length: int, label: string,
                     context: openArray[byte]): seq[byte] =
  ## Encode HkdfLabel { uint16 length; opaque label<7..255>;
  ## opaque context<0..255>; } with label = "tls13 " & label.
  let fullLabel = "tls13 " & label
  if fullLabel.len < 7 or fullLabel.len > 255:
    raise newException(ValueError, "HKDF label length out of range")
  if context.len > 255:
    raise newException(ValueError, "HKDF context too long")
  if length < 0 or length > 0xFFFF:
    raise newException(ValueError, "HKDF length out of range")
  result = newSeq[byte]()
  writeUint16(result, uint16(length))
  var lb = newSeq[byte](fullLabel.len)
  for i, c in fullLabel: lb[i] = byte(c)
  writeOpaque8(result, lb)
  writeOpaque8(result, context)

proc hkdfExpandLabel*(h: TlsHash, secret: openArray[byte], label: string,
                      context: openArray[byte], length: int): seq[byte] =
  ## HKDF-Expand-Label(Secret, Label, Context, Length) per RFC 8446 S7.1.
  let info = hkdfLabelBytes(length, label, context)
  hkdfExpand(h, secret, info, length)

proc deriveSecret*(h: TlsHash, secret: openArray[byte], label: string,
                   transcriptHash: openArray[byte]): seq[byte] =
  ## Derive-Secret(Secret, Label, Messages) = Expand-Label(Secret, Label,
  ## Transcript-Hash(Messages), HashLen).
  hkdfExpandLabel(h, secret, label, transcriptHash, h.hashLen)

proc transcriptHash*(h: TlsHash, messages: openArray[byte]): seq[byte] =
  hashData(h, messages)

proc finishedKey*(h: TlsHash, baseKey: openArray[byte]): seq[byte] =
  hkdfExpandLabel(h, baseKey, TlsFinishedKeyLabel, [], h.hashLen)

proc finishedVerifyData*(h: TlsHash, finishedKey,
                         transcriptHash: openArray[byte]): seq[byte] =
  case h
  of thSha256:
    let t = sha256Algo.sha256Hmac(finishedKey, transcriptHash)
    result = newSeq[byte](32)
    for i in 0 ..< 32: result[i] = t[i]
  of thSha384:
    let t = sha384Algo.sha384Hmac(finishedKey, transcriptHash)
    result = newSeq[byte](48)
    for i in 0 ..< 48: result[i] = t[i]

proc deriveTrafficKeys*(h: TlsHash, trafficSecret: openArray[byte],
                        keyLen, ivLen: int): tuple[key, iv: seq[byte]] =
  result.key = hkdfExpandLabel(h, trafficSecret, TlsKeyLabel, [], keyLen)
  result.iv = hkdfExpandLabel(h, trafficSecret, TlsIvLabel, [], ivLen)

# --- staged schedule (no-PSK path used by the first handshake) ---

proc earlySecretNoPsk*(h: TlsHash): seq[byte] =
  ## Early Secret with no PSK: Extract(0s, 0s).
  hkdfExtract(h, [], zeros(h.hashLen))

proc toHandshakeSecret*(h: TlsHash, earlySecret,
                        ecdheSecret: openArray[byte]): seq[byte] =
  var derived = deriveSecret(h, earlySecret, TlsDerivedLabel,
                             hashData(h, []))
  result = hkdfExtract(h, derived, ecdheSecret)
  commonAlgo.wipe(derived)

proc toMasterSecret*(h: TlsHash, handshakeSecret: openArray[byte]): seq[byte] =
  var derived = deriveSecret(h, handshakeSecret, TlsDerivedLabel,
                             hashData(h, []))
  result = hkdfExtract(h, derived, zeros(h.hashLen))
  commonAlgo.wipe(derived)

proc handshakeTrafficSecrets*(h: TlsHash, handshakeSecret,
                              helloHash: openArray[byte]): tuple[
    client, server: seq[byte]] =
  result.client = deriveSecret(h, handshakeSecret, "c hs traffic", helloHash)
  result.server = deriveSecret(h, handshakeSecret, "s hs traffic", helloHash)

proc applicationTrafficSecrets*(h: TlsHash, masterSecret,
                                handshakeHash: openArray[byte]): tuple[
    client, server, exporter, resumption: seq[byte]] =
  result.client = deriveSecret(h, masterSecret, "c ap traffic", handshakeHash)
  result.server = deriveSecret(h, masterSecret, "s ap traffic", handshakeHash)
  result.exporter = deriveSecret(h, masterSecret, "exp master", handshakeHash)
  result.resumption = deriveSecret(h, masterSecret, "res master", handshakeHash)

proc ratchetSecret*(h: TlsHash, secret: openArray[byte]): seq[byte] =
  ## KeyUpdate: next traffic secret (RFC 8446 S4.6.3).
  hkdfExpandLabel(h, secret, "traffic upd", [], h.hashLen)
