# TLS 1.3 record layer (RFC 8446 S5).
#
# Fresh implementation from the RFC; behavior cross-checked against
# rustls conn/ + openssl s_server interop (no code copied).
#
# SPDX-License-Identifier: BSD-2-Clause

import std/options

import ./enums
import ./codec
import ./aead
import ./key_schedule

const
  TlsLegacyVersion*: uint16 = 0x0303
  TlsMaxFragment* = 16384
  TlsMaxRecordOverhead* = 256

type
  TlsTrafficKeys* = object
    suite*: CipherSuiteId
    key*: seq[byte]
    iv*: array[12, byte]
    seqNum*: uint64
    secret*: seq[byte] # empty when built from raw key/iv (no ratchet)

proc initTrafficKeys*(suite: CipherSuiteId, key: openArray[byte],
                      iv: openArray[byte]): TlsTrafficKeys =
  if iv.len != TlsIvLen:
    raise newException(ValueError, "TLS IV must be 12 bytes")
  if key.len != suite.cipherKeyLen:
    raise newException(ValueError, "TLS key length mismatch for suite")
  result.suite = suite
  result.key = @key
  for i in 0 ..< 12: result.iv[i] = iv[i]
  result.seqNum = 0

proc initTrafficKeysFromSecret*(suite: CipherSuiteId,
                                secret: openArray[byte]): TlsTrafficKeys =
  let h = hashOfSuite(suite)
  let (key, iv) = deriveTrafficKeys(h, secret, suite.cipherKeyLen, TlsIvLen)
  result.suite = suite
  result.key = key
  for i in 0 ..< 12: result.iv[i] = iv[i]
  result.seqNum = 0
  result.secret = @secret

proc ratchet*(keys: var TlsTrafficKeys) =
  ## KeyUpdate rollover: secret <- Expand-Label(secret, "traffic upd"),
  ## fresh key/iv, sequence reset (RFC 8446 S4.6.3 / S7.2).
  if keys.secret.len == 0:
    raise newException(ValueError, "cannot ratchet keys without a secret")
  let h = hashOfSuite(keys.suite)
  let next = ratchetSecret(h, keys.secret)
  let (key, iv) = deriveTrafficKeys(h, next, keys.suite.cipherKeyLen,
                                    TlsIvLen)
  keys.secret = next
  keys.key = key
  for i in 0 ..< 12: keys.iv[i] = iv[i]
  keys.seqNum = 0

proc encodePlaintext*(outerType: ContentType,
                      fragment: openArray[byte]): seq[byte] =
  ## Unprotected TLSPlaintext record (handshake, alerts, CCS).
  if fragment.len > TlsMaxFragment:
    raise newException(ValueError, "TLS fragment too large")
  result = @[byte(ord(outerType)), byte(TlsLegacyVersion shr 8),
             byte(TlsLegacyVersion and 0xFF),
             byte(fragment.len shr 8), byte(fragment.len and 0xFF)]
  for b in fragment: result.add(b)

proc sealCcs*(): seq[byte] =
  ## Middlebox-compat dummy ChangeCipherSpec (RFC 8446 D.4).
  encodePlaintext(ctChangeCipherSpec, [byte 1])

func isCcsRecord*(packet: openArray[byte]): bool =
  packet.len == 6 and packet[0] == byte(ord(ctChangeCipherSpec)) and
    packet[3] == 0 and packet[4] == 1 and packet[5] == 1

proc sealAlertFatal*(desc: AlertDescription): seq[byte] =
  encodePlaintext(ctAlert, [byte 2, byte(ord(desc))])

func tlsNonce*(iv: array[12, byte], seqNum: uint64): array[12, byte] =
  ## RFC 8446 S5.3: nonce = left-pad(iv) XOR seqNum (big-endian, 8 bytes).
  result = iv
  for i in 0 ..< 8:
    result[4 + i] = result[4 + i] xor byte((seqNum shr (8 * (7 - i))) and 0xFF)

proc sealRecord*(keys: var TlsTrafficKeys, content: openArray[byte],
                 innerType: ContentType): seq[byte] =
  ## Protect one record. Outer type is always application_data (S5.2).
  ## Inner plaintext = content || innerType || zeros (no padding here).
  if content.len > TlsMaxFragment:
    raise newException(ValueError, "TLS fragment too large")
  if keys.seqNum == high(uint64):
    raise newException(ValueError, "TLS sequence number exhausted (KeyUpdate needed)")
  var inner = newSeq[byte](content.len + 1)
  for i, b in content: inner[i] = b
  inner[content.len] = byte(ord(innerType))
  let nonce = tlsNonce(keys.iv, keys.seqNum)
  # AD is the 5-byte outer header with the encrypted length.
  let ctLen = inner.len + TlsTagLen
  var ad: array[5, byte]
  ad[0] = byte(ord(ctApplicationData))
  ad[1] = byte(TlsLegacyVersion shr 8)
  ad[2] = byte(TlsLegacyVersion and 0xFF)
  ad[3] = byte(ctLen shr 8)
  ad[4] = byte(ctLen and 0xFF)
  let (ct, tag) = tlsSeal(keys.suite, keys.key, nonce, inner, ad)
  result = newSeq[byte](5 + ct.len + TlsTagLen)
  result[0] = ad[0]; result[1] = ad[1]; result[2] = ad[2]
  result[3] = ad[3]; result[4] = ad[4]
  for i, b in ct: result[5 + i] = b
  for i in 0 ..< TlsTagLen: result[5 + ct.len + i] = tag[i]
  inc keys.seqNum

proc openRecord*(keys: var TlsTrafficKeys,
                 packet: openArray[byte]): tuple[
    content: seq[byte], innerType: ContentType] =
  ## Open one record. Strips inner padding zeros, returns inner type.
  if packet.len < 5 + TlsTagLen:
    raise newException(ValueError, "TLS record too short")
  if byte(ord(ctApplicationData)) != packet[0]:
    raise newException(ValueError, "TLS 1.3 outer type must be application_data")
  let wireVer = (uint16(packet[1]) shl 8) or uint16(packet[2])
  if wireVer != TlsLegacyVersion:
    raise newException(ValueError, "TLS legacy version must be 0x0303")
  let recLen = (int(packet[3]) shl 8) or int(packet[4])
  if recLen != packet.len - 5:
    raise newException(ValueError, "TLS record length mismatch")
  if recLen > TlsMaxFragment + TlsMaxRecordOverhead:
    raise newException(ValueError, "TLS record overflow")
  let ctLen = recLen - TlsTagLen
  let nonce = tlsNonce(keys.iv, keys.seqNum)
  var ad: array[5, byte]
  for i in 0 ..< 5: ad[i] = packet[i]
  let plainOpt = tlsOpen(keys.suite, keys.key, nonce,
    packet.toOpenArray(5, 5 + ctLen - 1),
    packet.toOpenArray(5 + ctLen, packet.len - 1), ad)
  if plainOpt.isNone:
    raise newException(ValueError, "TLS bad record MAC")
  let inner = plainOpt.get
  if inner.len < 1:
    raise newException(ValueError, "TLS empty inner plaintext")
  # Strip zero padding from the end; first non-zero from the right is the type.
  var typeIdx = inner.high
  while typeIdx > 0 and inner[typeIdx] == 0:
    dec typeIdx
  let itype = inner[typeIdx]
  if itype == 0:
    raise newException(ValueError, "TLS invalid inner content type")
  result.content = inner[0 ..< typeIdx]
  result.innerType = ContentType(itype)
  inc keys.seqNum
