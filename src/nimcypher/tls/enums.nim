# TLS 1.3 protocol enums (RFC 8446).
#
# Fresh implementation from the RFC wire values; module boundaries are
# inspired by rustls (msgs/enums.rs, suites.rs, versions.rs) with no
# code copied.
#
# SPDX-License-Identifier: BSD-2-Clause

type
  TlsVersion* = enum
    Tls12 = 0x0303
    Tls13 = 0x0304

  ContentType* = enum
    ctInvalid = 0
    ctChangeCipherSpec = 20
    ctAlert = 21
    ctHandshake = 22
    ctApplicationData = 23

  HandshakeType* = enum
    htClientHello = 1
    htServerHello = 2
    htNewSessionTicket = 4
    htEndOfEarlyData = 5
    htEncryptedExtensions = 8
    htCertificate = 11
    htCertificateRequest = 13
    htCertificateVerify = 15
    htFinished = 20
    htKeyUpdate = 24
    htMessageHash = 254

  CipherSuiteId* = enum
    TlsAes128GcmSha256 = 0x1301
    TlsAes256GcmSha384 = 0x1302
    TlsChacha20Poly1305Sha256 = 0x1303

  ExtensionType* = enum
    extServerName = 0
    extSupportedGroups = 10
    extSignatureAlgorithms = 13
    extAlpn = 16
    extPreSharedKey = 41
    extEarlyData = 42
    extSupportedVersions = 43
    extCookie = 44
    extPskKeyExchangeModes = 45
    extKeyShare = 51

  NamedGroup* = enum
    ngSecp256r1 = 23
    ngSecp384r1 = 24
    ngSecp521r1 = 25
    ngX25519 = 29

  SignatureScheme* = enum
    ssEcdsaSecp256r1Sha256 = 0x0403
    ssEcdsaSecp384r1Sha384 = 0x0503
    ssEcdsaSecp521r1Sha512 = 0x0603
    ssRsaPssRsaeSha256 = 0x0804
    ssRsaPssRsaeSha384 = 0x0805
    ssRsaPssRsaeSha512 = 0x0806
    ssEd25519 = 0x0807

  AlertDescription* = enum
    adCloseNotify = 0
    adUnexpectedMessage = 10
    adBadRecordMac = 20
    adRecordOverflow = 22
    adHandshakeFailure = 40
    adBadCertificate = 42
    adCertificateExpired = 45
    adIllegalParameter = 47
    adDecodeError = 50
    adDecryptError = 51
    adProtocolVersion = 70
    adInternalError = 80
    adMissingExtension = 109
    adUnsupportedExtension = 110

func cipherHashLen*(s: CipherSuiteId): int =
  ## Hash length for the suite's HKDF hash (RFC 8446 S7.2).
  case s
  of TlsAes128GcmSha256, TlsChacha20Poly1305Sha256: 32
  of TlsAes256GcmSha384: 48

func cipherKeyLen*(s: CipherSuiteId): int =
  ## AEAD key length for the suite.
  case s
  of TlsAes128GcmSha256: 16
  of TlsAes256GcmSha384, TlsChacha20Poly1305Sha256: 32

const
  TlsIvLen* = 12
  TlsFinishedKeyLabel* = "finished"
  TlsDerivedLabel* = "derived"
  TlsKeyLabel* = "key"
  TlsIvLabel* = "iv"
