# TLS client/server configuration.
#
# SPDX-License-Identifier: BSD-2-Clause

import ./enums
import ./verify

type
  ClientConfig* = object
    suites*: seq[CipherSuiteId]
    groups*: seq[NamedGroup]
    sigSchemes*: seq[SignatureScheme]
    alpn*: seq[string]
    roots*: TrustStore

proc defaultClientConfig*(): ClientConfig =
  result.suites = @[TlsAes128GcmSha256, TlsAes256GcmSha384,
                    TlsChacha20Poly1305Sha256]
  result.groups = @[ngX25519, ngSecp256r1]
  result.sigSchemes = @[ssEcdsaSecp256r1Sha256, ssEcdsaSecp384r1Sha384,
                        ssEcdsaSecp521r1Sha512, ssRsaPssRsaeSha256,
                        ssRsaPssRsaeSha384, ssRsaPssRsaeSha512, ssEd25519]
  result.alpn = @["h2", "http/1.1"]
  result.roots = loadSystemRoots()

proc defaultClientConfigWithRoots*(roots: TrustStore): ClientConfig =
  result = defaultClientConfig()
  result.roots = roots

type
  ServerConfig* = object
    suites*: seq[CipherSuiteId]
    groups*: seq[NamedGroup]
    sigSchemes*: seq[SignatureScheme]
    alpn*: seq[string]

proc defaultServerConfig*(): ServerConfig =
  result.suites = @[TlsAes128GcmSha256, TlsAes256GcmSha384,
                    TlsChacha20Poly1305Sha256]
  result.groups = @[ngX25519, ngSecp256r1]
  result.sigSchemes = @[ssRsaPssRsaeSha256, ssRsaPssRsaeSha384,
                        ssRsaPssRsaeSha512, ssEcdsaSecp256r1Sha256,
                        ssEcdsaSecp384r1Sha384, ssEcdsaSecp521r1Sha512,
                        ssEd25519]
  result.alpn = @["h2", "http/1.1"]
