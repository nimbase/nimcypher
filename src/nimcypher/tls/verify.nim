# X.509 path validation for TLS clients (RFC 5280 + RFC 6125 S6.4).
#
# Validates leaf -> intermediates -> trusted root: signatures, validity
# periods, basicConstraints (CA + pathLen), keyUsage, EKU serverAuth,
# and dNSName/CN hostname matching with single-label wildcards.
# Out of scope for v1: CRL/OCSP, name constraints, policies, IDNA.
#
# SPDX-License-Identifier: BSD-2-Clause

import std/os
import std/times
import std/strutils

import ./x509
import ./pem
import ./asn1
import ./codec

const
  KuDigitalSignature* = 0x8000'u16
  KuKeyCertSign* = 0x0400'u16
  KuCrlSign* = 0x0200'u16
  MaxChainLen* = 10

type
  TrustStore* = object
    roots*: seq[Certificate]

proc addDer*(store: var TrustStore, der: openArray[byte]) =
  store.roots.add(parseCertificate(der))

proc addPemFile*(store: var TrustStore, path: string) =
  for der in pemParseFile(path):
    store.roots.add(parseCertificate(der))

proc addPemDir*(store: var TrustStore, dir: string) =
  for kind, path in walkDir(dir):
    if kind != pcFile: continue
    let lower = path.toLowerAscii()
    if lower.endsWith(".pem") or lower.endsWith(".crt") or
        lower.endsWith(".cer") or lower.endsWith(".der"):
      try:
        for der in pemParseFile(path):
          store.roots.add(parseCertificate(der))
      except ValueError, IOError:
        # A stray non-cert file (e.g. hashed-dir symlinks to CRLs or
        # private keys) must not poison the store; skip it.
        continue

proc systemTrustPaths*(): tuple[files, dirs: seq[string]] =
  when defined(macosx):
    result.files = @["/etc/ssl/cert.pem",
                     "/opt/homebrew/etc/openssl@3/cert.pem",
                     "/opt/local/etc/openssl/cert.pem"]
    result.dirs = @[]
  elif defined(windows):
    result.files = @[]
    result.dirs = @[]
  else:
    result.files = @["/etc/ssl/certs/ca-certificates.crt",
                     "/etc/pki/tls/certs/ca-bundle.crt",
                     "/etc/ssl/cert.pem"]
    result.dirs = @["/etc/ssl/certs"]

proc loadSystemRoots*(): TrustStore =
  let (files, dirs) = systemTrustPaths()
  for f in files:
    if fileExists(f):
      try: result.addPemFile(f)
      except ValueError, IOError: continue
  for d in dirs:
    if dirExists(d):
      result.addPemDir(d)

# --- hostname (RFC 6125 S6.4) ---

func asciiLower(s: string): string =
  result = newString(s.len)
  for i, c in s:
    result[i] = if c in {'A' .. 'Z'}: char(ord(c) + 32) else: c

func matchDnsPattern(pattern, host: string): bool =
  let p = asciiLower(pattern)
  let h = asciiLower(host)
  if p == "" or h == "" or p.contains("..") or h.contains(".."):
    return false
  if not p.startsWith("*."):
    return p == h
  # Wildcard: single leftmost label only, and the suffix past the
  # wildcard must itself contain a dot (never match a bare TLD).
  let suffix = p[1 .. ^1] # ".example.com"
  if '.' notin suffix[1 .. ^1]:
    return false
  if not h.endsWith(suffix):
    return false
  let left = h[0 ..< h.len - suffix.len]
  left.len > 0 and '.' notin left

proc verifyHostname*(cert: Certificate, hostname: string): bool =
  var host = hostname
  if host.endsWith("."): host = host[0 ..< ^1] # trailing-dot FQDN
  if host == "" or host.len > 253:
    return false
  for c in host:
    if ord(c) > 127:
      return false # no IDNA in v1; caller passes A-labels
  if cert.tbs.sanDns.len > 0:
    for dns in cert.tbs.sanDns:
      if matchDnsPattern(dns, host):
        return true
    return false
  matchDnsPattern(cert.tbs.subjectCn, host)

# --- chain ---

proc findIssuer*(candidates: openArray[Certificate],
                 issuerDer: openArray[byte]): int =
  for i, c in candidates:
    if c.tbs.subjectDer == issuerDer:
      return i
  -1

proc verifyChain*(leafDer: openArray[byte],
                  intermediatesDer: openArray[seq[byte]],
                  store: TrustStore, hostname: string,
                  now = getTime().toUnix()): bool =
  ## Full path validation. Returns false on any failure (no exceptions
  ## for bad chains; malformed DER still raises ValueError).
  if store.roots.len == 0 or hostname == "":
    return false
  let leaf = parseCertificate(leafDer)
  if leaf.tbs.isCa: # end entity must not assert CA
    return false
  if not (leaf.tbs.notBefore <= now and now <= leaf.tbs.notAfter):
    return false
  if leaf.tbs.hasKeyUsage and
      (leaf.tbs.keyUsage and KuDigitalSignature) == 0:
    return false
  if leaf.tbs.hasEku and not leaf.tbs.ekuServerAuth:
    return false
  if not verifyHostname(leaf, hostname):
    return false

  var intermediates: seq[Certificate]
  for der in intermediatesDer:
    intermediates.add(parseCertificate(der))

  var current = leaf
  var depth = 0
  var caBelow = 0 # number of CA certs below the prospective issuer
  while depth <= MaxChainLen:
    var idx = findIssuer(intermediates, current.tbs.issuerDer)
    var issuer: Certificate
    var fromStore = false
    if idx >= 0:
      issuer = intermediates[idx]
    else:
      idx = findIssuer(store.roots, current.tbs.issuerDer)
      if idx < 0:
        return false # no trust anchor
      issuer = store.roots[idx]
      fromStore = true
    if not (issuer.tbs.notBefore <= now and now <= issuer.tbs.notAfter):
      return false
    if not verifyCertSignature(current, issuer.tbs.spki):
      return false
    if fromStore:
      # Anchor reached. A root is trusted by store membership; its
      # self-signature is checked opportunistically but a store-listed
      # root with an unverifiable self-signature still anchors.
      if issuer.tbs.subjectDer == issuer.tbs.issuerDer:
        discard verifyCertSignature(issuer, issuer.tbs.spki)
      return true
    # Intermediate constraints.
    if not issuer.tbs.isCa:
      return false
    if issuer.tbs.hasKeyUsage and
        (issuer.tbs.keyUsage and KuKeyCertSign) == 0:
      return false
    if issuer.tbs.pathLen >= 0 and caBelow > issuer.tbs.pathLen:
      return false
    inc caBelow
    current = issuer
    inc depth
  false
