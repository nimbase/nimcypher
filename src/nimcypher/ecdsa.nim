# High-level ECDSA/ECDH API over NIST P-256/P-384/P-521 and secp256k1.
#
# Thin wrappers over `nimcypher/algos/ecdsa`. Signatures use deterministic
# nonces per RFC 6979; JWS format is `R || S` (fixed width). Call
# `wipeEcKey` explicitly when done with a private key.
#
# JOSE mapping (RFC 7518): ES256 = P-256/SHA-256, ES384 = P-384/SHA-384,
# ES512 = P-521/SHA-512, ES256K = secp256k1/SHA-256.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps

import nimcypher/algos/ecdsa as ecdsaAlgo
import nimcypher/algos/hkdf as hkdfAlgo

import ./utils

export ecdsaAlgo.EcCurve
export ecdsaAlgo.EcPrivateKey
export ecdsaAlgo.EcPublicKey

proc generateEcKeyPair*(curve: ecdsaAlgo.EcCurve):
    (ecdsaAlgo.EcPrivateKey, ecdsaAlgo.EcPublicKey) =
  ## Generate a fresh key pair with an OS-random secret in [1, n-1].
  ecdsaAlgo.generateKeyPair(curve)

proc ecPublicKeyFromPrivate*(priv: ecdsaAlgo.EcPrivateKey):
    ecdsaAlgo.EcPublicKey =
  ## Derive the public key from a private key.
  ecdsaAlgo.publicKeyFromPrivate(priv)

proc ecValidatePublicKey*(pub: ecdsaAlgo.EcPublicKey): bool =
  ## Check a peer public key is on the curve (and in the subgroup).
  ecdsaAlgo.validatePublicKey(pub)

proc wipeEcKey*(key: var ecdsaAlgo.EcPrivateKey) =
  ## Best-effort wipe (drops the scalar reference; see `algos/ecdsa.wipe`).
  ecdsaAlgo.wipe(key)

proc ecdsaSign*(priv: ecdsaAlgo.EcPrivateKey,
                msg: openArray[byte]): seq[byte] =
  ## ECDSA sign with RFC 6979 nonce. Returns `R || S` (coordLen each).
  ## Raises ValueError on invalid keys or on a degenerate deterministic
  ## nonce (probability ~2^-256 per key/message pair; deterministic, so
  ## retrying the same input cannot help --- treat as fatal).
  ecdsaAlgo.sign(priv, msg)

proc ecdsaSign*(priv: ecdsaAlgo.EcPrivateKey, msg: string): seq[byte] =
  ecdsaSign(priv, toBytes(msg))

proc ecdsaVerify*(pub: ecdsaAlgo.EcPublicKey, msg: openArray[byte],
                  sig: openArray[byte]): bool =
  ## ECDSA verify over a JWS `R || S` signature. False on any failure.
  ecdsaAlgo.verify(pub, msg, sig)

proc ecdsaVerify*(pub: ecdsaAlgo.EcPublicKey, msg: string,
                  sig: openArray[byte]): bool =
  ecdsaVerify(pub, toBytes(msg), sig)

proc ecdhSharedSecret*(priv: ecdsaAlgo.EcPrivateKey,
                       peer: ecdsaAlgo.EcPublicKey): seq[byte] =
  ## ECDH shared secret Z = x(d*Q) as coordLen big-endian bytes.
  ## Raises on curve mismatch, invalid peer, or infinity result.
  ## Raw key material: never use it directly as a symmetric key; pass
  ## it through `ecdhHashedSecret` (or another KDF) first.
  ecdsaAlgo.ecdh(priv, peer)

proc ecdhHashedSecret*(priv: ecdsaAlgo.EcPrivateKey,
                       peer: ecdsaAlgo.EcPublicKey,
                       info: openArray[byte] = []): array[32, byte] =
  ## ECDH shared secret run through HKDF-SHA-256 (empty salt, `info`
  ## as context). Use this instead of `ecdhSharedSecret` whenever the
  ## output keys symmetric encryption.
  let z = ecdsaAlgo.ecdh(priv, peer)
  var zz = z
  var okm = hkdfAlgo.sha256Hkdf(zz, [], info, 32)
  wipe(zz)
  for i in 0 ..< 32:
    result[i] = okm[i]
  wipe(okm)
