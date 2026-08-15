# High-level signing API: EdDSA signing key pairs, sign and verify.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps

import std/sysrand

import nimcypher/algos/eddsa as eddsaAlgo

import ./utils
import ./secret

type
  SigningKeyPair* = object
    publicKey*: PublicKey
      ## The 32-byte public key, derived from the secret key. Share this
      ## to let others verify your signatures.
    secretKey*: Secret[SecretKey]
      ## The 64-byte secret key: the 32-byte seed followed by the 32-byte
      ## public key. Never share this. Wiped automatically when the key
      ## pair goes out of scope.

proc generateSigningKeyPair*(seed: Seed32): SigningKeyPair =
  ## Generate an EdDSA signing key pair from a 32-byte seed.
  let (secretKey, publicKey) = eddsaAlgo.eddsaKeyPair(seed)
  result.secretKey = secret(secretKey)
  result.publicKey = publicKey

proc generateSigningKeyPair*(): SigningKeyPair =
  ## Generate an EdDSA signing key pair with a random seed.
  generateSigningKeyPair(randomBytes[32]())

proc sign*(secretKey: Secret[SecretKey], message: openArray[byte]): Signature =
  ## Sign a message with the secret key.
  eddsaAlgo.eddsaSign(message, secretKey.data)

proc sign*(secretKey: Secret[SecretKey], message: string): Signature =
  sign(secretKey, toBytes(message))

proc sign*(secretKey: SecretKey, message: openArray[byte]): Signature =
  ## Sign a message with a raw secret key.
  eddsaAlgo.eddsaSign(message, secretKey)

proc sign*(secretKey: SecretKey, message: string): Signature =
  sign(secretKey, toBytes(message))

proc verify*(publicKey: PublicKey, message: openArray[byte],
             signature: Signature): bool =
  ## Verify a signature against the message and public key.
  eddsaAlgo.eddsaCheck(signature, publicKey, message)

proc verify*(publicKey: PublicKey, message: string,
             signature: Signature): bool =
  verify(publicKey, toBytes(message), signature)

# Hex encoding helpers
proc publicKeyToHex*(k: PublicKey): string = toHex(k)
proc secretKeyToHex*(k: SecretKey): string = toHex(k)
proc secretKeyToHex*(k: Secret[SecretKey]): string = toHex(k.data)
proc signatureToHex*(s: Signature): string = toHex(s)

proc publicKeyFromHex*(s: string): PublicKey =
  if s.len != 64:
    raise newException(ValueError, "Public key must be 64 hex chars")
  fromHex[32, uint8](s)

proc secretKeyFromHex*(s: string): SecretKey =
  if s.len != 128:
    raise newException(ValueError, "Secret key must be 128 hex chars")
  fromHex[64, uint8](s)

proc signatureFromHex*(s: string): Signature =
  if s.len != 128:
    raise newException(ValueError, "Signature must be 128 hex chars")
  fromHex[64, uint8](s)
