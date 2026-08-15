# High-level password hashing and key derivation: Argon2id.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps

import std/strutils

import nimcypher/algos/argon2 as argon2Algo

import ./utils
import ./encrypt
import ./secret

const
  HashLen = 32
  SaltLen = 16

when defined(e2eeFastTests):
  const
    Argon2Blocks = 32'u32 # fast test mode
    Argon2Passes = 1'u32
else:
  const
    Argon2Blocks = 1024'u32 # production defaults
    Argon2Passes = 3'u32

proc argon2Config(): argon2Algo.Argon2Config {.inline.} =
  result.algorithm = argon2Algo.Argon2Algorithm.id
  result.nbBlocks = Argon2Blocks
  result.nbPasses = Argon2Passes
  result.nbLanes = 1

proc hashPassword*(password: string): string =
  ## Hash a password for storage using Argon2id.
  ## Returns "hex(salt):hex(hash)".
  let salt = generateSalt(SaltLen)
  let hash = argon2Algo.argon2(argon2Config(), HashLen, toBytes(password), salt)
  result = toHex(salt) & ":" & toHex(hash)

proc verifyPassword*(password, stored: string): bool =
  ## Verify a password against a stored "hex(salt):hex(hash)" string.
  let parts = stored.split(":")
  if parts.len != 2 or parts[0].len != SaltLen * 2 or parts[1].len != HashLen * 2:
    return false
  let salt = fromHex[SaltLen, uint8](parts[0])
  let expected = fromHex[HashLen, uint8](parts[1])
  let hash = argon2Algo.argon2(argon2Config(), HashLen, toBytes(password), salt)
  result = constantTimeEqual(hash, expected)

proc deriveKeyFromPassword*(password: string, salt: RandomBytes): Secret[Key32] =
  ## Derive a 32-byte key from a password and salt using Argon2id.
  ## The derived key is wiped automatically when it goes out of scope.
  var derived = argon2Algo.argon2(argon2Config(), 32, toBytes(password), salt)
  result = secret(toArray[32](derived))
  wipe(derived)

proc keyPairFromPassword*(password: string, salt: RandomBytes):
    (Secret[Key32], Key32) =
  ## Derive an X25519 key pair from a password and salt.
  ## Returns (secret, publicKey); the secret is wiped on scope exit.
  let secretKey = deriveKeyFromPassword(password, salt)
  let (rawSecret, publicKey) = x25519KeyPair(secretKey.data)
  result = (secret(rawSecret), publicKey)
