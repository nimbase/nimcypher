# High-level encryption API: XChaCha20-Poly1305 AEAD, sealing, streaming,
# and X25519 key exchange.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps

import std/options
import std/sysrand

import nimcypher/algos/aead as aeadAlgo
import nimcypher/algos/x25519 as xAlgo
import nimcypher/algos/blake2b as blakeAlgo

import ./utils
import ./secret

type
  SealedMessage* = object
    nonce*: Nonce24
    mac*: Mac16
    cipherText*: seq[uint8]

  AeadStreamMode* = enum
    ## The AEAD mode to use for streaming. Each mode corresponds to a
    ## different nonce size.
    aeadX, aeadDjb, aeadIetf

  AeadStream* = object
    ctx: aeadAlgo.AeadContext
    mode: AeadStreamMode

# One-shot AEAD (XChaCha20-Poly1305)
proc encrypt*(text: openArray[byte], key: Key32,
              nonce: Nonce24): (seq[uint8], Mac16) =
  ## Encrypt and authenticate `text`. Returns (cipherText, mac).
  aeadAlgo.aeadLock(key, nonce, text)

proc encrypt*(text: string, key: Key32,
              nonce: Nonce24): (seq[uint8], Mac16) =
  encrypt(toBytes(text), key, nonce)

proc decrypt*(cipherText: openArray[byte], mac: Mac16, key: Key32,
              nonce: Nonce24): seq[byte] =
  ## Authenticate and decrypt `cipherText`. Raises ValueError if the MAC
  ## does not verify.
  let plain = aeadAlgo.aeadUnlock(key, nonce, cipherText, mac)
  if plain.isNone:
    raise newException(ValueError, "decryption failed or MAC verification failed")
  result = plain.get

proc decrypt*(cipherText: string, mac: Mac16, key: Key32,
              nonce: Nonce24): string =
  toString(decrypt(toBytes(cipherText), mac, key, nonce))

# Sealing with a random nonce
proc seal*(plainText: openArray[byte], key: Key32): SealedMessage =
  ## Encrypt `plainText` with a fresh random nonce.
  let nonce = randomBytes[24]()
  let (cipherText, mac) = encrypt(plainText, key, nonce)
  result = SealedMessage(nonce: nonce, mac: mac, cipherText: cipherText)

proc seal*(plainText: string, key: Key32): SealedMessage =
  seal(toBytes(plainText), key)

proc unseal*(msg: SealedMessage, key: Key32): seq[byte] =
  ## Decrypt a sealed message. Raises ValueError if the MAC does not verify.
  decrypt(msg.cipherText, msg.mac, key, msg.nonce)

# Streaming AEAD
proc aeadStreamInit*(mode: AeadStreamMode, key: Key32,
                     nonce: openArray[uint8]): AeadStream =
  ## Initialize a streaming AEAD context for the given mode.
  var ctx: aeadAlgo.AeadContext
  case mode
  of aeadX:
    if nonce.len != 24:
      raise newException(ValueError,
        "AEAD stream (XChaCha20) requires a 24-byte nonce")
    aeadAlgo.initX(ctx, key, toArray[24](nonce))
  of aeadDjb:
    if nonce.len != 8:
      raise newException(ValueError,
        "AEAD stream (ChaCha20-DJB) requires an 8-byte nonce")
    aeadAlgo.initDjb(ctx, key, toArray[8](nonce))
  of aeadIetf:
    if nonce.len != 12:
      raise newException(ValueError,
        "AEAD stream (ChaCha20-IETF) requires a 12-byte nonce")
    aeadAlgo.initIetf(ctx, key, toArray[12](nonce))
  result = AeadStream(ctx: ctx, mode: mode)

proc aeadStreamInitX*(key: Key32, nonce: Nonce24): AeadStream =
  var ctx: aeadAlgo.AeadContext
  aeadAlgo.initX(ctx, key, nonce)
  result = AeadStream(ctx: ctx, mode: aeadX)

proc aeadStreamInitDjb*(key: Key32, nonce: array[8, uint8]): AeadStream =
  var ctx: aeadAlgo.AeadContext
  aeadAlgo.initDjb(ctx, key, nonce)
  result = AeadStream(ctx: ctx, mode: aeadDjb)

proc aeadStreamInitIetf*(key: Key32, nonce: array[12, uint8]): AeadStream =
  var ctx: aeadAlgo.AeadContext
  aeadAlgo.initIetf(ctx, key, nonce)
  result = AeadStream(ctx: ctx, mode: aeadIetf)

proc aeadStreamWrite*(stream: var AeadStream, plainText: openArray[byte],
                      ad: openArray[byte] = []): (seq[uint8], Mac16) =
  ## Encrypt and authenticate one chunk, rekeying the stream for the next.
  aeadAlgo.write(stream.ctx, plainText, ad)

proc aeadStreamRead*(stream: var AeadStream, cipherText: openArray[byte],
                     mac: Mac16, ad: openArray[byte] = []): seq[byte] =
  ## Authenticate and decrypt one chunk. Raises ValueError on failure.
  let plain = aeadAlgo.read(stream.ctx, cipherText, mac, ad)
  if plain.isNone:
    raise newException(ValueError, "AEAD stream decryption failed or MAC verification failed")
  result = plain.get

# X25519 key exchange
proc x25519KeyPair*(secret: Key32): (Key32, Key32) =
  ## Generate an X25519 key pair from a secret. Returns (secret, publicKey).
  result = (secret, xAlgo.x25519PublicKey(secret))

proc x25519KeyPair*(): (Key32, Key32) =
  ## Generate an X25519 key pair with a random secret. Returns (secret, publicKey).
  let secret = randomBytes[32]()
  result = x25519KeyPair(secret)

proc sharedSecret*(mySecret: Key32, theirPublic: Key32): Secret[Key32] =
  ## Compute the X25519 shared secret. Hash it to derive a symmetric key.
  ## The shared secret is wiped automatically when it goes out of scope.
  secret(xAlgo.x25519(mySecret, theirPublic))

# Challenge-response MAC for mutual authentication
proc computeChallengeMac*(secret: Key32, challenge: Mac16): Mac16 =
  ## Compute a keyed BLAKE2b MAC of the challenge using the shared secret.
  let mac = blakeAlgo.keyedBlake2b(challenge, secret, 16)
  for i in 0 ..< 16:
    result[i] = mac[i]

proc verifyChallengeMac*(secret: Key32, challenge: Mac16,
                         received: Mac16): bool =
  ## Verify the received MAC against the expected MAC.
  constantTimeEqual(computeChallengeMac(secret, challenge), received)
