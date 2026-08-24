# High-level AES API: AES-128/192/256 with ECB/CBC/CTR/CFB/OFB/GCM.
#
# Wraps the constant-time bitsliced core (`nimcypher/algos/aes`) and its
# GCM construction (`nimcypher/algos/gcm`); builds compiled with the
# `nimsimd` feature automatically use the AES-NI / CLMUL kernels.
#
# Modes at a glance:
# - GCM: authenticated encryption. Prefer it for new designs. Use a fresh
#   random 12-byte nonce per message under a given key (gcmSeal does).
# - CTR/OFB/CFB: stream modes. Reusing a nonce/IV with the same key breaks
#   confidentiality catastrophically.
# - CBC: requires an unpredictable IV and authentication (pair it with a
#   MAC or use GCM instead).
# - ECB: insecure for structured data; kept for interop only. Inputs are
#   PKCS#7-padded by default.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps

import std/options

import nimcypher/algos/aes as aesAlgo
import nimcypher/algos/gcm as gcmAlgo

import ./utils

type
  AesKey128* = array[16, uint8]
  AesKey192* = array[24, uint8]
  AesKey256* = array[32, uint8]
  IvBlock* = array[16, uint8]
  Nonce12* = array[12, uint8]
  Tag16* = array[16, uint8]

  GcmSealed* = object
    ## A sealed message: random 96-bit nonce, auth tag, ciphertext.
    nonce*: Nonce12
    tag*: Tag16
    cipherText*: seq[uint8]

func checkKey(key: openArray[byte]) =
  if key.len notin [16, 24, 32]:
    raise newException(ValueError,
      "invalid AES key length: expected 16, 24 or 32 bytes, got " & $key.len)

func toArray16(b: openArray[byte]): IvBlock =
  if b.len != 16:
    raise newException(ValueError, "expected a 16-byte IV/counter block")
  copyMem(addr result[0], unsafeAddr b[0], 16)

func toArray12(b: openArray[byte]): Nonce12 =
  if b.len != 12:
    raise newException(ValueError, "expected a 12-byte GCM nonce")
  copyMem(addr result[0], unsafeAddr b[0], 12)

# ---------------------------------------------------------------------------
# ECB
# ---------------------------------------------------------------------------

proc aesEcbEncrypt*(key: openArray[byte], text: openArray[byte],
                    padded = true): seq[byte] =
  ## AES-ECB encryption. PKCS#7-pads by default; set `padded = false` for
  ## raw block-for-block encryption (length must be a multiple of 16).
  checkKey(key)
  let ctx = aesAlgo.initAes(key)
  if padded:
    result = aesAlgo.ecbEncrypt(ctx, pkcs7Pad(text))
  else:
    result = aesAlgo.ecbEncrypt(ctx, text)

proc aesEcbDecrypt*(key: openArray[byte], data: openArray[byte],
                    padded = true): seq[byte] =
  ## AES-ECB decryption (strips PKCS#7 padding by default).
  checkKey(key)
  let ctx = aesAlgo.initAes(key)
  if padded:
    result = aesAlgo.pkcs7Unpad(aesAlgo.ecbDecrypt(ctx, data))
  else:
    result = aesAlgo.ecbDecrypt(ctx, data)

# ---------------------------------------------------------------------------
# CBC
# ---------------------------------------------------------------------------

proc aesCbcEncrypt*(key: openArray[byte], iv: openArray[byte],
                    text: openArray[byte], padded = true): seq[byte] =
  ## AES-CBC encryption with a 16-byte IV. PKCS#7-pads by default.
  checkKey(key)
  let ctx = aesAlgo.initAes(key)
  if padded:
    result = aesAlgo.cbcEncryptOne(ctx, toArray16(iv), pkcs7Pad(text))
  else:
    result = aesAlgo.cbcEncryptOne(ctx, toArray16(iv), text)

proc aesCbcDecrypt*(key: openArray[byte], iv: openArray[byte],
                    data: openArray[byte], padded = true): seq[byte] =
  ## AES-CBC decryption (strips PKCS#7 padding by default). CBC provides no
  ## authentication; pair it with a MAC or prefer `aesGcmEncrypt`.
  checkKey(key)
  let ctx = aesAlgo.initAes(key)
  if padded:
    result = aesAlgo.pkcs7Unpad(aesAlgo.cbcDecryptOne(ctx, toArray16(iv), data))
  else:
    result = aesAlgo.cbcDecryptOne(ctx, toArray16(iv), data)

# ---------------------------------------------------------------------------
# Stream modes: CTR, OFB, CFB
# ---------------------------------------------------------------------------

proc aesCtrCrypt*(key: openArray[byte], counter: openArray[byte],
                  text: openArray[byte]): seq[byte] =
  ## AES-CTR encryption/decryption (identical operation). The whole 16-byte
  ## counter block increments big-endian per block. Never reuse a counter
  ## block with the same key.
  checkKey(key)
  let ctx = aesAlgo.initAes(key)
  result = aesAlgo.ctrCryptOne(ctx, toArray16(counter), text)

proc aesOfbCrypt*(key: openArray[byte], iv: openArray[byte],
                  text: openArray[byte]): seq[byte] =
  ## AES-OFB encryption/decryption (identical operation). Never reuse an
  ## IV with the same key.
  checkKey(key)
  let ctx = aesAlgo.initAes(key)
  result = aesAlgo.ofbCryptOne(ctx, toArray16(iv), text)

proc aesCfbEncrypt*(key: openArray[byte], iv: openArray[byte],
                    text: openArray[byte]): seq[byte] =
  ## AES-CFB (CFB128) encryption. Never reuse an IV with the same key.
  checkKey(key)
  let ctx = aesAlgo.initAes(key)
  result = aesAlgo.cfbEncryptOne(ctx, toArray16(iv), text)

proc aesCfbDecrypt*(key: openArray[byte], iv: openArray[byte],
                    data: openArray[byte]): seq[byte] =
  ## AES-CFB (CFB128) decryption.
  checkKey(key)
  let ctx = aesAlgo.initAes(key)
  result = aesAlgo.cfbDecryptOne(ctx, toArray16(iv), data)

# ---------------------------------------------------------------------------
# GCM (authenticated encryption)
# ---------------------------------------------------------------------------

proc aesGcmEncrypt*(key: openArray[byte], nonce: openArray[byte],
                    text: openArray[byte],
                    ad: openArray[byte] = []): (seq[byte], Tag16) =
  ## AES-GCM authenticated encryption. Returns (ciphertext, 16-byte tag).
  ## Use a unique nonce per message under a given key.
  checkKey(key)
  let (ct, tag) = gcmAlgo.gcmLock(key, nonce, text, ad)
  var t: Tag16
  copyMem(addr t[0], unsafeAddr tag[0], 16)
  result = (ct, t)

proc aesGcmDecrypt*(key: openArray[byte], nonce: openArray[byte],
                    cipherText: openArray[byte], tag: openArray[byte],
                    ad: openArray[byte] = []): seq[byte] =
  ## AES-GCM authenticated decryption. Raises ValueError when the tag does
  ## not verify; never returns partial plaintext.
  checkKey(key)
  let plain = gcmAlgo.gcmUnlock(key, nonce, cipherText, tag, ad)
  if plain.isNone:
    raise newException(ValueError, "decryption failed or tag verification failed")
  result = plain.get

proc gcmSeal*(text: openArray[byte], key: openArray[byte],
              ad: openArray[byte] = []): GcmSealed =
  ## Encrypt `text` with a fresh random 96-bit nonce.
  let nonce = randomBytes[12]()
  let (ct, tag) = aesGcmEncrypt(key, nonce, text, ad)
  result = GcmSealed(nonce: nonce, tag: tag, cipherText: ct)

proc gcmSeal*(text: string, key: openArray[byte],
              ad: openArray[byte] = []): GcmSealed =
  gcmSeal(toBytes(text), key, ad)

proc gcmOpen*(msg: GcmSealed, key: openArray[byte],
              ad: openArray[byte] = []): seq[byte] =
  ## Decrypt a sealed message. Raises ValueError when the tag fails.
  aesGcmDecrypt(key, msg.nonce, msg.cipherText, msg.tag, ad)

# Convenience: string in / string out variants

proc aesGcmEncryptStr*(key: openArray[byte], nonce: openArray[byte],
                       text: string,
                       ad: openArray[byte] = []): (seq[byte], Tag16) =
  aesGcmEncrypt(key, nonce, toBytes(text), ad)

proc aesGcmDecryptStr*(key: openArray[byte], nonce: openArray[byte],
                       cipherText: openArray[byte], tag: openArray[byte],
                       ad: openArray[byte] = []): string =
  toString(aesGcmDecrypt(key, nonce, cipherText, tag, ad))

proc gcmOpenStr*(msg: GcmSealed, key: openArray[byte],
                 ad: openArray[byte] = []): string =
  toString(gcmOpen(msg, key, ad))

# ---------------------------------------------------------------------------
# Streaming GCM
# ---------------------------------------------------------------------------

type
  AesGcmStream* = object
    ctx: gcmAlgo.GcmContext
    encrypting: bool
    done: bool

proc gcmStreamInit*(key: openArray[byte], nonce: openArray[byte],
                    ad: openArray[byte] = [], encrypting: bool): AesGcmStream =
  ## Initialize a streaming GCM context. Associated data must be given up
  ## front (as with one-shot GCM).
  checkKey(key)
  initGcm(result.ctx, key, nonce)
  if ad.len > 0:
    gcmAddAad(result.ctx, ad)
  else:
    gcmAddAad(result.ctx, [])
  result.encrypting = encrypting

proc gcmStreamUpdate*(s: var AesGcmStream, chunk: openArray[byte]): seq[byte] =
  ## Process the next chunk (plaintext while encrypting, ciphertext while
  ## decrypting). Decryption output must not be trusted until the stream
  ## finishes successfully.
  if s.done:
    raise newException(ValueError, "GCM stream already finished")
  if s.encrypting:
    result = gcmEncryptUpdate(s.ctx, chunk)
  else:
    result = gcmDecryptUpdate(s.ctx, chunk)

proc gcmStreamFinal*(s: var AesGcmStream): Tag16 =
  ## Finish an encryption stream and return the tag. Wipes the context.
  if not s.encrypting:
    raise newException(ValueError, "not an encryption stream")
  s.done = true
  result = gcmFinishEnc(s.ctx)

proc gcmStreamVerify*(s: var AesGcmStream, tag: openArray[byte]): bool =
  ## Finish a decryption stream, verifying the expected tag. Wipes the
  ## context either way.
  if s.encrypting:
    raise newException(ValueError, "not a decryption stream")
  s.done = true
  gcmFinishDec(s.ctx, tag)
