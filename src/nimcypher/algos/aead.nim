# Authenticated encryption (XChaCha20-Poly1305).
#
# Ported from `monocypher.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import std/options

import ./common
import ./chacha20
import ./poly1305

{.push checks: off.}

type
  AeadContext* = object
    counter*: uint64
    key*: array[32, byte]
    nonce*: array[8, byte]

proc lockAuth(authKey: array[32, byte], ad, cipherText: openArray[byte]):
    array[16, byte] =
  var sizes: array[16, byte]
  store64Le(cast[BytePtr](unsafeAddr sizes[0]), uint64(ad.len))
  store64Le(cast[BytePtr](unsafeAddr sizes[8]), uint64(cipherText.len))
  var polyCtx: Poly1305Context
  initPoly1305(polyCtx, authKey)
  update(polyCtx, ad)
  let adGap = gap(ad.len, 16)
  if adGap > 0:
    update(polyCtx, newSeq[byte](adGap))
  update(polyCtx, cipherText)
  let ctGap = gap(cipherText.len, 16)
  if ctGap > 0:
    update(polyCtx, newSeq[byte](ctGap))
  update(polyCtx, sizes)
  result = final(polyCtx)

proc initX*(ctx: var AeadContext, key: array[32, byte], nonce: array[24, byte]) =
  ## Initialize an AEAD context with XChaCha20 (192-bit nonce).
  var nonce16: array[16, byte]
  for i in 0 ..< 16:
    nonce16[i] = nonce[i]
  ctx.key = chacha20H(key, nonce16)
  for i in 0 ..< 8:
    ctx.nonce[i] = nonce[16 + i]
  ctx.counter = 0

proc initDjb*(ctx: var AeadContext, key: array[32, byte], nonce: array[8, byte]) =
  ## Initialize an AEAD context with the DJB variant of ChaCha20
  ## (64-bit nonce).
  ctx.key = key
  ctx.nonce = nonce
  ctx.counter = 0

proc initIetf*(ctx: var AeadContext, key: array[32, byte], nonce: array[12, byte]) =
  ## Initialize an AEAD context with the IETF variant of ChaCha20
  ## (96-bit nonce).
  ctx.key = key
  for i in 0 ..< 8:
    ctx.nonce[i] = nonce[4 + i]
  ctx.counter = uint64(load32Le(cast[BytePtr](unsafeAddr nonce[0]))) shl 32

proc write*(ctx: var AeadContext, plaintext, ad: openArray[byte]):
    (seq[byte], array[16, byte]) =
  ## Encrypt and authenticate a chunk of plaintext. Returns the ciphertext
  ## and a 16-byte MAC. Also rekeys the context for the next chunk.
  var authKey: array[64, byte]
  discard chacha20Djb(cast[BytePtr](unsafeAddr authKey[0]), nil, 64,
                      ctx.key, ctx.nonce, ctx.counter)
  result[0] = newSeqUninit[byte](plaintext.len)
  var dp = if plaintext.len > 0: cast[BytePtr](unsafeAddr plaintext[0]) else: nil
  var rp = if result[0].len > 0: cast[BytePtr](unsafeAddr result[0][0]) else: nil
  discard chacha20Djb(rp, dp, plaintext.len, ctx.key, ctx.nonce,
                      ctx.counter + 1)
  var auth32: array[32, byte]
  for i in 0 ..< 32:
    auth32[i] = authKey[i]
  result[1] = lockAuth(auth32, ad, result[0])
  # rekey
  for i in 0 ..< 32:
    ctx.key[i] = authKey[32 + i]
  wipe(authKey)

proc read*(ctx: var AeadContext, ciphertext, mac: openArray[byte],
           ad: openArray[byte] = []): Option[seq[byte]] =
  ## Authenticate and decrypt a chunk of ciphertext. Returns `some`
  ## plaintext if the MAC matches, `none` otherwise. Also rekeys the
  ## context when authentication succeeds.
  var authKey: array[64, byte]
  discard chacha20Djb(cast[BytePtr](unsafeAddr authKey[0]), nil, 64,
                      ctx.key, ctx.nonce, ctx.counter)
  var auth32: array[32, byte]
  for i in 0 ..< 32:
    auth32[i] = authKey[i]
  let realMac = lockAuth(auth32, ad, ciphertext)
  if constantTimeEqual(mac, realMac):
    var plain = newSeqUninit[byte](ciphertext.len)
    var cp = if ciphertext.len > 0: cast[BytePtr](unsafeAddr ciphertext[0]) else: nil
    var rp = if plain.len > 0: cast[BytePtr](unsafeAddr plain[0]) else: nil
    discard chacha20Djb(rp, cp, ciphertext.len, ctx.key, ctx.nonce,
                        ctx.counter + 1)
    # rekey
    for i in 0 ..< 32:
      ctx.key[i] = authKey[32 + i]
    result = some(plain)
  wipe(authKey)

proc aeadLock*(key: array[32, byte], nonce: array[24, byte],
               plaintext: openArray[byte], ad: openArray[byte] = []):
    (seq[byte], array[16, byte]) =
  ## Authenticated encryption with XChaCha20-Poly1305.
  ## Returns (ciphertext, mac).
  var ctx: AeadContext
  initX(ctx, key, nonce)
  result = write(ctx, plaintext, ad)
  wipe(ctx)

proc aeadUnlock*(key: array[32, byte], nonce: array[24, byte],
                 ciphertext: openArray[byte], mac: array[16, byte],
                 ad: openArray[byte] = []): Option[seq[byte]] =
  ## Authenticated decryption. Returns `some` plaintext on success,
  ## `none` if authentication fails.
  var ctx: AeadContext
  initX(ctx, key, nonce)
  result = read(ctx, ciphertext, mac, ad)
  wipe(ctx)

{.pop.}
