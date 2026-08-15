# Low-level FFI bindings to the C Monocypher library.
#
# Copied from the `openpeeps/e2ee` nimble package
# (`e2ee/private/monocypher.nim` + `e2ee/private/utils.nim`) for use in the
# interop tests, so the pure-Nim port can be cross-checked against the real C
# implementation. Not declared as a nimble dependency.
#
# Requires the C Monocypher library to be installed and discoverable via
# pkg-config (headers in the include path, libmonocypher linkable).

import std/strutils

# pkg-config flags for the installed C Monocypher library.
# The shared library ships with a broken install name on macOS, so we link
# the static archive explicitly.
{.passC: staticExec("pkg-config --cflags monocypher").strip.}
{.passL: staticExec("pkg-config --variable=libdir monocypher").strip & "/libmonocypher.a".}

const
  CRYPTO_ARGON2_D* = 0
  CRYPTO_ARGON2_I* = 1
  CRYPTO_ARGON2_ID* = 2

{.push cdecl, importc, header: "monocypher.h".}

type
  crypto_aead_ctx* {.importc, bycopy.} = object
    counter*: uint64
    key*: array[32, uint8]
    nonce*: array[8, uint8]

  crypto_blake2b_ctx* {.importc, bycopy.} = object
    hash*: array[8, uint64]
    input_offset*: array[2, uint64]
    input*: array[16, uint64]
    input_idx*: csize_t
    hash_size*: csize_t

  crypto_argon2_config* {.importc, bycopy.} = object
    algorithm*: uint32
    nb_blocks*: uint32
    nb_passes*: uint32
    nb_lanes*: uint32

  crypto_argon2_inputs* {.importc, bycopy.} = object
    pass*: ptr uint8
    salt*: ptr uint8
    pass_size*: uint32
    salt_size*: uint32

  crypto_argon2_extras* {.importc, bycopy.} = object
    key*: ptr uint8
    ad*: ptr uint8
    key_size*: uint32
    ad_size*: uint32

  crypto_poly1305_ctx* {.importc, bycopy.} = object
    c*: array[16, uint8]
    c_idx*: csize_t
    r*: array[4, uint32]
    pad*: array[4, uint32]
    h*: array[5, uint32]

# Constant time comparisons
proc crypto_verify16*(a: ptr uint8, b: ptr uint8): cint
proc crypto_verify32*(a: ptr uint8, b: ptr uint8): cint
proc crypto_verify64*(a: ptr uint8, b: ptr uint8): cint

# Erase sensitive data
proc crypto_wipe*(secret: pointer, size: csize_t)

# Authenticated encryption
proc crypto_aead_lock*(
  cipher_text: ptr uint8, mac: ptr uint8, key: ptr uint8, nonce: ptr uint8,
  ad: ptr uint8, ad_size: csize_t, plain_text: ptr uint8, text_size: csize_t)

proc crypto_aead_unlock*(
  plain_text: ptr uint8, mac: ptr uint8, key: ptr uint8, nonce: ptr uint8,
  ad: ptr uint8, ad_size: csize_t, cipher_text: ptr uint8, text_size: csize_t): cint

# Authenticated stream
proc crypto_aead_init_x*(ctx: ptr crypto_aead_ctx, key: ptr uint8, nonce: ptr uint8)
proc crypto_aead_init_djb*(ctx: ptr crypto_aead_ctx, key: ptr uint8, nonce: ptr uint8)
proc crypto_aead_init_ietf*(ctx: ptr crypto_aead_ctx, key: ptr uint8, nonce: ptr uint8)
proc crypto_aead_write*(
  ctx: ptr crypto_aead_ctx, cipher_text: ptr uint8, mac: ptr uint8,
  ad: ptr uint8, ad_size: csize_t, plain_text: ptr uint8, text_size: csize_t
)
proc crypto_aead_read*(
  ctx: ptr crypto_aead_ctx, plain_text: ptr uint8, mac: ptr uint8,
  ad: ptr uint8, ad_size: csize_t, cipher_text: ptr uint8, text_size: csize_t
): cint

# General purpose hash (BLAKE2b)
proc crypto_blake2b*(hash: ptr uint8, hash_size: csize_t, message: ptr uint8, message_size: csize_t)
proc crypto_blake2b_keyed*(hash: ptr uint8, hash_size: csize_t, key: ptr uint8, key_size: csize_t, message: ptr uint8, message_size: csize_t)
proc crypto_blake2b_init*(ctx: ptr crypto_blake2b_ctx, hash_size: csize_t)
proc crypto_blake2b_keyed_init*(ctx: ptr crypto_blake2b_ctx, hash_size: csize_t, key: ptr uint8, key_size: csize_t)
proc crypto_blake2b_update*(ctx: ptr crypto_blake2b_ctx, message: ptr uint8, message_size: csize_t)
proc crypto_blake2b_final*(ctx: ptr crypto_blake2b_ctx, hash: ptr uint8)

# Password key derivation (Argon2)
var crypto_argon2_no_extras*: crypto_argon2_extras
proc crypto_argon2*(hash: ptr uint8, hash_size: uint32, work_area: pointer, config: crypto_argon2_config, inputs: crypto_argon2_inputs, extras: crypto_argon2_extras)

# Key exchange (X-25519)
proc crypto_x25519_public_key*(public_key: ptr uint8, secret_key: ptr uint8)
proc crypto_x25519*(raw_shared_secret: ptr uint8, your_secret_key: ptr uint8, their_public_key: ptr uint8)
proc crypto_x25519_to_eddsa*(eddsa: ptr uint8, x25519: ptr uint8)
proc crypto_x25519_inverse*(blind_salt: ptr uint8, private_key: ptr uint8, curve_point: ptr uint8)
proc crypto_x25519_dirty_small*(pk: ptr uint8, sk: ptr uint8)
proc crypto_x25519_dirty_fast*(pk: ptr uint8, sk: ptr uint8)

# Signatures
proc crypto_eddsa_key_pair*(secret_key: ptr uint8, public_key: ptr uint8, seed: ptr uint8)
proc crypto_eddsa_sign*(signature: ptr uint8, secret_key: ptr uint8, message: ptr uint8, message_size: csize_t)
proc crypto_eddsa_check*(signature: ptr uint8, public_key: ptr uint8, message: ptr uint8, message_size: csize_t): cint
proc crypto_eddsa_to_x25519*(x25519: ptr uint8, eddsa: ptr uint8)
proc crypto_eddsa_trim_scalar*(`out`: ptr uint8, `in`: ptr uint8)
proc crypto_eddsa_reduce*(reduced: ptr uint8, expanded: ptr uint8)
proc crypto_eddsa_mul_add*(r: ptr uint8, a: ptr uint8, b: ptr uint8, c: ptr uint8)
proc crypto_eddsa_scalarbase*(point: ptr uint8, scalar: ptr uint8)
proc crypto_eddsa_check_equation*(signature: ptr uint8, public_key: ptr uint8, h_ram: ptr uint8): cint

# Chacha20
proc crypto_chacha20_h*(`out`: ptr uint8, key: ptr uint8, `in`: ptr uint8)
proc crypto_chacha20_djb*(
  cipher_text: ptr uint8, plain_text: ptr uint8, text_size: csize_t,
  key: ptr uint8, nonce: ptr uint8, ctr: uint64
): uint64
proc crypto_chacha20_ietf*(
  cipher_text: ptr uint8, plain_text: ptr uint8, text_size: csize_t,
  key: ptr uint8, nonce: ptr uint8, ctr: uint32
): uint32
proc crypto_chacha20_x*(
  cipher_text: ptr uint8, plain_text: ptr uint8, text_size: csize_t,
  key: ptr uint8, nonce: ptr uint8, ctr: uint64
): uint64

# Poly1305
proc crypto_poly1305*(mac: array[16, uint8], message: ptr uint8, message_size: csize_t, key: array[32, uint8])
proc crypto_poly1305_init*(ctx: ptr crypto_poly1305_ctx, key: array[32, uint8])
proc crypto_poly1305_update*(ctx: ptr crypto_poly1305_ctx, message: ptr uint8, message_size: csize_t)
proc crypto_poly1305_final*(ctx: ptr crypto_poly1305_ctx, mac: array[16, uint8])

# Elligator 2
proc crypto_elligator_map*(curve: array[32, uint8], hidden: array[32, uint8])
proc crypto_elligator_rev*(hidden: array[32, uint8], curve: array[32, uint8], tweak: uint8): cint
proc crypto_elligator_key_pair*(hidden: array[32, uint8], secret_key: array[32, uint8], seed: array[32, uint8])

{.pop.}

{.push cdecl, importc, header: "monocypher-ed25519.h".}

type
  crypto_sha512_ctx* {.importc, bycopy.} = object
    hash*: array[8, uint64]
    input*: array[16, uint64]
    input_size*: array[2, uint64]
    input_idx*: csize_t

  crypto_sha512_hmac_ctx* {.importc, bycopy.} = object
    sha*: crypto_sha512_ctx
    key*: array[128, uint8]

# SHA-512
proc crypto_sha512*(hash: ptr uint8, message: ptr uint8, message_size: csize_t)
proc crypto_sha512_init*(ctx: ptr crypto_sha512_ctx)
proc crypto_sha512_update*(ctx: ptr crypto_sha512_ctx, message: ptr uint8, message_size: csize_t)
proc crypto_sha512_final*(ctx: ptr crypto_sha512_ctx, hash: ptr uint8)

# SHA-512 HMAC
proc crypto_sha512_hmac*(hmac: ptr uint8, key: ptr uint8, key_size: csize_t, message: ptr uint8, message_size: csize_t)
proc crypto_sha512_hmac_init*(ctx: ptr crypto_sha512_hmac_ctx, key: ptr uint8, key_size: csize_t)
proc crypto_sha512_hmac_update*(ctx: ptr crypto_sha512_hmac_ctx, message: ptr uint8, message_size: csize_t)
proc crypto_sha512_hmac_final*(ctx: ptr crypto_sha512_hmac_ctx, hmac: ptr uint8)

# SHA-512 HKDF
proc crypto_sha512_hkdf*(okm: ptr uint8, okm_size: csize_t, ikm: ptr uint8, ikm_size: csize_t, salt: ptr uint8, salt_size: csize_t, info: ptr uint8, info_size: csize_t)
proc crypto_sha512_hkdf_expand*(okm: ptr uint8, okm_size: csize_t, prk: ptr uint8, prk_size: csize_t, info: ptr uint8, info_size: csize_t)

# Ed25519 (EdDSA with SHA-512)
proc crypto_ed25519_key_pair*(secret_key: ptr uint8, public_key: ptr uint8, seed: ptr uint8)
proc crypto_ed25519_sign*(signature: ptr uint8, secret_key: ptr uint8, message: ptr uint8, message_size: csize_t)
proc crypto_ed25519_check*(signature: ptr uint8, public_key: ptr uint8, message: ptr uint8, message_size: csize_t): cint
proc crypto_ed25519_ph_sign*(signature: ptr uint8, secret_key: ptr uint8, message_hash: ptr uint8)
proc crypto_ed25519_ph_check*(signature: ptr uint8, public_key: ptr uint8, message_hash: ptr uint8): cint

{.pop.}

# Helper utilities (trimmed from e2ee/private/utils.nim)

type
  Key32* = array[32, uint8]
  Nonce24* = array[24, uint8]
  Mac16* = array[16, uint8]

proc toPtr*(data: openArray[byte]): ptr uint8 {.inline.} =
  if data.len == 0: nil
  else: cast[ptr uint8](unsafeAddr data[0])

proc seqPtr*(data: var seq[uint8]): ptr uint8 {.inline.} =
  if data.len == 0: nil
  else: data[0].addr

proc fromHex*[N: static int, T](s: string): array[N, T] =
  ## Convert a hex string back to an array of bytes of type T.
  if s.len != N * 2:
    raise newException(ValueError, "invalid hex length")
  for i in 0 ..< N:
    let a = i * 2
    let b = a + 1
    result[i] = T(parseHexInt(s[a .. b]))
