# PCLMULQDQ-accelerated GHASH (amd64, requires the `nimsimd` feature).
#
# Single-block fold following BearSSL's `ghash_pclmul` technique: operands
# are byte-swapped into a full big-endian representation, where the identity
# rev(x) * rev(y) = rev255(x * y) turns carry-less multiplication into a
# plain three-clmul Karatsuba plus a 1-bit left shift and the standard
# GF(2^128) reduction. The scalar constant-time reference in `../gcm`
# produces identical results and is cross-checked against it by the tests.
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

when not defined(amd64):
  {.error: "ghash_simd currently requires amd64.".}

{.passC: "-mpclmul -mssse3".}

import ../common
import nimsimd/sse2
import nimsimd/ssse3
import nimsimd/pclmulqdq

proc ghashFoldClmul*(acc: var array[16, byte], h: array[16, byte],
                     src: BytePtr) =
  ## acc = (acc xor block) * H mod (x^128 + x^7 + x^2 + x + 1)
  let bswapIdx = mm_set_epi8(0'i8, 1, 2, 3, 4, 5, 6, 7,
                             8, 9, 10, 11, 12, 13, 14, 15)
  var yw = mm_loadu_si128(cast[ptr M128i](addr acc[0]))
  yw = mm_shuffle_epi8(yw, bswapIdx)

  var hw = mm_loadu_si128(cast[ptr M128i](unsafeAddr h[0]))
  hw = mm_shuffle_epi8(hw, bswapIdx)
  # kx = xor of the two 64-bit halves of kw (placed in the low half)
  template bk(kw, kx) =
    kx = mm_xor_si128(kw, mm_shuffle_epi32(kw, 0x0E))
  var hx: M128i
  bk(hw, hx)

  var aw = mm_loadu_si128(cast[ptr M128i](src))
  aw = mm_shuffle_epi8(aw, bswapIdx)
  aw = mm_xor_si128(aw, yw)
  var ax: M128i
  bk(aw, ax)

  var t1 = mm_clmulepi64_si128(aw, hw, 0x11)
  var t3 = mm_clmulepi64_si128(aw, hw, 0x00)
  var t2 = mm_xor_si128(mm_clmulepi64_si128(ax, hx, 0x00),
                        mm_xor_si128(t1, t3))
  var t0 = mm_shuffle_epi32(t1, 0x0E)
  t1 = mm_xor_si128(t1, mm_shuffle_epi32(t2, 0x0E))
  t2 = mm_xor_si128(t2, mm_shuffle_epi32(t3, 0x0E))

  # left-shift the 256-bit product by one bit (t0..t3, most significant first)
  template sl256(x0, x1, x2, x3) =
    x0 = mm_or_si128(mm_slli_epi64(x0, 1), mm_srli_epi64(x1, 63))
    x1 = mm_or_si128(mm_slli_epi64(x1, 1), mm_srli_epi64(x2, 63))
    x2 = mm_or_si128(mm_slli_epi64(x2, 1), mm_srli_epi64(x3, 63))
    x3 = mm_slli_epi64(x3, 1)

  # reduce modulo x^128 + x^7 + x^2 + x + 1; result in x0..x1
  template reduce(x0, x1, x2, x3) =
    x1 = mm_xor_si128(x1,
           mm_xor_si128(
             mm_xor_si128(x3, mm_srli_epi64(x3, 1)),
             mm_xor_si128(mm_srli_epi64(x3, 2), mm_srli_epi64(x3, 7))))
    x2 = mm_xor_si128(
           mm_xor_si128(x2, mm_slli_epi64(x3, 63)),
           mm_xor_si128(mm_slli_epi64(x3, 62), mm_slli_epi64(x3, 57)))
    x0 = mm_xor_si128(x0,
           mm_xor_si128(
             mm_xor_si128(x2, mm_srli_epi64(x2, 1)),
             mm_xor_si128(mm_srli_epi64(x2, 2), mm_srli_epi64(x2, 7))))
    x1 = mm_xor_si128(x1,
           mm_xor_si128(mm_slli_epi64(x2, 63),
             mm_xor_si128(mm_slli_epi64(x2, 62), mm_slli_epi64(x2, 57))))

  sl256(t0, t1, t2, t3)
  reduce(t0, t1, t2, t3)

  yw = mm_unpacklo_epi64(t1, t0)
  yw = mm_shuffle_epi8(yw, bswapIdx)
  mm_storeu_si128(cast[ptr M128i](addr acc[0]), yw)
