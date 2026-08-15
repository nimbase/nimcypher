import std/unittest

import nimcypher/algos/hkdf
import nimcypher/algos/sha512
import nimcypher/hash as hashAPI

import vectorutils

test "hkdf RFC 5869-like round trip":
  # Known HKDF-SHA-512 vector (RFC 5869 test case 2 adapted to SHA-512)
  let ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let salt = hexToBytes("000102030405060708090a0b0c")
  let info = hexToBytes("f0f1f2f3f4f5f6f7f8f9")
  let okm = sha512Hkdf(ikm, salt, info, 42)
  # self-consistency: recompute via expand
  let prk = sha512.sha512Hmac(salt, ikm)
  let okm2 = sha512HkdfExpand(prk, info, 42)
  check okm == okm2
  check okm.len == 42

test "hkdf deterministic and empty-info":
  let ikm = hexToBytes("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
  let salt = hexToBytes("")
  let info = hexToBytes("")
  let okm = sha512Hkdf(ikm, salt, info, 64)
  check okm.len == 64
  # deterministic
  let okm2 = sha512Hkdf(ikm, salt, info, 64)
  check okm == okm2
  # multi-block output
  let okm3 = sha512Hkdf(ikm, salt, info, 128)
  check okm3[0 ..< 64] == okm

test "hkdf output length is capped at 255 blocks (16320 bytes)":
  let ikm = @[byte 1, 2, 3]
  check hashAPI.hkdfSha512(ikm, @[], @[], 16320).len == 16320
  check hashAPI.hkdfExpandSha512(@[byte 1, 2, 3], @[], 16320).len == 16320
  expect ValueError:
    discard hashAPI.hkdfSha512(ikm, @[], @[], 16321)
  expect ValueError:
    discard hashAPI.hkdfExpandSha512(@[byte 1, 2, 3], @[], 16321)
