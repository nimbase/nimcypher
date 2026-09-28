import std/unittest

import nimcypher/algos/hkdf
import nimcypher/algos/sha512
import nimcypher/algos/sha384 as sha384Algo
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
  # the low-level expand enforces the cap too (defense in depth)
  expect ValueError:
    discard sha512HkdfExpand(@[byte 1, 2, 3], @[], 16321)
  expect ValueError:
    discard sha512Hkdf(ikm, @[], @[], 16321)
  expect ValueError:
    discard sha256HkdfExpand(@[byte 1, 2, 3], @[], 8161)
  check sha256HkdfExpand(@[byte 1, 2, 3], @[], 8160).len == 8160

test "hkdf-sha384 known-answer vectors (independent Python/hmac reference)":
  # Case 1: short inputs, single-block output (L=42 < 48)
  let ikm1 = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let salt1 = hexToBytes("000102030405060708090a0b0c")
  let info1 = hexToBytes("f0f1f2f3f4f5f6f7f8f9")
  let prk1 = hexToBytes("704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade")
  let okm1 = hexToBytes("9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5")
  check sha384Hkdf(ikm1, salt1, info1, 42) == okm1
  check sha384Algo.sha384Hmac(salt1, ikm1) == prk1
  check sha384HkdfExpand(prk1, info1, 42) == okm1
  # Case 2: long inputs, multi-block output (L=82 > 48)
  var ikm2 = newSeq[byte](80)
  var salt2 = newSeq[byte](80)
  var info2 = newSeq[byte](80)
  for i in 0 ..< 80:
    ikm2[i] = byte(i)
    salt2[i] = byte(0x80 + i)
    info2[i] = byte(0xb0 + i)
  let okm2 = hexToBytes("d50343c3f4877d76426d9e8d3a6af29873d7135e45d8f0637c127b17857747e9dd4ba70b65cf11e53af7742ab7dc38793463cd379a85d37be1dbe53c9bb1f0728799d30342026cacfc2a60bca944076cd79a")
  check sha384Hkdf(ikm2, salt2, info2, 82) == okm2
  # multi-block output is prefix-consistent
  check sha384Hkdf(ikm2, salt2, info2, 82)[0 ..< 42] ==
    sha384Hkdf(ikm2, salt2, info2, 42)
  # Case 3: empty salt/info
  let ikm3 = hexToBytes("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
  let okm3 = hexToBytes("6ad7c726c84009546a76e0545df266787e2b2cd6ca4373a1f31450a7bdf9482bfab811f554200ead8f533fd911b052c2")
  check sha384Hkdf(ikm3, @[], @[], 48) == okm3
  # deterministic
  check sha384Hkdf(ikm1, salt1, info1, 42) == sha384Hkdf(ikm1, salt1, info1, 42)

test "hkdf-sha384 high-level API and output cap (12240 bytes)":
  let ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let salt = hexToBytes("000102030405060708090a0b0c")
  let info = hexToBytes("f0f1f2f3f4f5f6f7f8f9")
  let okm = hexToBytes("9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5")
  check hashAPI.hkdfSha384(ikm, salt, info, 42) == okm
  let prk = hexToBytes("704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade")
  check hashAPI.hkdfExpandSha384(prk, info, 42) == okm
  check hashAPI.hkdfSha384[42](ikm, salt, info) == toArray[42](okm)
  check hashAPI.hkdfExpandSha384[42](prk, info) == toArray[42](okm)
  check hashAPI.hkdfSha384(ikm, @[], @[], 12240).len == 12240
  check hashAPI.hkdfExpandSha384(@[byte 1, 2, 3], @[], 12240).len == 12240
  expect ValueError:
    discard hashAPI.hkdfSha384(ikm, @[], @[], 12241)
  expect ValueError:
    discard hashAPI.hkdfExpandSha384(@[byte 1, 2, 3], @[], 12241)
  expect ValueError:
    discard sha384HkdfExpand(@[byte 1, 2, 3], @[], 12241)
  expect ValueError:
    discard sha384Hkdf(ikm, @[], @[], 12241)
