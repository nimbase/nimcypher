# Tests for BigInt byte conversions and prime generation.
import std/unittest

import bigints
import nimcypher/algos/bigint_ext

suite "bigint_ext":
  test "os2ip/i2osp roundtrip":
    let v = fromBytesBE([byte 0x01, 0x00, 0xFF])
    check $v == "65791"
    check toBytesBE(v, 3) == @[byte 0x01, 0x00, 0xFF]
    check toBytesBETrimmed(v) == @[byte 0x01, 0x00, 0xFF]

  test "i2osp pads on the left":
    check toBytesBE(initBigInt(1), 4) ==
      @[byte 0x00, 0x00, 0x00, 0x01]

  test "i2osp rejects overflow":
    expect ValueError:
      discard toBytesBE(initBigInt(256), 1)

  test "zero encodes empty":
    check toBytesBETrimmed(initBigInt(0)) == newSeq[byte](0)
    check byteLen(initBigInt(0)) == 0
    check bitLen(initBigInt(0)) == 0

  test "isProbablePrime on known values":
    check isProbablePrime(initBigInt(2))
    check isProbablePrime(initBigInt(3))
    check isProbablePrime(initBigInt(65537))
    check not isProbablePrime(initBigInt(1))
    check not isProbablePrime(initBigInt(4))
    check not isProbablePrime(initBigInt(65535))
    # 2^89 - 1 (Mersenne prime)
    check isProbablePrime(pow(initBigInt(2), 89) - initBigInt(1), 8)

  test "randomPrime yields primes of exact size":
    for _ in 0 ..< 3:
      let p = randomPrime(64, rounds = 8)
      check bitLen(p) == 64
      check isProbablePrime(p, 8)

  test "randomBigIntBelow is in range":
    let n = initBigInt(1000)
    for _ in 0 ..< 20:
      let r = randomBigIntBelow(n)
      check r >= initBigInt(1)
      check r < n

  test "powmod sanity":
    check powmod(initBigInt(2), initBigInt(3), initBigInt(7)) == initBigInt(1)
    check invmod(initBigInt(3), initBigInt(7)) == initBigInt(5)
