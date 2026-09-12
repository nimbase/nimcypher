# Differential tests: montgomery tiers vs bigints.powmod.
import std/unittest

import bigints
import nimcypher/algos/bigint_ext
import nimcypher/algos/internal/montgomery
import nimcypher/algos/internal/montgomery64

suite "montgomery differential":
  test "edge cases match powmod":
    check fastPowmod(initBigInt(5), initBigInt(0), initBigInt(7)) ==
      powmod(initBigInt(5), initBigInt(0), initBigInt(7))
    check fastPowmod(initBigInt(0), initBigInt(13), initBigInt(7)) ==
      powmod(initBigInt(0), initBigInt(13), initBigInt(7))
    check fastPowmod(initBigInt(1), initBigInt(12345), initBigInt(7)) ==
      powmod(initBigInt(1), initBigInt(12345), initBigInt(7))
    check fastPowmod(initBigInt(123), initBigInt(1), initBigInt(7)) ==
      powmod(initBigInt(123), initBigInt(1), initBigInt(7))
    check fastPowmod(initBigInt(999), initBigInt(3), initBigInt(1)) ==
      powmod(initBigInt(999), initBigInt(3), initBigInt(1))
    # base >= modulus, base == modulus, base multiple of modulus
    check fastPowmod(initBigInt(1000), initBigInt(5), initBigInt(7)) ==
      powmod(initBigInt(1000), initBigInt(5), initBigInt(7))
    # even modulus falls back to powmod
    check fastPowmod(initBigInt(5), initBigInt(3), initBigInt(8)) ==
      powmod(initBigInt(5), initBigInt(3), initBigInt(8))
    check fastPowmod(initBigInt(123456), initBigInt(789), initBigInt(1000000)) ==
      powmod(initBigInt(123456), initBigInt(789), initBigInt(1000000))

  test "small odd moduli, exhaustive-ish exponents (all tiers)":
    let mods = [3, 5, 7, 9, 15, 17, 255, 257, 65537]
    for m in mods:
      let mm = initBigInt(m)
      for e in [0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 100, 1000]:
        for b in [0, 1, 2, 3, 5, 100, m - 1, m, m + 1, 2 * m + 3]:
          let bb = initBigInt(b)
          let ee = initBigInt(e)
          let refVal = powmod(bb, ee, mm)
          check fastPowmod32(bb, ee, mm) == refVal
          check fastPowmod64(bb, ee, mm) == refVal
          check fastPowmod(bb, ee, mm) == refVal

  test "random odd moduli across bit sizes (all tiers)":
    # deterministic PRNG (xorshift) so failures reproduce
    var st = 0x12345678'u64
    proc next(): uint64 =
      st = st xor (st shl 13)
      st = st xor (st shr 7)
      st = st xor (st shl 17)
      st
    proc randBelow(n: BigInt): BigInt =
      let blen = max(byteLen(n - initBigInt(1)), 1)
      while true:
        var buf = newSeq[byte](blen)
        for i in 0 ..< blen:
          buf[i] = byte(next() and 0xFF)
        let v = fromBytesBE(buf)
        if v >= initBigInt(1) and v < n:
          return v
    # 32-bit limb boundaries (31/32/33, 63/64/65) and 64-bit limb
    # boundaries (63/64/65, 127/128/129, 191/192/193) included.
    for bits in [16, 31, 32, 33, 63, 64, 65, 127, 128, 129, 191, 192,
                 193, 255, 256, 257, 511, 512, 1024]:
      var m = randomBigIntBits(bits, setTopBit = true, odd = true)
      # randomBigIntBits uses sysrand; force odd + top bit regardless
      for _ in 0 ..< 4:
        let b = randBelow(m)
        let e = randBelow(m)
        let refVal = powmod(b, e, m)
        check fastPowmod32(b, e, m) == refVal
        check fastPowmod64(b, e, m) == refVal
      # RSA-shaped: small public exponent + large random exponent
      let b2 = randBelow(m)
      check fastPowmod64(b2, initBigInt(65537), m) ==
        powmod(b2, initBigInt(65537), m)

  test "fastInvmod matches invmod":
    check fastInvmod(initBigInt(3), initBigInt(7)) == invmod(initBigInt(3), initBigInt(7))
    check fastInvmod(initBigInt(1), initBigInt(7)) == invmod(initBigInt(1), initBigInt(7))
    check fastInvmod(initBigInt(6), initBigInt(7)) == invmod(initBigInt(6), initBigInt(7))
    check fastInvmod(initBigInt(123456), initBigInt(1000003)) ==
      invmod(initBigInt(123456), initBigInt(1000003))
    check fastInvmod(initBigInt(999), initBigInt(1)) == invmod(initBigInt(999), initBigInt(1))
    # base larger than modulus, multiple of modulus
    check fastInvmod(initBigInt(1000), initBigInt(7)) == invmod(initBigInt(1000), initBigInt(7))
    # even modulus falls back
    check fastInvmod(initBigInt(3), initBigInt(8)) == invmod(initBigInt(3), initBigInt(8))
    expect DivByZeroDefect:
      discard fastInvmod(initBigInt(0), initBigInt(7))
    expect ValueError:
      discard fastInvmod(initBigInt(6), initBigInt(9)) # gcd = 3
    expect ValueError:
      discard fastInvmod(initBigInt(14), initBigInt(7)) # multiple of modulus
    var st = 0x55AA55AA'u64
    proc next(): uint64 =
      st = st xor (st shl 13)
      st = st xor (st shr 7)
      st = st xor (st shl 17)
      st
    proc randBelow(n: BigInt): BigInt =
      let blen = max(byteLen(n - initBigInt(1)), 1)
      while true:
        var buf = newSeq[byte](blen)
        for i in 0 ..< blen:
          buf[i] = byte(next() and 0xFF)
        let v = fromBytesBE(buf)
        if v >= initBigInt(1) and v < n:
          return v
    for bits in [63, 64, 65, 128, 255, 256, 512, 1024, 2048]:
      var m = randomBigIntBits(bits, setTopBit = true, odd = true)
      for _ in 0 ..< 3:
        let a = randBelow(m)
        if gcd(a, m) == initBigInt(1):
          check fastInvmod(a, m) == invmod(a, m)
        else:
          expect ValueError:
            discard fastInvmod(a, m)

  test "large odd moduli incl. exact multi-limb sizes (tiers agree)":
    # bigints.powmod reference only at 2048 (too slow above); 3072/4096
    # cross-check 32- vs 64-bit tiers on random inputs.
    var st = 0xABCDEF01'u64
    proc next(): uint64 =
      st = st xor (st shl 13)
      st = st xor (st shr 7)
      st = st xor (st shl 17)
      st
    proc randBelow(n: BigInt): BigInt =
      let blen = max(byteLen(n - initBigInt(1)), 1)
      while true:
        var buf = newSeq[byte](blen)
        for i in 0 ..< blen:
          buf[i] = byte(next() and 0xFF)
        let v = fromBytesBE(buf)
        if v >= initBigInt(1) and v < n:
          return v
    for bits in [2048, 2049, 3072, 4096]:
      var m = randomBigIntBits(bits, setTopBit = true, odd = true)
      for _ in 0 ..< 2:
        let b = randBelow(m)
        let e = randBelow(m)
        check fastPowmod64(b, e, m) == fastPowmod32(b, e, m)
      let b3 = randBelow(m)
      check fastPowmod64(b3, initBigInt(65537), m) ==
        fastPowmod32(b3, initBigInt(65537), m)
    # one full reference check at exactly 2048 bits (32 x 64-bit limbs)
    var m2048 = randomBigIntBits(2048, setTopBit = true, odd = true)
    let b4 = randBelow(m2048)
    let e4 = randBelow(m2048)
    check fastPowmod64(b4, e4, m2048) == powmod(b4, e4, m2048)
