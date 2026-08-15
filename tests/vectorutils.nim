# Test helpers for the vector-driven test suite.

proc hexVal(c: char): int =
  case c
  of '0' .. '9': int(c) - int('0')
  of 'a' .. 'f': int(c) - int('a') + 10
  of 'A' .. 'F': int(c) - int('A') + 10
  else: raise newException(ValueError, "invalid hex char: " & c)

proc hexToBytes*(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(hexVal(s[2 * i]) * 16 + hexVal(s[2 * i + 1]))

proc loadU64Le*(b: openArray[byte]): uint64 =
  for i in 0 ..< b.len:
    result = result or (uint64(b[i]) shl (8 * i))

proc loadU32Le*(b: openArray[byte]): uint32 =
  for i in 0 ..< b.len:
    result = result or (uint32(b[i]) shl (8 * i))

template toArray*[N: static[int]](b: openArray[byte]): array[N, byte] =
  block:
    var res: array[N, byte]
    assert b.len == N
    for i in 0 ..< N:
      res[i] = b[i]
    res
