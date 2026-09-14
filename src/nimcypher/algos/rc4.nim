# RC4 (ARC4) stream cipher — pure Nim, no C dependency.
#
# Alleged RC4 per RFC 6229 (KSA + PRGA). Provided for interop with legacy
# formats (notably PDF V=1/V=2/V=4 encryption); do not use in new designs.
# Key length 1..256 bytes; encryption and decryption are the same operation.
#
# Dual-licensed under BSD-2-Clause OR CC0-1.0.

{.push checks: off.}

proc rc4Keystream(key: openArray[byte], n: int): seq[byte] =
  if key.len < 1 or key.len > 256:
    raise newException(ValueError,
      "invalid RC4 key length: expected 1..256 bytes, got " & $key.len)
  var s: array[256, byte]
  for i in 0 ..< 256:
    s[i] = byte(i)
  var j = 0
  for i in 0 ..< 256:
    j = (j + int(s[i]) + int(key[i mod key.len])) and 0xFF
    let t = s[i]
    s[i] = s[j]
    s[j] = t
  result = newSeq[byte](n)
  var ii = 0
  var jj = 0
  for k in 0 ..< n:
    ii = (ii + 1) and 0xFF
    jj = (jj + int(s[ii])) and 0xFF
    let t = s[ii]
    s[ii] = s[jj]
    s[jj] = t
    result[k] = s[(int(s[ii]) + int(s[jj])) and 0xFF]
  for i in 0 ..< 256:
    s[i] = 0

proc rc4Crypt*(key: openArray[byte], data: openArray[byte]): seq[byte] =
  ## Encrypt or decrypt `data` with RC4 under `key` (1..256 bytes).
  ## RC4 is symmetric: applying it twice returns the original input.
  ## Raises ValueError on an empty or over-long key.
  let ks = rc4Keystream(key, data.len)
  result = newSeq[byte](data.len)
  for i in 0 ..< data.len:
    result[i] = data[i] xor ks[i]

proc rc4CryptInPlace*(key: openArray[byte], data: var openArray[byte]) =
  ## In-place variant of rc4Crypt. Raises ValueError on a bad key.
  let ks = rc4Keystream(key, data.len)
  for i in 0 ..< data.len:
    data[i] = data[i] xor ks[i]
