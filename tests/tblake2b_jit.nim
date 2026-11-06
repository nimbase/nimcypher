import std/unittest
import std/random

import nimcypher/algos/blake2b
import nimcypher/algos/internal/blake2b_jit
import nimcypher/algos/internal/cpu_jit
import nimcypher/algos/common

# Differential: JIT 4-lane compress vs per-lane scalar compress.
# Runs with -d:features.nimcypher.nimdynasm on amd64.

template sg(a, b, c, d, x, y: untyped) =
  a += b + x
  d = rotr64(d xor a, 32'u64)
  c += d
  b = rotr64(b xor c, 24'u64)
  a += b + y
  d = rotr64(d xor a, 16'u64)
  c += d
  b = rotr64(b xor c, 63'u64)

proc scalarCompress(hash: array[8, uint64], off: array[2, uint64],
                    blk: array[16, uint64]): array[8, uint64] =
  var v: array[16, uint64]
  for i in 0 ..< 8: v[i] = hash[i]
  v[8] = blake2bIv[0]; v[9] = blake2bIv[1]
  v[10] = blake2bIv[2]; v[11] = blake2bIv[3]
  v[12] = blake2bIv[4] xor off[0]
  v[13] = blake2bIv[5] xor off[1]
  v[14] = blake2bIv[6]
  v[15] = blake2bIv[7]
  for r in 0 ..< 12:
    sg(v[0], v[4], v[8], v[12], blk[blake2bSigma[r][0]], blk[blake2bSigma[r][1]])
    sg(v[1], v[5], v[9], v[13], blk[blake2bSigma[r][2]], blk[blake2bSigma[r][3]])
    sg(v[2], v[6], v[10], v[14], blk[blake2bSigma[r][4]], blk[blake2bSigma[r][5]])
    sg(v[3], v[7], v[11], v[15], blk[blake2bSigma[r][6]], blk[blake2bSigma[r][7]])
    sg(v[0], v[5], v[10], v[15], blk[blake2bSigma[r][8]], blk[blake2bSigma[r][9]])
    sg(v[1], v[6], v[11], v[12], blk[blake2bSigma[r][10]], blk[blake2bSigma[r][11]])
    sg(v[2], v[7], v[8], v[13], blk[blake2bSigma[r][12]], blk[blake2bSigma[r][13]])
    sg(v[3], v[4], v[9], v[14], blk[blake2bSigma[r][14]], blk[blake2bSigma[r][15]])
  for i in 0 ..< 8:
    result[i] = hash[i] xor v[i] xor v[8 + i]

proc scalarLane(hashes: var array[4, array[8, uint64]],
                offs: array[4, array[2, uint64]],
                blocks: array[4, array[16, uint64]],
                laneMask: uint64) =
  for k in 0 ..< 4:
    if (laneMask and (1'u64 shl k)) != 0:
      hashes[k] = scalarCompress(hashes[k], offs[k], blocks[k])

suite "blake2b jit vs scalar":
  test "random lanes agree":
    if cpuHasAvx2():
      randomize(0xB24B)
      for _ in 0 ..< 60:
        var hashes: array[4, array[8, uint64]]
        var offs: array[4, array[2, uint64]]
        var blocks: array[4, array[16, uint64]]
        for k in 0 ..< 4:
          for j in 0 ..< 8:
            hashes[k][j] = uint64(rand(high(int)))
          offs[k][0] = 128'u64 + uint64(rand(1000000))
          offs[k][1] = uint64(rand(1000))
          for j in 0 ..< 16:
            blocks[k][j] = uint64(rand(high(int)))
        for mask in [0xF'u64, 0x5, 0x1, 0x8, 0x0]:
          var h1 = hashes
          var h2 = hashes
          scalarLane(h1, offs, blocks, mask)
          compress4Jit(h2, offs, blocks, mask)
          check h1 == h2
    else:
      skip()
