import std/unittest

import nimcypher/algos/argon2

import vectorutils
import vectors

test "argon2 vectors":
  var i = 0
  while i < argon2Vectors.len:
    let algorithm = loadU32Le(hexToBytes(argon2Vectors[i])); inc i
    let nbBlocks = loadU32Le(hexToBytes(argon2Vectors[i])); inc i
    let nbPasses = loadU32Le(hexToBytes(argon2Vectors[i])); inc i
    let nbLanes = loadU32Le(hexToBytes(argon2Vectors[i])); inc i
    let pass = hexToBytes(argon2Vectors[i]); inc i
    let salt = hexToBytes(argon2Vectors[i]); inc i
    let key = hexToBytes(argon2Vectors[i]); inc i
    let ad = hexToBytes(argon2Vectors[i]); inc i
    let expected = hexToBytes(argon2Vectors[i]); inc i
    let config = Argon2Config(
      algorithm: Argon2Algorithm(algorithm),
      nbBlocks: nbBlocks,
      nbPasses: nbPasses,
      nbLanes: nbLanes,
    )
    let got = argon2(config, expected.len, pass, salt, key, ad)
    check got == expected
