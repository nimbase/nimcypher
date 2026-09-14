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

test "argon2 rejects degenerate configs":
  let good = Argon2Config(algorithm: id, nbBlocks: 32, nbPasses: 1, nbLanes: 1)
  template rejects(cfg: Argon2Config, size: int) =
    var raised = false
    try:
      discard argon2(cfg, size, @[byte 1], @[byte 2])
    except ValueError:
      raised = true
    check raised
  rejects(Argon2Config(algorithm: id, nbBlocks: 32, nbPasses: 1, nbLanes: 0), 32)
  rejects(Argon2Config(algorithm: id, nbBlocks: 32, nbPasses: 0, nbLanes: 1), 32)
  rejects(Argon2Config(algorithm: id, nbBlocks: 3, nbPasses: 1, nbLanes: 1), 32)
  rejects(Argon2Config(algorithm: id, nbBlocks: 0, nbPasses: 1, nbLanes: 1), 32)
  rejects(good, 0)
  # boundary: nbBlocks div nbLanes >= 4 is valid (Monocypher rounds down;
  # the 8-block/2-lane interop vector must stay accepted)
  check argon2(Argon2Config(algorithm: id, nbBlocks: 8, nbPasses: 1,
                            nbLanes: 2), 32, @[byte 1], @[byte 2]).len == 32
  check argon2(good, 32, @[byte 1], @[byte 2]).len == 32
