# High-level RSA API: PKCS#1 v1.5, PSS, OAEP, key generation.
#
# Thin wrappers over `nimcypher/algos/rsa`. Keys are the low-level
# `RsaPublicKey` / `RsaPrivateKey` objects (BigInt-backed); call `wipeRsaKey`
# explicitly when done with a private key. See `algos/rsa` for the JOSE
# mapping (RS256/384/512, PS256/384/512, RSA-OAEP, RSA-OAEP-256, RSA1_5).
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps

import nimcypher/algos/rsa as rsaAlgo

import ./utils

export rsaAlgo.RsaHash
export rsaAlgo.RsaPublicKey
export rsaAlgo.RsaPrivateKey

proc generateRsaKeyPair*(bits = 2048, e = 65537): rsaAlgo.RsaPrivateKey =
  ## Generate an RSA key pair. `bits` defaults to 2048; sizes below 2048
  ## are insecure and exist for tests only.
  rsaAlgo.generateRsaKeyPair(bits, e)

proc rsaPublicKey*(key: rsaAlgo.RsaPrivateKey): rsaAlgo.RsaPublicKey =
  ## Derive the public key from a private key.
  rsaAlgo.publicKey(key)

proc wipeRsaKey*(key: var rsaAlgo.RsaPrivateKey) =
  ## Best-effort wipe of private material (drops BigInt references;
  ## see `algos/rsa.wipe` for limits).
  rsaAlgo.wipe(key)

proc rsaPkcs1v15Sign*(key: rsaAlgo.RsaPrivateKey, h: rsaAlgo.RsaHash,
                      msg: openArray[byte]): seq[byte] =
  ## RSASSA-PKCS1-v1_5 sign (JWA RS256/384/512). SHA-1 is rejected.
  rsaAlgo.pkcs1v15Sign(key, h, msg)

proc rsaPkcs1v15Sign*(key: rsaAlgo.RsaPrivateKey, h: rsaAlgo.RsaHash,
                      msg: string): seq[byte] =
  rsaPkcs1v15Sign(key, h, toBytes(msg))

proc rsaPkcs1v15Verify*(key: rsaAlgo.RsaPublicKey, h: rsaAlgo.RsaHash,
                        msg: openArray[byte], sig: openArray[byte]): bool =
  ## RSASSA-PKCS1-v1_5 verify. Returns false on bad signature.
  rsaAlgo.pkcs1v15Verify(key, h, msg, sig)

proc rsaPkcs1v15Verify*(key: rsaAlgo.RsaPublicKey, h: rsaAlgo.RsaHash,
                        msg: string, sig: openArray[byte]): bool =
  rsaPkcs1v15Verify(key, h, toBytes(msg), sig)

proc rsaPssSign*(key: rsaAlgo.RsaPrivateKey, h: rsaAlgo.RsaHash,
                 msg: openArray[byte]): seq[byte] =
  ## RSASSA-PSS sign with saltLen = hashLen (JWA PS256/384/512).
  rsaAlgo.pssSign(key, h, msg)

proc rsaPssSign*(key: rsaAlgo.RsaPrivateKey, h: rsaAlgo.RsaHash,
                 msg: string): seq[byte] =
  rsaPssSign(key, h, toBytes(msg))

proc rsaPssVerify*(key: rsaAlgo.RsaPublicKey, h: rsaAlgo.RsaHash,
                   msg: openArray[byte], sig: openArray[byte]): bool =
  ## RSASSA-PSS verify. Returns false on bad signature.
  rsaAlgo.pssVerify(key, h, msg, sig)

proc rsaPssVerify*(key: rsaAlgo.RsaPublicKey, h: rsaAlgo.RsaHash,
                   msg: string, sig: openArray[byte]): bool =
  rsaPssVerify(key, h, toBytes(msg), sig)

proc rsaOaepEncrypt*(key: rsaAlgo.RsaPublicKey, h: rsaAlgo.RsaHash,
                     msg: openArray[byte]): seq[byte] =
  ## RSAES-OAEP encrypt (`rhSha1` = RSA-OAEP, `rhSha256` = RSA-OAEP-256).
  rsaAlgo.oaepEncrypt(key, h, msg)

proc rsaOaepEncrypt*(key: rsaAlgo.RsaPublicKey, h: rsaAlgo.RsaHash,
                     msg: string): seq[byte] =
  rsaOaepEncrypt(key, h, toBytes(msg))

proc rsaOaepDecrypt*(key: rsaAlgo.RsaPrivateKey, h: rsaAlgo.RsaHash,
                     cipher: openArray[byte]): seq[byte] =
  ## RSAES-OAEP decrypt. Raises `ValueError` on failure.
  rsaAlgo.oaepDecrypt(key, h, cipher)

proc rsaPkcs1v15Encrypt*(key: rsaAlgo.RsaPublicKey,
                         msg: openArray[byte]): seq[byte] =
  ## RSAES-PKCS1-v1_5 encrypt (JWA `RSA1_5`, legacy).
  rsaAlgo.pkcs1v15Encrypt(key, msg)

proc rsaPkcs1v15Encrypt*(key: rsaAlgo.RsaPublicKey, msg: string): seq[byte] =
  rsaPkcs1v15Encrypt(key, toBytes(msg))

proc rsaPkcs1v15Decrypt*(key: rsaAlgo.RsaPrivateKey,
                         cipher: openArray[byte]): seq[byte] =
  ## RSAES-PKCS1-v1_5 decrypt. Raises `ValueError` on failure.
  rsaAlgo.pkcs1v15Decrypt(key, cipher)
