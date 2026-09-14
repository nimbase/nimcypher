# Low-level hash extras: MD5 and xxHash.
#
# Importing `nimcypher/hashes` gives direct access to the `hashes/md5`
# and `hashes/xxhash` primitives. The high-level wrappers live in
# `nimcypher/hash`.

import nimcypher/hashes/md5 as md5
import nimcypher/hashes/xxhash as xxhash

export md5
export xxhash
