# RAII secret wiping.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps

import nimcypher/algos/common as commonAlgo

type
  Secret*[T] = object
    ## A value that is wiped in constant time when it goes out of scope.
    ## Wrap private keys and other sensitive material so its memory is
    ## erased automatically, no matter how the scope is left. Access the
    ## wrapped value through `data`.
    data*: T

proc secret*[T](data: T): Secret[T] =
  ## Wrap `data` in a `Secret` that wipes it on scope exit.
  Secret[T](data: data)

proc wipeSecret*[T](s: var Secret[T]) =
  ## Wipe the wrapped value immediately.
  commonAlgo.wipe(s.data)

proc `=destroy`*[T](s: var Secret[T]) =
  ## Wipe the wrapped value. The keys wrapped by this package are
  ## array-backed; a seq/string wrap is also handled (the backing buffer is
  ## wiped and released) so `Secret[T]` stays safe for any T.
  when T is seq or T is string:
    if s.data.len > 0:
      commonAlgo.wipe(s.data.toOpenArray(0, s.data.len - 1))
    reset(s.data)
  else:
    commonAlgo.wipe(s.data)
