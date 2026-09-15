// randombytes for the standalone keytool: the node tree declares randombytes()
// (src/pqcrypto/common/randombytes.h) and provides it from its own RNG, so a
// tool built outside the node supplies its own. macOS arc4random_buf is the
// kernel CSPRNG; it cannot fail.
#include <stdint.h>
#include <stdlib.h>
#include "randombytes.h"
int randombytes(uint8_t *output, size_t n) { arc4random_buf(output, n); return 0; }
