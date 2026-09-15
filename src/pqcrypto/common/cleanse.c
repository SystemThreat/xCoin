/* xCoin addition (not in PQClean), see cleanse.h. */

#include "cleanse.h"

#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

void PQCLEAN_cleanse(void *ptr, size_t len) {
#if defined(_WIN32)
    /* SecureZeroMemory is guaranteed not to be optimized out. */
    SecureZeroMemory(ptr, len);
#else
    memset(ptr, 0, len);
    /* Memory barrier that scares the compiler away from optimizing out the
     * memset: the asm statement claims to read *ptr, so the stores cannot be
     * treated as dead (the same construct as memory_cleanse in
     * src/support/cleanse.cpp, memzero_explicit in Linux and
     * OPENSSL_cleanse in BoringSSL). */
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}
