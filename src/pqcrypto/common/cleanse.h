#ifndef PQCLEAN_COMMON_CLEANSE_H
#define PQCLEAN_COMMON_CLEANSE_H

/* xCoin addition (not in PQClean): a secret wipe that survives dead-store
 * elimination, for the vendored ML-DSA-65 and SLH-DSA code. A plain memset of
 * a buffer that is never read again is removed by the optimizer; this is the
 * same technique as the node's memory_cleanse (src/support/cleanse.cpp),
 * duplicated here so the vendored C stays self-contained.
 * See the PQCLEAN provenance records in the sibling algorithm directories. */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCLEAN_cleanse PQCLEAN_common_cleanse
void PQCLEAN_cleanse(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PQCLEAN_COMMON_CLEANSE_H */
