/*
 * Copyright (c) 2026 The xCoin developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

/* xCoin addition (not in mlkem-native): the one compilation unit of the
 * vendored library (target mlkem_native, see PINNED). */

#define MLK_CONFIG_FILE "crypto/mlkem-native/xcoin_config.h"
#include "mlkem/mlkem_native.c"
