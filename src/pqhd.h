// Copyright (c) 2026 The NEX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEX_PQHD_H
#define NEX_PQHD_H

#include <pqkey.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

/**
 * Post-Quantum HD Key Derivation for NEX.
 *
 * BIP-39 24-word mnemonic → master seed → PQ keypairs
 *
 * Derivation path:
 *   1. BIP-39 mnemonic → 64-byte master seed (PBKDF2-HMAC-SHA512)
 *   2. Master seed → SHAKE-256(seed || "NEX-PQ-MASTER") → 32-byte PQ master secret
 *   3. PQ master secret + index → SHAKE-256(master || uint32_le(index) || "NEX-PQ-CHILD")
 *      → 32-byte child seed → ML-DSA-65 keypair
 *
 * This is NOT BIP-32 (ECDSA-specific). ML-DSA-65 uses different math.
 * The mnemonic and PBKDF2 step is standard BIP-39; only the key derivation differs.
 */

/** Domain separator for PQ master key derivation. */
static const std::string PQ_MASTER_DOMAIN = "NEX-PQ-MASTER";

/** Domain separator for PQ child key derivation. */
static const std::string PQ_CHILD_DOMAIN = "NEX-PQ-CHILD";

/**
 * Derive a PQ master secret from a BIP-39 master seed.
 *
 * @param masterSeed   The 64-byte BIP-39 master seed (from PBKDF2)
 * @param masterSecret Output: 32-byte PQ master secret
 */
void DerivePQMasterSecret(std::span<const unsigned char> masterSeed,
                          std::array<unsigned char, 32>& masterSecret);

/**
 * Derive an ML-DSA-65 keypair at a given index from a PQ master secret.
 *
 * @param masterSecret  The 32-byte PQ master secret
 * @param index         Child key index (0, 1, 2, ...)
 * @param key           Output: the derived ML-DSA-65 secret key
 * @param pubkey        Output: the corresponding public key
 * @return true on success
 */
bool DerivePQChildKey(const std::array<unsigned char, 32>& masterSecret,
                      uint32_t index,
                      CPQKey& key,
                      CPQPubKey& pubkey);

/**
 * Convenience: derive a PQ keypair directly from a BIP-39 master seed + index.
 *
 * @param masterSeed  The 64-byte BIP-39 master seed
 * @param index       Child key index
 * @param key         Output: ML-DSA-65 secret key
 * @param pubkey      Output: ML-DSA-65 public key
 * @return true on success
 */
bool DerivePQKeyFromSeed(std::span<const unsigned char> masterSeed,
                         uint32_t index,
                         CPQKey& key,
                         CPQPubKey& pubkey);

// ── xCoin HD derivation for descriptors ──────────────────────────────────────
//
// A pq() or slh() descriptor key expression carries an xpub/xprv path exactly like
// a Bitcoin key expression, but the post-quantum key pair at each position is
// seeded from the ROOT extended private key and the full derivation path, never
// from a child key:
//
//   material          = root_privkey32 || root_chaincode32 || u32le(path[0]) || ... || u32le(path[n-1])
//   ML-DSA-65 seed 32 = SHAKE-256(material || "xcoin/hd/ml-dsa-65/seed/v2")
//   SLH-DSA seed  48  = SHAKE-256(material || "xcoin/hd/slh-dsa-sha2-128s/seed/v2")
//
// (path elements keep their hardened bit; the ranged position is the last one).
//
// Why the root and not the child (audit finding 5, 2026-09-14): the wallet hands
// out account xpubs as public artifacts (listdescriptors, getaddressinfo). A
// child key reachable from an exported xpub has a public counterpart, so an
// adversary who can solve discrete logarithms would recover the child private
// key and, with the old scheme, every post-quantum key seeded from it. The root
// key sits behind hardened steps and its xpub is never exported, so nothing
// public leads to it even with discrete logarithms broken. There is still no
// public derivation: expanding a pq()/slh() BIP32 expression needs the private
// key, and the wallet caches every derived public key. This scheme is a wallet
// convention, not consensus; it is frozen so a seed backup restores every
// address (contrib/regenesis/REGENESIS.md section 4).

static const std::string XCOIN_HD_MLDSA_SEED_DOMAIN = "xcoin/hd/ml-dsa-65/seed/v2";
static const std::string XCOIN_HD_SLH_SEED_DOMAIN = "xcoin/hd/slh-dsa-sha2-128s/seed/v2";

/** SHAKE-256(root_privkey32 || root_chaincode32 || path || XCOIN_HD_MLDSA_SEED_DOMAIN) -> 32 bytes. */
void DeriveXcoinMLDSASeed(std::span<const unsigned char> root_privkey32, std::span<const unsigned char> root_chaincode32, std::span<const uint32_t> path, std::array<unsigned char, 32>& seed_out);
/** SHAKE-256(root_privkey32 || root_chaincode32 || path || XCOIN_HD_SLH_SEED_DOMAIN) -> 48 bytes. */
void DeriveXcoinSLHSeed(std::span<const unsigned char> root_privkey32, std::span<const unsigned char> root_chaincode32, std::span<const uint32_t> path, std::array<unsigned char, 48>& seed_out);

#endif // NEX_PQHD_H
