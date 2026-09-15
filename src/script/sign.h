// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGN_H
#define BITCOIN_SCRIPT_SIGN_H

#include <attributes.h>
#include <coins.h>
#include <hash.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/keyorigin.h>
#include <script/signingprovider.h>
#include <uint256.h>

#include <optional>
#include <string>
#include <vector>

class CKey;
class CKeyID;
class CScript;
class CTransaction;
class SigningProvider;

struct bilingual_str;
struct CMutableTransaction;
struct SignatureData;

/** Interface for signature creators. */
class BaseSignatureCreator {
public:
    virtual ~BaseSignatureCreator() = default;
    virtual const BaseSignatureChecker& Checker() const =0;

    /** Create a singular (non-script) signature. */
    virtual bool CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const =0;
    virtual bool CreateSchnorrSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const XOnlyPubKey& pubkey, const uint256* leaf_hash, const uint256* merkle_root, SigVersion sigversion) const =0;
    virtual std::vector<uint8_t> CreateMuSig2Nonce(const SigningProvider& provider, const CPubKey& aggregate_pubkey, const CPubKey& script_pubkey, const CPubKey& part_pubkey, const uint256* leaf_hash, const uint256* merkle_root, SigVersion sigversion, const SignatureData& sigdata) const =0;
    virtual bool CreateMuSig2PartialSig(const SigningProvider& provider, uint256& partial_sig, const CPubKey& aggregate_pubkey, const CPubKey& script_pubkey, const CPubKey& part_pubkey, const uint256* leaf_hash, const std::vector<std::pair<uint256, bool>>& tweaks, SigVersion sigversion, const SignatureData& sigdata) const =0;
    virtual bool CreateMuSig2AggregateSig(const std::vector<CPubKey>& participants, std::vector<uint8_t>& sig, const CPubKey& aggregate_pubkey, const CPubKey& script_pubkey, const uint256* leaf_hash, const std::vector<std::pair<uint256, bool>>& tweaks, SigVersion sigversion, const SignatureData& sigdata) const =0;

    // xCoin post-quantum signatures (contrib/regenesis/REGENESIS.md section 4).
    /** Witness v2 (legacy): ML-DSA-65 signature over the BIP143-style sighash with scriptCode
     *  OP_2 <program> (SigVersion::WITNESS_V0), followed by the hash-type byte (SIGHASH_DEFAULT
     *  is signed as SIGHASH_ALL). */
    virtual bool CreatePQSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const CPQKeyID& keyid, const CScript& scriptCode) const =0;
    /** Witness v3 ML-DSA leaf (SigVersion::XCOIN_PQ_TAPSCRIPT): ML-DSA-65 signature over the
     *  tagged v3 sighash of the leaf; the hash-type byte is appended unless SIGHASH_DEFAULT. */
    virtual bool CreateXcoinV3PQSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const CPQKeyID& keyid, const uint256& leaf_hash) const =0;
    /** Witness v3 SLH leaf (SigVersion::XCOIN_SLH_TAPSCRIPT): SLH-DSA-SHA2-128s signature (FIPS 205
     *  pure mode, empty context) over the tagged v3 sighash; hash-type byte as above. */
    virtual bool CreateXcoinV3SLHSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const CSLHPubKey& pubkey, const uint256& leaf_hash) const =0;
};

/** A signature creator for transactions. */
class MutableTransactionSignatureCreator : public BaseSignatureCreator
{
    const CMutableTransaction& m_txto;
    unsigned int nIn;
    int nHashType;
    CAmount amount;
    const MutableTransactionSignatureChecker checker;
    const PrecomputedTransactionData* m_txdata;

    std::optional<uint256> ComputeSchnorrSignatureHash(const uint256* leaf_hash, SigVersion sigversion) const;
    std::optional<uint256> ComputeXcoinV3SignatureHash(const uint256& leaf_hash, SigVersion sigversion) const;

public:
    MutableTransactionSignatureCreator(const CMutableTransaction& tx LIFETIMEBOUND, unsigned int input_idx, const CAmount& amount, int hash_type);
    MutableTransactionSignatureCreator(const CMutableTransaction& tx LIFETIMEBOUND, unsigned int input_idx, const CAmount& amount, const PrecomputedTransactionData* txdata, int hash_type);
    const BaseSignatureChecker& Checker() const override { return checker; }
    bool CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const override;
    bool CreateSchnorrSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const XOnlyPubKey& pubkey, const uint256* leaf_hash, const uint256* merkle_root, SigVersion sigversion) const override;
    std::vector<uint8_t> CreateMuSig2Nonce(const SigningProvider& provider, const CPubKey& aggregate_pubkey, const CPubKey& script_pubkey, const CPubKey& part_pubkey, const uint256* leaf_hash, const uint256* merkle_root, SigVersion sigversion, const SignatureData& sigdata) const override;
    bool CreateMuSig2PartialSig(const SigningProvider& provider, uint256& partial_sig, const CPubKey& aggregate_pubkey, const CPubKey& script_pubkey, const CPubKey& part_pubkey, const uint256* leaf_hash, const std::vector<std::pair<uint256, bool>>& tweaks, SigVersion sigversion, const SignatureData& sigdata) const override;
    bool CreateMuSig2AggregateSig(const std::vector<CPubKey>& participants, std::vector<uint8_t>& sig, const CPubKey& aggregate_pubkey, const CPubKey& script_pubkey, const uint256* leaf_hash, const std::vector<std::pair<uint256, bool>>& tweaks, SigVersion sigversion, const SignatureData& sigdata) const override;
    bool CreatePQSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const CPQKeyID& keyid, const CScript& scriptCode) const override;
    bool CreateXcoinV3PQSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const CPQKeyID& keyid, const uint256& leaf_hash) const override;
    bool CreateXcoinV3SLHSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const CSLHPubKey& pubkey, const uint256& leaf_hash) const override;
};

/** A signature checker that accepts all signatures */
extern const BaseSignatureChecker& DUMMY_CHECKER;
/** A signature creator that just produces 71-byte empty signatures. */
extern const BaseSignatureCreator& DUMMY_SIGNATURE_CREATOR;
/** A signature creator that just produces 72-byte empty signatures. */
extern const BaseSignatureCreator& DUMMY_MAXIMUM_SIGNATURE_CREATOR;

typedef std::pair<CPubKey, std::vector<unsigned char>> SigPair;

// This struct contains information from a transaction input and also contains signatures for that input.
// The information contained here can be used to create a signature and is also filled by ProduceSignature
// in order to construct final scriptSigs and scriptWitnesses.
struct SignatureData {
    bool complete = false; ///< Stores whether the scriptSig and scriptWitness are complete
    bool witness = false; ///< Stores whether the input this SigData corresponds to is a witness input
    CScript scriptSig; ///< The scriptSig of an input. Contains complete signatures or the traditional partial signatures format
    CScript redeem_script; ///< The redeemScript (if any) for the input
    CScript witness_script; ///< The witnessScript (if any) for the input. witnessScripts are used in P2WSH outputs.
    CScriptWitness scriptWitness; ///< The scriptWitness of an input. Contains complete signatures or the traditional partial signatures format. scriptWitness is part of a transaction input per BIP 144.
    TaprootSpendData tr_spenddata; ///< Taproot spending data.
    std::optional<TaprootBuilder> tr_builder; ///< Taproot tree used to build tr_spenddata.
    XcoinV3SpendData xcoin_v3_spenddata; ///< xCoin witness v3 spending data (leaf scripts and control blocks).
    std::map<CPQKeyID, CPQPubKey> pq_pubkeys; ///< ML-DSA-65 public keys involved in this input, by SHA-256(pubkey).
    std::map<CKeyID, SigPair> signatures; ///< BIP 174 style partial signatures for the input. May contain all signatures necessary for producing a final scriptSig or scriptWitness.
    std::map<CKeyID, std::pair<CPubKey, KeyOriginInfo>> misc_pubkeys;
    std::vector<unsigned char> taproot_key_path_sig; /// Schnorr signature for key path spending
    std::map<std::pair<XOnlyPubKey, uint256>, std::vector<unsigned char>> taproot_script_sigs; ///< (Partial) schnorr signatures, indexed by XOnlyPubKey and leaf_hash.
    std::map<XOnlyPubKey, std::pair<std::set<uint256>, KeyOriginInfo>> taproot_misc_pubkeys; ///< Miscellaneous Taproot pubkeys involved in this input along with their leaf script hashes and key origin data. Also includes the Taproot internal and output keys (may have no leaf script hashes).
    std::map<CKeyID, XOnlyPubKey> tap_pubkeys; ///< Misc Taproot pubkeys involved in this input, by hash. (Equivalent of misc_pubkeys but for Taproot.)
    std::vector<CKeyID> missing_pubkeys; ///< KeyIDs of pubkeys which could not be found
    std::vector<CKeyID> missing_sigs; ///< KeyIDs of pubkeys for signatures which could not be found
    uint160 missing_redeem_script; ///< ScriptID of the missing redeemScript (if any)
    uint256 missing_witness_script; ///< SHA256 of the missing witnessScript (if any)
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> sha256_preimages; ///< Mapping from a SHA256 hash to its preimage provided to solve a Script
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> hash256_preimages; ///< Mapping from a HASH256 hash to its preimage provided to solve a Script
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> ripemd160_preimages; ///< Mapping from a RIPEMD160 hash to its preimage provided to solve a Script
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> hash160_preimages; ///< Mapping from a HASH160 hash to its preimage provided to solve a Script
    //! Map MuSig2 aggregate pubkeys to its participants
    std::map<CPubKey, std::vector<CPubKey>> musig2_pubkeys;
    //! Mapping from pair of MuSig2 aggregate pubkey, and tapleaf hash to map of MuSig2 participant pubkeys to MuSig2 public nonce
    std::map<std::pair<CPubKey, uint256>, std::map<CPubKey, std::vector<uint8_t>>> musig2_pubnonces;
    //! Mapping from pair of MuSig2 aggregate pubkey, and tapleaf hash to map of MuSig2 participant pubkeys to MuSig2 partial signature
    std::map<std::pair<CPubKey, uint256>, std::map<CPubKey, uint256>> musig2_partial_sigs;

    SignatureData() = default;
    explicit SignatureData(const CScript& script) : scriptSig(script) {}
    void MergeSignatureData(SignatureData sigdata);
};

/** Produce a script signature using a generic signature creator. */
bool ProduceSignature(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& scriptPubKey, SignatureData& sigdata);

/** The leaf scripts the built-in signer understands inside an xCoin witness v3 tree
 *  (contrib/regenesis/REGENESIS.md section 4; the pqtr() descriptor leaves):
 *    pq(K):                  <SHA256(mldsa_pubkey)> OP_CHECKSIG                           (leaf 0xc0)
 *    slh(K):                 <slh_pubkey32> OP_CHECKSIG                                   (leaf 0xc2)
 *    and_v(v:pq(K),after(n)): <SHA256(mldsa_pubkey)> OP_CHECKSIGVERIFY <n> OP_CHECKLOCKTIMEVERIFY
 *    and_v(v:pq(K),older(n)): <SHA256(mldsa_pubkey)> OP_CHECKSIGVERIFY <n> OP_CHECKSEQUENCEVERIFY
 *  and the same two time-locked forms with an SLH key. */
struct XcoinV3LeafTemplate {
    enum class Algorithm { MLDSA, SLH };
    enum class Timelock { NONE, AFTER, OLDER };
    Algorithm algorithm;
    /** 32 bytes: SHA-256 of the ML-DSA-65 key, or the SLH-DSA public key itself. */
    std::vector<unsigned char> key;
    Timelock timelock{Timelock::NONE};
    uint32_t timelock_value{0};
};
/** Recognize one of the leaf templates above (leaf_version selects the algorithm). */
std::optional<XcoinV3LeafTemplate> ParseXcoinV3LeafTemplate(int leaf_version, const CScript& script);

/** Human-readable reasons a script would be ANYONE-CAN-SPEND as an xCoin
 *  witness v3 leaf script: it carries an OP_SUCCESSx byte, or the key push
 *  before a signature opcode is not 32 bytes (an upgradable key type, which
 *  passes the check without verifying anything). Empty when there is nothing
 *  to warn about. Used by decodescript and getaddressinfo so a wallet can warn
 *  before someone pays such a leaf; it is not a validity rule. */
std::vector<std::string> XcoinV3LeafWarnings(const CScript& script);

/** Extract signature data from a transaction input, and insert it. */
SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn, const CTxOut& txout);
void UpdateInput(CTxIn& input, const SignatureData& data);

/** Check whether a scriptPubKey is known to be segwit. */
bool IsSegWitOutput(const SigningProvider& provider, const CScript& script);

/** Sign the CMutableTransaction */
bool SignTransaction(CMutableTransaction& mtx, const SigningProvider* provider, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors);

#endif // BITCOIN_SCRIPT_SIGN_H
