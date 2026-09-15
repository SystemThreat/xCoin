// Copyright (c) 2026 The xCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pqkey.h>
#include <slhkey.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <span>
#include <vector>

namespace {
//! Either exactly `exact` bytes (so the size checks pass and the vendored
//! parser sees the bytes) or a random length up to a little beyond it.
std::vector<unsigned char> ConsumeSizedOrRandom(FuzzedDataProvider& fdp, size_t exact)
{
    return fdp.ConsumeBool() ? ConsumeFixedLengthByteVector<unsigned char>(fdp, exact)
                             : ConsumeRandomLengthByteVector<unsigned char>(fdp, exact + 16);
}
} // namespace

// The two post-quantum verifiers that consensus calls with attacker-supplied
// bytes (script/interpreter.cpp: witness v2 and the v3 leaves 0xc0 and 0xc2),
// fed arbitrary keys, digests, messages and signatures. Neither may crash,
// read out of bounds, or accept anything with an invalid key or a
// wrong-sized signature.
FUZZ_TARGET(pqkey_verify)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    // ML-DSA-65 (CPQPubKey): the key travels on the witness, so any length reaches Set().
    {
        const std::vector<unsigned char> key_bytes{ConsumeSizedOrRandom(fdp, PQ_PUBKEY_SIZE)};
        const CPQPubKey pub{key_bytes};
        assert(pub.IsValid() == (key_bytes.size() == PQ_PUBKEY_SIZE));
        assert(pub.size() == (pub.IsValid() ? PQ_PUBKEY_SIZE : 0));

        const uint256 digest{ConsumeUInt256(fdp)};
        const std::vector<unsigned char> sig{ConsumeSizedOrRandom(fdp, PQ_SIGNATURE_SIZE)};
        const bool ok{pub.Verify(digest, sig)};
        if (ok) {
            assert(pub.IsValid());
            assert(sig.size() == PQ_SIGNATURE_SIZE);
        }
        // Verify(digest, sig) is VerifyMessage over the 32 digest bytes.
        assert(pub.VerifyMessage(std::span<const unsigned char>{digest.begin(), digest.size()}, sig) == ok);

        const std::vector<unsigned char> msg{ConsumeRandomLengthByteVector<unsigned char>(fdp, 4096)};
        if (pub.VerifyMessage(msg, sig)) {
            assert(pub.IsValid());
            assert(sig.size() == PQ_SIGNATURE_SIZE);
        }
    }

    // SLH-DSA-SHA2-128s (CSLHPubKey): the 32-byte key is pushed by the leaf script.
    {
        const std::vector<unsigned char> key_bytes{ConsumeSizedOrRandom(fdp, SLH_PUBKEY_SIZE)};
        const CSLHPubKey pub{key_bytes};
        assert(pub.IsValid() == (key_bytes.size() == SLH_PUBKEY_SIZE));

        const uint256 digest{ConsumeUInt256(fdp)};
        const std::vector<unsigned char> sig{ConsumeSizedOrRandom(fdp, SLH_SIGNATURE_SIZE)};
        const bool ok{pub.Verify(digest, sig)};
        if (ok) {
            assert(pub.IsValid());
            assert(sig.size() == SLH_SIGNATURE_SIZE);
        }
        // Verify(digest, sig) is pure mode with an empty context, i.e.
        // VerifyInternal over 0x00 || 0x00 || digest.
        std::vector<unsigned char> mprime{0x00, 0x00};
        mprime.insert(mprime.end(), digest.begin(), digest.end());
        assert(pub.VerifyInternal(mprime, sig) == ok);
        assert(pub.VerifyMessage(std::span<const unsigned char>{digest.begin(), digest.size()}, sig) == ok);

        const std::vector<unsigned char> msg{ConsumeRandomLengthByteVector<unsigned char>(fdp, 4096)};
        const std::vector<unsigned char> context{ConsumeRandomLengthByteVector<unsigned char>(fdp, SLH_MAX_CONTEXT_SIZE + 16)};
        if (pub.VerifyInternal(msg, sig)) {
            assert(pub.IsValid());
            assert(sig.size() == SLH_SIGNATURE_SIZE);
        }
        const bool pure_ok{pub.VerifyMessage(msg, sig, context)};
        if (pure_ok) {
            assert(pub.IsValid());
            assert(sig.size() == SLH_SIGNATURE_SIZE);
            assert(context.size() <= SLH_MAX_CONTEXT_SIZE);
        }
    }

    // CPQPubKey::Unserialize on an arbitrary stream: the wire length field must
    // not size an allocation (it is bounded only by MAX_SIZE), and anything but
    // exactly PQ_PUBKEY_SIZE bytes yields an invalid key.
    {
        DataStream ds{ConsumeDataStream(fdp, PQ_PUBKEY_SIZE + 64)};
        CPQPubKey pub;
        try {
            ds >> pub;
            assert(pub.size() == (pub.IsValid() ? PQ_PUBKEY_SIZE : 0));
            DataStream again;
            again << pub;
            CPQPubKey copy;
            again >> copy;
            assert(copy == pub);
        } catch (const std::ios_base::failure&) {
        }
    }
}

// Signing side of ML-DSA-65 under a fuzz-chosen seed: the wrapper's own
// signature must verify, and a single flipped bit anywhere must not. (SLH-DSA
// signing is too slow for a fuzz iteration; its verifier is covered above and
// its signer by the unit tests.)
FUZZ_TARGET(pqkey_sign_verify)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const std::vector<unsigned char> seed{ConsumeFixedLengthByteVector<unsigned char>(fdp, 32)};
    CPQKey key;
    const CPQPubKey pub{key.MakeKeyFromSeed(seed)};
    assert(key.IsValid());
    assert(pub.IsValid());
    assert(key.GetPubKey() == pub);

    const uint256 digest{ConsumeUInt256(fdp)};
    std::vector<unsigned char> sig;
    assert(key.Sign(digest, sig));
    assert(sig.size() == PQ_SIGNATURE_SIZE);
    assert(pub.Verify(digest, sig));

    const size_t byte_pos{fdp.ConsumeIntegralInRange<size_t>(0, sig.size() - 1)};
    const unsigned char bit{static_cast<unsigned char>(1u << fdp.ConsumeIntegralInRange<unsigned>(0, 7))};
    sig[byte_pos] ^= bit;
    assert(!pub.Verify(digest, sig));
    sig[byte_pos] ^= bit;
    assert(pub.Verify(digest, sig));

    uint256 other{digest};
    other.data()[fdp.ConsumeIntegralInRange<size_t>(0, 31)] ^= bit;
    assert(!pub.Verify(other, sig));
}
