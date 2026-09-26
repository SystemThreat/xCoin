#!/usr/bin/env python3
# Copyright (c) 2026 The xCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test-only implementation of ML-KEM-768 (FIPS 203, August 2024)

ML-KEM is the post-quantum key encapsulation mechanism that NIST standardized
in FIPS 203. This file follows the final standard, not the round-3 Kyber
submission it grew out of. The two give different outputs for the same seeds:
- K-PKE.KeyGen hashes d||k, not d alone (Algorithm 13, line 1);
- Encaps uses the 32-byte m as given, where Kyber hashed it first;
- the shared secret is the first half of G(m||H(ek)) itself, where Kyber
  hashed it again together with H(c) (Algorithm 17);
- implicit rejection returns J(z||c) (Algorithm 18, line 7).

Function names and the algorithm numbers in the comments are the ones in
FIPS 203, so each function can be read next to the standard. Only the
ML-KEM-768 parameter set (section 8, Table 2) is implemented, because that is
the one the hybrid v2 transport uses.

The only dependency is hashlib, for SHA3-256, SHA3-512, SHAKE128 and SHAKE256
(FIPS 203 section 4.1).

It is designed for ease of understanding, not performance.

WARNING: This code is slow, is not constant time, and is trivially vulnerable
to side channel attacks. Do not use for anything but tests.
"""

import hashlib
import os
import random
import unittest

# ML-KEM-768 parameters (FIPS 203, section 8, Table 2).
N = 256    # coefficients per polynomial
Q = 3329   # the prime modulus q
K = 3      # the rank k: vectors hold k polynomials, the matrix is k x k
ETA1 = 2
ETA2 = 2
DU = 10
DV = 4

# Sizes in bytes (FIPS 203, section 8, Table 3).
EK_SIZE = 384 * K + 32          # 1184, encapsulation key
DK_SIZE = 768 * K + 96          # 2400, decapsulation key
CT_SIZE = 32 * (DU * K + DV)    # 1088, ciphertext
SS_SIZE = 32                    # shared secret
SEED_SIZE = 32                  # each of the seeds d, z and m


# Hash functions (FIPS 203, section 4.1).

def H(s):
    """H(s) = SHA3-256(s)."""
    return hashlib.sha3_256(s).digest()


def J(s):
    """J(s) = SHAKE256(s, 8*32): 32 bytes of output."""
    return hashlib.shake_256(s).digest(32)


def G(c):
    """G(c) = SHA3-512(c), split into two 32-byte halves."""
    out = hashlib.sha3_512(c).digest()
    return out[:32], out[32:]


def PRF(eta, s, b):
    """PRF_eta(s, b) = SHAKE256(s||b, 8*64*eta), where b is a single byte."""
    assert len(s) == 32 and 0 <= b < 256
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


# The number-theoretic transform constants (FIPS 203, section 4.3).

def bitrev7(i):
    """BitRev7(i): reverse the 7-bit binary representation of 0 <= i < 128."""
    return int(format(i, '07b')[::-1], 2)


# zeta = 17 is a primitive 256-th root of unity modulo q.
ZETA = 17
# zeta^BitRev7(i) mod q: the twiddle factors of Algorithms 9 and 10 (Appendix A).
NTT_ZETAS = [pow(ZETA, bitrev7(i), Q) for i in range(128)]
# zeta^(2*BitRev7(i)+1) mod q: the gamma values of Algorithm 11 (Appendix A).
MULT_GAMMAS = [pow(ZETA, 2 * bitrev7(i) + 1, Q) for i in range(128)]
# 128^-1 mod q, the final scaling in Algorithm 10.
INV_128 = 3303
assert (128 * INV_128) % Q == 1


# Encoding and compression (FIPS 203, section 4.2.1).

def byte_encode(f, d):
    """ByteEncode_d (Algorithm 5): pack 256 d-bit integers into 32*d bytes.

    Bit j of f[i] becomes bit number i*d+j of the output, and bit number b of
    the output sits in byte b//8 at position b%8 (BitsToBytes, Algorithm 3).
    That is exactly the little-endian encoding of sum(f[i] * 2^(d*i)).
    """
    assert len(f) == N
    m = Q if d == 12 else 1 << d
    acc = 0
    for i, a in enumerate(f):
        assert 0 <= a < m
        acc |= a << (d * i)
    return acc.to_bytes(32 * d, 'little')


def byte_decode(b, d):
    """ByteDecode_d (Algorithm 6): unpack 32*d bytes into 256 integers.

    The inverse of byte_encode, except that for d = 12 each 12-bit value is
    reduced modulo q. The section 7.2 modulus check relies on that reduction.
    """
    assert len(b) == 32 * d
    m = Q if d == 12 else 1 << d
    acc = int.from_bytes(b, 'little')   # BytesToBits (Algorithm 4)
    mask = (1 << d) - 1
    return [((acc >> (d * i)) & mask) % m for i in range(N)]


def compress(d, x):
    """Compress_d(x) = round((2^d / q) * x) mod 2^d (equation 4.7).

    FIPS 203 rounds halves up. q is odd, so (2^d * x) / q is never exactly
    halfway between two integers, and adding floor(q/2) before the integer
    division gives the same result as adding q/2.
    """
    return (((x << d) + Q // 2) // Q) % (1 << d)


def decompress(d, y):
    """Decompress_d(y) = round((q / 2^d) * y) (equation 4.8), halves rounded up."""
    return (Q * y + (1 << (d - 1))) >> d


# Sampling (FIPS 203, section 4.2.2).

def sample_ntt(b):
    """SampleNTT (Algorithm 7): a uniform polynomial in NTT form, from the
    34-byte seed b = rho||j||i, by rejection sampling SHAKE128 output.

    hashlib cannot squeeze SHAKE128 a few bytes at a time, but SHAKE output is
    a stream: the first n bytes of a longer digest are the n-byte digest. So
    reading 3 bytes at a time from one long digest is the same as squeezing 3
    bytes at a time, and if the digest runs out a longer one is taken.
    """
    assert len(b) == 34
    xof_len = 3 * 168   # three SHAKE128 blocks, a multiple of 3
    stream = hashlib.shake_128(b).digest(xof_len)
    pos = 0
    a = []
    while len(a) < N:
        if pos == len(stream):
            xof_len *= 2
            stream = hashlib.shake_128(b).digest(xof_len)
        c0, c1, c2 = stream[pos], stream[pos + 1], stream[pos + 2]
        pos += 3
        d1 = c0 + 256 * (c1 % 16)
        d2 = c1 // 16 + 16 * c2
        if d1 < Q:
            a.append(d1)
        if d2 < Q and len(a) < N:
            a.append(d2)
    return a


def sample_poly_cbd(eta, b):
    """SamplePolyCBD_eta (Algorithm 8): a polynomial with small coefficients,
    from 64*eta bytes b.

    Coefficient i is x - y mod q, where x counts the one bits among bits
    2*i*eta .. 2*i*eta+eta-1 of b, and y counts them among the next eta bits.
    """
    assert len(b) == 64 * eta
    bits = int.from_bytes(b, 'little')   # BytesToBits (Algorithm 4)
    mask = (1 << eta) - 1
    f = []
    for i in range(N):
        x = ((bits >> (2 * i * eta)) & mask).bit_count()
        y = ((bits >> (2 * i * eta + eta)) & mask).bit_count()
        f.append((x - y) % Q)
    return f


# Polynomial arithmetic (FIPS 203, section 4.3).

def ntt(f):
    """NTT (Algorithm 9): the number-theoretic transform of polynomial f."""
    f_hat = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = NTT_ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = (zeta * f_hat[j + length]) % Q
                f_hat[j + length] = (f_hat[j] - t) % Q
                f_hat[j] = (f_hat[j] + t) % Q
        length //= 2
    return f_hat


def ntt_inv(f_hat):
    """NTT^-1 (Algorithm 10): the inverse of ntt()."""
    f = list(f_hat)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = NTT_ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = (zeta * (f[j + length] - t)) % Q
        length *= 2
    return [(x * INV_128) % Q for x in f]


def base_case_multiply(a0, a1, b0, b1, gamma):
    """BaseCaseMultiply (Algorithm 12): (a0 + a1*X) * (b0 + b1*X) modulo
    X^2 - gamma."""
    c0 = (a0 * b0 + a1 * b1 * gamma) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1


def multiply_ntts(f_hat, g_hat):
    """MultiplyNTTs (Algorithm 11): the NTT form of the product of the two
    polynomials whose NTT forms are f_hat and g_hat."""
    h_hat = [0] * N
    for i in range(128):
        h_hat[2 * i], h_hat[2 * i + 1] = base_case_multiply(
            f_hat[2 * i], f_hat[2 * i + 1], g_hat[2 * i], g_hat[2 * i + 1], MULT_GAMMAS[i])
    return h_hat


def poly_add(f, g):
    return [(a + b) % Q for a, b in zip(f, g)]


def poly_sub(f, g):
    return [(a - b) % Q for a, b in zip(f, g)]


def inner_product_ntt(u_hat, v_hat):
    """u_hat^T o v_hat for two length-k vectors in NTT form (section 2.4.7,
    equation 2.14): the sum of the k products u_hat[j] x v_hat[j]."""
    acc = [0] * N
    for a, b in zip(u_hat, v_hat):
        acc = poly_add(acc, multiply_ntts(a, b))
    return acc


def sample_matrix(rho):
    """A_hat, with A_hat[i][j] = SampleNTT(rho||j||i).

    Lines 3-7 of Algorithm 13 and lines 4-8 of Algorithm 14. Note the order:
    the column index j comes before the row index i.
    """
    return [[sample_ntt(rho + bytes([j, i])) for j in range(K)] for i in range(K)]


# The K-PKE component scheme (FIPS 203, section 5).

def kpke_keygen(d):
    """K-PKE.KeyGen (Algorithm 13). Returns (ek_PKE, dk_PKE)."""
    assert len(d) == 32
    rho, sigma = G(d + bytes([K]))   # the domain-separating byte k is new in FIPS 203
    a_hat = sample_matrix(rho)
    n = 0
    s = []
    for _ in range(K):
        s.append(sample_poly_cbd(ETA1, PRF(ETA1, sigma, n)))
        n += 1
    e = []
    for _ in range(K):
        e.append(sample_poly_cbd(ETA1, PRF(ETA1, sigma, n)))
        n += 1
    s_hat = [ntt(p) for p in s]
    e_hat = [ntt(p) for p in e]
    # t_hat = A_hat o s_hat + e_hat: row i of A_hat times the vector s_hat.
    t_hat = [poly_add(inner_product_ntt(a_hat[i], s_hat), e_hat[i]) for i in range(K)]
    ek_pke = b''.join(byte_encode(p, 12) for p in t_hat) + rho
    dk_pke = b''.join(byte_encode(p, 12) for p in s_hat)
    return ek_pke, dk_pke


def kpke_encrypt(ek_pke, m, r):
    """K-PKE.Encrypt (Algorithm 14): encrypt the 32-byte message m with the
    32 bytes of randomness r. Returns the ciphertext c."""
    assert len(ek_pke) == EK_SIZE and len(m) == 32 and len(r) == 32
    n = 0
    t_hat = [byte_decode(ek_pke[384 * i:384 * (i + 1)], 12) for i in range(K)]
    rho = ek_pke[384 * K:384 * K + 32]
    a_hat = sample_matrix(rho)
    y = []
    for _ in range(K):
        y.append(sample_poly_cbd(ETA1, PRF(ETA1, r, n)))
        n += 1
    e1 = []
    for _ in range(K):
        e1.append(sample_poly_cbd(ETA2, PRF(ETA2, r, n)))
        n += 1
    e2 = sample_poly_cbd(ETA2, PRF(ETA2, r, n))
    y_hat = [ntt(p) for p in y]
    # u = NTT^-1(A_hat^T o y_hat) + e1: entry i uses column i of A_hat.
    u = []
    for i in range(K):
        column_i = [a_hat[j][i] for j in range(K)]
        u.append(poly_add(ntt_inv(inner_product_ntt(column_i, y_hat)), e1[i]))
    mu = [decompress(1, bit) for bit in byte_decode(m, 1)]
    v = poly_add(poly_add(ntt_inv(inner_product_ntt(t_hat, y_hat)), e2), mu)
    c1 = b''.join(byte_encode([compress(DU, x) for x in p], DU) for p in u)
    c2 = byte_encode([compress(DV, x) for x in v], DV)
    return c1 + c2


def kpke_decrypt(dk_pke, c):
    """K-PKE.Decrypt (Algorithm 15). Returns the 32-byte message."""
    assert len(dk_pke) == 384 * K and len(c) == CT_SIZE
    c1 = c[:32 * DU * K]
    c2 = c[32 * DU * K:]
    u_prime = [[decompress(DU, x) for x in byte_decode(c1[32 * DU * i:32 * DU * (i + 1)], DU)]
               for i in range(K)]
    v_prime = [decompress(DV, x) for x in byte_decode(c2, DV)]
    s_hat = [byte_decode(dk_pke[384 * i:384 * (i + 1)], 12) for i in range(K)]
    w = poly_sub(v_prime, ntt_inv(inner_product_ntt(s_hat, [ntt(p) for p in u_prime])))
    return byte_encode([compress(1, x) for x in w], 1)


# The internal algorithms (FIPS 203, section 6). They take their randomness as
# arguments, which makes them deterministic and suitable for test vectors.

def keygen_internal(d, z):
    """ML-KEM.KeyGen_internal (Algorithm 16). Returns (ek, dk)."""
    assert len(d) == SEED_SIZE and len(z) == SEED_SIZE
    ek_pke, dk_pke = kpke_keygen(d)
    ek = ek_pke
    dk = dk_pke + ek + H(ek) + z
    return ek, dk


def encaps_internal(ek, m):
    """ML-KEM.Encaps_internal (Algorithm 17). Returns (shared secret, c).

    It does not check ek. Callers that received ek from someone else must run
    check_encaps_key() first, as encaps() does.
    """
    assert len(m) == SEED_SIZE
    shared_secret, r = G(m + H(ek))
    c = kpke_encrypt(ek, m, r)
    return shared_secret, c


def decaps_internal(dk, c):
    """ML-KEM.Decaps_internal (Algorithm 18). Returns the shared secret.

    If c is not a valid encapsulation under this key the result is the
    implicit-rejection value J(z||c), a pseudorandom value that the sender
    cannot predict. There is no error; the two sides then simply hold
    different secrets.
    """
    assert len(dk) == DK_SIZE and len(c) == CT_SIZE
    dk_pke = dk[0:384 * K]
    ek_pke = dk[384 * K:768 * K + 32]
    h = dk[768 * K + 32:768 * K + 64]
    z = dk[768 * K + 64:768 * K + 96]
    m_prime = kpke_decrypt(dk_pke, c)
    k_prime, r_prime = G(m_prime + h)
    k_bar = J(z + c)
    c_prime = kpke_encrypt(ek_pke, m_prime, r_prime)
    if c != c_prime:
        k_prime = k_bar
    return k_prime


# Input checks (FIPS 203, sections 7.2 and 7.3).

def check_encaps_key(ek):
    """Section 7.2: the input checks ML-KEM.Encaps requires on ek.

    Type check: ek is exactly 384*k + 32 bytes.
    Modulus check (equation 7.1): every 12-bit coefficient in the first 384*k
    bytes is less than q. ByteDecode_12 reduces modulo q, so re-encoding the
    decoded key gives back the original bytes exactly when no coefficient is
    out of range.
    """
    if len(ek) != EK_SIZE:
        return False
    for i in range(K):
        chunk = ek[384 * i:384 * (i + 1)]
        if byte_encode(byte_decode(chunk, 12), 12) != chunk:
            return False
    return True


def check_decaps_key(dk):
    """Section 7.3: the input checks ML-KEM.Decaps requires on dk.

    Type check: dk is exactly 768*k + 96 bytes.
    Hash check (equation 7.2): the H(ek) stored in dk matches the ek stored
    in dk.
    """
    if len(dk) != DK_SIZE:
        return False
    return H(dk[384 * K:768 * K + 32]) == dk[768 * K + 32:768 * K + 64]


# The external algorithms (FIPS 203, section 7). They draw their own
# randomness and check their inputs.

def keygen():
    """ML-KEM.KeyGen (Algorithm 19). Returns (ek, dk).

    os.urandom raises rather than returning short output, which covers the
    "return an error if the random bit generator fails" step.
    """
    d = os.urandom(SEED_SIZE)
    z = os.urandom(SEED_SIZE)
    return keygen_internal(d, z)


def encaps(ek):
    """ML-KEM.Encaps (Algorithm 20) with the section 7.2 checks.
    Returns (shared secret, c). Raises ValueError if ek fails the checks."""
    ek = bytes(ek)
    if not check_encaps_key(ek):
        raise ValueError("ML-KEM-768 encapsulation key failed the FIPS 203 section 7.2 check")
    m = os.urandom(SEED_SIZE)
    return encaps_internal(ek, m)


def decaps(dk, c):
    """ML-KEM.Decaps (Algorithm 21) with the section 7.3 checks.
    Returns the shared secret. Raises ValueError if c has the wrong length or
    dk fails the checks. A wrong but well-formed c is not an error: it gives
    the implicit-rejection value J(z||c)."""
    dk = bytes(dk)
    c = bytes(c)
    if len(c) != CT_SIZE:
        raise ValueError("ML-KEM-768 ciphertext has the wrong length")
    if not check_decaps_key(dk):
        raise ValueError("ML-KEM-768 decapsulation key failed the FIPS 203 section 7.3 check")
    return decaps_internal(dk, c)


def set_ek_coefficient(ek, index, value):
    """Test helper: return ek with its 12-bit coefficient number index
    (0 <= index < 256*k) replaced by value (0 <= value < 4096). Values of q or
    more give an encapsulation key that fails the section 7.2 modulus check."""
    assert 0 <= index < N * K and 0 <= value < 4096
    poly, pos = divmod(index, N)
    chunk = int.from_bytes(ek[384 * poly:384 * (poly + 1)], 'little')
    chunk = (chunk & ~(0xfff << (12 * pos))) | (value << (12 * pos))
    return ek[:384 * poly] + chunk.to_bytes(384, 'little') + ek[384 * (poly + 1):]


# Vectors produced by OpenSSL 3.6.4 alone, with no Python ML-KEM involved:
# genpkey -algorithm ML-KEM-768 -pkeyopt hexseed:d||z, pkeyutl -encap
# -pkeyopt hexikme:m, and pkeyutl -decap of c with bit 0 of byte 0 flipped.
# Each entry: d, z, m, SHA3-256(ek), SHA3-256(dk), SHA3-256(c), the shared
# secret, and the implicit-rejection output for the flipped ciphertext.
MLKEM768_OPENSSL_VECTORS = [
    ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
     "6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283",
     "a24e16d8f8f9383a95b77050f4d9fd2f5733eec1d63ef3c23ebf9918173669a7",
     "1149f17c3c4ac6ab1e3e2d9d8bd0171355ac0fa31bb8855c48ceade874c0864b",
     "ce221a0989a8597aa562b69a8c235edc93ccf72fadc91d96785c9a09075e5cd1",
     "c5a74110c158acbaf9c01deb86fa6cc10c14533feda54bec1fdd000d61f07e4e",
     "bb28c25ed3222c13ce49d65f663f1c9f148565a664747e142f1abe06f33f4826"],
    ["0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "07f81a8b0e266a3ee92d3a63cdae5cff921905544c9dd797a849e1d054180eca",
     "b476cca5af51be72dd16e096491931b4c7c2236772d3a091d6cff0287e83c70b",
     "458a9896b26a4cba613b45288e09d89f688d69f181d4f11e3c486057fb3066ac",
     "b4d29cd55bab43e16554b74b9098cdfce583996c968bcd2cfd1ad9455e351fbf",
     "48bd302115c9ec6fbf24885b7e3d1bbbd2c8f57072d1f0e2479828451742fd55"],
    ["ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "60e00b9acb3bfb391eb3493e6547715bfee49debcb272ec3629254d1f574fb8d",
     "f9dec5faab2bf62212e6f3b4431576e562a8478f17717f735e3843a482b6b67a",
     "98b93f375ed28821f0a510571f4b54365b0e00e7ebba58f574f2132599e78a8a",
     "e8ee7d2cca02b283880f34d21c11224fc0460a04bfef571fa99df87ff4b104c8",
     "54c0ad3bed9627ba84a0a4cc4dca4f23f1b2cb61f0f9178cec3ebe53e64228a5"],
    ["c2647eebe7324479a9a439b394c02acb17d9c54c8fc0ab7e35a1d5766a3c4c6e",
     "7b4b1dd2aa447448fb931f50d9f6fe5550ecbfccfb4791b62cc3348f2e91d32f",
     "a18b68778e4a467a34c78ca735dd53dfeb558aabc740072a275cf94cca2df78a",
     "e9adeed5a0431d0f344f52aef191762d3427d7cad7ffe1c2353b79cfd7ab598d",
     "c8b549971bdd778e5a167b26af50610316b0e4292076e1ca9d5708e7ecbfd9bd",
     "37c3734eda5915c9dadf3409fe28a38543fb71edccf7758a62e5012101d706fe",
     "3e4f483f4bbea87975e4b5ade78f55166fae25bdb979cbb57d47dd61031cfb2f",
     "c06840e98cf81a52ddf1ec7f16b75194664886397eaa13f2dce44d6dedccc7bc"],
]

# The accumulated test of Go's crypto/mlkem package (TestAccumulated, short
# mode). One SHAKE128 stream with empty input supplies, for each iteration,
# d||z, then m, then a random 1088-byte ciphertext. A second SHAKE128 absorbs
# ek, c, the shared secret, and the decapsulation of the random ciphertext
# (an implicit rejection). The hash is the first 32 bytes of the second
# stream after 100 iterations. With 10,000 iterations it is
# 8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc, which this
# file also reproduces but which takes about two minutes.
# The C2SP CCTV accumulated hashes are not used here: they target the FIPS 203
# draft, which lacks the d||k domain separation of Algorithm 13, line 1. With
# only that line changed back to G(d), this file reproduces the CCTV
# 10,000-iteration ML-KEM-768 hash
# f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3.
MLKEM768_ACCUMULATED_100 = "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415"


class TestFrameworkMLKEM(unittest.TestCase):
    def test_sizes(self):
        """Key and ciphertext sizes of FIPS 203, section 8, Table 3."""
        self.assertEqual((EK_SIZE, DK_SIZE, CT_SIZE, SS_SIZE), (1184, 2400, 1088, 32))
        ek, dk = keygen()
        self.assertEqual((len(ek), len(dk)), (EK_SIZE, DK_SIZE))
        ss, c = encaps(ek)
        self.assertEqual((len(ss), len(c)), (SS_SIZE, CT_SIZE))
        self.assertEqual(decaps(dk, c), ss)

    def test_compress(self):
        """Compress_d(Decompress_d(y)) = y for all d < 12 (FIPS 203, section 4.2.1)."""
        for d in (1, DV, DU, 11):
            for y in range(1 << d):
                self.assertEqual(compress(d, decompress(d, y)), y)

    def test_ntt(self):
        """NTT^-1 undoes NTT, and MultiplyNTTs multiplies polynomials modulo
        X^256 + 1 (FIPS 203, equation 4.9), checked against schoolbook
        multiplication."""
        rng = random.Random(203)
        for _ in range(3):
            f = [rng.randrange(Q) for _ in range(N)]
            g = [rng.randrange(Q) for _ in range(N)]
            self.assertEqual(ntt_inv(ntt(f)), f)
            product = [0] * N
            for i in range(N):
                for j in range(N):
                    if i + j < N:
                        product[i + j] += f[i] * g[j]
                    else:
                        product[i + j - N] -= f[i] * g[j]   # X^256 = -1
            product = [x % Q for x in product]
            self.assertEqual(ntt_inv(multiply_ntts(ntt(f), ntt(g))), product)

    def test_openssl_vectors(self):
        """Keys, ciphertexts, shared secrets and implicit rejection match OpenSSL."""
        for d_hex, z_hex, m_hex, ek_hash, dk_hash, c_hash, ss_hex, rejected_hex in MLKEM768_OPENSSL_VECTORS:
            d, z, m = bytes.fromhex(d_hex), bytes.fromhex(z_hex), bytes.fromhex(m_hex)
            ek, dk = keygen_internal(d, z)
            self.assertEqual(H(ek).hex(), ek_hash)
            self.assertEqual(H(dk).hex(), dk_hash)
            self.assertTrue(check_encaps_key(ek))
            self.assertTrue(check_decaps_key(dk))
            ss, c = encaps_internal(ek, m)
            self.assertEqual(H(c).hex(), c_hash)
            self.assertEqual(ss.hex(), ss_hex)
            self.assertEqual(decaps(dk, c), ss)
            flipped = bytes([c[0] ^ 1]) + c[1:]
            self.assertEqual(decaps(dk, flipped).hex(), rejected_hex)
            self.assertEqual(decaps(dk, flipped), J(z + flipped))

    def test_accumulated(self):
        """Go's crypto/mlkem accumulated vector: 100 key generations,
        encapsulations, decapsulations and implicit rejections. It also
        reaches the rare branch of SampleNTT that needs more than three
        SHAKE128 blocks (about 20 times)."""
        per_iteration = 64 + 32 + CT_SIZE
        rng_stream = hashlib.shake_128(b'').digest(100 * per_iteration)
        out = hashlib.shake_128()
        for i in range(100):
            chunk = rng_stream[i * per_iteration:(i + 1) * per_iteration]
            d, z, m, random_c = chunk[:32], chunk[32:64], chunk[64:96], chunk[96:]
            ek, dk = keygen_internal(d, z)
            ss, c = encaps_internal(ek, m)
            self.assertEqual(decaps(dk, c), ss)
            out.update(ek + c + ss + decaps(dk, random_c))
        self.assertEqual(out.hexdigest(32), MLKEM768_ACCUMULATED_100)

    def test_encaps_key_check(self):
        """Section 7.2: wrong lengths and out-of-range coefficients are refused."""
        ek, _ = keygen_internal(bytes(range(32)), bytes(range(32, 64)))
        self.assertTrue(check_encaps_key(ek))
        # The first and last coefficient of each of the k polynomials.
        for index in (0, 255, 256, 511, 512, 767):
            for value, valid in ((0, True), (Q - 1, True), (Q, False), (Q + 1, False), (4095, False)):
                modified = set_ek_coefficient(ek, index, value)
                self.assertEqual(check_encaps_key(modified), valid)
                if not valid:
                    with self.assertRaises(ValueError):
                        encaps(modified)
        # The 32-byte seed rho at the end is not range checked.
        self.assertTrue(check_encaps_key(ek[:-32] + b'\xff' * 32))
        for wrong_length in (b'', ek[:-1], ek + b'\x00'):
            self.assertFalse(check_encaps_key(wrong_length))
            with self.assertRaises(ValueError):
                encaps(wrong_length)

    def test_decaps_input_check(self):
        """Section 7.3: wrong lengths and a dk whose H(ek) does not match are refused."""
        ek, dk = keygen_internal(bytes(range(32)), bytes(range(32, 64)))
        ss, c = encaps_internal(ek, bytes(range(100, 132)))
        # A corrupted byte of the stored H(ek), or of the stored ek itself.
        for position in (768 * K + 32, 768 * K + 63, 384 * K, 768 * K + 31):
            corrupted = dk[:position] + bytes([dk[position] ^ 0x80]) + dk[position + 1:]
            self.assertFalse(check_decaps_key(corrupted))
            with self.assertRaises(ValueError):
                decaps(corrupted, c)
        for wrong_length in (dk[:-1], dk + b'\x00'):
            with self.assertRaises(ValueError):
                decaps(wrong_length, c)
        for wrong_length in (b'', c[:-1], c + b'\x00'):
            with self.assertRaises(ValueError):
                decaps(dk, wrong_length)
        # z is not covered by the hash: a different z still decapsulates valid
        # ciphertexts, but changes the implicit-rejection output.
        other_z = dk[:-32] + bytes(32)
        self.assertTrue(check_decaps_key(other_z))
        self.assertEqual(decaps(other_z, c), ss)
        flipped = c[:-1] + bytes([c[-1] ^ 1])
        self.assertNotEqual(decaps(other_z, flipped), decaps(dk, flipped))
        self.assertEqual(decaps(other_z, flipped), J(bytes(32) + flipped))
