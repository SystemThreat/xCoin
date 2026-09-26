#!/usr/bin/env python3
# Copyright (c) 2026 The xCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
Generate src/test/data/ml_kem_768_fips203.json, the ML-KEM-768 vectors that
src/test/mlkem768_tests.cpp checks the vendored mlkem-native against
(XIP-4, "Test vectors and tests", "ML-KEM-768 primitive"):

- every ML-KEM-768 case of NIST's ACVP ML-KEM-keyGen-FIPS203 and
  ML-KEM-encapDecap-FIPS203 vector sets (usnistgov/ACVP-Server), including the
  decapsulation of modified ciphertexts and both key checks;
- the C2SP CCTV ML-KEM-768 bad encapsulation keys (modulus/), stored as one
  valid key plus the one coefficient each bad key changes, and the unlucky
  NTT sampling and strcmp vectors;
- the accumulated hashes of Go's crypto/mlkem TestAccumulated (the CCTV
  accumulated hash is not used: it targets the FIPS 203 draft, see XIP-4);
- the OpenSSL 3.6.4 vectors pinned in the test framework's mlkem.py;
- 50 cases computed here by the test framework's mlkem.py from fixed seeds,
  so that the C++ and the Python implementation are checked against each
  other.

Usage:

    ./gen_mlkem768_vectors.py <acvp-dir> <cctv-dir> > ../../src/test/data/ml_kem_768_fips203.json

<acvp-dir> holds ML-KEM-keyGen-FIPS203/ and ML-KEM-encapDecap-FIPS203/ from
ACVP-Server's gen-val/json-files, <cctv-dir> the ML-KEM directory of C2SP/CCTV.
Every input file must match the SHA-256 pinned below, and every vector taken
from them is recomputed with test/functional/test_framework/crypto/mlkem.py
before it is written. The output is deterministic.
'''

import gzip
import hashlib
import json
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '../../test/functional'))

from test_framework.crypto import mlkem  # noqa: E402

ACVP_COMMIT = '975de31eb83d87039ec88934fdc47d8c312b892d'
CCTV_COMMIT = '4448f2097b2daa812c91a26141f9f36c2096b9ca'

INPUT_SHA256 = {
    'ML-KEM-keyGen-FIPS203/prompt.json': '3f9ce34f6c836c77958bad2729e837c3b213f44ac36c3065976e7acca6389523',
    'ML-KEM-keyGen-FIPS203/expectedResults.json': 'a253d0ad91c95ebea5b409673defef0aa49d65d4ed72286399e2e798ddf073a4',
    'ML-KEM-keyGen-FIPS203/internalProjection.json': 'd7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b',
    'ML-KEM-encapDecap-FIPS203/prompt.json': '998e22dfb12efb14ce9fdff911ca634b13612819a1806f25da69adba7e16db91',
    'ML-KEM-encapDecap-FIPS203/expectedResults.json': '9089ec6ff2424da9f2782b89b2f831a329a3e28d6e5e24b802b78ff36ac61cdf',
    'ML-KEM-encapDecap-FIPS203/internalProjection.json': 'a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f',
    'modulus/ML-KEM-768.txt.gz': '22308df988866e2731c9b79bfa0ce754ea962a77b198436d56bde6481a526af7',
    'unluckysample/ML-KEM-768.txt': 'fede6f787581dc708e5c3337d7e49de33333d23023470668cd0588b65ad0ba90',
    'strcmp/ML-KEM-768.txt': '2b09aa46d8b1c7b9a549a25f009cbd3937b98df177e868d3eb6395930079e4fa',
}
# SHA-256 of modulus/ML-KEM-768.txt.gz after decompression.
CCTV_MODULUS_TXT_SHA256 = '1070efdae5c268a57935a33097316990831e7d4bb45d59abf0bfe4812535839a'

# Go's crypto/mlkem TestAccumulated for ML-KEM-768 (XIP-4). The 100-iteration
# value is recomputed below; the 10,000-iteration value takes Python minutes,
# so it is only pinned here (mlkem.py's docstring records it being reproduced).
GO_ACCUMULATED_100 = '1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415'
GO_ACCUMULATED_10000 = '8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc'

FRAMEWORK_CASES = 50


def read_input(base, name):
    with open(os.path.join(base, name), 'rb') as f:
        data = f.read()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == INPUT_SHA256[name], f"{name}: SHA-256 {digest}, expected {INPUT_SHA256[name]}"
    return data


def acvp_groups(acvp_dir, vector_set):
    """The ML-KEM-768 test groups of one ACVP vector set, keyed by tgId, with
    each test's prompt and expected result merged. internalProjection.json
    must agree with both."""
    prompt = json.loads(read_input(acvp_dir, f'{vector_set}/prompt.json'))
    expected = json.loads(read_input(acvp_dir, f'{vector_set}/expectedResults.json'))
    internal = json.loads(read_input(acvp_dir, f'{vector_set}/internalProjection.json'))
    expected_groups = {g['tgId']: {t['tcId']: t for t in g['tests']} for g in expected['testGroups']}
    internal_groups = {g['tgId']: {t['tcId']: t for t in g['tests']} for g in internal['testGroups']}
    groups = []
    for group in prompt['testGroups']:
        if group['parameterSet'] != 'ML-KEM-768':
            continue
        tests = []
        for test in group['tests']:
            merged = dict(test)
            merged.update(expected_groups[group['tgId']][test['tcId']])
            for key, value in merged.items():
                assert internal_groups[group['tgId']][test['tcId']][key] == value
            merged['reason'] = internal_groups[group['tgId']][test['tcId']].get('reason')
            tests.append(merged)
        groups.append((group, tests))
    return groups


def acvp_vectors(acvp_dir):
    out = {}
    keygen_groups = acvp_groups(acvp_dir, 'ML-KEM-keyGen-FIPS203')
    assert len(keygen_groups) == 1
    out['keyGen'] = []
    for t in keygen_groups[0][1]:
        ek, dk = mlkem.keygen_internal(bytes.fromhex(t['d']), bytes.fromhex(t['z']))
        assert (ek.hex(), dk.hex()) == (t['ek'].lower(), t['dk'].lower())
        out['keyGen'].append({'tcId': t['tcId'], 'd': t['d'], 'z': t['z'], 'ek': t['ek'], 'dk': t['dk']})

    for group, tests in acvp_groups(acvp_dir, 'ML-KEM-encapDecap-FIPS203'):
        function = group['function']
        entries = out.setdefault(function, [])
        for t in tests:
            if function == 'encapsulation':
                k, c = mlkem.encaps_internal(bytes.fromhex(t['ek']), bytes.fromhex(t['m']))
                assert (k.hex(), c.hex()) == (t['k'].lower(), t['c'].lower())
                entries.append({'tcId': t['tcId'], 'ek': t['ek'], 'm': t['m'], 'c': t['c'], 'k': t['k']})
            elif function == 'decapsulation':
                k = mlkem.decaps(bytes.fromhex(t['dk']), bytes.fromhex(t['c']))
                assert k.hex() == t['k'].lower()
                entries.append({'tcId': t['tcId'], 'reason': t['reason'], 'dk': t['dk'], 'c': t['c'], 'k': t['k']})
            elif function == 'encapsulationKeyCheck':
                assert mlkem.check_encaps_key(bytes.fromhex(t['ek'])) == t['testPassed']
                entries.append({'tcId': t['tcId'], 'reason': t['reason'], 'ek': t['ek'], 'testPassed': t['testPassed']})
            elif function == 'decapsulationKeyCheck':
                assert mlkem.check_decaps_key(bytes.fromhex(t['dk'])) == t['testPassed']
                entries.append({'tcId': t['tcId'], 'reason': t['reason'], 'dk': t['dk'], 'testPassed': t['testPassed']})
            else:
                raise AssertionError(f"unknown ACVP function {function}")
    assert [len(out[f]) for f in ('keyGen', 'encapsulation', 'decapsulation', 'encapsulationKeyCheck', 'decapsulationKeyCheck')] == [25, 25, 10, 10, 10]
    return out


def ek_coefficients(ek):
    coefficients = []
    for i in range(mlkem.K):
        chunk = int.from_bytes(ek[384 * i:384 * (i + 1)], 'little')
        coefficients += [(chunk >> (12 * j)) & 0xfff for j in range(mlkem.N)]
    return coefficients


def cctv_modulus(cctv_dir):
    """The bad keys differ from one another in exactly one coefficient, which
    is 3329 or more; all other coefficients and rho are shared. Store that
    shared key and each bad key's (coefficient index, value)."""
    text = gzip.decompress(read_input(cctv_dir, 'modulus/ML-KEM-768.txt.gz'))
    assert hashlib.sha256(text).hexdigest() == CCTV_MODULUS_TXT_SHA256
    bad_keys = [bytes.fromhex(line) for line in text.decode().split('\n') if line]
    assert all(len(ek) == mlkem.EK_SIZE for ek in bad_keys)
    rho = bad_keys[0][384 * mlkem.K:]
    assert all(ek[384 * mlkem.K:] == rho for ek in bad_keys)
    columns = list(zip(*(ek_coefficients(ek) for ek in bad_keys)))
    shared = [max(set(column), key=column.count) for column in columns]
    base = b''.join(mlkem.byte_encode(shared[256 * i:256 * (i + 1)], 12) for i in range(mlkem.K)) + rho
    assert mlkem.check_encaps_key(base)
    changes = []
    for ek in bad_keys:
        diff = [(i, c) for i, c in enumerate(ek_coefficients(ek)) if c != shared[i]]
        assert len(diff) == 1 and diff[0][1] >= mlkem.Q
        index, value = diff[0]
        assert mlkem.set_ek_coefficient(base, index, value) == ek
        assert not mlkem.check_encaps_key(ek)
        changes.append([index, value])
    return {'ek': base.hex(), 'changes': changes}


def cctv_fields(cctv_dir, name):
    fields = {}
    for line in read_input(cctv_dir, name).decode().split('\n'):
        if line:
            key, value = line.split(' = ')
            fields[key] = value
    return fields


def sample_ntt_bytes(b):
    """How many SHAKE128 bytes SampleNTT (FIPS 203 Algorithm 7) reads for the
    34-byte seed b."""
    stream = hashlib.shake_128(b).digest(8 * 168)
    pos = count = 0
    while count < mlkem.N:
        c0, c1, c2 = stream[pos:pos + 3]
        pos += 3
        count += (c0 + 256 * (c1 % 16) < mlkem.Q)
        count += (c1 // 16 + 16 * c2 < mlkem.Q and count < mlkem.N)
    return pos


def cctv_unluckysample(cctv_dir):
    """Only ek, dk, m, c and K are kept. CCTV found d by brute force under the
    FIPS 203 draft's K-PKE.KeyGen, which hashes d alone: FIPS 203's
    KeyGen_internal(d, z) gives a different, ordinary key. The ek it lists
    still needs more than 575 SHAKE128 bytes in SampleNTT, which Encaps and
    the re-encryption in Decaps both run, and its Encaps and Decaps values are
    FIPS 203's."""
    f = cctv_fields(cctv_dir, 'unluckysample/ML-KEM-768.txt')
    d, z = bytes.fromhex(f['d']), bytes.fromhex(f['z'])
    ek, dk = bytes.fromhex(f['ek']), bytes.fromhex(f['dk'])
    assert mlkem.keygen_internal(d, z)[0] != ek
    rho, _ = mlkem.G(d)  # the draft's K-PKE.KeyGen, line 1
    assert ek[384 * mlkem.K:] == rho
    assert dk[384 * mlkem.K:] == ek + mlkem.H(ek) + z
    assert max(sample_ntt_bytes(rho + bytes([j, i])) for i in range(mlkem.K) for j in range(mlkem.K)) > 575
    k, c = mlkem.encaps_internal(ek, bytes.fromhex(f['m']))
    assert (k.hex(), c.hex()) == (f['K'], f['c'])
    assert mlkem.decaps(dk, c) == k
    return {'ek': f['ek'], 'dk': f['dk'], 'm': f['m'], 'c': f['c'], 'k': f['K']}


def cctv_strcmp(cctv_dir):
    f = cctv_fields(cctv_dir, 'strcmp/ML-KEM-768.txt')
    dk, c = bytes.fromhex(f['dk']), bytes.fromhex(f['c'])
    assert mlkem.decaps(dk, c).hex() == f['K']
    # The vector exists because this is an implicit rejection whose
    # re-encryption agrees with c up to a zero byte.
    assert f['K'] == mlkem.J(dk[-32:] + c).hex()
    return {'dk': f['dk'], 'c': f['c'], 'k': f['K']}


def go_accumulated_100():
    per_iteration = 64 + 32 + mlkem.CT_SIZE
    stream = hashlib.shake_128(b'').digest(100 * per_iteration)
    out = hashlib.shake_128()
    for i in range(100):
        chunk = stream[i * per_iteration:(i + 1) * per_iteration]
        ek, dk = mlkem.keygen_internal(chunk[:32], chunk[32:64])
        k, c = mlkem.encaps_internal(ek, chunk[64:96])
        assert mlkem.decaps(dk, c) == k
        out.update(ek + c + k + mlkem.decaps(dk, chunk[96:]))
    return out.hexdigest(32)


def openssl_vectors():
    fields = ('d', 'z', 'm', 'ek_sha3_256', 'dk_sha3_256', 'c_sha3_256', 'k', 'k_flipped')
    out = []
    for vector in mlkem.MLKEM768_OPENSSL_VECTORS:
        v = dict(zip(fields, vector))
        ek, dk = mlkem.keygen_internal(bytes.fromhex(v['d']), bytes.fromhex(v['z']))
        k, c = mlkem.encaps_internal(ek, bytes.fromhex(v['m']))
        flipped = bytes([c[0] ^ 1]) + c[1:]
        assert [mlkem.H(ek).hex(), mlkem.H(dk).hex(), mlkem.H(c).hex(), k.hex(), mlkem.decaps(dk, flipped).hex()] == list(vector[3:])
        out.append(v)
    return out


def framework_cases():
    out = []
    for i in range(FRAMEWORK_CASES):
        d, z, m = (hashlib.sha256(f'XIP-4 ML-KEM-768 cross-check {i} {name}'.encode()).digest() for name in 'dzm')
        ek, dk = mlkem.keygen_internal(d, z)
        k, c = mlkem.encaps_internal(ek, m)
        assert mlkem.decaps(dk, c) == k
        position = i * (mlkem.CT_SIZE - 1) // (FRAMEWORK_CASES - 1)
        tampered = c[:position] + bytes([c[position] ^ (1 << (i % 8))]) + c[position + 1:]
        k_tampered = mlkem.decaps(dk, tampered)
        assert k_tampered == mlkem.J(z + tampered)
        out.append({
            'd': d.hex(), 'z': z.hex(), 'm': m.hex(),
            'ek_sha256': hashlib.sha256(ek).hexdigest(),
            'dk_sha256': hashlib.sha256(dk).hexdigest(),
            'c_sha256': hashlib.sha256(c).hexdigest(),
            'k': k.hex(),
            'tampered_byte': position,
            'tampered_bit': i % 8,
            'k_tampered': k_tampered.hex(),
        })
    return out


def main():
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} <acvp-dir> <cctv-dir>")
    acvp_dir, cctv_dir = sys.argv[1], sys.argv[2]
    assert go_accumulated_100() == GO_ACCUMULATED_100

    vectors = {
        'source': (
            'Generated by contrib/testgen/gen_mlkem768_vectors.py; every vector was also recomputed with '
            'test/functional/test_framework/crypto/mlkem.py. '
            'keyGen, encapsulation, decapsulation, encapsulationKeyCheck, decapsulationKeyCheck: every ML-KEM-768 case of '
            f'usnistgov/ACVP-Server {ACVP_COMMIT} gen-val/json-files/ML-KEM-keyGen-FIPS203 (vsId 42, tgId 2) and '
            f'ML-KEM-encapDecap-FIPS203 (vsId 42, tgIds 2, 5, 9, 10), hex as NIST gives it; reason from internalProjection.json. '
            f'cctv_*: C2SP/CCTV {CCTV_COMMIT} ML-KEM/{{modulus,unluckysample,strcmp}}/ML-KEM-768; cctv_modulus is the '
            f'780 lines of modulus/ML-KEM-768.txt.gz (decompressed SHA-256 {CCTV_MODULUS_TXT_SHA256}) as one valid key '
            'and, per line, the index (0..767) and value (3329..4095) of the one 12-bit coefficient that line changes. '
            "go_accumulated: Go crypto/mlkem TestAccumulated for ML-KEM-768 (XIP-4). "
            'openssl: OpenSSL 3.6.4 vectors from mlkem.py (MLKEM768_OPENSSL_VECTORS; hashes are SHA3-256, k_flipped is '
            'the decapsulation of c with bit 0 of byte 0 flipped). '
            f'framework: {FRAMEWORK_CASES} cases computed by mlkem.py; d, z and m are SHA-256 of '
            "'XIP-4 ML-KEM-768 cross-check <i> d' (z, m), k_tampered decapsulates c with bit tampered_bit of byte "
            'tampered_byte flipped.'
        ),
    }
    vectors.update(acvp_vectors(acvp_dir))
    vectors['cctv_modulus'] = cctv_modulus(cctv_dir)
    vectors['cctv_unluckysample'] = cctv_unluckysample(cctv_dir)
    vectors['cctv_strcmp'] = cctv_strcmp(cctv_dir)
    vectors['go_accumulated'] = {'iterations_100': GO_ACCUMULATED_100, 'iterations_10000': GO_ACCUMULATED_10000}
    vectors['openssl'] = openssl_vectors()
    vectors['framework'] = framework_cases()
    print(json.dumps(vectors, indent=1))


if __name__ == '__main__':
    main()
