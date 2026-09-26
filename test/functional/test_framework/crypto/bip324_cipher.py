#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test-only implementation of ChaCha20 Poly1305 AEAD Construction in RFC 8439 and FSChaCha20Poly1305 for BIP 324

It also holds the parts of XIP-4 (HX1, the hybrid post-quantum upgrade of the
v2 transport) that are plain functions: the version-packet record format and
the stage-2 key schedule. The HX1 state machine is in test_framework/v2_p2p.py.

It is designed for ease of understanding, not performance.

WARNING: This code is slow and trivially vulnerable to side channel attacks. Do not use for
anything but tests.
"""

import hashlib
import hmac
import random
import unittest

from .chacha20 import chacha20_block, REKEY_INTERVAL
from .hkdf import hkdf_sha256
from .mlkem import CT_SIZE, EK_SIZE, SS_SIZE, encaps_internal, keygen_internal
from .poly1305 import Poly1305


def pad16(x):
    if len(x) % 16 == 0:
        return b''
    return b'\x00' * (16 - (len(x) % 16))


def aead_chacha20_poly1305_encrypt(key, nonce, aad, plaintext):
    """Encrypt a plaintext using ChaCha20Poly1305."""
    if plaintext is None:
        return None
    ret = bytearray()
    msg_len = len(plaintext)
    for i in range((msg_len + 63) // 64):
        now = min(64, msg_len - 64 * i)
        keystream = chacha20_block(key, nonce, i + 1)
        for j in range(now):
            ret.append(plaintext[j + 64 * i] ^ keystream[j])
    poly1305 = Poly1305(chacha20_block(key, nonce, 0)[:32])
    mac_data = aad + pad16(aad)
    mac_data += ret + pad16(ret)
    mac_data += len(aad).to_bytes(8, 'little') + msg_len.to_bytes(8, 'little')
    ret += poly1305.tag(mac_data)
    return bytes(ret)


def aead_chacha20_poly1305_decrypt(key, nonce, aad, ciphertext):
    """Decrypt a ChaCha20Poly1305 ciphertext."""
    if ciphertext is None or len(ciphertext) < 16:
        return None
    msg_len = len(ciphertext) - 16
    poly1305 = Poly1305(chacha20_block(key, nonce, 0)[:32])
    mac_data = aad + pad16(aad)
    mac_data += ciphertext[:-16] + pad16(ciphertext[:-16])
    mac_data += len(aad).to_bytes(8, 'little') + msg_len.to_bytes(8, 'little')
    if ciphertext[-16:] != poly1305.tag(mac_data):
        return None
    ret = bytearray()
    for i in range((msg_len + 63) // 64):
        now = min(64, msg_len - 64 * i)
        keystream = chacha20_block(key, nonce, i + 1)
        for j in range(now):
            ret.append(ciphertext[j + 64 * i] ^ keystream[j])
    return bytes(ret)


class FSChaCha20Poly1305:
    """Rekeying wrapper AEAD around ChaCha20Poly1305."""
    def __init__(self, initial_key):
        self._key = initial_key
        self._packet_counter = 0

    def _crypt(self, aad, text, is_decrypt):
        nonce = ((self._packet_counter % REKEY_INTERVAL).to_bytes(4, 'little') +
                 (self._packet_counter // REKEY_INTERVAL).to_bytes(8, 'little'))
        if is_decrypt:
            ret = aead_chacha20_poly1305_decrypt(self._key, nonce, aad, text)
        else:
            ret = aead_chacha20_poly1305_encrypt(self._key, nonce, aad, text)
        if (self._packet_counter + 1) % REKEY_INTERVAL == 0:
            rekey_nonce = b"\xFF\xFF\xFF\xFF" + nonce[4:]
            self._key = aead_chacha20_poly1305_encrypt(self._key, rekey_nonce, b"", b"\x00" * 32)[:32]
        self._packet_counter += 1
        return ret

    def decrypt(self, aad, ciphertext):
        return self._crypt(aad, ciphertext, True)

    def encrypt(self, aad, plaintext):
        return self._crypt(aad, plaintext, False)


# XIP-4 (HX1): version-packet records and the stage-2 key schedule.
#
# A v2 version packet's contents are either empty or one HX1 record:
#   tag (8) || version (1) || kind (1) || body length (2, little-endian) || body
# The responder's version packet (VP_R) carries an OFFER whose body is the
# ML-KEM-768 encapsulation key ek; the initiator's (VP_I) carries an ACCEPT
# whose body is the ML-KEM-768 ciphertext ct.

HX1_TAG = b"xcoin-pq"  # 78 63 6f 69 6e 2d 70 71
HX1_VERSION = 0x01
HX1_KIND_OFFER = 0x01
HX1_KIND_ACCEPT = 0x02
HX1_HEADER_LEN = 12
HX1_BODY_LEN = {HX1_KIND_OFFER: EK_SIZE, HX1_KIND_ACCEPT: CT_SIZE}

# How a received version packet is classified (XIP-4, "Version packet contents").
HX1_NONE = "none"            # the peer is classical, or speaks an extension we don't know
HX1_MALFORMED = "malformed"  # our tag and version, but the rest is wrong: disconnect
HX1_RECORD = "hx1"           # a well-formed record of the expected kind

HX1_SALT_PREFIX = b"xcoin_v2_hybrid_mlkem768"
HX1_LABELS = (
    "xcoin_hx1_initiator_L",
    "xcoin_hx1_initiator_P",
    "xcoin_hx1_responder_L",
    "xcoin_hx1_responder_P",
    "xcoin_hx1_session_id",
)
# The stage-1 (BIP324) HKDF labels. No stage-2 label may equal one of these.
BIP324_LABELS = ("initiator_L", "initiator_P", "responder_L", "responder_P", "garbage_terminators", "session_id")
ELLSWIFT_LEN = 64


def hx1_encode_record(kind, body):
    """Build the one HX1 record a mode 1 or 2 sender puts in its version packet."""
    assert kind in HX1_BODY_LEN and len(body) == HX1_BODY_LEN[kind]
    return HX1_TAG + bytes([HX1_VERSION, kind]) + len(body).to_bytes(2, 'little') + bytes(body)


def hx1_classify_record(contents, expected_kind):
    """Classify received version-packet contents as XIP-4's table does.

    The rows are exclusive and are decided from the front of the contents:
    - fewer than 9 bytes, or the first 8 bytes are not the tag: "none";
    - the tag, then a version byte other than 01: "none";
    - the tag and version 01: either exactly the expected record (HX1_RECORD)
      or "malformed". That includes contents that end inside the 12-byte
      header: only a broken HX1 sender produces the tag and version 01 and
      then stops.

    Returns (classification, body); body is None unless the classification is
    HX1_RECORD. Only the first record is read: bytes after its body are
    ignored, so a later version that offers several records puts the HX1
    record first.
    """
    contents = bytes(contents)
    if len(contents) < len(HX1_TAG) + 1 or contents[:len(HX1_TAG)] != HX1_TAG:
        return HX1_NONE, None
    if contents[8] != HX1_VERSION:
        return HX1_NONE, None
    if len(contents) < HX1_HEADER_LEN:
        return HX1_MALFORMED, None
    body_len = int.from_bytes(contents[10:12], 'little')
    if (contents[9] != expected_kind or body_len != HX1_BODY_LEN[expected_kind] or
            len(contents) < HX1_HEADER_LEN + body_len):
        return HX1_MALFORMED, None
    return HX1_RECORD, contents[HX1_HEADER_LEN:HX1_HEADER_LEN + body_len]


def hx1_stage2_ikm(kem_secret, ecdh_secret, ct, ell_initiator, ek, ell_responder):
    """IKM2 = K || ecdh_secret || ct || ell_I || ek || ell_R (2464 bytes)."""
    assert len(kem_secret) == SS_SIZE and len(ecdh_secret) == 32
    assert len(ct) == CT_SIZE and len(ek) == EK_SIZE
    assert len(ell_initiator) == ELLSWIFT_LEN and len(ell_responder) == ELLSWIFT_LEN
    return bytes(kem_secret) + bytes(ecdh_secret) + bytes(ct) + bytes(ell_initiator) + bytes(ek) + bytes(ell_responder)


def hx1_stage2_keys(magic, kem_secret, ecdh_secret, ct, ell_initiator, ek, ell_responder):
    """Derive the four stage-2 packet keys and the stage-2 session id.

    HKDF-SHA256 with salt "xcoin_v2_hybrid_mlkem768" || MessageStart over
    IKM2; one 32-byte output per label in HX1_LABELS. Returns a dict keyed by
    label.
    """
    assert len(magic) == 4
    salt = HX1_SALT_PREFIX + magic
    ikm = hx1_stage2_ikm(kem_secret, ecdh_secret, ct, ell_initiator, ek, ell_responder)
    return {label: hkdf_sha256(length=32, ikm=ikm, salt=salt, info=label.encode('ascii')) for label in HX1_LABELS}


# Test vectors from RFC8439 consisting of plaintext, aad, 32 byte key, 12 byte nonce and ciphertext
AEAD_TESTS = [
    # RFC 8439 Example from section 2.8.2
    ["4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
     "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
     "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
     "637265656e20776f756c642062652069742e",
     "50515253c0c1c2c3c4c5c6c7",
     "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
     [7, 0x4746454443424140],
     "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
     "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
     "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
     "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd060"
     "0691"],
    # RFC 8439 Test vector A.5
    ["496e7465726e65742d4472616674732061726520647261667420646f63756d65"
     "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d"
     "6f6e74687320616e64206d617920626520757064617465642c207265706c6163"
     "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65"
     "6e747320617420616e792074696d652e20497420697320696e617070726f7072"
     "6961746520746f2075736520496e7465726e65742d4472616674732061732072"
     "65666572656e6365206d6174657269616c206f7220746f206369746520746865"
     "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67"
     "726573732e2fe2809d",
     "f33388860000000000004e91",
     "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
     [0, 0x0807060504030201],
     "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
     "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
     "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
     "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
     "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
     "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
     "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
     "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
     "a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38"],
    # Test vectors exercising aad and plaintext which are multiples of 16 bytes.
    ["8d2d6a8befd9716fab35819eaac83b33269afb9f1a00fddf66095a6c0cd91951"
     "a6b7ad3db580be0674c3f0b55f618e34",
     "",
     "72ddc73f07101282bbbcf853b9012a9f9695fc5d36b303a97fd0845d0314e0c3",
     [0x3432b75f, 0xb3585537eb7f4024],
     "f760b8224fb2a317b1b07875092606131232a5b86ae142df5df1c846a7f6341a"
     "f2564483dd77f836be45e6230808ffe402a6f0a3e8be074b3d1f4ea8a7b09451"],
    ["",
     "36970d8a704c065de16250c18033de5a400520ac1b5842b24551e5823a3314f3"
     "946285171e04a81ebfbe3566e312e74ab80e94c7dd2ff4e10de0098a58d0f503",
     "77adda51d6730b9ad6c995658cbd49f581b2547e7c0c08fcc24ceec797461021",
     [0x1f90da88, 0x75dafa3ef84471a4],
     "aaae5bb81e8407c94b2ae86ae0c7efbe"],
]

FSAEAD_TESTS = [
    ["d6a4cb04ef0f7c09c1866ed29dc24d820e75b0491032a51b4c3366f9ca35c19e"
     "a3047ec6be9d45f9637b63e1cf9eb4c2523a5aab7b851ebeba87199db0e839cf"
     "0d5c25e50168306377aedbe9089fd2463ded88b83211cf51b73b150608cc7a60"
     "0d0f11b9a742948482e1b109d8faf15b450aa7322e892fa2208c6691e3fecf4c"
     "711191b14d75a72147",
     "786cb9b6ebf44288974cf0",
     "5c9e1c3951a74fba66708bf9d2c217571684556b6a6a3573bff2847d38612654",
     500,
     "9dcebbd3281ea3dd8e9a1ef7d55a97abd6743e56ebc0c190cb2c4e14160b385e"
     "0bf508dddf754bd02c7c208447c131ce23e47a4a14dfaf5dd8bc601323950f75"
     "4e05d46e9232f83fc5120fbbef6f5347a826ec79a93820718d4ec7a2b7cfaaa4"
     "4b21e16d726448b62f803811aff4f6d827ed78e738ce8a507b81a8ae13131192"
     "8039213de18a5120dc9b7370baca878f50ff254418de3da50c"],
    ["8349b7a2690b63d01204800c288ff1138a1d473c832c90ea8b3fc102d0bb3adc"
     "44261b247c7c3d6760bfbe979d061c305f46d94c0582ac3099f0bf249f8cb234",
     "",
     "3bd2093fcbcb0d034d8c569583c5425c1a53171ea299f8cc3bbf9ae3530adfce",
     60000,
     "30a6757ff8439b975363f166a0fa0e36722ab35936abd704297948f45083f4d4"
     "99433137ce931f7fca28a0acd3bc30f57b550acbc21cbd45bbef0739d9caf30c"
     "14b94829deb27f0b1923a2af704ae5d6"],
]


class TestFrameworkAEAD(unittest.TestCase):
    def test_aead(self):
        """ChaCha20Poly1305 AEAD test vectors."""
        for test_vector in AEAD_TESTS:
            hex_plain, hex_aad, hex_key, hex_nonce, hex_cipher = test_vector
            plain = bytes.fromhex(hex_plain)
            aad = bytes.fromhex(hex_aad)
            key = bytes.fromhex(hex_key)
            nonce = hex_nonce[0].to_bytes(4, 'little') + hex_nonce[1].to_bytes(8, 'little')

            ciphertext = aead_chacha20_poly1305_encrypt(key, nonce, aad, plain)
            self.assertEqual(hex_cipher, ciphertext.hex())
            plaintext = aead_chacha20_poly1305_decrypt(key, nonce, aad, ciphertext)
            self.assertEqual(plain, plaintext)

    def test_fschacha20poly1305aead(self):
        "FSChaCha20Poly1305 AEAD test vectors."
        for test_vector in FSAEAD_TESTS:
            hex_plain, hex_aad, hex_key, msg_idx, hex_cipher = test_vector
            plain = bytes.fromhex(hex_plain)
            aad = bytes.fromhex(hex_aad)
            key = bytes.fromhex(hex_key)

            enc_aead = FSChaCha20Poly1305(key)
            dec_aead = FSChaCha20Poly1305(key)

            for _ in range(msg_idx):
                enc_aead.encrypt(b"", None)
            ciphertext = enc_aead.encrypt(aad, plain)
            self.assertEqual(hex_cipher, ciphertext.hex())

            for _ in range(msg_idx):
                dec_aead.decrypt(b"", None)
            plaintext = dec_aead.decrypt(aad, ciphertext)
            self.assertEqual(plain, plaintext)


# XIP-4 test vector inputs: each value is SHA-256 of "XIP-4 test vector: " and
# a name (the garbage values are truncated). See XIP-4, "Handshake vectors".
HX1_TEST_ELL_I = bytes.fromhex(
    "77912a89a57b3a2991c56274b9b24aa672b12e7f4a70653ca7e521ec614971ce"
    "7a438fee0858c46d0b32e28e0d8510f937c26c57d2e1ab274c066e362c7248f8")
HX1_TEST_ELL_R = bytes.fromhex(
    "2163a7d9fb5c171c53cd06a7d1bc390a8c6343bba7fbe273aeadb3ce8d9d0cc9"
    "d1fdb6dd34f6257fa3b07216374b9ac60edb585ff4e48bc5362561bb943abc1d")
HX1_TEST_ECDH = bytes.fromhex("cbf5296f35d2840f8f0f31d58e01a626b6d69b31c846b8212c3ec1701499637f")
HX1_TEST_D = bytes.fromhex("944becfa471193433f423fb1e6459505957eace2a3a2343ae25f84c5d602cb46")
HX1_TEST_Z = bytes.fromhex("101ca7e793947879e8c8a02911faea5f4f5b021b1f0a0c91911028159051dfcb")
HX1_TEST_M = bytes.fromhex("b21100cd8bfa86e05d3416452f314a1f99e61303273c8e9afc78f77cf5e2b066")

# Stage-2 key schedule results for those inputs (XIP-4 vectors V1, V2, V3):
# magic, PRK2, then the outputs for the five labels in HX1_LABELS order.
HX1_KEY_SCHEDULE_TESTS = [
    ["58504103",
     "9ad96f028414d8f6123c3457c230c80212ac166967ae431f656591c135b7c1fc",
     ["987c7721b507dc6f05b1e9c4795427201713f706fe5029dad2bd5a6fb62b2c2b",
      "0b7ec1c95c5cc68dfdaf3db50685d7841e18db6cd28a3ad01b80989d3316e82d",
      "abba444b3e09cf7ce781b354a2e1ae128f79548528309edd98de103830885e83",
      "9882cd2296fe9dc8d8273830629724e6d283fa42dee53aa24e36b1a28e1bab93",
      "383be571688a04d73885796b0616b9f30789118387aa798ab720c564015f26d6"]],
    ["58544102",
     "8ea3919a3c840d49392b4ed9b15b07fc54570c97373a37773e028bd9c492f38f",
     ["2bf855034819622472dcbd10e24eaf1bb6cd1d0aebee002453ed9b9e344b12bd",
      "87d3d959947ab80596e8d3a2083e51815fab5fae38dd2010a1100dfcf096341f",
      "d7cb71567d3028e7ee67702496d2a87f4dcc327874671fd8fb8956437227e363",
      "d57ce9d3dd9f7653d4e45e67f0126f373f00b06c8cc68b11dcd4e21d7cd332ef",
      "3c9db0655f576822d9141707787bb6cf6c0f5603f1cf8ab0e24c934fe60c0ab4"]],
    ["4e455803",
     "002dd412a9591af8590a0e2ba2d13f1f6fa0aaa8e201562bf1fde7cacbc441ab",
     ["2558ea2689c1e9cff7a6d016932d3a404b255972eaebeda6568e0561f3518872",
      "5793a72a7db9352e79411e31934d6e9521e8714f9c921717995c4ef322413c12",
      "dfb3e0502c93095beb482cf54daf789e552fb5cd3de496b34f6b6cef0c7b7260",
      "b5bab6379b46b66fa8891134b8fe1e83e4e8cf6c0b8888335d4fdf8efa6e7ff8",
      "f701ac8116eef5eafcb1fae255f72c00236328370dd774fd1f3074170e257a09"]],
]


class TestFrameworkHX1(unittest.TestCase):
    def test_record_encoding(self):
        """OFFER and ACCEPT records have the XIP-4 header and sizes."""
        offer = hx1_encode_record(HX1_KIND_OFFER, bytes(EK_SIZE))
        accept = hx1_encode_record(HX1_KIND_ACCEPT, bytes(CT_SIZE))
        self.assertEqual(offer[:12].hex(), "78636f696e2d70710101a004")
        self.assertEqual(accept[:12].hex(), "78636f696e2d707101024004")
        self.assertEqual((len(offer), len(accept)), (1196, 1100))
        # Each record is one BIP324 packet: 3 length bytes, 1 header byte, 16 tag bytes.
        self.assertEqual((len(offer) + 20, len(accept) + 20), (1216, 1120))

    def test_record_classification(self):
        """Every row of the XIP-4 classification table, for both directions."""
        for kind, other in ((HX1_KIND_OFFER, HX1_KIND_ACCEPT), (HX1_KIND_ACCEPT, HX1_KIND_OFFER)):
            body = bytes(range(256)) * 5
            body = body[:HX1_BODY_LEN[kind]]
            record = hx1_encode_record(kind, body)
            length = record[10:12]
            self.assertEqual(hx1_classify_record(record, kind), (HX1_RECORD, body))
            # Trailing bytes are ignored.
            self.assertEqual(hx1_classify_record(record + b"\x00", kind), (HX1_RECORD, body))
            self.assertEqual(hx1_classify_record(record + record, kind), (HX1_RECORD, body))
            # Only the first record is read: a later version that offers several must put the HX1 record first.
            later = record[:8] + b"\x02" + record[9:]
            self.assertEqual(hx1_classify_record(record + later, kind), (HX1_RECORD, body))
            self.assertEqual(hx1_classify_record(later + record, kind), (HX1_NONE, None))
            # "none": empty, short, not our tag, or not our version.
            self.assertEqual(hx1_classify_record(b"", kind), (HX1_NONE, None))
            for n in range(1, 9):
                # Up to and including the bare tag: no version byte yet.
                self.assertEqual(hx1_classify_record(record[:n], kind), (HX1_NONE, None))
            for n in range(9, 12):
                # The tag and version 01, then the header stops: only a broken HX1 sender does this.
                self.assertEqual(hx1_classify_record(record[:n], kind), (HX1_MALFORMED, None))
                self.assertEqual(hx1_classify_record(record[:8] + b"\x02" + record[9:n], kind), (HX1_NONE, None))
            for i in range(8):
                for bit in (0x01, 0x80):
                    bad_tag = bytearray(record)
                    bad_tag[i] ^= bit
                    self.assertEqual(hx1_classify_record(bad_tag, kind), (HX1_NONE, None))
            for version in (0x00, 0x02, 0xff):
                self.assertEqual(hx1_classify_record(record[:8] + bytes([version]) + record[9:], kind), (HX1_NONE, None))
            # BIP324's own tests send random contents of up to 999 bytes; they are "none".
            rng = random.Random(kind)
            for _ in range(100):
                contents = rng.randbytes(rng.randrange(1000))
                self.assertEqual(hx1_classify_record(contents, kind), (HX1_NONE, None))
            # "malformed": tag and version match, but kind, length or body is wrong.
            for bad_kind in (0x00, other, 0x03, 0xff):
                self.assertEqual(hx1_classify_record(record[:9] + bytes([bad_kind]) + record[10:], kind), (HX1_MALFORMED, None))
            for bad_len in (0, len(body) - 1, len(body) + 1, HX1_BODY_LEN[other], 0xffff):
                bad = record[:10] + bad_len.to_bytes(2, 'little') + record[12:]
                self.assertEqual(hx1_classify_record(bad, kind), (HX1_MALFORMED, None))
            self.assertEqual(hx1_classify_record(record[:-1], kind), (HX1_MALFORMED, None))
            self.assertEqual(hx1_classify_record(record[:12], kind), (HX1_MALFORMED, None))
            self.assertEqual(length, len(body).to_bytes(2, 'little'))

    def test_labels(self):
        """Stage-2 labels are new, distinct, and not BIP324 labels."""
        self.assertEqual(len(set(HX1_LABELS)), len(HX1_LABELS))
        self.assertFalse(set(HX1_LABELS) & set(BIP324_LABELS))
        self.assertEqual(HX1_SALT_PREFIX + bytes.fromhex("58504103"), b"xcoin_v2_hybrid_mlkem768XPA\x03")

    def test_stage2_key_schedule(self):
        """Stage-2 keys for the XIP-4 V1-V3 inputs, checked against the XIP and
        against a direct HMAC-SHA256 computation."""
        ek, _ = keygen_internal(HX1_TEST_D, HX1_TEST_Z)
        kem_secret, ct = encaps_internal(ek, HX1_TEST_M)
        self.assertEqual(kem_secret.hex(), "ec378be1bd4d2cc452b73ae26af3c066c3941ddf715d2bf2b09e1d5b3a7737dd")
        ikm = hx1_stage2_ikm(kem_secret, HX1_TEST_ECDH, ct, HX1_TEST_ELL_I, ek, HX1_TEST_ELL_R)
        self.assertEqual(len(ikm), 2464)
        self.assertEqual(hashlib.sha256(ikm).hexdigest(), "2296bcbb7d0261abd3c78b012ebb2ee2dc96641731d03b89afa8f2f2c69c93a6")
        for magic_hex, prk_hex, outputs in HX1_KEY_SCHEDULE_TESTS:
            magic = bytes.fromhex(magic_hex)
            keys = hx1_stage2_keys(magic, kem_secret, HX1_TEST_ECDH, ct, HX1_TEST_ELL_I, ek, HX1_TEST_ELL_R)
            prk = hmac.new(HX1_SALT_PREFIX + magic, ikm, hashlib.sha256).digest()
            self.assertEqual(prk.hex(), prk_hex)
            for label, expected in zip(HX1_LABELS, outputs):
                self.assertEqual(keys[label].hex(), expected)
                self.assertEqual(hmac.new(prk, label.encode() + b"\x01", hashlib.sha256).digest(), keys[label])
            self.assertEqual(len(set(keys.values())), len(HX1_LABELS))
        # Every input is used: changing any one byte of any part changes every key.
        parts = [kem_secret, HX1_TEST_ECDH, ct, HX1_TEST_ELL_I, ek, HX1_TEST_ELL_R]
        base = hx1_stage2_keys(bytes.fromhex("58504103"), *parts)
        for i in range(len(parts)):
            changed = list(parts)
            changed[i] = bytes([parts[i][0] ^ 1]) + parts[i][1:]
            other = hx1_stage2_keys(bytes.fromhex("58504103"), *changed)
            for label in HX1_LABELS:
                self.assertNotEqual(other[label], base[label])
