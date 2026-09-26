#!/usr/bin/env python3
# Copyright (c) 2026 The xCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Seed corpora for the HX1 (XIP-4) fuzz targets, from the pinned vectors.

Writes one directory per target under the given corpus directory:

    mlkem768_encaps, mlkem768_decaps, mlkem768_keygen,
    p2p_transport_hx1_record, p2p_transport_hx1_initiator, p2p_transport_hx1_responder,
    p2p_transport_bidirectional_v2, p2p_transport_bidirectional_v1v2, bip324_cipher_roundtrip

The inputs come from src/test/data/hx1_handshake_vectors.json (XIP-4 V1..V6) and
src/test/data/ml_kem_768_fips203.json (NIST ACVP and C2SP CCTV). Each seed is laid out the way
the target's FuzzedDataProvider reads it: byte strings from the front, integers from the end,
in the order the target consumes them (see the targets in src/test/fuzz/).

Usage: gen_hx1_fuzz_seeds.py <corpus_dir>
"""

import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "test", "functional"))
from test_framework.crypto import mlkem  # noqa: E402

TAG = b"xcoin-pq"
KIND_OFFER = 0x01
KIND_ACCEPT = 0x02
EK_LEN = 1184
CT_LEN = 1088
DK_LEN = 2400
EXPANSION = 20
FIRST_PACKET_MAX = 4095
KEY_LEN = 64
TERMINATOR_LEN = 16
MODE_OFF, MODE_PREFER, MODE_REQUIRE = 0, 1, 2
# mlkem768::Error
ERR_INVALID_EK, ERR_INVALID_DK, ERR_RNG, ERR_LIBRARY = 0, 1, 2, 3


def record(kind, body, version=0x01):
    return TAG + bytes([version, kind, len(body) & 0xff, len(body) >> 8]) + body


def set_coefficient(ek, index, value):
    """Set 12-bit coefficient `index` of ek to `value` (ByteEncode12, FIPS 203 Algorithm 5)."""
    ek = bytearray(ek)
    pos = 384 * (index // 256) + 3 * ((index % 256) // 2)
    if index % 2 == 0:
        ek[pos] = value & 0xff
        ek[pos + 1] = (ek[pos + 1] & 0xf0) | (value >> 8)
    else:
        ek[pos + 1] = (ek[pos + 1] & 0x0f) | ((value & 0x0f) << 4)
        ek[pos + 2] = value >> 4
    return bytes(ek)


class Input:
    """A fuzz input: `front` is read by ConsumeBytes, `tail` by the integer consumers, which read
    from the end of the buffer, most significant byte first, as many bytes as the range needs."""

    def __init__(self):
        self.front = bytearray()
        self.tail = []  # (value, byte count) in consumption order

    @staticmethod
    def width(rng):
        n = 0
        while rng > 0 and n < 8:
            n += 1
            rng >>= 8
        return n

    def bytes(self, data):
        self.front += data
        return self

    def range(self, value, lo, hi):
        """ConsumeIntegralInRange(lo, hi)."""
        assert lo <= value <= hi, (value, lo, hi)
        self.tail.append((value - lo, self.width(hi - lo)))
        return self

    def u8(self, value):
        return self.range(value, 0, 0xff)

    def u16(self, value):
        return self.range(value, 0, 0xffff)

    def u64(self, value):
        return self.range(value, 0, 0xffffffffffffffff)

    def bool(self, value):
        return self.u8(1 if value else 0)

    def feed(self, size):
        """Feed(): one piece holding the whole buffer of `size` bytes."""
        if size > 0:
            self.range(size, 1, size)
        return self

    def build(self):
        tail = b"".join(v.to_bytes(n, "little") for v, n in reversed(self.tail))
        return bytes(self.front) + tail


def write(corpus, target, name, data):
    d = os.path.join(corpus, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    corpus = sys.argv[1]
    with open(os.path.join(REPO, "src", "test", "data", "hx1_handshake_vectors.json")) as f:
        hx1 = json.load(f)
    with open(os.path.join(REPO, "src", "test", "data", "ml_kem_768_fips203.json")) as f:
        fips = json.load(f)
    inputs = hx1["inputs"]
    v1 = hx1["handshakes"][0]
    d = bytes.fromhex(inputs["mlkem_d"])
    z = bytes.fromhex(inputs["mlkem_z"])
    m = bytes.fromhex(inputs["mlkem_m"])
    ek = bytes.fromhex(v1["mlkem"]["ek"])
    ct = bytes.fromhex(v1["mlkem"]["ct"])
    ek2, dk = mlkem.keygen_internal(d, z)
    assert ek2 == ek and len(dk) == DK_LEN
    bad_keys = [(k["name"], bytes.fromhex(k["ek"])) for k in hx1["bad_encapsulation_keys"]["keys"]]
    cctv_ek = bytes.fromhex(fips["cctv_modulus"]["ek"])
    priv_i, aux_i = bytes.fromhex(inputs["priv_initiator"]), bytes.fromhex(inputs["aux_initiator"])
    priv_r, aux_r = bytes.fromhex(inputs["priv_responder"]), bytes.fromhex(inputs["aux_responder"])
    garbage_i, garbage_r = bytes.fromhex(inputs["garbage_initiator"]), bytes.fromhex(inputs["garbage_responder"])
    n = 0

    # mlkem768_encaps: ek || m
    write(corpus, "mlkem768_encaps", "xip4_v1", ek + m); n += 1
    for name, bad in bad_keys:
        write(corpus, "mlkem768_encaps", "xip4_v6_" + name, bad + m); n += 1
    for case in fips["encapsulation"]:
        write(corpus, "mlkem768_encaps", "acvp_enc_" + str(case["tcId"]), bytes.fromhex(case["ek"]) + bytes.fromhex(case["m"])); n += 1
    for case in fips["encapsulationKeyCheck"]:
        write(corpus, "mlkem768_encaps", "acvp_ekcheck_" + str(case["tcId"]), bytes.fromhex(case["ek"]) + m); n += 1
    write(corpus, "mlkem768_encaps", "cctv_unluckysample",
          bytes.fromhex(fips["cctv_unluckysample"]["ek"]) + bytes.fromhex(fips["cctv_unluckysample"]["m"])); n += 1
    for index, value in fips["cctv_modulus"]["changes"]:
        write(corpus, "mlkem768_encaps", f"cctv_modulus_{index}_{value}", set_coefficient(cctv_ek, index, value) + m); n += 1

    # mlkem768_decaps: flags (last byte; 0 = dk from the input) then dk || ct
    def decaps_seed(name, dk_bytes, ct_bytes):
        nonlocal n
        write(corpus, "mlkem768_decaps", name, Input().bytes(dk_bytes + ct_bytes).u8(0).build()); n += 1
    decaps_seed("xip4_v1", dk, ct)
    flipped = bytes([ct[0] ^ 1]) + ct[1:]
    decaps_seed("xip4_v1_flipped", dk, flipped)
    for case in fips["decapsulation"]:
        decaps_seed("acvp_dec_" + str(case["tcId"]), bytes.fromhex(case["dk"]), bytes.fromhex(case["c"]))
    for case in fips["decapsulationKeyCheck"]:
        decaps_seed("acvp_dkcheck_" + str(case["tcId"]), bytes.fromhex(case["dk"]), ct)
    decaps_seed("cctv_strcmp", bytes.fromhex(fips["cctv_strcmp"]["dk"]), bytes.fromhex(fips["cctv_strcmp"]["c"]))
    decaps_seed("cctv_unluckysample", bytes.fromhex(fips["cctv_unluckysample"]["dk"]), bytes.fromhex(fips["cctv_unluckysample"]["c"]))
    # flags 1: dk from the seeds d || z, then an arbitrary ct; flags 3: ct = Encaps(ek, m) with bit flips
    write(corpus, "mlkem768_decaps", "xip4_seeds_random_ct", Input().bytes(d + z + flipped).u8(1).build()); n += 1
    write(corpus, "mlkem768_decaps", "xip4_seeds_tampered",
          Input().bytes(d + z + m).u8(3).range(1, 0, 8).range(0, 0, CT_LEN * 8 - 1).build()); n += 1
    write(corpus, "mlkem768_decaps", "xip4_seeds_untouched", Input().bytes(d + z + m).u8(3).range(0, 0, 8).build()); n += 1

    # mlkem768_keygen: d || z || m
    write(corpus, "mlkem768_keygen", "xip4_v1", d + z + m); n += 1
    for case in fips["keyGen"]:
        write(corpus, "mlkem768_keygen", "acvp_keygen_" + str(case["tcId"]), bytes.fromhex(case["d"]) + bytes.fromhex(case["z"]) + m); n += 1

    # p2p_transport_hx1_record: contents, then the kind (last byte: 1 = OFFER, 0 = ACCEPT)
    offer, accept = record(KIND_OFFER, ek), record(KIND_ACCEPT, ct)
    records = {
        "offer": (offer, 1), "accept": (accept, 0),
        "offer_as_accept": (offer, 0), "accept_as_offer": (accept, 1),
        "offer_trailing": (offer + record(KIND_OFFER, ek, 0x02), 1),
        "offer_later_version_first": (record(KIND_OFFER, ek, 0x02) + offer, 1),
        "offer_9": (offer[:9], 1), "offer_11": (offer[:11], 1), "offer_12": (offer[:12], 1),
        "offer_truncated": (offer[:-1], 1), "accept_truncated": (accept[:-1], 0),
        "offer_wrong_length": (offer[:10] + bytes([0x9f, 0x04]) + offer[12:], 1),
        "offer_bad_tag": (bytes([offer[0] ^ 1]) + offer[1:], 1), "empty": (b"", 1), "tag_only": (TAG, 1),
    }
    for name, bad in bad_keys:
        records["offer_" + name] = (record(KIND_OFFER, bad), 1)
    for name, (contents, kind) in records.items():
        write(corpus, "p2p_transport_hx1_record", name, Input().bytes(contents).bool(kind).build()); n += 1

    # bip324_cipher_roundtrip: keys and entropy from the front; hybrid mode, RNG seed, switch point, discard flag,
    # then per packet a mode byte and a length.
    b = Input().bytes(priv_i + aux_i + priv_r + aux_r).u8(MODE_PREFER).u64(0x5eed).range(3, 0, 300).bool(False)
    for i in range(12):
        # bit 1: from the initiator; bits 5-7: length up to 2^6 - 1
        b.u8((3 << 5) | (2 if i % 2 else 0)).range(40 + i, 0, 63)
    write(corpus, "bip324_cipher_roundtrip", "xip4_prefer_switch", b.build()); n += 1
    b = Input().bytes(priv_i + aux_i + priv_r + aux_r).u8(MODE_OFF).u64(0x5eed).range(3, 0, 300).bool(False)
    for i in range(4):
        b.u8((3 << 5) | (2 if i % 2 else 0)).range(40 + i, 0, 63)
    write(corpus, "bip324_cipher_roundtrip", "xip4_off", b.build()); n += 1

    # p2p_transport_bidirectional_v2 / _v1v2: RNG seed, the modes, then per V2 transport its key, garbage length,
    # garbage and entropy; the rest drives the simulation.
    def bidirectional(modes_byte, v1_initiator):
        b = Input().u64(0x5eed).u8(modes_byte)
        if not v1_initiator:
            b.bytes(priv_i).range(len(garbage_i), 0, 4095).bytes(garbage_i + aux_i)
        b.bytes(priv_r).range(len(garbage_r), 0, 4095).bytes(garbage_r + aux_r)
        b.range(100, 0, 75000).range(5000, 0, 75000)  # the two version messages
        for i in range(40):
            b.range([2, 4, 3, 5, 0, 1][i % 6], 0, 5).u16(0xffff)  # send or receive everything, queue messages
        return b.build()
    for init in range(3):
        for resp in range(3):
            write(corpus, "p2p_transport_bidirectional_v2", f"xip4_modes_{init}_{resp}", bidirectional(init + 3 * resp, False)); n += 1
    for resp in range(3):
        write(corpus, "p2p_transport_bidirectional_v1v2", f"xip4_mode_{resp}", bidirectional(resp, True)); n += 1

    # p2p_transport_hx1_initiator / _responder
    def side(b, priv, garbage, aux):
        b.bytes(priv).range(len(garbage), 0, 4095)
        if len(garbage) <= 64:
            b.bytes(garbage)
        b.bytes(aux)

    def peer_sends(b, packets):
        b.range(len(packets), 0, 2)
        for decoy, length in packets:
            b.bool(decoy).range(length, 0, 20000).feed(length + EXPANSION + (0 if decoy else 13))

    def send_messages(b, messages):
        b.range(len(messages), 0, 3)
        for ping, big in messages:
            b.bool(ping).bool(big)
            if big:
                b.range(FIRST_PACKET_MAX if big is True else big, FIRST_PACKET_MAX - 13, FIRST_PACKET_MAX + 100)
            else:
                b.range(100, 0, 300)

    def exchange(b):
        peer_sends(b, [(False, 200), (True, 0)])
        send_messages(b, [(True, False), (False, True)])
        peer_sends(b, [(False, 3000)])

    def stage2(b, *, wrong_key, over, decoy, length, send_first, first_payload=True):
        b.bool(wrong_key).bool(send_first)
        if send_first:
            send_messages(b, [(False, first_payload)])
        b.bool(over)
        b.range(length, 0, FIRST_PACKET_MAX)
        b.bool(decoy)
        packet = (length + FIRST_PACKET_MAX + 1 if over else length) + EXPANSION
        b.feed(packet)
        if wrong_key or over:
            b.feed(FIRST_PACKET_MAX + EXPANSION)  # the filler, if the random length let the packet through
            return
        exchange(b)

    def contents(b, cls, kind, body, *, mutation=None, extra=None):
        """ConsumeContents(): returns the contents length."""
        b.range(cls, 0, 5)
        full = 12 + len(body)
        if cls == 0:
            return 0
        if cls == 2:
            return full
        if cls == 3:
            assert len(extra) == len(body)
            b.bytes(extra)
            return full
        assert cls == 4
        b.range(mutation, 0, 7)
        if mutation in (0, 1):
            b.u8(extra)
            return full
        if mutation == 2:
            b.u16(extra)
            return full
        if mutation == 3:
            b.range(extra, 0, full)
            return extra
        if mutation == 4:
            b.range(extra, 0, 63)
            return full
        if mutation == 5:
            b.u8(extra)
            return 2 * full
        assert mutation == 7
        b.range(extra[0], 0, full - 1).u8(extra[1])
        return full

    def initiator(name, *, mode, cls=2, decoys=(), encaps_fails=None, wrong_key=False, over=False, decoy=True,
                  length=0, send_first=False, first_payload=True, **kwargs):
        nonlocal n
        b = Input().u64(0x5eed).range(mode, 0, 2)
        side(b, priv_i, garbage_i, aux_i)
        side(b, priv_r, garbage_r, aux_r)
        b.bytes(d + z + m).bool(encaps_fails is not None)
        if encaps_fails is not None:
            b.range(encaps_fails, 0, 3)
        b.range(len(decoys), 0, 3)
        for length_ in decoys:
            b.range(length_, 0, 200)
        b.feed(KEY_LEN + len(garbage_r) + TERMINATOR_LEN + sum(x + EXPANSION for x in decoys))
        vp_r = contents(b, cls, KIND_OFFER, ek, **kwargs)
        b.feed(vp_r + EXPANSION)
        if mode == MODE_OFF or (cls == 0 and mode == MODE_PREFER):
            exchange(b)
        elif cls in (2, 3) and mode != MODE_OFF and encaps_fails is None:
            stage2(b, wrong_key=wrong_key, over=over, decoy=decoy, length=length, send_first=send_first,
                   first_payload=first_payload)
        write(corpus, "p2p_transport_hx1_initiator", name, b.build()); n += 1

    initiator("xip4_v1_prefer", mode=MODE_PREFER)
    initiator("xip4_v1_require", mode=MODE_REQUIRE)
    initiator("xip4_v1_off", mode=MODE_OFF)
    initiator("xip4_v4_decoys", mode=MODE_PREFER, decoys=(6,), length=100, decoy=False, send_first=True)
    initiator("xip4_v5_classical", mode=MODE_PREFER, cls=0)
    initiator("xip4_v5_refused", mode=MODE_REQUIRE, cls=0)
    for name, bad in bad_keys:
        initiator("xip4_v6_" + name, mode=MODE_PREFER, cls=3, extra=bad)
    initiator("xip4_v6_bad1_require", mode=MODE_REQUIRE, cls=3, extra=bad_keys[0][1])
    initiator("prefer_first_packet_limit", mode=MODE_PREFER, length=FIRST_PACKET_MAX, decoy=False)
    initiator("prefer_first_packet_over", mode=MODE_PREFER, over=True)
    initiator("prefer_wrong_key", mode=MODE_PREFER, wrong_key=True)
    # The first stage-2 message at the send limit: a "version" has 13 bytes of framing, so 4095 and 4096 bytes of
    # contents, without and with an empty decoy in front.
    initiator("prefer_first_send_4095", mode=MODE_PREFER, length=100, decoy=False, send_first=True,
              first_payload=FIRST_PACKET_MAX - 13)
    initiator("prefer_first_send_4096", mode=MODE_PREFER, length=100, decoy=False, send_first=True,
              first_payload=FIRST_PACKET_MAX - 12)
    initiator("require_wrong_key", mode=MODE_REQUIRE, wrong_key=True)
    initiator("prefer_malformed_11", mode=MODE_PREFER, cls=4, mutation=3, extra=11)
    initiator("prefer_malformed_kind", mode=MODE_PREFER, cls=4, mutation=1, extra=KIND_ACCEPT)
    initiator("prefer_malformed_length", mode=MODE_PREFER, cls=4, mutation=2, extra=1183)
    initiator("prefer_later_version", mode=MODE_PREFER, cls=4, mutation=0, extra=0x02)
    initiator("prefer_later_version_first", mode=MODE_PREFER, cls=4, mutation=5, extra=0x02)
    initiator("prefer_bad_tag", mode=MODE_PREFER, cls=4, mutation=4, extra=7)
    initiator("prefer_bad_body_byte", mode=MODE_PREFER, cls=4, mutation=7, extra=(13, 0xff))
    initiator("prefer_encaps_fails", mode=MODE_PREFER, encaps_fails=ERR_RNG)

    def responder(name, *, mode, cls=2, opening=0, local_failure=0, error=ERR_RNG, decoys=(), wrong_key=False,
                  over=False, decoy=False, length=120, send_first=False, **kwargs):
        nonlocal n
        b = Input().u64(0x5eed).range(mode, 0, 2)
        side(b, priv_r, garbage_r, aux_r)
        side(b, priv_i, garbage_i, aux_i)
        b.bytes(d + z + m).range(local_failure, 0, 2).range(opening, 0, 15)
        if local_failure:
            b.range(error, 0, 3)
        if opening in (1, 2):
            b.feed(16 if opening == 1 else KEY_LEN)
        else:
            b.feed(KEY_LEN + len(garbage_i))
            if not (local_failure == 1 and mode != MODE_OFF):
                vp_i = contents(b, cls, KIND_ACCEPT, ct, **kwargs)
                b.range(len(decoys), 0, 3)
                for length_ in decoys:
                    b.range(length_, 0, 200)
                b.feed(TERMINATOR_LEN + sum(x + EXPANSION for x in decoys) + vp_i + EXPANSION)
                if mode == MODE_OFF or (cls == 0 and mode == MODE_PREFER):
                    exchange(b)
                elif cls in (2, 3) and local_failure != 2:
                    stage2(b, wrong_key=wrong_key, over=over, decoy=decoy, length=length, send_first=send_first)
        write(corpus, "p2p_transport_hx1_responder", name, b.build()); n += 1

    responder("xip4_v1_prefer", mode=MODE_PREFER)
    responder("xip4_v1_require", mode=MODE_REQUIRE)
    responder("xip4_v1_off", mode=MODE_OFF)
    responder("xip4_v4_decoys", mode=MODE_PREFER, decoys=(0, 5), decoy=True, length=6, send_first=True)
    responder("xip4_v5_classical", mode=MODE_PREFER, cls=0)
    responder("xip4_v5_refused", mode=MODE_REQUIRE, cls=0)
    responder("prefer_random_ct", mode=MODE_PREFER, cls=3, extra=flipped)
    responder("prefer_first_packet_limit", mode=MODE_PREFER, length=FIRST_PACKET_MAX)
    responder("prefer_first_packet_over", mode=MODE_PREFER, over=True)
    responder("prefer_wrong_key", mode=MODE_PREFER, wrong_key=True)
    responder("prefer_malformed_10", mode=MODE_PREFER, cls=4, mutation=3, extra=10)
    responder("prefer_malformed_kind", mode=MODE_PREFER, cls=4, mutation=1, extra=KIND_OFFER)
    responder("prefer_malformed_length", mode=MODE_PREFER, cls=4, mutation=2, extra=1000)
    responder("prefer_later_version", mode=MODE_PREFER, cls=4, mutation=0, extra=0x07)
    responder("prefer_later_version_first", mode=MODE_PREFER, cls=4, mutation=5, extra=0x02)
    responder("prefer_keygen_fails", mode=MODE_PREFER, local_failure=1)
    responder("prefer_decaps_fails", mode=MODE_PREFER, local_failure=2, error=ERR_LIBRARY)
    responder("require_v1_refused", mode=MODE_REQUIRE, opening=1)
    responder("prefer_v1_fallback", mode=MODE_PREFER, opening=1)
    responder("prefer_v1_wrong_magic", mode=MODE_PREFER, opening=2)

    print(f"{n} seed files written under {corpus}")


if __name__ == "__main__":
    main()
