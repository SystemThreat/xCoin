#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Class for v2 P2P protocol (see BIP 324), with the HX1 hybrid post-quantum upgrade (see XIP-4)"""

import hashlib
import hmac
from io import BytesIO
import random
import unittest

from .crypto import mlkem
from .crypto.bip324_cipher import (
    BIP324_LABELS,
    FSChaCha20Poly1305,
    HX1_KIND_ACCEPT,
    HX1_KIND_OFFER,
    HX1_LABELS,
    HX1_MALFORMED,
    HX1_NONE,
    HX1_RECORD,
    HX1_SALT_PREFIX,
    hx1_classify_record,
    hx1_encode_record,
    hx1_stage2_keys,
)
from .crypto.chacha20 import FSChaCha20, REKEY_INTERVAL
from .crypto.ellswift import ellswift_create, ellswift_ecdh_xonly
from .crypto.hkdf import hkdf_sha256
from .key import TaggedHash
from .messages import MAGIC_BYTES


CHACHA20POLY1305_EXPANSION = 16
HEADER_LEN = 1
IGNORE_BIT_POS = 7
LENGTH_FIELD_LEN = 3
MAX_GARBAGE_LEN = 4095

SHORTID = {
    1: b"addr",
    2: b"block",
    3: b"blocktxn",
    4: b"cmpctblock",
    5: b"feefilter",
    6: b"filteradd",
    7: b"filterclear",
    8: b"filterload",
    9: b"getblocks",
    10: b"getblocktxn",
    11: b"getdata",
    12: b"getheaders",
    13: b"headers",
    14: b"inv",
    15: b"mempool",
    16: b"merkleblock",
    17: b"notfound",
    18: b"ping",
    19: b"pong",
    20: b"sendcmpct",
    21: b"tx",
    22: b"getcfilters",
    23: b"cfilter",
    24: b"getcfheaders",
    25: b"cfheaders",
    26: b"getcfcheckpt",
    27: b"cfcheckpt",
    28: b"addrv2",
}

# Dictionary which contains short message type ID for the P2P message
MSGTYPE_TO_SHORTID = {msgtype: shortid for shortid, msgtype in SHORTID.items()}

# HX1 modes, as in the node option -v2hybrid=<0|1|2> (XIP-4, "Modes").
HX1_MODE_OFF = 0      # plain BIP324, byte for byte as before HX1
HX1_MODE_PREFER = 1   # offer/accept HX1, stay classical with a peer that doesn't
HX1_MODE_REQUIRE = 2  # HX1 or nothing
# The framework's peers default to mode 0, so every existing test keeps
# sending exactly the bytes it sent before HX1. A mode-0 peer ignores an HX1
# offer, so this also works against a node in mode 1 (XIP-4 interop matrix,
# row N0). Tests that want HX1 pass v2hybrid=1 or 2 to add_p2p_connection()
# or add_outbound_p2p_connection().
DEFAULT_HX1_MODE = HX1_MODE_OFF

# XIP-4, "First stage-2 packet": each side's first packet under stage-2 keys has at most this many bytes of contents
# (the responder's is the empty confirmation packet; the initiator's is its VERSION message or a small decoy). Before
# key confirmation, a received length above it can only come from a stage-2 key mismatch, so the receiver fails at
# once instead of waiting for bytes that never come. A wrong key passes the check about once in 4096 tries.
HX1_FIRST_STAGE2_MAX_CONTENTS = 4095
# The responder's confirmation packet: a decoy with these (empty) contents, its first stage-2 packet, sent right after
# it switches to stage 2, so the initiator gets key confirmation without waiting for the responder's VERSION.
HX1_CONFIRMATION_CONTENTS = b""
# How a connection ends up, named as the node's getnetworkinfo v2hybrid_counts counters are (XIP-4).
HX1_OUTCOMES = ("hybrid", "classical", "refused", "bad_record", "stage2_failed", "local_error")


class V2HandshakeError(ValueError):
    """Raised when the v2 handshake must end the connection outside authenticate_handshake(),
    which reports failures by returning False instead."""


class EncryptedP2PState:
    """A class for managing the state when v2 P2P protocol is used. Performs initial v2 handshake and encrypts/decrypts
    P2P messages. P2PConnection uses an object of this class.


    Args:
        initiating (bool): defines whether the P2PConnection is an initiator or responder.
            - initiating = True for inbound connections in the test framework   [TestNode <------- P2PConnection]
            - initiating = False for outbound connections in the test framework [TestNode -------> P2PConnection]

        net (string): chain used (regtest, testnet etc..)

        hybrid_mode (int): the XIP-4 HX1 mode, 0 (off), 1 (prefer) or 2 (require). Mode 0 is BIP324 exactly as
            before HX1. In modes 1 and 2 the responder offers an ML-KEM-768 encapsulation key in its version
            packet, the initiator answers with a ciphertext in its own version packet, and every later packet in
            both directions uses stage-2 keys derived from both the ECDH secret and the ML-KEM shared secret.

    Methods:
        perform an advanced form of diffie-hellman handshake to instantiate the encrypted transport. before exchanging
        any P2P messages, 2 nodes perform this handshake in order to determine a shared secret that is unique to both
        of them and use it to derive keys to encrypt/decrypt P2P messages.
            - initial v2 handshakes is performed by: (see BIP324 section #overall-handshake-pseudocode)
                1. initiator using initiate_v2_handshake(), complete_handshake() and authenticate_handshake()
                2. responder using respond_v2_handshake(), complete_handshake() and authenticate_handshake()
            - initialize_v2_transport() sets various BIP324 derived keys and ciphers.

        encrypt/decrypt v2 P2P messages using v2_enc_packet() and v2_receive_packet().

        HX1 (modes 1 and 2) changes when the initiator's version packet is sent: authenticate_handshake() produces
        it after reading the responder's version packet, and the caller must send take_pending_handshake_bytes()
        before anything else.
    """
    def __init__(self, *, initiating, net, hybrid_mode=DEFAULT_HX1_MODE):
        assert hybrid_mode in (HX1_MODE_OFF, HX1_MODE_PREFER, HX1_MODE_REQUIRE)
        self.initiating = initiating  # True if initiator
        self.net = net
        self.peer = {}  # object with various BIP324 derived keys and ciphers
        self.privkey_ours = None
        self.ellswift_ours = None
        self.sent_garbage = b""
        self.received_garbage = b""
        self.received_prefix = b""  # received ellswift bytes till the first mismatch from 16 bytes v1_prefix
        self.tried_v2_handshake = False  # True when the initial handshake is over
        # stores length of packet contents to detect whether first 3 bytes (which contains length of packet contents)
        # has been decrypted. set to -1 if decryption hasn't been done yet.
        self.contents_len = -1
        self.found_garbage_terminator = False
        self.transport_version = b''
        self.received_version_contents = None  # contents of the peer's version packet, once received
        # HX1 (XIP-4) state. None of it is used in mode 0.
        self.hybrid_mode = hybrid_mode
        self.hybrid = False  # True once both directions use stage-2 keys
        self.hybrid_confirmed = False  # True once a stage-2 packet from the peer has authenticated
        self.hx1_classification = None  # how the peer's version packet classified: HX1_NONE, HX1_MALFORMED or HX1_RECORD
        self.hx1_tag_seen = False  # the peer's version packet carried the HX1 tag and version byte
        self.hx1_local_error = False  # the handshake failed because of our own ML-KEM call
        self.hx1_outcome = None  # which of HX1_OUTCOMES this connection counts as, once known
        self.failure_reason = None  # why the handshake failed, when it did
        self._hx1_first_send = False  # our next packet is our first under stage-2 keys (it must be small)
        self.pending_handshake_bytes = b""  # produced by authenticate_handshake(); must be sent before anything else
        self.hx1_ell_initiator = None
        self.hx1_ell_responder = None
        self.hx1_ek = None
        self.hx1_ct = None
        self._hx1_send_aad = b""  # our garbage, until the first packet we send has authenticated it
        self._hx1_ecdh_secret = None  # kept from stage 1 until stage 2 or the classical decision, then wiped
        self._hx1_dk = None  # responder only: kept until decapsulation or the classical decision, then wiped

    @staticmethod
    def v2_ecdh(priv, ellswift_theirs, ellswift_ours, initiating):
        """Compute BIP324 shared secret.

        Returns:
        bytes - BIP324 shared secret
        """
        ecdh_point_x32 = ellswift_ecdh_xonly(ellswift_theirs, priv)
        if initiating:
            # Initiating, place our public key encoding first.
            return TaggedHash("bip324_ellswift_xonly_ecdh", ellswift_ours + ellswift_theirs + ecdh_point_x32)
        else:
            # Responding, place their public key encoding first.
            return TaggedHash("bip324_ellswift_xonly_ecdh", ellswift_theirs + ellswift_ours + ecdh_point_x32)

    def generate_keypair_and_garbage(self, garbage_len=None):
        """Generates ellswift keypair and 4095 bytes garbage at max"""
        self.privkey_ours, self.ellswift_ours = ellswift_create()
        if garbage_len is None:
            garbage_len = random.randrange(MAX_GARBAGE_LEN + 1)
        self.sent_garbage = random.randbytes(garbage_len)
        return self.ellswift_ours + self.sent_garbage

    def initiate_v2_handshake(self):
        """Initiator begins the v2 handshake by sending its ellswift bytes and garbage

        Returns:
        bytes - bytes to be sent to the peer when starting the v2 handshake as an initiator
        """
        return self.generate_keypair_and_garbage()

    def respond_v2_handshake(self, response):
        """Responder begins the v2 handshake by sending its ellswift bytes and garbage. However, the responder
        sends this after having received at least one byte that mismatches 16-byte v1_prefix.

        Returns:
        1. int - length of bytes that were consumed so that recvbuf can be updated
        2. bytes - bytes to be sent to the peer when starting the v2 handshake as a responder.
                 - returns b"" if more bytes need to be received before we can respond and start the v2 handshake.
                 - returns -1 to downgrade the connection to v1 P2P.
        """
        v1_prefix = MAGIC_BYTES[self.net] + b'version\x00\x00\x00\x00\x00'
        while len(self.received_prefix) < 16:
            byte = response.read(1)
            # return b"" if we need to receive more bytes
            if not byte:
                return len(self.received_prefix), b""
            self.received_prefix += byte
            if self.received_prefix[-1] != v1_prefix[len(self.received_prefix) - 1]:
                return len(self.received_prefix), self.generate_keypair_and_garbage()
        # return -1 to decide v1 only after all 16 bytes processed
        if self.hybrid_mode == HX1_MODE_REQUIRE:
            # XIP-4: require mode refuses inbound plaintext v1.
            self._hx1_fail("inbound v1 connection refused in HX1 require mode", "refused")
            raise V2HandshakeError(self.failure_reason)
        return len(self.received_prefix), -1

    def complete_handshake(self, response):
        """ Instantiates the encrypted transport and
        sends garbage terminator + optional decoy packets + transport version packet.
        Done by both initiator and responder.

        Returns:
        1. int - length of bytes that were consumed. returns 0 if all 64 bytes from ellswift haven't been received yet.
        2. bytes - bytes to be sent to the peer when completing the v2 handshake
        """
        ellswift_theirs = self.received_prefix + response.read(64 - len(self.received_prefix))
        # return b"" if we need to receive more bytes
        if len(ellswift_theirs) != 64:
            return 0, b""
        ecdh_secret = self.v2_ecdh(self.privkey_ours, ellswift_theirs, self.ellswift_ours, self.initiating)
        self.initialize_v2_transport(ecdh_secret)
        if self.hybrid_mode != HX1_MODE_OFF:
            return 64 - len(self.received_prefix), self._hx1_complete_handshake(ellswift_theirs, ecdh_secret)
        # Send garbage terminator
        msg_to_send = self.peer['send_garbage_terminator']
        # Optionally send decoy packets after garbage terminator.
        aad = self.sent_garbage
        for decoy_contents in self.decoys_before_version():
            msg_to_send += self.v2_enc_packet(decoy_contents, aad=aad, ignore=True)
            aad = b''
        # Send version packet.
        msg_to_send += self.v2_enc_packet(self.transport_version, aad=aad)
        return 64 - len(self.received_prefix), msg_to_send

    def decoys_before_version(self):
        """Contents of the decoy packets sent between the garbage terminator and the version packet:
        0 to 10 packets of 1 to 100 zero bytes. Tests override this to fix them."""
        return [random.randint(1, 100) * b'\x00' for _ in range(random.randint(0, 10))]

    def authenticate_handshake(self, response):
        """ Ensures that the received optional decoy packets and transport version packet are authenticated.
        Marks the v2 handshake as complete. Done by both initiator and responder.

        Returns:
        1. int - length of bytes that were processed so that recvbuf can be updated
        2. bool - True if the authentication was successful/more bytes need to be received and False otherwise
        """
        processed_length = 0

        # Detect garbage terminator in the received bytes
        if not self.found_garbage_terminator:
            received_garbage = response[:16]
            response = response[16:]
            processed_length = len(received_garbage)
            for i in range(MAX_GARBAGE_LEN + 1):
                if received_garbage[-16:] == self.peer['recv_garbage_terminator']:
                    # Receive, decode, and ignore version packet.
                    # This includes skipping decoys and authenticating the received garbage.
                    self.found_garbage_terminator = True
                    self.received_garbage = received_garbage[:-16]
                    break
                else:
                    # don't update recvbuf since more bytes need to be received
                    if len(response) == 0:
                        return 0, True
                    received_garbage += response[:1]
                    processed_length += 1
                    response = response[1:]
            else:
                # disconnect since garbage terminator was not seen after 4 KiB of garbage.
                return processed_length, False

        # Process optional decoy packets and transport version packet
        while not self.tried_v2_handshake:
            length, contents = self.v2_receive_packet(response, aad=self.received_garbage)
            if length == -1:
                return processed_length, False
            elif length == 0:
                return processed_length, True
            processed_length += length
            self.received_garbage = b""
            # decoy packets have contents = None. v2 handshake is complete only when version packet
            # (can be empty with contents = b"") with contents != None is received.
            if contents is not None:
                # The contents are reserved for extensions. Mode 0 ignores them, as BIP324 says; a node in HX1
                # mode 1 or 2 sends an HX1 record here.
                self.received_version_contents = contents
                if self.hybrid_mode != HX1_MODE_OFF and not self._hx1_process_version_packet(contents):
                    return processed_length, False
                self.tried_v2_handshake = True
                return processed_length, True
            response = response[length:]

    def initialize_v2_transport(self, ecdh_secret):
        """Sets the peer object with various BIP324 derived keys and ciphers."""
        peer = {}
        salt = b'bitcoin_v2_shared_secret' + MAGIC_BYTES[self.net]
        for name in ('initiator_L', 'initiator_P', 'responder_L', 'responder_P', 'garbage_terminators', 'session_id'):
            peer[name] = hkdf_sha256(salt=salt, ikm=ecdh_secret, info=name.encode('utf-8'), length=32)
        if self.initiating:
            self.peer['send_L'] = FSChaCha20(peer['initiator_L'])
            self.peer['send_P'] = FSChaCha20Poly1305(peer['initiator_P'])
            self.peer['send_garbage_terminator'] = peer['garbage_terminators'][:16]
            self.peer['recv_L'] = FSChaCha20(peer['responder_L'])
            self.peer['recv_P'] = FSChaCha20Poly1305(peer['responder_P'])
            self.peer['recv_garbage_terminator'] = peer['garbage_terminators'][16:]
        else:
            self.peer['send_L'] = FSChaCha20(peer['responder_L'])
            self.peer['send_P'] = FSChaCha20Poly1305(peer['responder_P'])
            self.peer['send_garbage_terminator'] = peer['garbage_terminators'][16:]
            self.peer['recv_L'] = FSChaCha20(peer['initiator_L'])
            self.peer['recv_P'] = FSChaCha20Poly1305(peer['initiator_P'])
            self.peer['recv_garbage_terminator'] = peer['garbage_terminators'][:16]
        self.peer['session_id'] = peer['session_id']

    def v2_enc_packet(self, contents, aad=b'', ignore=False):
        """Encrypt a BIP324 packet.

        Returns:
        bytes - encrypted packet contents
        """
        if self.hybrid_mode != HX1_MODE_OFF:
            # XIP-4: no application packet may go out before the HX1 handshake has finished (it would use stage-1
            # keys), and the responder may send nothing at all between its version packet and the initiator's.
            # The handshake's own packets use _encrypt_packet().
            assert self.tried_v2_handshake, "HX1: nothing may be sent before the v2 handshake has finished"
            self._hx1_check_first_send(contents)
        return self._encrypt_packet(contents, aad, ignore)

    def _encrypt_packet(self, contents, aad=b'', ignore=False):
        """Encrypt a BIP324 packet with the current send ciphers, without the HX1 ordering check."""
        assert len(contents) <= 2**24 - 1
        header = (ignore << IGNORE_BIT_POS).to_bytes(HEADER_LEN, 'little')
        plaintext = header + contents
        aead_ciphertext = self.peer['send_P'].encrypt(aad, plaintext)
        enc_plaintext_len = self.peer['send_L'].crypt(len(contents).to_bytes(LENGTH_FIELD_LEN, 'little'))
        return enc_plaintext_len + aead_ciphertext

    def v2_receive_packet(self, response, aad=b''):
        """Decrypt a BIP324 packet

        Returns:
        1. int - number of bytes consumed (or -1 if error)
        2. bytes - contents of decrypted non-decoy packet if any (or None otherwise)
        """
        if self.contents_len == -1:
            if len(response) < LENGTH_FIELD_LEN:
                return 0, None
            enc_contents_len = response[:LENGTH_FIELD_LEN]
            self.contents_len = int.from_bytes(self.peer['recv_L'].crypt(enc_contents_len), 'little')
            if self.hybrid and not self.hybrid_confirmed and self.contents_len > HX1_FIRST_STAGE2_MAX_CONTENTS:
                # XIP-4: the peer's first stage-2 packet is small, so this length was decrypted with the wrong key.
                # (A node's own size limit cannot catch it: it is above every 3-byte length.)
                self._hx1_fail(f"the first stage-2 packet from the peer claims {self.contents_len} bytes of contents, "
                               f"over the {HX1_FIRST_STAGE2_MAX_CONTENTS}-byte limit before key confirmation", "stage2_failed")
                return -1, None  # disconnect
        response = response[LENGTH_FIELD_LEN:]
        if len(response) < HEADER_LEN + self.contents_len + CHACHA20POLY1305_EXPANSION:
            return 0, None
        aead_ciphertext = response[:HEADER_LEN + self.contents_len + CHACHA20POLY1305_EXPANSION]
        plaintext = self.peer['recv_P'].decrypt(aad, aead_ciphertext)
        if plaintext is None:
            if self.hybrid and not self.hybrid_confirmed:
                self._hx1_fail("the first stage-2 packet from the peer failed to authenticate", "stage2_failed")
            return -1, None  # disconnect
        if self.hybrid and not self.hybrid_confirmed:
            # XIP-4 key confirmation: the peer derived the same stage-2 keys.
            self.hybrid_confirmed = True
            self.hx1_outcome = "hybrid"
        header = plaintext[:HEADER_LEN]
        length = LENGTH_FIELD_LEN + HEADER_LEN + self.contents_len + CHACHA20POLY1305_EXPANSION
        self.contents_len = -1
        return length, None if (header[0] & (1 << IGNORE_BIT_POS)) else plaintext[HEADER_LEN:]

    # HX1 (XIP-4), modes 1 and 2.
    #
    # Initiator: sends ell_I || garbage_I as usual; on ell_R it sends the garbage terminator and any stage-1 decoys
    # but not its version packet (VP_I); on reading the responder's version packet (VP_R) it classifies it and either
    # answers with an empty VP_I (classical) or checks ek, encapsulates, sends VP_I with the ciphertext and switches
    # both directions to stage-2 keys.
    # Responder: on ell_I it generates an ML-KEM-768 keypair and sends the garbage terminator, any stage-1 decoys and
    # VP_R with ek, then sends nothing until it has read VP_I; if VP_I carries a ciphertext it decapsulates, switches
    # both directions to stage 2 and at once sends its confirmation packet (an empty stage-2 decoy).
    # Key confirmation: the first stage-2 packet from the peer authenticates. Before it, a stage-2 length over
    # HX1_FIRST_STAGE2_MAX_CONTENTS ends the connection at once.

    def hx1_keygen(self):
        """ML-KEM-768 key generation for the responder's offer. Returns (ek, dk).

        d and z are drawn separately, 32 bytes each: a node's GetStrongRandBytes serves at most 32 bytes per call
        (src/random.cpp:567), so XIP-4 draws them as two calls.

        The seeds come from the framework's PRNG, like the rest of its v2 randomness, so a run can be repeated from
        its seed. Tests override this to fix the seeds or to inject a failure."""
        return mlkem.keygen_internal(random.randbytes(32), random.randbytes(32))

    def hx1_encaps(self, ek):
        """ML-KEM-768 encapsulation by the initiator. ek has already passed the FIPS 203 section 7.2 check.
        Returns (shared secret, ciphertext). Tests override this to fix m or to inject a failure."""
        return mlkem.encaps_internal(ek, random.randbytes(32))

    def hx1_decaps(self, dk, ct):
        """ML-KEM-768 decapsulation by the responder. A bad ciphertext is not an error: implicit rejection returns
        an unrelated secret, so the two sides derive different stage-2 keys. That shows up on each side's first
        stage-2 packet from the other: its length decrypts to a random value, which is over
        HX1_FIRST_STAGE2_MAX_CONTENTS about 4095 times in 4096, so the receiver fails at once. Tests override this to
        inject a failure."""
        return mlkem.decaps_internal(dk, ct)

    def hx1_version_contents(self, record):
        """The contents to put in our version packet when it carries an HX1 record. Tests override this to send a
        malformed or extended record. (transport_version is used only where the version packet carries no record:
        in mode 0, and in the initiator's empty VP_I to a classical peer.)"""
        return record

    def hx1_decoys_after_switch(self):
        """Contents of decoy packets sent right after switching to stage 2 (the initiator: right after VP_I; the
        responder: right after its confirmation packet). None by default. The first stage-2 packet a side sends
        has at most HX1_FIRST_STAGE2_MAX_CONTENTS bytes of contents."""
        return []

    def take_pending_handshake_bytes(self):
        """Return, and forget, the bytes authenticate_handshake() produced for sending. In modes 1 and 2 the
        initiator's version packet is among them, so they must be sent before any application message."""
        data, self.pending_handshake_bytes = self.pending_handshake_bytes, b""
        return data

    def transport_info(self):
        """What a node in this state reports in getpeerinfo (XIP-4, "What a node reports")."""
        if not self.tried_v2_handshake or (self.hybrid and not self.hybrid_confirmed):
            return {"transport_protocol_type": "detecting", "session_id": "", "transport_hybrid": False}
        return {"transport_protocol_type": "v2", "session_id": self.peer['session_id'].hex(), "transport_hybrid": self.hybrid}

    @property
    def hx1_classical_retry_eligible(self):
        """Whether a node would retry this lost connection once as classical v2 (XIP-4, "One classical retry"): an
        outbound connection in prefer mode whose VP_R carried the HX1 tag and version, lost before key confirmation,
        not because of a local error. (A node also leaves out connections it chose to close itself: disconnectnode,
        a ban, shutdown. That is a decision above the transport, so this state cannot see it.)"""
        return (self.initiating and self.hybrid_mode == HX1_MODE_PREFER and self.hx1_tag_seen and
                not self.hybrid_confirmed and not self.hx1_local_error)

    @property
    def hx1_retry_cause(self):
        """The cause a node logs with a classical retry: the failure this side saw ("bad_record" or
        "stage2_failed"), or, when it saw none, that the peer closed the connection before key confirmation (or the
        handshake timed out, which a node counts as "stage2_failed"). None if the connection is not retried."""
        if not self.hx1_classical_retry_eligible:
            return None
        if self.hx1_outcome in ("bad_record", "stage2_failed"):
            return self.hx1_outcome
        return "closed before key confirmation"

    def _hx1_complete_handshake(self, ellswift_theirs, ecdh_secret):
        """complete_handshake() in modes 1 and 2. Returns the bytes to send."""
        self._hx1_ecdh_secret = ecdh_secret
        if self.initiating:
            self.hx1_ell_initiator, self.hx1_ell_responder = self.ellswift_ours, ellswift_theirs
        else:
            self.hx1_ell_initiator, self.hx1_ell_responder = ellswift_theirs, self.ellswift_ours
        self._hx1_send_aad = self.sent_garbage
        msg_to_send = self.peer['send_garbage_terminator']
        for decoy_contents in self.decoys_before_version():
            msg_to_send += self._hx1_encrypt_stage1(decoy_contents, ignore=True)
        if not self.initiating:
            try:
                ek, dk = self.hx1_keygen()
            except Exception as e:
                # Never downgrade on a local error.
                self._hx1_fail(f"local ML-KEM key generation failed: {e!r}", "local_error")
                raise V2HandshakeError(self.failure_reason) from e
            self.hx1_ek = bytes(ek)
            self._hx1_dk = dk
            msg_to_send += self._hx1_encrypt_stage1(self.hx1_version_contents(hx1_encode_record(HX1_KIND_OFFER, self.hx1_ek)))
            # From here the responder sends nothing until it has read VP_I (v2_enc_packet() enforces it).
        # The initiator's VP_I waits for VP_R: see _hx1_process_version_packet().
        return msg_to_send

    def _hx1_encrypt_stage1(self, contents, ignore=False):
        """Encrypt a handshake packet with the stage-1 keys; the first one carries our garbage as associated data."""
        packet = self._encrypt_packet(contents, aad=self._hx1_send_aad, ignore=ignore)
        self._hx1_send_aad = b""
        return packet

    def _hx1_process_version_packet(self, contents):
        """Act on the peer's version packet in modes 1 and 2. Returns False if the connection must end."""
        expected_kind = HX1_KIND_OFFER if self.initiating else HX1_KIND_ACCEPT
        classification, body = hx1_classify_record(contents, expected_kind)
        self.hx1_classification = classification
        self.hx1_tag_seen = classification != HX1_NONE
        if classification == HX1_NONE:
            if self.hybrid_mode == HX1_MODE_REQUIRE:
                self._hx1_fail("the peer's version packet has no HX1 record (require mode)", "refused")
                return False
            # A classical peer: stay on the stage-1 keys. The initiator still owes its version packet.
            if self.initiating:
                self.pending_handshake_bytes += self._hx1_encrypt_stage1(self.transport_version)
            self.hx1_outcome = "classical"
            self._hx1_wipe()
            return True
        if classification == HX1_MALFORMED:
            self._hx1_fail("malformed HX1 record in the peer's version packet", "bad_record")
            return False
        assert classification == HX1_RECORD
        if self.initiating:
            ek = body
            if not mlkem.check_encaps_key(ek):
                self._hx1_fail("the offered ML-KEM encapsulation key failed the FIPS 203 section 7.2 check", "bad_record")
                return False
            try:
                kem_secret, ct = self.hx1_encaps(ek)
            except Exception as e:
                self._hx1_fail(f"local ML-KEM encapsulation failed: {e!r}", "local_error")
                return False
            self.hx1_ek, self.hx1_ct = ek, bytes(ct)
            # VP_I is the last packet under stage-1 keys; everything after it uses stage 2.
            version_packet = self._hx1_encrypt_stage1(self.hx1_version_contents(hx1_encode_record(HX1_KIND_ACCEPT, self.hx1_ct)))
            self._hx1_switch_to_stage2(kem_secret)
            self.pending_handshake_bytes += version_packet
        else:
            self.hx1_ct = body
            try:
                kem_secret = self.hx1_decaps(self._hx1_dk, self.hx1_ct)
            except Exception as e:
                self._hx1_fail(f"local ML-KEM decapsulation failed: {e!r}", "local_error")
                return False
            self._hx1_switch_to_stage2(kem_secret)
            # The confirmation packet: the responder's first stage-2 packet, sent at once. The initiator gets key
            # confirmation from it about one round trip after VP_I, before the responder's node has read anything,
            # so a close by the responder's node after that (a self-connection, an eviction) is not mistaken for
            # an HX1 failure.
            self.pending_handshake_bytes += self._hx1_encrypt_stage2(HX1_CONFIRMATION_CONTENTS, ignore=True)
        for decoy_contents in self.hx1_decoys_after_switch():
            self.pending_handshake_bytes += self._hx1_encrypt_stage2(decoy_contents, ignore=True)
        return True

    def _hx1_encrypt_stage2(self, contents, ignore=False):
        """Encrypt a packet the handshake itself sends under stage-2 keys (the responder's confirmation packet and
        test decoys)."""
        self._hx1_check_first_send(contents)
        return self._encrypt_packet(contents, aad=b'', ignore=ignore)

    def _hx1_check_first_send(self, contents):
        """XIP-4: the first packet a side sends under stage-2 keys has at most HX1_FIRST_STAGE2_MAX_CONTENTS bytes
        of contents, so that the peer can tell a key mismatch from a large packet."""
        if self._hx1_first_send:
            assert len(contents) <= HX1_FIRST_STAGE2_MAX_CONTENTS, "HX1: the first stage-2 packet is too large"
            self._hx1_first_send = False

    def _hx1_switch_to_stage2(self, kem_secret):
        """Replace the four stage-1 ciphers with fresh stage-2 ciphers and adopt the stage-2 session id."""
        assert self.contents_len == -1  # no packet is half read
        keys = hx1_stage2_keys(MAGIC_BYTES[self.net], kem_secret, self._hx1_ecdh_secret, self.hx1_ct,
                               self.hx1_ell_initiator, self.hx1_ek, self.hx1_ell_responder)
        ours, theirs = ('initiator', 'responder') if self.initiating else ('responder', 'initiator')
        self.peer['send_L'] = FSChaCha20(keys[f'xcoin_hx1_{ours}_L'])
        self.peer['send_P'] = FSChaCha20Poly1305(keys[f'xcoin_hx1_{ours}_P'])
        self.peer['recv_L'] = FSChaCha20(keys[f'xcoin_hx1_{theirs}_L'])
        self.peer['recv_P'] = FSChaCha20Poly1305(keys[f'xcoin_hx1_{theirs}_P'])
        # A node never reports the stage-1 session id of a hybrid session; it is kept here only for tests.
        self.peer['stage1_session_id'] = self.peer['session_id']
        self.peer['session_id'] = keys['xcoin_hx1_session_id']
        self.hybrid = True
        self._hx1_first_send = True
        self._hx1_wipe()

    def _hx1_fail(self, reason, outcome):
        """End the HX1 handshake: record why and which counter it lands in, and wipe the secrets."""
        assert outcome in HX1_OUTCOMES
        self.failure_reason = reason
        self.hx1_outcome = outcome
        self.hx1_local_error = outcome == "local_error"
        self._hx1_wipe()

    def _hx1_wipe(self):
        """Forget the secrets HX1 keeps during the handshake. (Python cannot really wipe memory; the node must.)"""
        self._hx1_ecdh_secret = None
        self._hx1_dk = None


# Test support for HX1: fixed-input states, a back-to-back harness, and an independent reader for recorded
# transcripts. The reader and the key derivations below do not use EncryptedP2PState or hx1_stage2_keys(); they
# recompute everything from the recorded bytes with hmac, hashlib and the ML-KEM module, so they can check the
# state machine above.

def _hx1_input(name):
    return hashlib.sha256(b"XIP-4 test vector: " + name.encode()).digest()


# The inputs shared by every XIP-4 handshake vector. The ElligatorSwift keys are what libsecp256k1's
# secp256k1_ellswift_create(priv, aux) returns, the call CKey::EllSwiftCreate makes (src/key.cpp:312-326);
# contrib/testgen/gen_hx1_handshake_vectors.py recomputes them.
HX1_VECTOR_INPUTS = {
    "priv_I": _hx1_input("initiator secret key"),
    "aux_I": _hx1_input("initiator ellswift entropy"),
    "priv_R": _hx1_input("responder secret key"),
    "aux_R": _hx1_input("responder ellswift entropy"),
    "garbage_I": _hx1_input("initiator garbage")[:13],
    "garbage_R": _hx1_input("responder garbage")[:5],
    "d": _hx1_input("ML-KEM d"),
    "z": _hx1_input("ML-KEM z"),
    "m": _hx1_input("ML-KEM m"),
    "ell_I": bytes.fromhex("77912a89a57b3a2991c56274b9b24aa672b12e7f4a70653ca7e521ec614971ce"
                           "7a438fee0858c46d0b32e28e0d8510f937c26c57d2e1ab274c066e362c7248f8"),
    "ell_R": bytes.fromhex("2163a7d9fb5c171c53cd06a7d1bc390a8c6343bba7fbe273aeadb3ce8d9d0cc9"
                           "d1fdb6dd34f6257fa3b07216374b9ac60edb585ff4e48bc5362561bb943abc1d"),
}


class HX1FixedState(EncryptedP2PState):
    """An EncryptedP2PState whose random inputs are all given: key, garbage, decoys and ML-KEM seeds."""
    def __init__(self, *, initiating, net, hybrid_mode, privkey, ellswift, garbage,
                 decoys_before_version=(), decoys_after_switch=(), mlkem_d=None, mlkem_z=None, mlkem_m=None):
        super().__init__(initiating=initiating, net=net, hybrid_mode=hybrid_mode)
        self._fixed_key = (privkey, ellswift)
        self._fixed_garbage = garbage
        self._fixed_decoys_before = list(decoys_before_version)
        self._fixed_decoys_after = list(decoys_after_switch)
        self._fixed_mlkem = (mlkem_d, mlkem_z, mlkem_m)

    def generate_keypair_and_garbage(self, garbage_len=None):
        self.privkey_ours, self.ellswift_ours = self._fixed_key
        self.sent_garbage = self._fixed_garbage
        return self.ellswift_ours + self.sent_garbage

    def decoys_before_version(self):
        return list(self._fixed_decoys_before)

    def hx1_decoys_after_switch(self):
        return list(self._fixed_decoys_after)

    def hx1_keygen(self):
        d, z, _ = self._fixed_mlkem
        return mlkem.keygen_internal(d, z)

    def hx1_encaps(self, ek):
        _, _, m = self._fixed_mlkem
        return mlkem.encaps_internal(ek, m)


class V2Loopback:
    """Two EncryptedP2PState objects connected back to back, driven the way P2PConnection drives one against a node
    (see P2PConnection._on_data_v2_handshake), recording what each side puts on the wire. Side True is the initiator,
    side False the responder."""
    def __init__(self, initiator, responder):
        assert initiator.initiating and not responder.initiating
        self.states = {True: initiator, False: responder}
        self.wire = {True: b"", False: b""}  # everything each side sent, in order
        self.inbox = {True: b"", False: b""}  # sent to that side but not delivered yet
        self.recvbuf = {True: b"", False: b""}
        self.received = {True: [], False: []}  # packets received after the handshake: contents, or None for decoys
        self.error = {True: None, False: None}  # why that side ended the connection
        self.v1 = False  # the responder saw the v1 prefix and fell back to v1

    def ready(self, side):
        return self.states[side].tried_v2_handshake and self.error[side] is None

    def stalled(self, side):
        """Whether that side holds bytes it cannot use yet. A side that has not switched to stage 2 still waits like
        this when a length decrypts to a bogus value (a node until its handshake timeout, -peertimeout). A hybrid side
        before key confirmation waits only when a wrong key happens to give a length within
        HX1_FIRST_STAGE2_MAX_CONTENTS, about once in 4096."""
        return self.error[side] is None and len(self.recvbuf[side]) > 0

    def handshake(self):
        self.send_raw(True, self.states[True].initiate_v2_handshake())
        self.pump()

    def send_raw(self, side, data):
        assert self.error[side] is None
        self.wire[side] += data
        self.inbox[not side] += data

    def send(self, side, contents, ignore=False):
        self.send_raw(side, self.states[side].v2_enc_packet(contents, ignore=ignore))

    def pump(self):
        """Deliver everything in flight until neither side has anything more to say. A side that ended the
        connection receives nothing more; what it sent before still arrives."""
        while True:
            moved = False
            for side in (True, False):
                if self.inbox[side] and self.error[side] is None and not self.v1:
                    self.recvbuf[side] += self.inbox[side]
                    self.inbox[side] = b""
                    self._process(side)
                    moved = True
            if not moved:
                return

    def _process(self, side):
        st = self.states[side]
        try:
            if not st.tried_v2_handshake:
                if not st.peer:
                    if not st.initiating and not st.sent_garbage:
                        length, out = st.respond_v2_handshake(BytesIO(self.recvbuf[side]))
                        self.recvbuf[side] = self.recvbuf[side][length:]
                        if out == -1:
                            self.v1 = True
                            return
                        elif out:
                            self.send_raw(side, out)
                        else:
                            return
                    length, out = st.complete_handshake(BytesIO(self.recvbuf[side]))
                    self.recvbuf[side] = self.recvbuf[side][length:]
                    if out:
                        self.send_raw(side, out)
                    else:
                        return
                length, ok = st.authenticate_handshake(self.recvbuf[side])
                if not ok:
                    self.error[side] = st.failure_reason or "invalid v2 mac tag in handshake authentication"
                    return
                self.recvbuf[side] = self.recvbuf[side][length:]
                pending = st.take_pending_handshake_bytes()
                if pending:
                    self.send_raw(side, pending)
                if not st.tried_v2_handshake:
                    return
            while self.recvbuf[side]:
                length, contents = st.v2_receive_packet(self.recvbuf[side])
                if length == -1:
                    self.error[side] = st.failure_reason or "invalid v2 mac tag"
                    return
                if length == 0:
                    return
                self.recvbuf[side] = self.recvbuf[side][length:]
                self.received[side].append(contents)
        except V2HandshakeError as e:
            self.error[side] = str(e)


def hx1_hkdf32(salt, ikm, label):
    """HKDF-SHA256 with one 32-byte output, written out with hmac: PRK = HMAC(salt, ikm); OKM = HMAC(PRK, label || 1)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, label + b"\x01", hashlib.sha256).digest()


def hx1_reference_stage1_keys(ecdh_secret, magic):
    """The six BIP324 HKDF outputs (src/bip324.cpp:36-64), recomputed with hmac."""
    salt = b"bitcoin_v2_shared_secret" + magic
    return {label: hx1_hkdf32(salt, ecdh_secret, label.encode()) for label in BIP324_LABELS}


def hx1_reference_stage2_keys(magic, kem_secret, ecdh_secret, ct, ell_initiator, ek, ell_responder):
    """The XIP-4 stage-2 key schedule, recomputed with hmac. Also returns IKM2 and PRK2."""
    ikm2 = kem_secret + ecdh_secret + ct + ell_initiator + ek + ell_responder
    prk2 = hmac.new(HX1_SALT_PREFIX + magic, ikm2, hashlib.sha256).digest()
    keys = {label: hmac.new(prk2, label.encode() + b"\x01", hashlib.sha256).digest() for label in HX1_LABELS}
    return ikm2, prk2, keys


class V2PacketReader:
    """Reads BIP324 packets from one direction of a recorded connection, with ciphers the caller supplies."""
    def __init__(self, key_L, key_P):
        self.cipher_L = FSChaCha20(key_L)
        self.cipher_P = FSChaCha20Poly1305(key_P)
        self.index = 0  # index of the next packet under these keys

    def read(self, data, aad=b""):
        """Decrypt the packet at the start of data. Returns (ignore, contents, wire) or None if it is incomplete
        or does not authenticate. The ciphers advance as in a real receiver either way."""
        if len(data) < LENGTH_FIELD_LEN:
            return None
        contents_len = int.from_bytes(self.cipher_L.crypt(data[:LENGTH_FIELD_LEN]), 'little')
        end = LENGTH_FIELD_LEN + HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
        self.index += 1
        if len(data) < end:
            return None
        plaintext = self.cipher_P.decrypt(aad, data[LENGTH_FIELD_LEN:end])
        if plaintext is None:
            return None
        return bool(plaintext[0] & (1 << IGNORE_BIT_POS)), plaintext[HEADER_LEN:], data[:end]

    def authenticates(self, wire, aad=b""):
        """Whether a packet whose boundaries are known authenticates at the next index (the length field is not
        used). The ciphers advance either way."""
        self.cipher_L.crypt(wire[:LENGTH_FIELD_LEN])
        self.index += 1
        return self.cipher_P.decrypt(aad, wire[LENGTH_FIELD_LEN:]) is not None


def hx1_split_stream(stream, garbage_terminator, key_L, key_P):
    """Split one direction's recorded bytes at the end of its version packet, using that direction's stage-1 keys.
    Returns a dict with the ellswift key, the garbage, the stage-1 packets up to and including the version packet
    (each (ignore, contents, wire, index)), the offset where the version packet ends, the bytes after it, and the
    stage-1 reader, whose ciphers have advanced past the version packet."""
    ell = stream[:64]
    pos = stream.find(garbage_terminator, 64, 64 + MAX_GARBAGE_LEN + 16)
    assert pos >= 0, "garbage terminator not found"
    garbage = stream[64:pos]
    pos += len(garbage_terminator)
    reader = V2PacketReader(key_L, key_P)
    packets = []
    aad = garbage
    while True:
        index = reader.index
        packet = reader.read(stream[pos:], aad=aad)
        assert packet is not None, "stage-1 packet failed to authenticate"
        aad = b""
        ignore, contents, wire = packet
        packets.append((ignore, contents, wire, index))
        pos += len(wire)
        if not ignore:
            break
    return {"ell": ell, "garbage": garbage, "stage1_packets": packets, "version_end": pos,
            "after_version": stream[pos:], "stage1_reader": reader}


def hx1_read_all(data, key_L, key_P):
    """Read every packet in data with fresh ciphers; every one must authenticate and nothing may be left over.
    Returns a list of (ignore, contents, wire, index)."""
    reader = V2PacketReader(key_L, key_P)
    packets = []
    pos = 0
    while pos < len(data):
        index = reader.index
        packet = reader.read(data[pos:])
        assert packet is not None, f"packet {index} failed to authenticate"
        ignore, contents, wire = packet
        packets.append((ignore, contents, wire, index))
        pos += len(wire)
    return packets


HX1_VECTOR_APP_PACKETS = 226
HX1_VECTOR_PINNED_APP_PACKETS = (0, 1, 223, 224, 225)


def hx1_app_contents(from_initiator, i):
    """Application packet i of a vector: ASCII "I->R" or "R->I", then i as 4 bytes little-endian."""
    return (b"I->R" if from_initiator else b"R->I") + i.to_bytes(4, 'little')


def hx1_handshake_vector(name, net, *, initiator_mode=HX1_MODE_PREFER, responder_mode=HX1_MODE_PREFER,
                         initiator_decoys=(), initiator_decoys_after_switch=(), responder_decoys=(),
                         app_packets=HX1_VECTOR_APP_PACKETS):
    """Run a handshake with the XIP-4 vector inputs and return every field XIP-4 lists for a handshake vector.

    The wire bytes come from two EncryptedP2PState objects talking to each other. Every key, the ML-KEM values
    and every packet are then recomputed from the recorded bytes by the reference functions above, which do not
    use the state machine, and checked against it."""
    inp = HX1_VECTOR_INPUTS
    magic = MAGIC_BYTES[net]
    initiator = HX1FixedState(initiating=True, net=net, hybrid_mode=initiator_mode, privkey=inp["priv_I"],
                              ellswift=inp["ell_I"], garbage=inp["garbage_I"], decoys_before_version=initiator_decoys,
                              decoys_after_switch=initiator_decoys_after_switch, mlkem_m=inp["m"])
    responder = HX1FixedState(initiating=False, net=net, hybrid_mode=responder_mode, privkey=inp["priv_R"],
                              ellswift=inp["ell_R"], garbage=inp["garbage_R"], decoys_before_version=responder_decoys,
                              mlkem_d=inp["d"], mlkem_z=inp["z"])
    link = V2Loopback(initiator, responder)
    link.handshake()
    assert link.ready(True) and link.ready(False), link.error
    hybrid = initiator.hybrid
    assert responder.hybrid == hybrid
    # In a hybrid session the responder's confirmation packet has already confirmed the keys to the initiator; the
    # responder has confirmation only if the initiator sent a stage-2 decoy.
    assert initiator.hybrid_confirmed == hybrid
    assert responder.hybrid_confirmed == (hybrid and len(initiator_decoys_after_switch) > 0)
    for i in range(app_packets):
        link.send(True, hx1_app_contents(True, i))
        link.send(False, hx1_app_contents(False, i))
    link.pump()
    assert link.error == {True: None, False: None}, link.error
    expected_after = {True: [None] * len(initiator_decoys_after_switch) + [hx1_app_contents(True, i) for i in range(app_packets)],
                      False: ([None] if hybrid else []) + [hx1_app_contents(False, i) for i in range(app_packets)]}
    # What each side received is what the other sent.
    assert link.received[False] == expected_after[True] and link.received[True] == expected_after[False]

    # Recompute everything from the recorded bytes.
    ecdh = EncryptedP2PState.v2_ecdh(inp["priv_I"], inp["ell_R"], inp["ell_I"], True)
    assert ecdh == EncryptedP2PState.v2_ecdh(inp["priv_R"], inp["ell_I"], inp["ell_R"], False)
    st1 = hx1_reference_stage1_keys(ecdh, magic)
    term_I, term_R = st1["garbage_terminators"][:16], st1["garbage_terminators"][16:]
    split = {True: hx1_split_stream(link.wire[True], term_I, st1["initiator_L"], st1["initiator_P"]),
             False: hx1_split_stream(link.wire[False], term_R, st1["responder_L"], st1["responder_P"])}
    assert split[True]["ell"] == inp["ell_I"] and split[False]["ell"] == inp["ell_R"]
    assert split[True]["garbage"] == inp["garbage_I"] and split[False]["garbage"] == inp["garbage_R"]
    assert [p[1] for p in split[True]["stage1_packets"][:-1]] == list(initiator_decoys)
    assert [p[1] for p in split[False]["stage1_packets"][:-1]] == list(responder_decoys)
    vp = {side: split[side]["stage1_packets"][-1] for side in (True, False)}

    out = {"name": name, "network": net, "magic": magic.hex(),
           "initiator_mode": initiator_mode, "responder_mode": responder_mode,
           "initiator_decoys_before_version": [c.hex() for c in initiator_decoys],
           "initiator_decoys_after_switch": [c.hex() for c in initiator_decoys_after_switch],
           "responder_decoys_before_version": [c.hex() for c in responder_decoys],
           "ell_initiator": inp["ell_I"].hex(), "ell_responder": inp["ell_R"].hex(), "ecdh_secret": ecdh.hex(),
           "stage1": {"initiator_L": st1["initiator_L"].hex(), "initiator_P": st1["initiator_P"].hex(),
                      "responder_L": st1["responder_L"].hex(), "responder_P": st1["responder_P"].hex(),
                      "garbage_terminator_initiator": term_I.hex(), "garbage_terminator_responder": term_R.hex(),
                      "session_id": st1["session_id"].hex()}}
    if hybrid:
        ek, dk = mlkem.keygen_internal(inp["d"], inp["z"])
        kem_secret, ct = mlkem.encaps_internal(ek, inp["m"])
        assert mlkem.decaps_internal(dk, ct) == kem_secret
        assert vp[False][1] == hx1_encode_record(HX1_KIND_OFFER, ek)
        assert vp[True][1] == hx1_encode_record(HX1_KIND_ACCEPT, ct)
        ikm2, prk2, st2 = hx1_reference_stage2_keys(magic, kem_secret, ecdh, ct, inp["ell_I"], ek, inp["ell_R"])
        keys_after = {True: (st2["xcoin_hx1_initiator_L"], st2["xcoin_hx1_initiator_P"]),
                      False: (st2["xcoin_hx1_responder_L"], st2["xcoin_hx1_responder_P"])}
        # The eight keys of the two stages are pairwise different.
        eight = [st1[k] for k in ("initiator_L", "initiator_P", "responder_L", "responder_P")] + \
                [key for pair in keys_after.values() for key in pair]
        assert len(set(eight)) == 8
        assert initiator.peer["session_id"] == responder.peer["session_id"] == st2["xcoin_hx1_session_id"]
        out["mlkem"] = {"d": inp["d"].hex(), "z": inp["z"].hex(), "m": inp["m"].hex(),
                        "ek": ek.hex(), "ek_sha256": hashlib.sha256(ek).hexdigest(),
                        "dk_sha256": hashlib.sha256(dk).hexdigest(),
                        "ct": ct.hex(), "ct_sha256": hashlib.sha256(ct).hexdigest(),
                        "shared_secret": kem_secret.hex()}
    else:
        assert vp[False][1] == b"" and vp[True][1] == b""
        assert initiator.peer["session_id"] == responder.peer["session_id"] == st1["session_id"]

    for side, label in ((False, "responder"), (True, "initiator")):
        _, contents, wire, index = vp[side]
        handshake = link.wire[side][:split[side]["version_end"]]
        out[f"{label}_version_packet"] = {
            "stage1_index": index, "contents_len": len(contents), "contents_sha256": hashlib.sha256(contents).hexdigest(),
            "wire_len": len(wire), "wire_sha256": hashlib.sha256(wire).hexdigest(), "wire": wire.hex()}
        out[f"{label}_handshake"] = {"len": len(handshake), "sha256": hashlib.sha256(handshake).hexdigest(),
                                     "bytes": handshake.hex()}
    if hybrid:
        out["stage2"] = {"ikm2_len": len(ikm2), "ikm2_sha256": hashlib.sha256(ikm2).hexdigest(), "prk2": prk2.hex()}
        out["stage2"].update({label: st2[label].hex() for label in HX1_LABELS})

    out["packets_after_version"] = {}
    for side, label in ((True, "initiator_to_responder"), (False, "responder_to_initiator")):
        rest = split[side]["after_version"]
        if hybrid:
            packets = hx1_read_all(rest, *keys_after[side])
        else:
            # Classical: the same stage-1 ciphers carry on.
            reader = split[side]["stage1_reader"]
            packets, pos = [], 0
            while pos < len(rest):
                index = reader.index
                ignore, contents, wire = reader.read(rest[pos:])
                packets.append((ignore, contents, wire, index))
                pos += len(wire)
        assert [None if p[0] else p[1] for p in packets] == expected_after[side]
        entries = []
        app_index = 0
        for ignore, contents, wire, index in packets:
            if ignore:
                entries.append({"stage_index": index, "decoy": True, "contents": contents.hex(), "wire": wire.hex()})
            else:
                if app_index in HX1_VECTOR_PINNED_APP_PACKETS:
                    entries.append({"stage_index": index, "app_index": app_index, "contents": contents.hex(), "wire": wire.hex()})
                app_index += 1
        out["packets_after_version"][label] = {"stage": 2 if hybrid else 1, "count": len(packets), "entries": entries,
                                               "all_len": len(rest), "all_sha256": hashlib.sha256(rest).hexdigest()}
    out["reported"] = {"initiator": initiator.transport_info(), "responder": responder.transport_info()}
    return out


def hx1_bad_encapsulation_keys(ek):
    """XIP-4 vector V6: two encapsulation keys that fail the FIPS 203 section 7.2 modulus check."""
    bad1 = mlkem.set_ek_coefficient(ek, 0, mlkem.Q)                 # first coefficient = 3329
    bad2 = mlkem.set_ek_coefficient(ek, 3 * mlkem.N - 1, 4095)      # last coefficient of the third polynomial = 4095
    return bad1, bad2


# Values from XIP-4's handshake vectors V1-V3, which a separate program generated. Per vector: network, stage-1
# session id, SHA-256 of the responder's and the initiator's handshake bytes (key to version packet), PRK2, the
# stage-2 session id, the first stage-2 application packet from the initiator, the responder's confirmation packet,
# the first stage-2 application packet from the responder, and SHA-256 of everything sent after the version packet
# in each direction (226 application packets, and on the responder's side the confirmation packet before them).
HX1_XIP_VECTORS = {
    "V1": ("mainnet", "c4fe8ce34d2053a48e0fb2decc6493d48bef3513d043021e32f185ea76473148",
           "0879077c4151ad588b94d45aa5168f3d8065e8d6089eacf63152d01bb0a9e1a1", "3d69d091f5c1583f8f9164dfffe4768435fc6704e6bda7d3323559c4408d907d",
           "9ad96f028414d8f6123c3457c230c80212ac166967ae431f656591c135b7c1fc", "383be571688a04d73885796b0616b9f30789118387aa798ab720c564015f26d6",
           "65b72bb4de6a096385a275ab61039c2027cf2fd42a90c4162764cd36", "d9118135e094dad3253b93fb8b971a1c06d3d55e",
           "29efb994b90659316ab25a04c5ebdce39c8894e2743ead16fa0688be",
           "be7c3f62da5deca2ef247061118e3166ef7451d1590ba9028b98dee780a68de3", "35b5fd86d75379d723f68ddf1b0a1fb180a18f1eff0baa15e7f78adda5060533"),
    "V2": ("testnet", "aeccc669a8aec4c29bedd85eff6cc6e8ca8c67a7afbe655b850626f77179be03",
           "274520924dd56ee3bef4d6eb4f609551fa64438c064b6531b3f3303b2c3a6fa9", "7a501a2c40ac0a3c3560f47575a2a72bf3ad76b8cf03565d3a803f9ce30c5662",
           "8ea3919a3c840d49392b4ed9b15b07fc54570c97373a37773e028bd9c492f38f", "3c9db0655f576822d9141707787bb6cf6c0f5603f1cf8ab0e24c934fe60c0ab4",
           "0f8e5ddf1837cf1c6a3bc6220283251db563e87e50304b2bf97f4e7b", "ecf61ceffd32e511f1fbcb8626fd04d45be85884",
           "9e1b02e8a6a1d0d5dd1ce4c8a5632455e4caac639e98477ce128612c",
           "30afe90140b10d264f55073c025309be854d41e12d5c139c7a1eb6b1aa81843e", "a9d45ea349ae03a4618437f617342f590e2445d8874ae41640be848cdd7d2197"),
    "V3": ("regtest", "1b1591450962bb106529fa303fda43492379a71b90ef3889b460395d33a1cac4",
           "d3524089444b3c583866078dc27c3013252afac6a8994476e4d3bab68449af18", "8495cf1706675f2ef2487d8943b294d8f4970902e3177e6dca583267befb4802",
           "002dd412a9591af8590a0e2ba2d13f1f6fa0aaa8e201562bf1fde7cacbc441ab", "f701ac8116eef5eafcb1fae255f72c00236328370dd774fd1f3074170e257a09",
           "91cade8079d8920a9ba8e0e04c33e330b5055b9072c0ae9ebc30252e", "e45dc4c9ca7a789beef40d5236f09ebc13057a5d",
           "20c5494895e15a96f85cbb4b8f37c1f3660541a0486e6bf55b6ed63c",
           "cf8c95d01c2d31ebe80e38f0b430891b1c842ddcdad77f4f7d968f21eaeca01d", "8282f079b4846c2ec45b040c8892195ae2a148e705c4df9144dd4fe15b8918ba"),
}


class _NoHX1State(HX1FixedState):
    """A mode-0 state that fails loudly if any HX1 code runs (XIP-4, "Kill switch")."""
    def _no_hx1(self, *args, **kwargs):
        raise AssertionError("HX1 code ran in mode 0")
    hx1_keygen = hx1_encaps = hx1_decaps = hx1_version_contents = hx1_decoys_after_switch = _no_hx1
    _hx1_complete_handshake = _hx1_process_version_packet = _hx1_switch_to_stage2 = _no_hx1


class TestFrameworkV2HX1(unittest.TestCase):
    NET = "regtest"

    def make(self, initiating, mode, cls=HX1FixedState, net=None, **kwargs):
        """A state with the XIP-4 vector key and garbage for its role, so no ElligatorSwift key is generated."""
        inp = HX1_VECTOR_INPUTS
        s = "I" if initiating else "R"
        args = dict(initiating=initiating, net=net or self.NET, hybrid_mode=mode, privkey=inp[f"priv_{s}"],
                    ellswift=inp[f"ell_{s}"], garbage=inp[f"garbage_{s}"],
                    mlkem_d=inp["d"], mlkem_z=inp["z"], mlkem_m=inp["m"])
        args.update(kwargs)
        return cls(**args)

    def link(self, initiator_mode, responder_mode, *, initiator_cls=HX1FixedState, responder_cls=HX1FixedState,
             initiator_kwargs=None, responder_kwargs=None):
        link = V2Loopback(self.make(True, initiator_mode, initiator_cls, **(initiator_kwargs or {})),
                          self.make(False, responder_mode, responder_cls, **(responder_kwargs or {})))
        link.handshake()
        return link

    def exchange(self, link, count=1):
        for i in range(count):
            for side in (True, False):
                if link.ready(side):
                    link.send(side, hx1_app_contents(side, i))
        link.pump()

    def assert_broken(self, link, side, msg=None):
        """Nothing the peer sent after the switch point authenticated: that side failed a length or MAC check, saw
        the peer end the connection first, or is stuck on a length that decrypted to garbage (see
        V2Loopback.stalled())."""
        self.assertEqual(link.received[side], [], msg)
        self.assertFalse(link.states[side].hybrid_confirmed, msg)
        self.assertTrue(link.error[side] is not None or link.error[not side] is not None or link.stalled(side), msg)

    def assert_wiped(self, state):
        self.assertIsNone(state._hx1_ecdh_secret)
        self.assertIsNone(state._hx1_dk)

    def test_vector_inputs(self):
        """The XIP-4 vector inputs, and their ElligatorSwift keys encode the right public keys."""
        inp = HX1_VECTOR_INPUTS
        self.assertEqual(inp["priv_I"].hex(), "9061fed1aee8e0301caa7b1126808503aaad4697366ecea599d029a132291a3b")
        self.assertEqual(inp["aux_R"].hex(), "1698776b4d4313da8366d148d9067749a4baa1aa7f76ba1591907d646256a46c")
        self.assertEqual(inp["garbage_I"].hex(), "4b535bde6efd3a742ea37ed43e")
        self.assertEqual(inp["garbage_R"].hex(), "93258a1a00")
        self.assertEqual(inp["m"].hex(), "b21100cd8bfa86e05d3416452f314a1f99e61303273c8e9afc78f77cf5e2b066")
        ecdh = EncryptedP2PState.v2_ecdh(inp["priv_I"], inp["ell_R"], inp["ell_I"], True)
        self.assertEqual(ecdh, EncryptedP2PState.v2_ecdh(inp["priv_R"], inp["ell_I"], inp["ell_R"], False))
        self.assertEqual(ecdh.hex(), "cbf5296f35d2840f8f0f31d58e01a626b6d69b31c846b8212c3ec1701499637f")

    def test_handshake_vectors(self):
        """The state machine reproduces XIP-4's vectors V1-V5 (and V6's keys), in all three networks."""
        computed = {}
        for name, (net, sid1, hs_r, hs_i, prk2, sid2, pkt_ir, confirm_ri, pkt_ri, all_ir, all_ri) in HX1_XIP_VECTORS.items():
            v = computed[name] = hx1_handshake_vector(name, net)
            self.assertEqual(v["stage1"]["session_id"], sid1)
            self.assertEqual((v["responder_handshake"]["sha256"], v["responder_handshake"]["len"]), (hs_r, 1301))
            self.assertEqual((v["initiator_handshake"]["sha256"], v["initiator_handshake"]["len"]), (hs_i, 1213))
            self.assertEqual(v["mlkem"]["shared_secret"], "ec378be1bd4d2cc452b73ae26af3c066c3941ddf715d2bf2b09e1d5b3a7737dd")
            self.assertEqual((v["stage2"]["prk2"], v["stage2"]["xcoin_hx1_session_id"]), (prk2, sid2))
            after = v["packets_after_version"]
            self.assertEqual(after["initiator_to_responder"]["entries"][0], {"stage_index": 0, "app_index": 0,
                                                                            "contents": hx1_app_contents(True, 0).hex(), "wire": pkt_ir})
            # The responder's confirmation packet is its stage-2 packet 0; its application packets start at index 1.
            self.assertEqual(after["responder_to_initiator"]["entries"][:2], [
                {"stage_index": 0, "decoy": True, "contents": "", "wire": confirm_ri},
                {"stage_index": 1, "app_index": 0, "contents": hx1_app_contents(False, 0).hex(), "wire": pkt_ri}])
            self.assertEqual((after["initiator_to_responder"]["all_sha256"], after["initiator_to_responder"]["all_len"]), (all_ir, 6328))
            self.assertEqual((after["responder_to_initiator"]["all_sha256"], after["responder_to_initiator"]["all_len"]), (all_ri, 20 + 6328))
            reported = {"transport_protocol_type": "v2", "session_id": sid2, "transport_hybrid": True}
            self.assertEqual(v["reported"], {"initiator": reported, "responder": reported})
        # V4: decoys in both stages change only the streams.
        v1 = computed["V1"]
        v4 = hx1_handshake_vector("V4", "mainnet", responder_decoys=[bytes.fromhex("dec001")],
                                  initiator_decoys=[b"", bytes.fromhex("dec0020304")],
                                  initiator_decoys_after_switch=[bytes.fromhex("dec005")])
        self.assertEqual((v4["responder_handshake"]["sha256"], v4["responder_handshake"]["len"]),
                         ("a20be5ee02eb82a5baf68347e3595dc00eff5a0d9a4d99df013464acf41dad09", 1324))
        self.assertEqual((v4["initiator_handshake"]["sha256"], v4["initiator_handshake"]["len"]),
                         ("9be00a64fbf91182cab1ed1d8e96e226fceee8f8690bb1c5f7cdb5b7caadc9f1", 1258))
        self.assertEqual((v4["responder_version_packet"]["stage1_index"], v4["initiator_version_packet"]["stage1_index"]), (1, 2))
        ir = v4["packets_after_version"]["initiator_to_responder"]
        self.assertEqual(ir["entries"][0], {"stage_index": 0, "decoy": True, "contents": "dec005",
                                            "wire": "6eb72b344987323d065e6ecba0b962f679250f86260bab"})
        self.assertEqual((ir["all_sha256"], ir["all_len"]), ("1e3d669f907731cd067e54f054c967f321c6e798c36b18fa766f7160b0a5b6a8", 6351))
        self.assertEqual(v4["stage2"], v1["stage2"])
        self.assertEqual(v4["packets_after_version"]["responder_to_initiator"], v1["packets_after_version"]["responder_to_initiator"])
        # V5: a prefer-mode initiator and a classical responder stay on stage 1, with empty version packets.
        v5 = hx1_handshake_vector("V5", "mainnet", responder_mode=HX1_MODE_OFF)
        self.assertEqual(v5["responder_version_packet"]["wire"], "1a8206a195b1be3d9db404b1ed23b50f351713ad")
        self.assertEqual(v5["initiator_version_packet"]["wire"], "020252babf28b0df7605c4c6c64c21f81877533d")
        ir = v5["packets_after_version"]["initiator_to_responder"]
        self.assertEqual((ir["stage"], ir["entries"][0]["stage_index"], ir["entries"][0]["wire"]),
                         (1, 1, "b6bd74df7af2c65f0568bc3c3006fe46da5dbadcbc8e04a5a1399039"))
        reported = {"transport_protocol_type": "v2", "session_id": v1["stage1"]["session_id"], "transport_hybrid": False}
        self.assertEqual(v5["reported"], {"initiator": reported, "responder": reported})
        # V6: the two bad encapsulation keys.
        ek = bytes.fromhex(v1["mlkem"]["ek"])
        bad1, bad2 = hx1_bad_encapsulation_keys(ek)
        self.assertEqual(hashlib.sha256(bad1).hexdigest(), "f7b117ca93a1a7ecdd7ac4c8633c16dc4e5cdd669d1f0570b252826b26896c4f")
        self.assertEqual(hashlib.sha256(bad2).hexdigest(), "6c98f6febda74c7f19030c2f8c07e5c7415459d00d698610c042e49ee4b20402")

    def test_interop_matrix(self):
        """Every pair of modes, both roles (XIP-4, "Interop matrix"). A mode-0 side runs no HX1 code at all."""
        expected = {
            (0, 0): "classical", (0, 1): "classical", (0, 2): "responder refuses",
            (1, 0): "classical", (1, 1): "hybrid", (1, 2): "hybrid",
            (2, 0): "initiator refuses", (2, 1): "hybrid", (2, 2): "hybrid",
        }
        for (mode_i, mode_r), outcome in expected.items():
            link = self.link(mode_i, mode_r, initiator_cls=_NoHX1State if mode_i == 0 else HX1FixedState,
                             responder_cls=_NoHX1State if mode_r == 0 else HX1FixedState)
            self.exchange(link)
            initiator, responder = link.states[True], link.states[False]
            if outcome in ("classical", "hybrid"):
                self.assertEqual(link.error, {True: None, False: None})
                hybrid = outcome == "hybrid"
                # In a hybrid session the initiator first receives the responder's confirmation packet (a decoy).
                self.assertEqual(link.received, {True: [None] * hybrid + [hx1_app_contents(False, 0)],
                                                 False: [hx1_app_contents(True, 0)]})
                for state in (initiator, responder):
                    self.assertEqual(state.transport_info(), {"transport_protocol_type": "v2", "transport_hybrid": hybrid,
                                                              "session_id": initiator.peer["session_id"].hex()})
                    if state.hybrid_mode != HX1_MODE_OFF:
                        self.assertEqual(state.hx1_outcome, outcome)
                self.assertEqual(initiator.peer["session_id"], responder.peer["session_id"])
            elif outcome == "initiator refuses":
                # Dropped after VP_R: the initiator never sends its version packet.
                self.assertIn("require mode", link.error[True])
                self.assertEqual(initiator.hx1_outcome, "refused")
                self.assertFalse(responder.tried_v2_handshake)
                self.assertEqual(len(link.wire[True]), 64 + len(HX1_VECTOR_INPUTS["garbage_I"]) + 16)
            else:
                # Dropped after VP_I.
                self.assertIn("require mode", link.error[False])
                self.assertEqual(responder.hx1_outcome, "refused")
                self.assertTrue(initiator.tried_v2_handshake)
            for state in (initiator, responder):
                if state.hybrid_mode == HX1_MODE_OFF:
                    # The kill switch: a mode-0 side keeps no ECDH secret past the stage-1 derivation, allocates no
                    # HX1 state and counts nothing.
                    self.assert_wiped(state)
                    self.assertEqual((state.hybrid, state.hx1_outcome, state.hx1_ek, state.hx1_ct), (False, None, None, None))
            if mode_i == 0:
                # A mode-0 peer ignores whatever the version packet holds, including an HX1 offer.
                self.assertIsNone(initiator.hx1_classification)
                self.assertEqual(len(initiator.received_version_contents), 1196 if mode_r else 0)

    def check_quantum_adversary(self, link, ecdh_secret, dk, sent_after_version):
        """XIP-4, "The quantum-adversary test", steps 2 to 5, on the recorded byte streams."""
        magic = MAGIC_BYTES[self.NET]
        st1 = hx1_reference_stage1_keys(ecdh_secret, magic)
        terminators = {True: st1["garbage_terminators"][:16], False: st1["garbage_terminators"][16:]}
        keys1 = {True: (st1["initiator_L"], st1["initiator_P"]), False: (st1["responder_L"], st1["responder_P"])}
        split = {side: hx1_split_stream(link.wire[side], terminators[side], *keys1[side]) for side in (True, False)}
        # Step 2: with the ECDH secret the version packets decrypt; they only carry ek and ct. Step 4: nothing but
        # decoys and the version packet went out under stage-1 keys in either direction.
        for side in (True, False):
            packets = split[side]["stage1_packets"]
            self.assertTrue(all(p[0] for p in packets[:-1]) and not packets[-1][0])
            self.assertGreater(len(packets), 1)  # the test sends stage-1 decoys
        kind, ek = hx1_classify_record(split[False]["stage1_packets"][-1][1], HX1_KIND_OFFER)
        self.assertEqual(kind, HX1_RECORD)
        kind, ct = hx1_classify_record(split[True]["stage1_packets"][-1][1], HX1_KIND_ACCEPT)
        self.assertEqual(kind, HX1_RECORD)
        ell_i, ell_r = split[True]["ell"], split[False]["ell"]
        # Step 5: with dk added, derive the stage-2 keys outside the state machine; every packet after the version
        # packets decrypts and is what was sent.
        kem_secret = mlkem.decaps_internal(dk, ct)
        _, _, st2 = hx1_reference_stage2_keys(magic, kem_secret, ecdh_secret, ct, ell_i, ek, ell_r)
        keys2 = {True: (st2["xcoin_hx1_initiator_L"], st2["xcoin_hx1_initiator_P"]),
                 False: (st2["xcoin_hx1_responder_L"], st2["xcoin_hx1_responder_P"])}
        # Stage-2 derivations an attacker without the KEM secret could try, and broken ones that must not work either.
        wrong = []
        for fake_kem in (bytes(32), ecdh_secret, mlkem.J(ct)):
            wrong.append(hx1_reference_stage2_keys(magic, fake_kem, ecdh_secret, ct, ell_i, ek, ell_r)[2])
        wrong.append(hx1_reference_stage2_keys(magic, kem_secret, bytes(32), ct, ell_i, ek, ell_r)[2])  # ECDH matters too
        for side in (True, False):
            rest = split[side]["after_version"]
            packets = hx1_read_all(rest, *keys2[side])
            self.assertEqual([None if p[0] else p[1] for p in packets], sent_after_version[side])
            self.assertGreater(len(packets), REKEY_INTERVAL + 5)  # past the first rekey
            # Step 3: with only the ECDH secret, not one packet after the version packets authenticates.
            # (a) Carrying on with the stage-1 ciphers after the version packet, reading lengths as a receiver would:
            naive = hx1_split_stream(link.wire[side], terminators[side], *keys1[side])["stage1_reader"]
            self.assertIsNone(naive.read(rest))
            # (b) The same, with the true packet boundaries: stage-1 counters continued ...
            continued = split[side]["stage1_reader"]
            restarted = V2PacketReader(*keys1[side])  # (c) ... and restarted at 0,
            swapped = V2PacketReader(*keys1[not side])  # (d) the other direction's stage-1 keys,
            other_dir = V2PacketReader(*keys2[not side])  # (e) the other direction's stage-2 keys,
            guesses = [V2PacketReader(k[f"xcoin_hx1_{'initiator' if side else 'responder'}_L"],
                                      k[f"xcoin_hx1_{'initiator' if side else 'responder'}_P"]) for k in wrong]
            for _, _, wire, _ in packets:
                for reader in [continued, restarted, swapped, other_dir] + guesses:
                    self.assertFalse(reader.authenticates(wire))

    def test_quantum_adversary(self):
        """A recorded hybrid session cannot be read with the ECDH secret alone, in both role assignments, with
        decoys in both stages and past the 224-packet rekey; with the KEM secret too it can."""
        for mode_i, mode_r in ((HX1_MODE_PREFER, HX1_MODE_REQUIRE), (HX1_MODE_REQUIRE, HX1_MODE_PREFER)):
            rng = random.Random(mode_i)
            seeds = {"d": rng.randbytes(32), "z": rng.randbytes(32), "m": rng.randbytes(32)}

            def decoys():
                return [rng.randbytes(rng.randrange(0, 40)) for _ in range(rng.randrange(1, 4))]
            i_after, r_after = decoys(), decoys()
            link = V2Loopback(
                self.make(True, mode_i, decoys_before_version=decoys(), decoys_after_switch=i_after,
                          mlkem_m=seeds["m"], garbage=rng.randbytes(rng.randrange(1, 100))),
                self.make(False, mode_r, decoys_before_version=decoys(), decoys_after_switch=r_after,
                          mlkem_d=seeds["d"], mlkem_z=seeds["z"], garbage=rng.randbytes(rng.randrange(1, 100))))
            link.handshake()
            self.assertTrue(link.ready(True) and link.ready(False))
            # The responder's stage-2 stream starts with its confirmation packet (a decoy), then its test decoys.
            sent = {True: [None] * len(i_after), False: [None] * (1 + len(r_after))}
            for i in range(230):
                for side in (True, False):
                    if i % 50 == 7:
                        link.send(side, rng.randbytes(10), ignore=True)
                        sent[side].append(None)
                    contents = hx1_app_contents(side, i) + rng.randbytes(rng.randrange(0, 50))
                    link.send(side, contents)
                    sent[side].append(contents)
            link.pump()
            self.assertEqual(link.error, {True: None, False: None})
            self.assertEqual((link.received[False], link.received[True]), (sent[True], sent[False]))
            # The attacker's ECDH secret: what a quantum computer gets from either public key.
            ecdh = EncryptedP2PState.v2_ecdh(HX1_VECTOR_INPUTS["priv_R"], HX1_VECTOR_INPUTS["ell_I"],
                                             HX1_VECTOR_INPUTS["ell_R"], False)
            _, dk = mlkem.keygen_internal(seeds["d"], seeds["z"])
            self.check_quantum_adversary(link, ecdh, dk, sent)

    def test_initiator_waits_for_offer(self):
        """In modes 1 and 2 the initiator sends only its garbage terminator when it gets the responder's key, sends
        nothing else until VP_R, and sends VP_I then; the responder sends nothing between VP_R and VP_I."""
        for mode in (HX1_MODE_PREFER, HX1_MODE_REQUIRE):
            initiator, responder = self.make(True, mode), self.make(False, mode)
            to_r = initiator.initiate_v2_handshake()
            used1, key_r = responder.respond_v2_handshake(BytesIO(to_r))
            used2, rest_r = responder.complete_handshake(BytesIO(to_r[used1:]))
            self.assertEqual(used1 + used2, 64)
            self.assertEqual(len(rest_r), 16 + 1216)  # gt_R and VP_R
            with self.assertRaises(AssertionError):
                responder.v2_enc_packet(b"\x00too early")
            _, to_i = initiator.complete_handshake(BytesIO(key_r[:64]))
            self.assertEqual(to_i, initiator.peer["send_garbage_terminator"])  # no version packet yet
            with self.assertRaises(AssertionError):
                initiator.v2_enc_packet(b"\x00version")
            # VP_R arrives: VP_I goes out, and both directions switch.
            _, ok = initiator.authenticate_handshake(key_r[64:] + rest_r)
            self.assertTrue(ok and initiator.tried_v2_handshake and initiator.hybrid)
            vp_i = initiator.take_pending_handshake_bytes()
            self.assertEqual(len(vp_i), 1120)
            self.assertEqual(initiator.transport_info()["transport_protocol_type"], "detecting")
            # The responder has consumed ell_I; garbage_I, gt_I and VP_I follow.
            _, ok = responder.authenticate_handshake(to_r[64:] + to_i + vp_i)
            self.assertTrue(ok and responder.hybrid)
            self.assertEqual(responder.peer["session_id"], initiator.peer["session_id"])
            # The responder's first stage-2 packet goes out at once: the confirmation packet, an empty decoy
            # (3 + 1 + 16 bytes). It confirms the keys to the initiator before any application message.
            confirmation = responder.take_pending_handshake_bytes()
            self.assertEqual(len(confirmation), 20)
            self.assertEqual(initiator.v2_receive_packet(confirmation), (20, None))
            self.assertTrue(initiator.hybrid_confirmed and not responder.hybrid_confirmed)
            self.assertEqual(initiator.transport_info()["transport_hybrid"], True)
        # Mode 0, for comparison: the version packet goes out with the garbage terminator.
        initiator = self.make(True, HX1_MODE_OFF)
        initiator.initiate_v2_handshake()
        _, to_i = initiator.complete_handshake(BytesIO(HX1_VECTOR_INPUTS["ell_R"]))
        self.assertEqual(len(to_i), 16 + 20)

    def test_received_offers(self):
        """How the initiator treats each kind of VP_R contents, in prefer and require mode."""
        def mutated(f):
            class State(HX1FixedState):
                def hx1_version_contents(self, record):
                    return f(record)
            return State

        def with_byte(i, value):
            return lambda r: r[:i] + bytes([value]) + r[i + 1:]
        cases = [
            # (description, how the responder's record is changed, outcome in prefer mode)
            ("unknown tag", with_byte(0, ord("y")), "classical"),
            ("unknown version", with_byte(8, 0x02), "classical"),
            ("bare tag", lambda r: r[:8], "classical"),
            ("header cut short after the version byte", lambda r: r[:9], "malformed"),
            ("header cut short", lambda r: r[:11], "malformed"),
            ("later version, header cut short", lambda r: r[:8] + b"\x02" + r[9:11], "classical"),
            ("a later version's record first", lambda r: r[:8] + b"\x02" + r[9:] + r, "classical"),
            ("wrong kind", with_byte(9, HX1_KIND_ACCEPT), "malformed"),
            ("wrong length", lambda r: r[:10] + (1183).to_bytes(2, 'little') + r[12:], "malformed"),
            ("truncated body", lambda r: r[:-1], "malformed"),
            ("trailing bytes", lambda r: r + b"\x02" * 7, "hybrid"),
        ]
        for description, change, outcome in cases:
            for mode in (HX1_MODE_PREFER, HX1_MODE_REQUIRE):
                link = self.link(mode, HX1_MODE_PREFER, responder_cls=mutated(change))
                self.exchange(link)
                initiator = link.states[True]
                if outcome == "hybrid" or (outcome == "classical" and mode == HX1_MODE_PREFER):
                    self.assertEqual(link.error, {True: None, False: None}, description)
                    self.assertEqual(initiator.hybrid, outcome == "hybrid", description)
                    self.assertTrue(initiator.hybrid_confirmed or outcome == "classical", description)
                else:
                    # Dropped after VP_R, before the initiator sends VP_I.
                    self.assertIsNotNone(link.error[True], description)
                    self.assertFalse(initiator.tried_v2_handshake or link.states[False].tried_v2_handshake, description)
                    self.assertEqual(len(link.wire[True]), 64 + 13 + 16, description)
                    self.assertEqual(initiator.hx1_classical_retry_eligible, outcome == "malformed" and mode == HX1_MODE_PREFER, description)
                    self.assertEqual(initiator.hx1_outcome, "bad_record" if outcome == "malformed" else "refused", description)
                    self.assert_wiped(initiator)
        # The keys of vector V6 fail the FIPS 203 section 7.2 check: disconnect without sending VP_I.
        ek, dk = mlkem.keygen_internal(HX1_VECTOR_INPUTS["d"], HX1_VECTOR_INPUTS["z"])
        for bad_ek in hx1_bad_encapsulation_keys(ek) + (mlkem.set_ek_coefficient(ek, 767, mlkem.Q),):
            class BadKey(HX1FixedState):
                def hx1_keygen(self):
                    return bad_ek, dk
            for mode in (HX1_MODE_PREFER, HX1_MODE_REQUIRE):
                link = self.link(mode, HX1_MODE_PREFER, responder_cls=BadKey)
                self.assertIn("section 7.2", link.error[True])
                self.assertEqual(len(link.wire[True]), 64 + 13 + 16)
                self.assertEqual(link.states[True].hx1_classical_retry_eligible, mode == HX1_MODE_PREFER)
                self.assertEqual(link.states[True].hx1_outcome, "bad_record")
                self.assertEqual(link.states[True].hx1_retry_cause, "bad_record" if mode == HX1_MODE_PREFER else None)
        # A key with every coefficient at q - 1 is valid.
        self.assertTrue(mlkem.check_encaps_key(mlkem.set_ek_coefficient(ek, 0, mlkem.Q - 1)))

    def test_received_accepts(self):
        """How the responder treats each kind of VP_I contents."""
        def mutated(f):
            class State(HX1FixedState):
                def hx1_version_contents(self, record):
                    return f(record)
            return State
        for description, change, outcome in [
            ("truncated body", lambda r: r[:-1], "malformed"),
            ("wrong kind", lambda r: r[:9] + bytes([HX1_KIND_OFFER]) + r[10:], "malformed"),
            ("wrong length", lambda r: r[:10] + (1184).to_bytes(2, 'little') + r[12:], "malformed"),
            ("trailing bytes", lambda r: r + b"\x00", "hybrid"),
            # A broken initiator that switched to stage 2 but sent no record: a prefer-mode responder stays
            # classical and then fails on the first stage-2 packet.
            ("unknown tag", lambda r: b"X" + r[1:], "classical, then fails"),
        ]:
            for mode in (HX1_MODE_PREFER, HX1_MODE_REQUIRE):
                link = self.link(HX1_MODE_PREFER, mode, initiator_cls=mutated(change))
                self.exchange(link)
                responder = link.states[False]
                if outcome == "hybrid":
                    self.assertEqual(link.error, {True: None, False: None}, description)
                    self.assertTrue(responder.hybrid_confirmed and link.states[True].hybrid_confirmed, description)
                elif outcome == "malformed" or mode == HX1_MODE_REQUIRE:
                    self.assertFalse(responder.tried_v2_handshake, description)
                    self.assertIsNotNone(link.error[False], description)
                else:
                    self.assertTrue(responder.tried_v2_handshake and not responder.hybrid, description)
                    self.assert_broken(link, False, description)
                self.assert_wiped(responder)
        # A random ciphertext decapsulates to an unrelated secret (implicit rejection): each side fails at the
        # first stage-2 packet from the other, at once (the first-packet limit), and shows "detecting" until then.
        # The initiator fails on the responder's confirmation packet, before sending anything under stage 2 but
        # the VP_I it already sent.
        class RandomCiphertext(HX1FixedState):
            def hx1_encaps(self, ek):
                kem_secret, _ = super().hx1_encaps(ek)
                return kem_secret, random.Random(1).randbytes(mlkem.CT_SIZE)
        link = self.link(HX1_MODE_PREFER, HX1_MODE_PREFER, initiator_cls=RandomCiphertext)
        self.assertIn("over the 4095-byte limit", link.error[True])
        self.assertTrue(link.ready(False))
        self.assertEqual(link.states[True].hx1_outcome, "stage2_failed")
        self.assertEqual(link.states[True].hx1_retry_cause, "stage2_failed")
        for side in (True, False):
            self.assert_broken(link, side)
            self.assertEqual(link.states[side].transport_info()["transport_protocol_type"], "detecting")
        # The responder, fed a stage-2 packet from the initiator, fails at once too.
        link = self.link(HX1_MODE_PREFER, HX1_MODE_PREFER, initiator_cls=RandomCiphertext)
        responder = link.states[False]
        self.assertEqual(responder.v2_receive_packet(link.states[True]._encrypt_packet(b"\x00version")), (-1, None))
        self.assertEqual(responder.hx1_outcome, "stage2_failed")
        self.assertIn("over the 4095-byte limit", responder.failure_reason)

    def test_responder_speaks_too_early(self):
        """A responder that sends anything, even a decoy, between VP_R and VP_I breaks the connection."""
        for ignore in (False, True):
            class Early(HX1FixedState):
                def _hx1_complete_handshake(self, ellswift_theirs, ecdh_secret):
                    out = super()._hx1_complete_handshake(ellswift_theirs, ecdh_secret)
                    return out + self._encrypt_packet(b"\x00early", ignore=ignore)
            link = self.link(HX1_MODE_PREFER, HX1_MODE_PREFER, responder_cls=Early)
            self.exchange(link, 3)
            self.assert_broken(link, True)
            self.assertTrue(link.states[True].hx1_classical_retry_eligible)

    def test_v1_prefix(self):
        """Inbound v1 falls back to v1 in modes 0 and 1 and is refused in mode 2, after exactly 16 bytes."""
        v1_prefix = MAGIC_BYTES[self.NET] + b"version\x00\x00\x00\x00\x00"
        for mode in (HX1_MODE_OFF, HX1_MODE_PREFER, HX1_MODE_REQUIRE):
            responder = self.make(False, mode)
            self.assertEqual(responder.respond_v2_handshake(BytesIO(v1_prefix[:15])), (15, b""))
            if mode == HX1_MODE_REQUIRE:
                with self.assertRaises(V2HandshakeError):
                    responder.respond_v2_handshake(BytesIO(v1_prefix[15:] + b"rest of the message"))
            else:
                self.assertEqual(responder.respond_v2_handshake(BytesIO(v1_prefix[15:] + b"rest of the message")), (16, -1))

    def test_local_failures(self):
        """A failure of our own ML-KEM call disconnects: no classical session, and the node that failed never
        retries."""
        def failing(method):
            class State(HX1FixedState):
                pass
            setattr(State, method, lambda self, *args: (_ for _ in ()).throw(RuntimeError("injected")))
            return State
        # Responder key generation: VP_R never goes out.
        link = self.link(HX1_MODE_PREFER, HX1_MODE_PREFER, responder_cls=failing("hx1_keygen"))
        self.assertIn("key generation", link.error[False])
        self.assertEqual(len(link.wire[False]), 64 + 5)
        self.assertFalse(link.states[True].tried_v2_handshake or link.states[True].hx1_classical_retry_eligible)
        # Initiator encapsulation: VP_I never goes out.
        link = self.link(HX1_MODE_PREFER, HX1_MODE_PREFER, initiator_cls=failing("hx1_encaps"))
        self.assertIn("encapsulation", link.error[True])
        self.assertEqual(len(link.wire[True]), 64 + 13 + 16)
        self.assertFalse(link.states[True].tried_v2_handshake or link.states[True].hx1_classical_retry_eligible)
        # Responder decapsulation.
        link = self.link(HX1_MODE_PREFER, HX1_MODE_PREFER, responder_cls=failing("hx1_decaps"))
        self.assertIn("decapsulation", link.error[False])
        self.assertFalse(link.states[False].tried_v2_handshake)
        for side in (True, False):
            self.assertTrue(link.states[side].hx1_local_error or link.error[side] is None)
            self.assert_wiped(link.states[side])
        self.assertEqual(link.states[False].hx1_outcome, "local_error")
        # The initiator sent VP_I and switched, then lost the connection before key confirmation; the responder's
        # own failure is not visible to it, so it retries, and logs that the peer closed first.
        self.assertEqual(link.states[True].hx1_retry_cause, "closed before key confirmation")

    def test_secret_lifetime(self):
        """The ECDH secret and dk are kept only until stage 2 or the classical decision."""
        initiator, responder = self.make(True, HX1_MODE_PREFER), self.make(False, HX1_MODE_PREFER)
        link = V2Loopback(initiator, responder)
        link.send_raw(True, initiator.initiate_v2_handshake())
        link.recvbuf[False], link.inbox[False] = link.inbox[False], b""
        link._process(False)  # the responder answers with its key, gt_R and VP_R
        self.assertIsNotNone(responder._hx1_ecdh_secret)
        self.assertIsNotNone(responder._hx1_dk)
        link.recvbuf[True], link.inbox[True] = link.inbox[True], b""
        link._process(True)  # the initiator reads VP_R and sends VP_I
        self.assert_wiped(initiator)
        self.assertIsNotNone(responder._hx1_dk)
        link.pump()
        self.assert_wiped(responder)
        # The classical decision wipes them too.
        for mode_i, mode_r in ((HX1_MODE_PREFER, HX1_MODE_OFF), (HX1_MODE_OFF, HX1_MODE_PREFER)):
            link = self.link(mode_i, mode_r)
            for side in (True, False):
                self.assertFalse(link.states[side].hybrid)
                self.assert_wiped(link.states[side])
        # Mode 0 never keeps them at all: a mode-0 transport wipes the ECDH secret inside the stage-1 derivation, as
        # before HX1, so it is gone the moment the peer's key has been read.
        for initiating in (True, False):
            state = self.make(initiating, HX1_MODE_OFF, cls=_NoHX1State)
            peer = self.make(not initiating, HX1_MODE_OFF)
            if initiating:
                state.initiate_v2_handshake()
                state.complete_handshake(BytesIO(peer.initiate_v2_handshake()[:64]))
            else:
                peer.initiate_v2_handshake()
                state.respond_v2_handshake(BytesIO(HX1_VECTOR_INPUTS["ell_I"][:1]))
                state.complete_handshake(BytesIO(HX1_VECTOR_INPUTS["ell_I"][1:]))
            self.assertTrue(state.peer)
            self.assert_wiped(state)

    def test_key_confirmation(self):
        """A hybrid link reports "detecting" until a stage-2 packet from the peer has authenticated, and never
        reports the stage-1 session id."""
        initiator, responder = self.make(True, HX1_MODE_PREFER), self.make(False, HX1_MODE_PREFER)
        link = V2Loopback(initiator, responder)

        def deliver(side):
            link.recvbuf[side], link.inbox[side] = link.recvbuf[side] + link.inbox[side], b""
            link._process(side)
        detecting = {"transport_protocol_type": "detecting", "session_id": "", "transport_hybrid": False}
        link.send_raw(True, initiator.initiate_v2_handshake())
        deliver(False)  # the responder sends its key, gt_R and VP_R
        deliver(True)  # the initiator sends gt_I and VP_I, and switches
        self.assertTrue(initiator.hybrid and not initiator.hybrid_confirmed)
        self.assertEqual((initiator.transport_info(), responder.transport_info()), (detecting, detecting))
        deliver(False)  # the responder switches and sends its confirmation packet
        self.assertTrue(responder.hybrid and not responder.hybrid_confirmed)
        self.assertEqual((initiator.transport_info(), responder.transport_info()), (detecting, detecting))
        deliver(True)  # the confirmation packet authenticates: the initiator has key confirmation
        confirmed = {"transport_protocol_type": "v2", "session_id": responder.peer["session_id"].hex(), "transport_hybrid": True}
        self.assertEqual((initiator.transport_info(), responder.transport_info()), (confirmed, detecting))
        self.assertEqual(link.received[True], [None])
        link.send(True, b"\x00version")
        link.pump()
        self.assertEqual((initiator.transport_info(), responder.transport_info()), (confirmed, confirmed))
        self.assertEqual((initiator.hx1_outcome, responder.hx1_outcome), ("hybrid", "hybrid"))
        self.assertNotEqual(initiator.peer["session_id"], initiator.peer["stage1_session_id"])
        self.assertEqual(initiator.peer["stage1_session_id"], responder.peer["stage1_session_id"])
        # The same plaintext encrypts differently in the two directions.
        a, b = self.make(True, HX1_MODE_PREFER), self.make(False, HX1_MODE_PREFER)
        link = V2Loopback(a, b)
        link.handshake()
        self.assertNotEqual(a.v2_enc_packet(b"\x00same"), b.v2_enc_packet(b"\x00same"))

    def test_classical_retry(self):
        """Two HX1 nodes whose stage-2 keys disagree lose the connection before key confirmation; in prefer mode the
        initiator may retry once in mode 0, which ends classical. Require mode never retries."""
        class Mismatched(HX1FixedState):
            def hx1_decaps(self, dk, ct):
                kem_secret = super().hx1_decaps(dk, ct)
                return bytes([kem_secret[0] ^ 1]) + kem_secret[1:]
        for mode in (HX1_MODE_PREFER, HX1_MODE_REQUIRE):
            link = self.link(mode, HX1_MODE_PREFER, responder_cls=Mismatched)
            self.exchange(link, 3)
            self.assert_broken(link, True)
            self.assert_broken(link, False)
            # The initiator fails at once, on the responder's confirmation packet, and never sends VERSION.
            self.assertIn("over the 4095-byte limit", link.error[True])
            self.assertEqual(link.states[True].hx1_outcome, "stage2_failed")
            self.assertEqual(link.received[False], [])
            self.assertEqual(link.states[True].hx1_classical_retry_eligible, mode == HX1_MODE_PREFER)
            self.assertEqual(link.states[True].hx1_retry_cause, "stage2_failed" if mode == HX1_MODE_PREFER else None)
        retry = self.link(HX1_MODE_OFF, HX1_MODE_PREFER, responder_cls=Mismatched)
        self.exchange(retry)
        self.assertEqual(retry.error, {True: None, False: None})
        self.assertEqual(retry.states[True].transport_info()["transport_hybrid"], False)
        self.assertFalse(retry.states[True].hx1_classical_retry_eligible)  # a retried connection is not retried again

    def test_first_stage2_packet_limit(self):
        """Before key confirmation a stage-2 length over HX1_FIRST_STAGE2_MAX_CONTENTS ends the connection at once
        (XIP-4, "First stage-2 packet"), so a key mismatch fails within one round trip instead of waiting for the
        handshake timeout; within the limit, and after confirmation, sizes are as before."""
        limit = HX1_FIRST_STAGE2_MAX_CONTENTS
        # An initiator whose first stage-2 packet is a decoy of exactly the limit: accepted.
        link = self.link(HX1_MODE_PREFER, HX1_MODE_PREFER, initiator_kwargs={"decoys_after_switch": [bytes(limit)]})
        self.exchange(link)
        self.assertEqual(link.error, {True: None, False: None})
        self.assertTrue(link.states[False].hybrid_confirmed)
        # After confirmation, packets of any size are fine.
        link.send(True, b"\x01" * (limit + 1000))
        link.send(False, b"\x02" * (limit + 1000))
        link.pump()
        self.assertEqual(link.error, {True: None, False: None})
        # One byte over the limit as the first stage-2 packet: the receiver fails as soon as it has the length.
        link = self.link(HX1_MODE_PREFER, HX1_MODE_PREFER)
        initiator, responder = link.states[True], link.states[False]
        packet = initiator._encrypt_packet(bytes(limit + 1), ignore=True)
        self.assertEqual(responder.v2_receive_packet(packet[:LENGTH_FIELD_LEN]), (-1, None))
        self.assertEqual(responder.hx1_outcome, "stage2_failed")
        self.assertIn(f"claims {limit + 1} bytes", responder.failure_reason)
        # A sender never produces one.
        link = self.link(HX1_MODE_PREFER, HX1_MODE_PREFER)
        with self.assertRaises(AssertionError):
            link.states[True].v2_enc_packet(bytes(limit + 1))
        link.states[True].v2_enc_packet(bytes(limit))
        link.states[True].v2_enc_packet(bytes(limit + 1))  # only the first stage-2 packet is limited
        # Random key mismatches (implicit rejection stands behind any of them): the initiator reads the
        # responder's confirmation packet, the responder the initiator's VERSION. A side fails at once unless its
        # bogus length happens to be within the limit (about 1 in 4096); both sides slipping through, the only way
        # left to reach the handshake timeout, is about 1 in 16.7 million.
        rng = random.Random(4095)
        failed_at_once = 0
        runs = 24
        for _ in range(runs):
            class WrongSecret(HX1FixedState):
                def hx1_decaps(self, dk, ct):
                    return rng.randbytes(32)
            link = self.link(HX1_MODE_PREFER, HX1_MODE_PREFER, responder_cls=WrongSecret)
            initiator, responder = link.states[True], link.states[False]
            version = initiator._encrypt_packet(b"\x00version\x00\x00\x00\x00\x00" + rng.randbytes(117))
            responder_result = responder.v2_receive_packet(version)
            self.assertFalse(initiator.hybrid_confirmed or responder.hybrid_confirmed)
            sides_failed = (link.error[True] is not None) + (responder_result[0] == -1)
            self.assertGreaterEqual(sides_failed, 1)
            failed_at_once += sides_failed
            for state in (initiator, responder):
                self.assertIn(state.hx1_outcome, ("stage2_failed", None))
        self.assertEqual(failed_at_once, 2 * runs)

    def test_responder_closes_after_confirmation(self):
        """The responder's confirmation packet confirms the keys to the initiator before the responder's node reads
        anything, so a close by that node afterwards is not an HX1 failure and is not retried: a self-connection
        (the node reads its own VERSION nonce and disconnects before sending VERSION), an eviction, a restart. A
        close in the one round trip before the responder's switch still looks like one."""
        link = self.link(HX1_MODE_PREFER, HX1_MODE_PREFER)
        link.send(True, b"\x00version\x00\x00\x00\x00\x00" + bytes(100))
        link.pump()
        self.assertEqual(link.received[False], [b"\x00version\x00\x00\x00\x00\x00" + bytes(100)])
        link.error[False] = "connected to self, disconnecting"  # what net_processing does before its own VERSION
        initiator = link.states[True]
        self.assertTrue(initiator.hybrid_confirmed)
        self.assertFalse(initiator.hx1_classical_retry_eligible)
        self.assertIsNone(initiator.hx1_retry_cause)
        # The same close before the responder has read VP_I: the initiator cannot tell it from a failure.
        initiator, responder = self.make(True, HX1_MODE_PREFER), self.make(False, HX1_MODE_PREFER)
        link = V2Loopback(initiator, responder)
        link.send_raw(True, initiator.initiate_v2_handshake())
        link.recvbuf[False], link.inbox[False] = link.inbox[False], b""
        link._process(False)
        link.recvbuf[True], link.inbox[True] = link.inbox[True], b""
        link._process(True)  # VP_I is sent; then the responder goes away without reading it
        self.assertTrue(initiator.hybrid and not initiator.hybrid_confirmed)
        self.assertEqual(initiator.hx1_retry_cause, "closed before key confirmation")

    def test_split_delivery(self):
        """The handshake works however the bytes are split into reads."""
        for seed in range(6):
            rng = random.Random(seed)
            link = V2Loopback(self.make(True, HX1_MODE_PREFER, decoys_before_version=[b"\x01"] * (seed % 3),
                                        decoys_after_switch=[b""] * (seed % 2)),
                              self.make(False, HX1_MODE_PREFER, decoys_before_version=[b"\x02" * 30] * (seed % 2)))
            link.send_raw(True, link.states[True].initiate_v2_handshake())
            for i in range(3):
                for side in (True, False):
                    if link.ready(side):
                        link.send(side, hx1_app_contents(side, i))
                while any(link.inbox.values()):
                    for side in (True, False):
                        if link.inbox[side]:
                            n = rng.randrange(1, len(link.inbox[side]) + 1)
                            link.recvbuf[side] += link.inbox[side][:n]
                            link.inbox[side] = link.inbox[side][n:]
                            link._process(side)
            link.pump()
            self.assertEqual(link.error, {True: None, False: None})
            self.assertTrue(link.states[True].hybrid_confirmed and link.states[False].hybrid_confirmed)
