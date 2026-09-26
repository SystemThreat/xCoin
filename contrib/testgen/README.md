### TestGen ###

Utilities to generate test vectors for the data-driven Bitcoin tests.

To use inside a scripted-diff (or just execute directly):

    ./gen_key_io_test_vectors.py valid 70 > ../../src/test/data/key_io_valid.json
    ./gen_key_io_test_vectors.py invalid 70 > ../../src/test/data/key_io_invalid.json

The XIP-4 (HX1) handshake vectors are generated from the test framework's v2 transport:

    ./gen_hx1_handshake_vectors.py > ../../src/test/data/hx1_handshake_vectors.json

The ML-KEM-768 vectors for the vendored mlkem-native are generated from NIST's ACVP-Server
json-files and the C2SP CCTV ML-KEM directory (each input file's SHA-256 is pinned in the
script), and every vector is recomputed with the test framework's ML-KEM-768:

    ./gen_mlkem768_vectors.py <acvp-dir> <cctv-dir> > ../../src/test/data/ml_kem_768_fips203.json
