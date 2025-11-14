import pytest
from authlib.jose import JsonWebEncryption

def make_token(size):
    key = b'0' * 32
    plaintext = b'A' * size
    jwe = JsonWebEncryption()
    header = {'alg': 'dir', 'enc': 'A256GCM', 'zip': 'DEF'}
    token = jwe.serialize_compact(header, plaintext, key)
    return token, key

def test_decompression_unbounded():
    token, key = make_token(500000)  # 500 KB payload (over limit)
    jwe = JsonWebEncryption()
    try:
        out = jwe.deserialize_compact(token, key)
        assert len(out['payload']) == 500000
    except ValueError:
        pytest.skip("Decompression limit enforced, skipping for patched versions.")

def test_decompression_bounded_pass():
    token, key = make_token(200000)  # Under 256 KB limit
    jwe = JsonWebEncryption()
    out = jwe.deserialize_compact(token, key)
    assert len(out['payload']) == 200000

def test_decompression_limit_exceeded():
    token, key = make_token(300000)  # Slightly over limit
    jwe = JsonWebEncryption()
    with pytest.raises(ValueError, match="Decompressed string exceeds"):
        jwe.deserialize_compact(token, key)
