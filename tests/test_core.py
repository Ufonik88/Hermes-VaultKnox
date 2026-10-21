import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import given
from hypothesis import strategies as st

from vaultknox.core import EncryptedPayload, decrypt_payload, derive_master_key, derive_scoped_key, encrypt_payload, generate_salt, zeroize


def test_encrypt_round_trip() -> None:
    salt = generate_salt()
    key = derive_scoped_key(derive_master_key("correct horse battery staple", salt))
    payload = {"number": "4111111111111111", "expiry": "12/28"}

    encrypted = encrypt_payload(key, payload)

    assert decrypt_payload(key, encrypted) == payload
    assert len(encrypted.nonce) == 12
    assert len(encrypted.tag) == 16


def test_key_derivation_uses_salt() -> None:
    first = derive_master_key("password", b"0" * 16)
    second = derive_master_key("password", b"1" * 16)

    assert first != second


def test_zeroize_clears_buffer() -> None:
    buf = bytearray(b"sensitive data in memory")
    zeroize(buf)
    assert all(b == 0 for b in buf)


def test_zeroize_empty_buffer_is_safe() -> None:
    buf = bytearray()
    zeroize(buf)  # must not raise


@given(key=st.binary(min_size=32, max_size=32), content=st.text(min_size=1, max_size=200))
def test_encrypt_decrypt_round_trip_arbitrary_content(key: bytes, content: str) -> None:
    payload = {"content": content}
    encrypted = encrypt_payload(key, payload)
    assert decrypt_payload(key, encrypted) == payload


@given(key=st.binary(min_size=32, max_size=32))
def test_tampered_ciphertext_raises(key: bytes) -> None:
    payload = {"test": "integrity check"}
    encrypted = encrypt_payload(key, payload)
    if not encrypted.ciphertext:
        return
    tampered = EncryptedPayload(
        nonce=encrypted.nonce,
        ciphertext=bytes([encrypted.ciphertext[0] ^ 0xFF]) + encrypted.ciphertext[1:],
        tag=encrypted.tag,
    )
    with pytest.raises(InvalidTag):
        decrypt_payload(key, tampered)


@given(key=st.binary(min_size=32, max_size=32))
def test_tampered_tag_raises(key: bytes) -> None:
    payload = {"test": "tag check"}
    encrypted = encrypt_payload(key, payload)
    tampered = EncryptedPayload(
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext,
        tag=bytes([encrypted.tag[0] ^ 0x01]) + encrypted.tag[1:],
    )
    with pytest.raises(InvalidTag):
        decrypt_payload(key, tampered)