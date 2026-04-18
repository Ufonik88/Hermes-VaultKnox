from vaultknox.core import decrypt_payload, derive_master_key, derive_scoped_key, encrypt_payload, generate_salt


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