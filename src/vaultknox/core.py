from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


NONCE_SIZE = 12
KEY_SIZE = 32
DEFAULT_KDF_PARAMS = {
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4,
    "hash_len": KEY_SIZE,
    "type": "argon2id",
}


@dataclass(slots=True)
class EncryptedPayload:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def generate_salt(length: int = 16) -> bytes:
    return secrets.token_bytes(length)


def generate_token(prefix: str = "vlt", entropy_bytes: int = 18) -> str:
    return f"{prefix}_{secrets.token_urlsafe(entropy_bytes)}"


def derive_master_key(password: str, salt: bytes, params: dict[str, Any] | None = None) -> bytes:
    effective_params = dict(DEFAULT_KDF_PARAMS)
    if params:
        effective_params.update(params)
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=effective_params["time_cost"],
        memory_cost=effective_params["memory_cost"],
        parallelism=effective_params["parallelism"],
        hash_len=effective_params["hash_len"],
        type=Type.ID,
    )


def derive_scoped_key(master_key: bytes, context: bytes = b"vaultknox-entry") -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None, info=context)
    return hkdf.derive(master_key)


def encrypt_payload(key: bytes, payload: dict[str, Any]) -> EncryptedPayload:
    plaintext = bytearray(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, bytes(plaintext), None)
    zeroize(plaintext)
    return EncryptedPayload(nonce=nonce, ciphertext=encrypted[:-16], tag=encrypted[-16:])


def decrypt_payload(key: bytes, payload: EncryptedPayload) -> dict[str, Any]:
    aesgcm = AESGCM(key)
    plaintext = bytearray(aesgcm.decrypt(payload.nonce, payload.ciphertext + payload.tag, None))
    try:
        return json.loads(plaintext.decode("utf-8"))
    finally:
        zeroize(plaintext)


def zeroize(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0