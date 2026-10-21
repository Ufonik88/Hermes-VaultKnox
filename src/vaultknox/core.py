from __future__ import annotations

import ctypes
import json
import secrets
from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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


def validate_kdf_params(params: dict[str, Any]) -> None:
    """Validate KDF parameters are within acceptable bounds."""
    required_keys = {"time_cost", "memory_cost", "parallelism", "hash_len", "type"}
    if not required_keys.issubset(params.keys()):
        missing = required_keys - params.keys()
        raise ValueError(f"Missing required KDF parameters: {missing}")
    
    if not isinstance(params["time_cost"], int) or params["time_cost"] < 1:
        raise ValueError("time_cost must be a positive integer")
    if not isinstance(params["memory_cost"], int) or params["memory_cost"] < 8:
        raise ValueError("memory_cost must be at least 8 KB")
    if not isinstance(params["parallelism"], int) or params["parallelism"] < 1:
        raise ValueError("parallelism must be a positive integer")
    if not isinstance(params["hash_len"], int) or params["hash_len"] < 16:
        raise ValueError("hash_len must be at least 16 bytes")
    if params["type"] not in ("argon2id", "argon2i", "argon2d"):
        raise ValueError("type must be one of: argon2id, argon2i, argon2d")


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
    """Overwrite the underlying C memory buffer to reduce residual plaintext exposure.

    Note: Python str objects created by json.loads() hold their own heap copies and
    cannot be zeroed from Python. This clears the bytearray buffer's C allocation only.
    """
    if buffer:
        ctypes.memset((ctypes.c_char * len(buffer)).from_buffer(buffer), 0, len(buffer))


def derive_search_key(master_key: bytes) -> bytes:
    """Derive a search-specific key from the master key using HKDF."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None, info=b"vaultknox-search")
    return hkdf.derive(master_key)


def encrypt_search_token(search_key: bytes, plaintext: str) -> str:
    """Encrypt a search token using AES-SIV (deterministic authenticated encryption).
    
    Returns a hex-encoded string suitable for storage and exact-match queries.
    """
    import hashlib

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    # Use SIV-like construction: derive nonce from plaintext hash for determinism
    nonce = hashlib.sha256(plaintext.encode()).digest()[:12]
    aesgcm = AESGCM(search_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return (nonce + ciphertext).hex()


def decrypt_search_token(search_key: bytes, token_hex: str) -> str:
    """Decrypt a search token encrypted with encrypt_search_token."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    data = bytes.fromhex(token_hex)
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(search_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


def derive_metadata_key(master_key: bytes) -> bytes:
    """Derive a metadata encryption key from the master key using HKDF."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None, info=b"vaultknox-metadata")
    return hkdf.derive(master_key)


def encrypt_metadata(meta_key: bytes, metadata: dict[str, Any]) -> str:
    """Encrypt metadata dict using AES-256-GCM.
    
    Returns hex-encoded string: nonce(12) + ciphertext + tag(16)
    """
    import json
    plaintext = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(meta_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return (nonce + ciphertext).hex()


def decrypt_metadata(meta_key: bytes, encrypted_hex: str) -> dict[str, Any]:
    """Decrypt metadata encrypted with encrypt_metadata."""
    import json
    data = bytes.fromhex(encrypted_hex)
    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]
    aesgcm = AESGCM(meta_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))