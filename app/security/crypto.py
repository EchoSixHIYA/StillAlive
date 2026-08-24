"""Small authenticated encryption helper for sensitive metadata."""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_secret(plaintext: str, master_key: bytes, *, context: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(master_key).encrypt(nonce, plaintext.encode("utf-8"), context)
    return nonce, ciphertext


def decrypt_secret(ciphertext: bytes, nonce: bytes, master_key: bytes, *, context: bytes) -> str:
    plaintext = AESGCM(master_key).decrypt(nonce, ciphertext, context)
    return plaintext.decode("utf-8")

