"""Encryption contexts for administrator-authored metadata."""

from __future__ import annotations

from app.security.crypto import decrypt_secret, encrypt_secret


PERSON_NAME_CONTEXT = b"still-alive/person/display-name/v1"
QUESTION_TEXT_CONTEXT = b"still-alive/question/text/v1"
TRAIT_NOTE_CONTEXT = b"still-alive/trait/source-note/v1"


def encrypt_person_name(value: str, master_key: bytes) -> tuple[bytes, bytes]:
    return encrypt_secret(value, master_key, context=PERSON_NAME_CONTEXT)


def decrypt_person_name(ciphertext: bytes, nonce: bytes, master_key: bytes) -> str:
    return decrypt_secret(ciphertext, nonce, master_key, context=PERSON_NAME_CONTEXT)


def encrypt_question_text(value: str, master_key: bytes) -> tuple[bytes, bytes]:
    return encrypt_secret(value, master_key, context=QUESTION_TEXT_CONTEXT)


def decrypt_question_text(ciphertext: bytes, nonce: bytes, master_key: bytes) -> str:
    return decrypt_secret(ciphertext, nonce, master_key, context=QUESTION_TEXT_CONTEXT)


def encrypt_trait_note(value: str, master_key: bytes) -> tuple[bytes, bytes]:
    return encrypt_secret(value, master_key, context=TRAIT_NOTE_CONTEXT)


def decrypt_trait_note(ciphertext: bytes, nonce: bytes, master_key: bytes) -> str:
    return decrypt_secret(ciphertext, nonce, master_key, context=TRAIT_NOTE_CONTEXT)

