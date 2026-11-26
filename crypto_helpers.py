import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEFAULT_PASSPHRASE = "blue-penguin-42"
PBKDF2_ITERATIONS = 600_000


def derive_key(
    passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS
) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_message(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + sealed


def decrypt_message(key: bytes, wire_payload: bytes) -> bytes:
    if len(wire_payload) < 12 + 16:
        raise InvalidTag("Frame too short to contain nonce and tag")
    nonce, body = wire_payload[:12], wire_payload[12:]
    return AESGCM(key).decrypt(nonce, body, None)