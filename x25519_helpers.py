from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RAW = dict(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    priv = X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(**RAW)
    return priv, pub_bytes


def derive_session_key(priv: X25519PrivateKey, peer_pub_bytes: bytes) -> bytes:
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared = priv.exchange(peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-chat v1",
    ).derive(shared)


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    signing_key = Ed25519PrivateKey.generate()
    return signing_key, signing_key.public_key()


def sign_public_key(signing_key: Ed25519PrivateKey, x25519_pub_bytes: bytes) -> bytes:
    return signing_key.sign(x25519_pub_bytes)  # 64 bytes


def verify_public_key_signature(
    verify_key: Ed25519PublicKey, x25519_pub_bytes: bytes, signature: bytes
) -> bool:
    try:
        verify_key.verify(signature, x25519_pub_bytes)
        return True
    except InvalidSignature:
        return False