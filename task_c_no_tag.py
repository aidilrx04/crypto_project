import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto_helpers import DEFAULT_PASSPHRASE, derive_key

SALT = b"fixed-salt-for-c"


def main() -> None:
    key = derive_key(DEFAULT_PASSPHRASE, SALT)
    msg = b"Pay RM100 to Ali"
    idx = msg.index(b"1")  # index 6

    # 1. AES-CTR (no tag)
    ctr_nonce = os.urandom(16)
    enc_ctr = Cipher(algorithms.AES(key), modes.CTR(ctr_nonce)).encryptor()
    ctr_ct = bytearray(enc_ctr.update(msg) + enc_ctr.finalize())
    ctr_ct[idx] ^= 0x08  # '1' (0x31) -> '9' (0x39)

    dec_ctr = Cipher(algorithms.AES(key), modes.CTR(ctr_nonce)).decryptor()
    ctr_out = dec_ctr.update(bytes(ctr_ct)) + dec_ctr.finalize()
    print("CTR decrypted after bit flip:", ctr_out)

    # 2. AES-GCM (with 16-byte tag)
    gcm_nonce = os.urandom(12)
    gcm_sealed = bytearray(AESGCM(key).encrypt(gcm_nonce, msg, None))
    # Layout of gcm_sealed: ciphertext (len(msg) bytes) + tag (16 bytes)
    gcm_sealed[idx] ^= 0x08

    try:
        gcm_out = AESGCM(key).decrypt(gcm_nonce, bytes(gcm_sealed), None)
        print("GCM decrypted after bit flip:", gcm_out)
    except InvalidTag:
        print("GCM rejected tampered ciphertext: InvalidTag")


if __name__ == "__main__":
    main()