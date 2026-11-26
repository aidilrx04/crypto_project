import socket
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from crypto_helpers import DEFAULT_PASSPHRASE, derive_key
from framing import recv_frame, send_frame

SALT = b"0123456789abcdef"  # fixed test salt for Task A experiment


def pad_16(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def unpad_16(data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(pad_16(plaintext)) + enc.finalize()


def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return unpad_16(dec.update(ciphertext) + dec.finalize())


def run_server(passphrase: str = DEFAULT_PASSPHRASE) -> None:
    key = derive_key(passphrase, SALT)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 5000))
    srv.listen()
    print("[Task A ECB Server] Listening on 127.0.0.1:5000...")
    conn, _ = srv.accept()
    with conn:
        while True:
            try:
                ct = recv_frame(conn)
            except ConnectionError:
                break
            pt = ecb_decrypt(key, ct)
            print("server got:", pt.decode("utf-8", errors="replace"))
            send_frame(conn, ecb_encrypt(key, f"OK: {len(pt)} bytes".encode("utf-8")))


def run_client(passphrase: str = DEFAULT_PASSPHRASE) -> None:
    key = derive_key(passphrase, SALT)
    msgs = [
        "hello",
        "hello",
        "ATTACK AT DAWN!!ATTACK AT DAWN!!",
    ]
    with socket.create_connection(("127.0.0.1", 5000)) as s:
        for m in msgs:
            send_frame(s, ecb_encrypt(key, m.encode("utf-8")))
            reply = ecb_decrypt(key, recv_frame(s))
            print("client got:", reply.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    mode = input("Run 'server' or 'client': ").strip().lower()
    if mode == "server":
        run_server()
    else:
        run_client()