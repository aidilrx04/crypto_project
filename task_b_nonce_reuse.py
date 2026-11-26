import os
import socket
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto_helpers import DEFAULT_PASSPHRASE, derive_key
from framing import recv_frame, send_frame

FIXED_NONCE = b"\x00" * 12


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_fixed_nonce(key: bytes, plaintext: bytes) -> bytes:
    sealed = AESGCM(key).encrypt(FIXED_NONCE, plaintext, None)
    return FIXED_NONCE + sealed


def decrypt_fixed_nonce(key: bytes, frame: bytes) -> bytes:
    nonce, body = frame[:12], frame[12:]
    return AESGCM(key).decrypt(nonce, body, None)


def run_server(passphrase: str = DEFAULT_PASSPHRASE) -> None:
    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 5000))
    srv.listen()
    print("[Task B Nonce-Reuse Server] Listening on 127.0.0.1:5000...")
    conn, _ = srv.accept()
    with conn:
        send_frame(conn, salt)
        while True:
            try:
                frame = recv_frame(conn)
                pt = decrypt_fixed_nonce(key, frame)
            except ConnectionError:
                break
            except InvalidTag:
                print("REJECTED: InvalidTag")
                break
            print("server got:", pt.decode("utf-8", errors="replace"))
            send_frame(conn, encrypt_fixed_nonce(key, f"OK: {len(pt)} bytes".encode("utf-8")))


def run_client(passphrase: str = DEFAULT_PASSPHRASE) -> None:
    msgs = [
        "Transfer RM100 to Ali",
        "Transfer RM900 to Bob",
    ]
    with socket.create_connection(("127.0.0.1", 5000)) as s:
        salt = recv_frame(s)
        key = derive_key(passphrase, salt)
        for m in msgs:
            send_frame(s, encrypt_fixed_nonce(key, m.encode("utf-8")))
            reply = decrypt_fixed_nonce(key, recv_frame(s))
            print("client got:", reply.decode("utf-8", errors="replace"))


def recover_from_hex() -> None:
    c1_hex = input("Paste 21-byte ciphertext 1 hex from Wireshark: ").strip()
    c2_hex = input("Paste 21-byte ciphertext 2 hex from Wireshark: ").strip()
    p1 = b"Transfer RM100 to Ali"
    c1 = bytes.fromhex(c1_hex)
    c2 = bytes.fromhex(c2_hex)
    ct_xor = xor_bytes(c1, c2)
    recovered_p2 = xor_bytes(ct_xor, p1)
    print("C1 ^ C2 (hex):", ct_xor.hex())
    print("Recovered P2:", recovered_p2.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    mode = input("Run 'server', 'client', or 'recover': ").strip().lower()
    if mode == "server":
        run_server()
    elif mode == "client":
        run_client()
    else:
        recover_from_hex()