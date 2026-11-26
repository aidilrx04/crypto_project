import os
import socket
from cryptography.exceptions import InvalidTag
from crypto_helpers import DEFAULT_PASSPHRASE, derive_key, decrypt_message, encrypt_message
from framing import recv_frame, send_frame


def main(passphrase: str = DEFAULT_PASSPHRASE) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 5000))
    srv.listen()
    print("Stage 2 server listening on 127.0.0.1:5000...")

    conn, addr = srv.accept()
    print("Connected by:", addr)

    with conn:
        salt = os.urandom(16)
        send_frame(conn, salt)
        key = derive_key(passphrase, salt)

        while True:
            try:
                frame = recv_frame(conn)
                plaintext = decrypt_message(key, frame)
            except ConnectionError:
                print("Client disconnected.")
                break
            except InvalidTag:
                print("REJECTED: wrong passphrase or tampered message. Closing connection.")
                break

            msg = plaintext.decode("utf-8", errors="replace")
            print(f"server got: {msg!r} ({len(plaintext)} bytes)")
            reply = encrypt_message(key, f"OK: {len(plaintext)} bytes".encode("utf-8"))
            send_frame(conn, reply)


if __name__ == "__main__":
    user_pass = input(f"Enter passphrase [{DEFAULT_PASSPHRASE}]: ").strip() or DEFAULT_PASSPHRASE
    main(user_pass)