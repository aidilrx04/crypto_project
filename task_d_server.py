import argparse
import os
import socket
from cryptography.exceptions import InvalidTag
from crypto_helpers import DEFAULT_PASSPHRASE, derive_key, decrypt_message, encrypt_message
from framing import recv_frame, send_frame

FIXED_SALT = b"0123456789abcdef"


def main(fixed_salt: bool, passphrase: str = DEFAULT_PASSPHRASE) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 5000))
    srv.listen()
    print(f"[Task D Server] fixed_salt={fixed_salt} on 127.0.0.1:5000...")

    while True:
        conn, addr = srv.accept()
        print("New connection from:", addr)
        with conn:
            salt = FIXED_SALT if fixed_salt else os.urandom(16)
            send_frame(conn, salt)
            key = derive_key(passphrase, salt)

            while True:
                try:
                    frame = recv_frame(conn)
                    pt = decrypt_message(key, frame)
                except ConnectionError:
                    print("Client closed connection.")
                    break
                except InvalidTag:
                    print("REJECTED replay/tamper: InvalidTag! Closing connection.")
                    break

                print("server accepted:", pt.decode("utf-8", errors="replace"))
                send_frame(conn, encrypt_message(key, f"OK: {len(pt)} bytes".encode("utf-8")))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixed-salt", action="store_true")
    args = parser.parse_args()
    main(args.fixed_salt)