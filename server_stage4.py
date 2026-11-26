import argparse
import socket
from pathlib import Path
from cryptography.exceptions import InvalidTag
from crypto_helpers import decrypt_message, encrypt_message
from framing import recv_frame, send_frame
from x25519_helpers import (
    derive_session_key,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    sign_public_key,
)

RAW_PUB_FILE = Path("server_ed25519.pub")


def main(signed: bool) -> None:
    signing_key = None
    if signed:
        signing_key, verify_key = generate_ed25519_keypair()
        RAW_PUB_FILE.write_bytes(
            verify_key.public_bytes(
                encoding=serialization.Encoding.Raw
                if "serialization" in globals()
                else __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
                format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
            )
        )
        print(f"Wrote server signing public key to {RAW_PUB_FILE}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 5000))
    srv.listen()
    print(f"Stage 4 server listening on 127.0.0.1:5000 (signed={signed})...")

    conn, addr = srv.accept()
    print("Connected by:", addr)

    with conn:
        client_x_pub = recv_frame(conn)
        my_x_priv, my_x_pub = generate_x25519_keypair()
        send_frame(conn, my_x_pub)

        if signed and signing_key is not None:
            sig = sign_public_key(signing_key, my_x_pub)
            send_frame(conn, sig)

        key = derive_session_key(my_x_priv, client_x_pub)

        while True:
            try:
                frame = recv_frame(conn)
                plaintext = decrypt_message(key, frame)
            except ConnectionError:
                print("Client disconnected.")
                break
            except InvalidTag:
                print("REJECTED: invalid tag.")
                break

            msg = plaintext.decode("utf-8", errors="replace")
            print(f"server got: {msg!r}")
            send_frame(conn, encrypt_message(key, f"OK: {len(plaintext)} bytes".encode("utf-8")))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sign", action="store_true", help="Sign X25519 public key with Ed25519")
    args = parser.parse_args()
    main(args.sign)