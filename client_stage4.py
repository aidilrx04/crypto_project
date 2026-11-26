import argparse
import socket
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from crypto_helpers import decrypt_message, encrypt_message
from framing import recv_frame, send_frame
from x25519_helpers import (
    derive_session_key,
    generate_x25519_keypair,
    verify_public_key_signature,
)


def main(port: int, verify_file: str | None) -> None:
    verify_key = None
    if verify_file:
        verify_key = Ed25519PublicKey.from_public_bytes(open(verify_file, "rb").read())

    messages = ["Secret rendezvous at midnight", "Second confidential note"]

    with socket.create_connection(("127.0.0.1", port)) as s:
        my_x_priv, my_x_pub = generate_x25519_keypair()
        send_frame(s, my_x_pub)

        peer_x_pub = recv_frame(s)
        if verify_key is not None:
            sig = recv_frame(s)
            if not verify_public_key_signature(verify_key, peer_x_pub, sig):
                print("ABORTED: Server public key signature verification failed (possible MITM)!")
                return
            print("Server signature verified OK.")

        key = derive_session_key(my_x_priv, peer_x_pub)

        for msg in messages:
            send_frame(s, encrypt_message(key, msg.encode("utf-8")))
            reply = decrypt_message(key, recv_frame(s))
            print("client got:", reply.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--verify-file", type=str, default=None)
    args = parser.parse_args()
    main(args.port, args.verify_file)