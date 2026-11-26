import socket
from cryptography.exceptions import InvalidTag
from crypto_helpers import DEFAULT_PASSPHRASE, derive_key, decrypt_message, encrypt_message
from framing import recv_frame, send_frame


def main(passphrase: str = DEFAULT_PASSPHRASE) -> None:
    messages = ["hello", "hello", "second message"]

    with socket.create_connection(("127.0.0.1", 5000)) as s:
        salt = recv_frame(s)
        key = derive_key(passphrase, salt)

        for msg in messages:
            send_frame(s, encrypt_message(key, msg.encode("utf-8")))
            try:
                reply_frame = recv_frame(s)
                reply = decrypt_message(key, reply_frame)
            except ConnectionError:
                print("Connection closed by server (likely wrong passphrase or invalid tag).")
                break
            except InvalidTag:
                print("REJECTED: server reply failed authentication.")
                break
            print("client got:", reply.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    user_pass = input(f"Enter passphrase [{DEFAULT_PASSPHRASE}]: ").strip() or DEFAULT_PASSPHRASE
    main(user_pass)