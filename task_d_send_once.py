# task_d_send_once.py — run once during Wireshark capture to send "Pay RM100 to Ali"
import socket
from crypto_helpers import DEFAULT_PASSPHRASE, derive_key, decrypt_message, encrypt_message
from framing import recv_frame, send_frame

with socket.create_connection(("127.0.0.1", 5000)) as s:
    salt = recv_frame(s)
    key = derive_key(DEFAULT_PASSPHRASE, salt)
    send_frame(s, encrypt_message(key, b"Pay RM100 to Ali"))
    reply = decrypt_message(key, recv_frame(s))
    print("sent once, got:", reply.decode("utf-8", errors="replace"))