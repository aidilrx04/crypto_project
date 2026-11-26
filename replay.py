# replay.py — connects as a new client, reads & ignores the first frame (salt), and replays saved bytes
import socket
from framing import recv_frame

SAVED_FILE = "recorded_c2s.bin"

raw_bytes = open(SAVED_FILE, "rb").read()
with socket.create_connection(("127.0.0.1", 5000)) as s:
    _ignored_salt = recv_frame(s)
    s.sendall(raw_bytes)
    print("Replayed", len(raw_bytes), "saved bytes.")