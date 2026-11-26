import socket
import struct


def send_frame(sock: socket.socket, data: bytes) -> None:
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_frame(sock: socket.socket) -> bytes:
    (n,) = struct.unpack(">I", recv_exact(sock, 4))
    return recv_exact(sock, n)