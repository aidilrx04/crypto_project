import socket
from framing import send_frame, recv_frame


def main() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 5000))
    srv.listen()
    print("Stage 1 server listening on 127.0.0.1:5000...")

    conn, addr = srv.accept()
    print("Connected by:", addr)
    with conn:
        while True:
            try:
                data = recv_frame(conn)
            except ConnectionError:
                print("Client disconnected.")
                break

            msg_text = data.decode("utf-8", errors="replace")
            print(f"server got: {msg_text!r} ({len(data)} bytes)")
            reply = f"OK: {len(data)} bytes".encode("utf-8")
            send_frame(conn, reply)


if __name__ == "__main__":
    main()