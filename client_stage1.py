import socket
from framing import send_frame, recv_frame


def main() -> None:
    messages = [
        "Hello Siti",
        "Testing plaintext chat on loopback",
        "Goodbye!",
    ]

    with socket.create_connection(("127.0.0.1", 5000)) as s:
        for msg in messages:
            payload = msg.encode("utf-8")
            send_frame(s, payload)
            reply = recv_frame(s)
            print("client got:", reply.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()