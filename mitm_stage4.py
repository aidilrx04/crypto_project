import socket
from crypto_helpers import decrypt_message, encrypt_message
from framing import recv_frame, send_frame
from x25519_helpers import derive_session_key, generate_x25519_keypair


def main() -> None:
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind(("127.0.0.1", 5001))
    proxy.listen()
    print("MITM proxy listening on 127.0.0.1:5001 -> forwarding to 127.0.0.1:5000...")

    client_conn, client_addr = proxy.accept()
    print("Client connected to MITM:", client_addr)

    with client_conn, socket.create_connection(("127.0.0.1", 5000)) as srv_conn:
        # Leg 1: MITM <-> Client
        client_x_pub = recv_frame(client_conn)
        mitm_to_client_priv, mitm_to_client_pub = generate_x25519_keypair()
        send_frame(client_conn, mitm_to_client_pub)
        key_client = derive_session_key(mitm_to_client_priv, client_x_pub)

        # Leg 2: MITM <-> Real Server
        mitm_to_srv_priv, mitm_to_srv_pub = generate_x25519_keypair()
        send_frame(srv_conn, mitm_to_srv_pub)
        srv_x_pub = recv_frame(srv_conn)
        key_server = derive_session_key(mitm_to_srv_priv, srv_x_pub)

        while True:
            try:
                enc_from_client = recv_frame(client_conn)
            except ConnectionError:
                break
            plain = decrypt_message(key_client, enc_from_client)
            print("[MITM INTERCEPTED]:", plain.decode("utf-8", errors="replace"))

            send_frame(srv_conn, encrypt_message(key_server, plain))
            enc_reply = recv_frame(srv_conn)
            reply_plain = decrypt_message(key_server, enc_reply)
            send_frame(client_conn, encrypt_message(key_client, reply_plain))


if __name__ == "__main__":
    main()