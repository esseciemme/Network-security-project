# WebSocket Relay Server

import asyncio, json, ssl, pathlib, base64, os, datetime
import websockets
from websockets.legacy.server import WebSocketServerProtocol

HOST = "127.0.0.1"
PORT = 8443
CERT_DIR = pathlib.Path("certs")
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE  = CERT_DIR / "server.key"

# ---------- dynamic self-signed cert generation ----------
def ensure_self_signed_cert():
    """
    Creates a self-signed certificate if not present.
    CN=localhost, SAN=127.0.0.1. For coursework only.
    """
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import timedelta

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CourseLab"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    alt_names = x509.SubjectAlternativeName([
        x509.DNSName(u"localhost"),
        x509.IPAddress(ipaddress_from_str("127.0.0.1")),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(alt_names, critical=False)
        .sign(key, hashes.SHA256())
    )

    with open(KEY_FILE, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def ipaddress_from_str(s: str):
    import ipaddress
    return ipaddress.ip_address(s)

# ---------- in-memory state ----------
clients: dict[str, WebSocketServerProtocol] = {}
identity_pubkeys: dict[str, bytes] = {}  # username -> Ed25519 public key bytes

async def handler(ws: WebSocketServerProtocol):
    username = None
    try:
        async for text in ws:
            try:
                msg = json.loads(text)
            except json.JSONDecodeError:
                continue

            mtype = msg.get("type")

            # 1) HELLO: bind username to this websocket
            if mtype == "hello":
                username = msg.get("user")
                if not username:
                    await ws.close(code=4000, reason="missing username")
                    return
                # replace any old connection
                clients[username] = ws
                await ws.send(json.dumps({"type": "hello_ack"}))

            # 2) REGISTER identity pubkey (Ed25519)
            elif mtype == "register":
                user = msg.get("user")
                pub_b64 = msg.get("identity_pubkey")
                if not (user and pub_b64):
                    continue
                try:
                    identity_pubkeys[user] = base64.b64decode(pub_b64)
                except Exception:
                    pass
                # ack
                await ws.send(json.dumps({"type": "register_ack"}))

            # 3) DIRECTORY lookup
            elif mtype == "get_pubkey":
                target = msg.get("user")
                pub = identity_pubkeys.get(target)
                resp = {
                    "type": "pubkey",
                    "user": target,
                    "identity_pubkey": base64.b64encode(pub).decode() if pub else None,
                }
                await ws.send(json.dumps(resp))

            # 4) RELAY opaque envelope
            elif mtype == "relay":
                to_user = msg.get("to")
                if not to_user:
                    continue
                msg["ts"] = int(datetime.datetime.utcnow().timestamp())
                target_ws = clients.get(to_user)
                if target_ws and not target_ws.closed:
                    print(f"[relay] {username} -> {to_user}")
                    await target_ws.send(json.dumps(msg))
                else:
                    print(f"[relay] Failed: {to_user} is not connected")

            # 5) USER LISTING (new)
            elif mtype == "list_users":
                user_list = list(identity_pubkeys.keys())
                resp = {
                    "type": "user_list",
                    "users": user_list
                }
                await ws.send(json.dumps(resp))

            # 6) CHAT REQUEST
            elif mtype == "chat_request":
                to_user = msg.get("to")
                if to_user in clients:
                    await clients[to_user].send(json.dumps(msg))
                else:
                    print(f"[chat_request] {to_user} is not connected")

            # 7) CHAT RESPONSE
            elif mtype == "chat_response":
                to_user = msg.get("to")
                if to_user in clients:
                    await clients[to_user].send(json.dumps(msg))
                else:
                    print(f"[chat_response] {to_user} is not connected")

            # 8) CHAT TERMINATION
            elif mtype in ["end_chat", "chat_terminate"]:
                to_user = msg.get("to")
                from_user = msg.get("from") or username

                response = {
                    "type": "chat_terminate",
                    "from": from_user,
                    "to": to_user
                }

                # Notify both users
                for user in (to_user, from_user):
                    target_ws = clients.get(user)
                    if target_ws and not target_ws.closed:
                        await target_ws.send(json.dumps(response))
                    else:
                        print(f"[chat_terminate] {user} is not connected")

    except websockets.ConnectionClosed:
        pass
    finally:
        # cleanup mapping on disconnect
        if username and clients.get(username) is ws:
            clients.pop(username, None)

async def main():
    ensure_self_signed_cert()
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))

    print(f"[*] Relay listening on wss://{HOST}:{PORT}")
    from websockets.legacy.server import serve

    # ...
    async with serve(handler, HOST, PORT, ssl=ssl_ctx, max_size=2 ** 20):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
