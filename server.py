import asyncio
import json
import ssl
import pathlib
import base64
import datetime
import websockets
from websockets.legacy.server import WebSocketServerProtocol

# WebSocket relay server with TLS and self-signed certificate for localhost
HOST = "127.0.0.1"
PORT = 8443
CERT_DIR = pathlib.Path("certs")
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"
GROUP_ID = "broadcast"
group_members: set[str] = set()
x25519_pubkeys: dict[str, bytes] = {}

def ensure_self_signed_cert():
    """
    Generate a self-signed certificate if not present (for localhost).
    """
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CourseLab"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    alt_names = x509.SubjectAlternativeName([
        x509.DNSName(u"localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
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

clients: dict[str, list[WebSocketServerProtocol]] = {}
identity_pubkeys: dict[str, bytes] = {}

async def handler(ws: WebSocketServerProtocol):
    """
    Handle a single WebSocket client connection.
    Message types:
      1) HELLO: bind username to this websocket
      2) REGISTER: register Ed25519 identity pubkey
      3) GET_PUBKEY: directory lookup
      4) RELAY: relay opaque envelope
      5) LIST_USERS: user listing
      6) CHAT_REQUEST: chat request
      7) CHAT_RESPONSE: chat response
      8) END_CHAT / CHAT_TERMINATE: chat termination
      9) GROUP_JOIN: user requests to join the broadcast group
      10) GROUP_COMMIT: committer sends new epoch and membership (signed on client)
      11) GROUP_MESSAGE: relay to all current members (except sender)
      12) GROUP_LEAVE: user wants to leave; server replies with current members
    """
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
                clients.setdefault(username, []).append(ws)
                await ws.send(json.dumps({"type": "hello_ack"}))

            # 2) REGISTER: register Ed25519 identity pubkey and optional X25519 directory pubkey
            elif mtype == "register":
                user = msg.get("user")
                pub_b64 = msg.get("identity_pubkey")
                xpub_b64 = msg.get("x25519_pubkey")
                if user and pub_b64:
                    try:
                        identity_pubkeys[user] = base64.b64decode(pub_b64)
                    except Exception:
                        pass
                if user and xpub_b64:
                    try:
                        x25519_pubkeys[user] = base64.b64decode(xpub_b64)
                    except Exception:
                        pass
                await ws.send(json.dumps({"type": "register_ack"}))

            # 3) GET_PUBKEY: directory lookup
            elif mtype == "get_pubkey":
                target = msg.get("user")
                pub = identity_pubkeys.get(target)
                xpub = x25519_pubkeys.get(target)
                resp = {
                    "type": "pubkey",
                    "user": target,
                    "identity_pubkey": base64.b64encode(pub).decode() if pub else None,
                    "x25519_pubkey": base64.b64encode(xpub).decode() if xpub else None,
                }
                await ws.send(json.dumps(resp))

            # 4) RELAY: relay opaque envelope
            elif mtype == "relay":
                to_user = msg.get("to")
                if not to_user:
                    continue
                msg["ts"] = int(datetime.datetime.utcnow().timestamp())
                sent = False
                for target_ws in clients.get(to_user, []):
                    if target_ws and not target_ws.closed:
                        print(f"[relay] {username} -> {to_user}")
                        await target_ws.send(json.dumps(msg))
                        sent = True
                if not sent:
                    print(f"[relay] Failed: {to_user} is not connected")

            # 5) LIST_USERS: user listing
            elif mtype == "list_users":
                user_list = list(identity_pubkeys.keys())
                resp = {
                    "type": "user_list",
                    "users": user_list
                }
                await ws.send(json.dumps(resp))

            # 6) CHAT_REQUEST: chat request
            elif mtype == "chat_request":
                to_user = msg.get("to")
                for target_ws in clients.get(to_user, []):
                    if target_ws and not target_ws.closed:
                        await target_ws.send(json.dumps(msg))

            # 7) CHAT_RESPONSE: chat response
            elif mtype == "chat_response":
                to_user = msg.get("to")
                for target_ws in clients.get(to_user, []):
                    if target_ws and not target_ws.closed:
                        await target_ws.send(json.dumps(msg))

            # 8) END_CHAT / CHAT_TERMINATE: chat termination
            elif mtype in ["end_chat", "chat_terminate"]:
                to_user = msg.get("to")
                from_user = msg.get("from") or username
                response = {
                    "type": "chat_terminate",
                    "from": from_user,
                    "to": to_user
                }
                for user in (to_user, from_user):
                    for target_ws in clients.get(user, []):
                        if target_ws and not target_ws.closed:
                            await target_ws.send(json.dumps(response))

            # 9) GROUP_JOIN: user requests to join the broadcast group
            elif mtype == "group_join":
                resp = {
                    "type": "group_members",
                    "group": GROUP_ID,
                    "members": sorted(list(group_members)),
                }
                await ws.send(json.dumps(resp))

            # 10) GROUP_COMMIT: committer sends new epoch and membership (signed on client)
            elif mtype == "group_commit":
                if msg.get("group") != GROUP_ID:
                    continue
                new_members = msg.get("members") or []
                group_members.clear()
                for u in new_members:
                    group_members.add(u)
                msg["ts"] = int(datetime.datetime.utcnow().timestamp())
                for u in new_members:
                    for target_ws in clients.get(u, []):
                        if target_ws and not target_ws.closed:
                            await target_ws.send(json.dumps(msg))

            # 11) GROUP_MESSAGE: relay to all current members (except sender)
            elif mtype == "group_message":
                if msg.get("group") != GROUP_ID:
                    continue
                sender = msg.get("from")
                msg["ts"] = int(datetime.datetime.utcnow().timestamp())
                for u in list(group_members):
                    if u == sender:
                        continue
                    for target_ws in clients.get(u, []):
                        if target_ws and not target_ws.closed:
                            await target_ws.send(json.dumps(msg))

            # 12) GROUP_LEAVE: user wants to leave; server replies with current members
            elif mtype == "group_leave":
                resp = {
                    "type": "group_members",
                    "group": GROUP_ID,
                    "members": sorted(list(group_members)),
                }
                await ws.send(json.dumps(resp))

    except websockets.ConnectionClosed:
        pass
    finally:
        if username in clients:
            clients[username] = [c for c in clients[username] if c != ws]
            if not clients[username]:
                del clients[username]

async def main():
    """
    Start the WebSocket relay server with TLS.
    """
    ensure_self_signed_cert()
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    print(f"[*] Relay listening on wss://{HOST}:{PORT}")
    from websockets.legacy.server import serve
    async with serve(handler, HOST, PORT, ssl=ssl_ctx, max_size=2 ** 20):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())