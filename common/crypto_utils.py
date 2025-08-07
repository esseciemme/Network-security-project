# common/crypto_utils.py
import os, base64, hashlib
from dataclasses import dataclass
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_DIR = os.path.expanduser("~/.minichat")

def b64e(b: bytes) -> str: return base64.b64encode(b).decode()
def b64d(s: str) -> bytes: return base64.b64decode(s.encode())

# ---------- Identity (Ed25519) ----------
def load_or_create_identity(username: str) -> Tuple[ed25519.Ed25519PrivateKey, bytes]:
    os.makedirs(KEY_DIR, exist_ok=True)
    priv_path = os.path.join(KEY_DIR, f"{username}_ed25519_priv.key")
    pub_path = os.path.join(KEY_DIR, f"{username}_ed25519_pub.key")

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
        with open(pub_path, "rb") as f:
            pub = f.read()
        return priv, pub

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    with open(priv_path, "wb") as f: f.write(priv.private_bytes_raw())
    with open(pub_path, "wb") as f: f.write(pub)
    return priv, pub

def fingerprint(pub_bytes: bytes) -> str:
    # Short decimal safety number (like Signal) derived from SHA256
    h = hashlib.sha256(pub_bytes).hexdigest()
    # group into 5-character chunks for readability
    return " ".join([h[i:i+5] for i in range(0, 40, 5)])

# ---------- Handshake primitives ----------
@dataclass
class HandshakeInit:
    ek_pub_b64: str
    sig_b64: str
    initiator: bool

@dataclass
class SessionKeys:
    # Two separate send/recv keys to avoid nonce/key reuse
    send_key: bytes
    recv_key: bytes

def sign_ed25519(priv: ed25519.Ed25519PrivateKey, msg: bytes) -> bytes:
    return priv.sign(msg)

def verify_ed25519(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except Exception:
        return False

def generate_ephemeral() -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.generate()

def derive_session_keys(shared_secret: bytes, initiator: bool) -> SessionKeys:
    # Derive 64 bytes and split into two 32‑byte AES‑GCM keys
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"chat-v1")
    okm = hkdf.derive(shared_secret)
    k1, k2 = okm[:32], okm[32:]
    # Deterministic role mapping: initiator uses k1 for sending, responder uses k2 for sending
    return SessionKeys(send_key=k1 if initiator else k2,
                       recv_key=k2 if initiator else k1)

# ---------- AEAD wrappers ----------
def aesgcm_encrypt(key: bytes, counter: int, ad: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Nonce derived from counter (12 bytes, big endian). Ensure counter increments per message.
    """
    nonce = counter.to_bytes(12, "big")
    ct = AESGCM(key).encrypt(nonce, plaintext, ad)
    return nonce, ct

def aesgcm_decrypt(key: bytes, nonce: bytes, ad: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, ad)