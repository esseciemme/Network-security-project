import os
import base64
import hashlib
from dataclasses import dataclass
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Directory to store identity keys
KEY_DIR = os.path.expanduser("~/.minichat")

def b64e(b: bytes) -> str:
    """Base64 encode bytes to string."""
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    """Base64 decode string to bytes."""
    return base64.b64decode(s.encode())

def load_or_create_identity(username: str) -> Tuple[ed25519.Ed25519PrivateKey, bytes]:
    """
    Load or generate an Ed25519 identity keypair for the given username.
    Returns (private_key, public_key_bytes).
    """
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
    with open(priv_path, "wb") as f:
        f.write(priv.private_bytes_raw())
    with open(pub_path, "wb") as f:
        f.write(pub)
    return priv, pub

def fingerprint(pub_bytes: bytes) -> str:
    """
    Return a short fingerprint string for a public key (SHA256, grouped).
    """
    h = hashlib.sha256(pub_bytes).hexdigest()
    return " ".join([h[i:i+5] for i in range(0, 40, 5)])

@dataclass
class HandshakeInit:
    """Handshake message fields."""
    ek_pub_b64: str
    sig_b64: str
    initiator: bool

@dataclass
class SessionKeys:
    """Session keys for sending and receiving."""
    send_key: bytes
    recv_key: bytes

def sign_ed25519(priv: ed25519.Ed25519PrivateKey, msg: bytes) -> bytes:
    """Sign a message with Ed25519 private key."""
    return priv.sign(msg)

def verify_ed25519(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify Ed25519 signature."""
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except Exception:
        return False

def generate_ephemeral() -> x25519.X25519PrivateKey:
    """Generate a new ephemeral X25519 private key."""
    return x25519.X25519PrivateKey.generate()

def derive_session_keys(shared_secret: bytes, initiator: bool) -> SessionKeys:
    """
    Derive two AES-GCM keys from a shared secret using HKDF.
    Initiator uses k1 for sending, responder uses k2.
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"chat-v1")
    okm = hkdf.derive(shared_secret)
    k1, k2 = okm[:32], okm[32:]
    return SessionKeys(send_key=k1 if initiator else k2,
                       recv_key=k2 if initiator else k1)

def aesgcm_encrypt(key: bytes, counter: int, ad: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-GCM.
    Nonce is derived from the message counter (12 bytes, big endian).
    """
    nonce = counter.to_bytes(12, "big")
    ct = AESGCM(key).encrypt(nonce, plaintext, ad)
    return nonce, ct

def aesgcm_decrypt(key: bytes, nonce: bytes, ad: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-GCM ciphertext."""
    return AESGCM(key).decrypt(nonce, ciphertext, ad)

def hkdf_expand(key_material: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 expand (no salt, project-wide standard)."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(key_material)

def wrap_secret_for_pub(secret: bytes, recipient_ecdh_pub_bytes: bytes) -> dict:
    """
    Asymmetrically wrap 'secret' for a recipient using ephemeral X25519 + HKDF + AES-GCM.
    Returns a dict with ephemeral_pub, nonce, ciphertext (all base64 strings).
    """
    eph_priv = x25519.X25519PrivateKey.generate()
    recipient_pub = x25519.X25519PublicKey.from_public_bytes(recipient_ecdh_pub_bytes)
    shared = eph_priv.exchange(recipient_pub)  # 32 bytes
    wrap_key = hkdf_expand(shared, info=b"group-epoch-wrap", length=32)
    nonce = os.urandom(12)
    ct = AESGCM(wrap_key).encrypt(nonce, secret, None)
    return {
        "ephemeral_pub": b64e(eph_priv.public_key().public_bytes_raw()),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ct),
    }

def unwrap_secret_with_priv(blob: dict, my_ecdh_priv: x25519.X25519PrivateKey) -> bytes:
    """
    Unwrap a secret using our X25519 private key and the sender's ephemeral pubkey.
    """
    eph_pub = x25519.X25519PublicKey.from_public_bytes(b64d(blob["ephemeral_pub"]))
    shared = my_ecdh_priv.exchange(eph_pub)
    wrap_key = hkdf_expand(shared, info=b"group-epoch-wrap", length=32)
    nonce = b64d(blob["nonce"])
    ct = b64d(blob["ciphertext"])
    return AESGCM(wrap_key).decrypt(nonce, ct, None)


def derive_group_sender_key(epoch_secret: bytes, group_id: str, sender_id: str) -> bytes:
    """
    Derive a unique AES-GCM key for (group, sender) from the epoch_secret.
    Using different keys per-sender avoids nonce reuse even if counters collide.
    """
    info = b"group-msg-key|" + group_id.encode() + b"|" + sender_id.encode()
    return hkdf_expand(epoch_secret, info=info, length=32)
