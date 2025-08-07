# Network Security Project

This project implements a secure peer-to-peer messaging system over **WebSockets and TLS**.

---

## Network Architecture

+–––––+      WSS (TLS)      +–––––+      WSS (TLS)      +–––––+
|  ClientA | <—————–> |  Server  | <—————–> |  ClientB |
+–––––+                    +–––––+                    +–––––+

- **Transport**: Communication occurs over **WebSockets over TLS (`wss://`)**.
- **Server Role**: The server is a passive relay that forwards encrypted messages between clients without decrypting or inspecting them.
- **Client Role**: Clients handle all cryptographic operations, including identity verification, key exchange, encryption, and decryption.

---

## Transport Security: TLS

The project uses **TLS (Transport Layer Security)** to secure all WebSocket communication between clients and the server.

- A self-signed certificate is generated automatically on server startup for testing.
- The WebSocket connection is upgraded to **`wss://`**, ensuring:
  - **Confidentiality**: Messages in transit are encrypted.
  - **Integrity**: Tampering is detectable.
  - **Authentication**: Prevents basic MITM attacks on transport.
- **TLS is the first layer of defense**, protecting against passive eavesdropping and active network-level attacks.

However, TLS alone is not sufficient, therefore this project also implements **application-layer end-to-end encryption** for complete security.

---

## Application-Layer Protocol

### Message Types

All communication between clients and server is done using **JSON messages** over the WSS connection. The main types include:

- `hello`, `register`: Identity handshake
- `get_pubkey`: Public key lookup
- `chat_request`, `chat_response`, `chat_terminate`: Chat control signaling
- `relay`: Encrypted message forwarding
- `user_list`: Periodic active user polling

### Server Responsibilities

- Maintain WebSocket connections per active user.
- Track registered identity public keys (Ed25519).
- Relay encrypted envelopes (including handshakes and chat messages).
- Never decrypt or inspect messages — acts as a **zero-trust message broker**.

---

## End-to-End Encryption (E2EE)

### Cryptographic Protocol Summary

- **Identity Keys**:
  - Each client has a persistent **Ed25519** key pair.
  - Used for signing during handshake initiation.
- **Ephemeral Session Keys**:
  - Each session generates a fresh **X25519** ephemeral key pair.
  - Key exchange uses Elliptic-Curve Diffie-Hellman (ECDH).
- **Session Key Derivation**:
  - Shared secret from ECDH is expanded using **HKDF (SHA-256)**.
  - Produces two 256-bit AES keys: one for sending, one for receiving.
- **Message Encryption**:
  - Uses **AES-GCM** for authenticated encryption.
  - Nonces are derived from message counters to prevent reuse.
  - Associated data includes message metadata (sender, recipient, type).

### Why This Is Secure

- **Transport security**: TLS protects against network sniffing and MITM at the connection level.
- **End-to-end encryption**: Even with a secure transport, all chat messages are also encrypted at the application level.
- **Forward secrecy**: Ephemeral keys ensure past messages remain secure even if long-term keys are compromised.
- **Message authenticity**: Digital signatures and AEAD prevent message spoofing or tampering.
- **Replay protection**: Nonces and counters ensure each message is unique and validated.

---

## Message Delivery Flow

```text
1. Client A connects to server via WSS and registers identity.
2. Client A sends a chat request to Client B via the server.
3. If accepted, both clients exchange signed ephemeral keys.
4. A shared session key is derived from the Diffie-Hellman exchange.
5. All chat messages are encrypted using AES-GCM and relayed through the server.
6. The server forwards encrypted payloads without accessing content.
7. Either client can terminate the session, resetting the session state.
