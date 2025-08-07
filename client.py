# Secure E2EE Chat Client

import tkinter as tk
from tkinter import simpledialog, messagebox, font
from threading import Thread
import asyncio, websockets, ssl, json, base64, queue, time

from cryptography.hazmat.primitives.asymmetric import x25519

from common.crypto_utils import (
    load_or_create_identity, fingerprint,
    sign_ed25519, verify_ed25519, generate_ephemeral,
    derive_session_keys, aesgcm_encrypt, aesgcm_decrypt, b64e, b64d
)

HOST = "127.0.0.1"
PORT = 8443
WS_URL = f"wss://{HOST}:{PORT}"

class ChatClient:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure E2EE Chat Client")
        self.root.geometry("700x650")  # Set initial window size

        # Prompt username
        self.username = simpledialog.askstring("Login", "Your username:")
        self.peer = None

        self.pending_handshake1 = None

        if not self.username:
            messagebox.showerror("Error", "Username is required.")
            root.destroy()
            return

        self.priv, self.pub = load_or_create_identity(self.username)

        # ---------- UI LAYOUT ----------
        main_frame = tk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Top: Your identity
        identity_frame = tk.LabelFrame(main_frame, text="Your Identity", padx=10, pady=5)
        identity_frame.pack(fill=tk.X, pady=5)
        mono = font.Font(family="Courier", size=12)
        self.identity_label = tk.Label(identity_frame, text=f"Fingerprint: {fingerprint(self.pub)}", font=mono, fg="white")
        self.identity_label.pack(anchor="w")
        tk.Label(identity_frame, text="Verify fingerprints out-of-band with your peer to defeat MITM.", fg="gray").pack(anchor="w")

        self.session_status = tk.Label(identity_frame, text="🔓 Not connected", fg="red")
        self.session_status.pack(anchor="w", pady=(2, 0))

        # Middle: Active users and chat area
        mid_frame = tk.Frame(main_frame)
        mid_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Active Users
        users_frame = tk.LabelFrame(mid_frame, text="Active Users", padx=5, pady=5)
        users_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))

        self.user_listbox = tk.Listbox(users_frame, height=15, width=20, font=("Arial", 12))
        self.user_listbox.pack(fill=tk.BOTH, expand=True)
        self.start_chat_btn = tk.Button(users_frame, text="Start Chat", command=self.start_chat)
        self.start_chat_btn.pack(fill=tk.X, pady=5)
        self.terminate_chat_btn = tk.Button(users_frame, text="End Chat", command=self.terminate_chat)
        self.terminate_chat_btn.pack(fill=tk.X)
        self.user_listbox.bind("<<ListboxSelect>>", self.on_user_selected)


        # CHAT DISPLAY AREA (Header + Scrollable Chat Area)
        chat_container = tk.LabelFrame(mid_frame, text="Chat", padx=5, pady=5, fg="white", bg="#2C2F33",font=("Arial", 12, "bold"))
        chat_container.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        chat_frame = tk.Frame(chat_container, bg="#2C2F33")
        chat_frame.pack(fill=tk.BOTH, expand=True)
        self.chat_canvas = tk.Canvas(chat_frame, bg="#2C2F33", highlightthickness=0)
        self.chat_scrollbar = tk.Scrollbar(chat_frame, command=self.chat_canvas.yview)
        self.chat_inner = tk.Frame(self.chat_canvas, bg="#2C2F33")
        self.chat_inner.bind("<Configure>",lambda e: self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all")))
        self.chat_canvas.create_window((0, 0), window=self.chat_inner, anchor="nw")
        self.chat_canvas.configure(yscrollcommand=self.chat_scrollbar.set)
        self.chat_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bottom: Message input
        input_frame = tk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5)

        self.msg_entry = tk.Entry(input_frame)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.send_button = tk.Button(input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=5)

        self.set_chat_controls_enabled(False)

        # ---------- Session and Networking ----------
        self.ws = None
        self.outq = queue.Queue()
        self.session_keys = None
        self.send_counter = 0
        self.recv_counter = 0
        self.peer_identity_pub = None
        self.ek_priv = None
        self.initiator = False

        # Async networking thread
        self.loop = asyncio.new_event_loop()
        t = Thread(target=lambda: self.loop.run_until_complete(self._main_async()), daemon=True)
        t.start()
        self.msg_entry.focus()

    # ---------- UI helpers ----------
    def styled_append(self, msg: str, sent: bool = False):
        is_log = msg.strip().startswith("[")
        frame = tk.Frame(self.chat_inner, bg="#2C2F33")

        if is_log:
            label = tk.Label(
                frame, text=msg, fg="white", bg="#2C2F33",
                anchor="w", justify="left", font=("Courier", 14),
                wraplength=450
            )
            label.pack(anchor="w", padx=5, pady=2)
            frame.pack(anchor="w", fill="x")
        else:
            bubble_color = "#DCF8C6" if sent else "#FFFFFF"
            align = "e" if sent else "w"
            anchor = "e" if sent else "w"
            padx = (60, 10) if sent else (10, 60)

            bubble = tk.Label(
                frame,
                text=msg,
                bg=bubble_color,
                fg="black",
                wraplength=450,
                justify="left",
                font=("Arial", 14),
                padx=10,
                pady=6,
                bd=0
            )
            bubble.pack(anchor=align)
            frame.pack(anchor=anchor, padx=padx, pady=4)

        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)

    def append(self, msg: str):
        self.styled_append(msg, sent=False)

    def send_message(self):
        msg = self.msg_entry.get().strip()
        if not msg:
            return
        if not self.session_keys:
            messagebox.showwarning("No session", "Session not established yet.")
            return
        self.outq.put(("chat", msg))
        self.msg_entry.delete(0, tk.END)
        self.styled_append(f"You: {msg}", sent=True)

    def on_user_selected(self, event):
        selection = event.widget.curselection()
        if selection:
            self.peer = event.widget.get(selection[0])
            self.append(f"[info] Selected peer: {self.peer}")

    async def request_peer_pubkey(self):
        await self.ws.send(json.dumps({"type": "get_pubkey", "user": self.peer}))

    def update_user_list(self, users):
        self.user_listbox.delete(0, tk.END)
        for user in users:
            self.user_listbox.insert(tk.END, user)

    # ---------- Async networking ----------
    async def _main_async(self):
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        try:
            async with websockets.connect(WS_URL, ssl=ssl_ctx, max_size=2**20) as ws:
                self.ws = ws
                await ws.send(json.dumps({"type":"hello", "user": self.username}))
                await ws.recv()
                await ws.send(json.dumps({"type":"register",
                                          "user": self.username,
                                          "identity_pubkey": b64e(self.pub)}))
                await ws.recv()

                # Start polling users
                userlist_task = asyncio.create_task(self._poll_user_list(ws))
                consumer = asyncio.create_task(self._recv_loop(ws))
                producer = asyncio.create_task(self._send_loop(ws))

                await asyncio.gather(consumer, producer, userlist_task)

        except Exception as e:
            self.append(f"[error] {e}")

    async def _send_loop(self, ws):
        while True:
            kind, payload = await asyncio.get_event_loop().run_in_executor(None, self.outq.get)
            if kind == "chat":
                ad = f"{self.username}|{self.peer}|chat|{self.send_counter}".encode()
                nonce, ct = aesgcm_encrypt(self.session_keys.send_key, self.send_counter, ad, payload.encode())
                env = {
                    "type": "relay",
                    "to": self.peer,
                    "from": self.username,
                    "ciphertext": b64e(ct),
                    "nonce": b64e(nonce),
                    "meta": {"kind":"chat", "ctr": self.send_counter},
                }
                self.send_counter += 1
                await ws.send(json.dumps(env))

    async def _recv_loop(self, ws):
        while True:
            text = await ws.recv()
            msg = json.loads(text)
            mtype = msg.get("type")

            if mtype == "pubkey":
                if msg.get("user") == self.peer and msg.get("identity_pubkey"):
                    self.peer_identity_pub = b64d(msg["identity_pubkey"])
                    self.append(f"[info] Peer {self.peer} fingerprint: {fingerprint(self.peer_identity_pub)}")

                    # If we were waiting to start handshake
                    if self.pending_handshake1:
                        msg = self.pending_handshake1
                        self.pending_handshake1 = None
                        await self._on_handshake1(msg)
                    elif self.initiator and not self.session_keys:
                        await asyncio.sleep(0.2)
                        await self._start_handshake()
                else:
                    self.append(f"[warn] Peer {self.peer} has not registered yet. Waiting...")

            elif mtype == "relay" and msg.get("from") == self.peer:
                meta = msg.get("meta", {})
                if meta.get("kind") == "hs1":
                    if not self.peer_identity_pub:
                        self.pending_handshake1 = msg
                        await self.request_peer_pubkey()
                    else:
                        await self._on_handshake1(msg)
                elif meta.get("kind") == "hs2":
                    await self._on_handshake2(msg)
                elif meta.get("kind") == "chat":
                    await self._on_chat(msg)

            elif mtype == "user_list":
                users = msg.get("users", [])
                if self.username in users:
                    users.remove(self.username)
                self.root.after(0, lambda: self.update_user_list(users))

            elif mtype == "chat_request" and msg.get("to") == self.username:
                peer = msg.get("from")
                response = messagebox.askyesno("Chat Request", f"{peer} wants to chat. Accept?")
                asyncio.run_coroutine_threadsafe(self._send_chat_response(peer, response), self.loop)
                if response:
                    self.peer = peer
                    self.initiator = False

            elif mtype == "chat_response" and msg.get("to") == self.username:
                accepted = msg.get("accepted", False)
                if accepted:
                    self.append(f"[info] {msg['from']} accepted the chat.")
                    asyncio.run_coroutine_threadsafe(self.request_peer_pubkey(), self.loop)
                else:
                    self.append(f"[info] {msg['from']} declined the chat.")
                    self.peer = None


            elif mtype == "chat_terminate" and msg.get("to") == self.username:
                peer_name = msg.get("from", "peer")

                def notify_termination():
                    self._end_session(local=False)
                    self.styled_append(f"{peer_name} ended the chat.", sent=False)
                    self.set_chat_controls_enabled(False)
                self.root.after(0, notify_termination)

    async def _poll_user_list(self, ws):
        while True:
            await ws.send(json.dumps({"type": "list_users"}))
            await asyncio.sleep(3)

    # ---------- Handshake ----------
    async def _start_handshake(self):
        if self.session_keys or not self.peer_identity_pub:
            return
        self.ek_priv = generate_ephemeral()
        ek_pub_bytes = self.ek_priv.public_key().public_bytes_raw()
        sig = sign_ed25519(self.priv, ek_pub_bytes)
        env = {
            "type": "relay",
            "to": self.peer,
            "from": self.username,
            "nonce": "", "ciphertext": "",
            "meta": {
                "kind": "hs1",
                "ek_pub": b64e(ek_pub_bytes),
                "sig": b64e(sig),
                "initiator": True
            }
        }
        await self.ws.send(json.dumps(env))
        self.append("[info] Sent handshake init.")

    async def _on_handshake1(self, msg):
        ek_pub_peer = b64d(msg["meta"]["ek_pub"])
        sig_peer = b64d(msg["meta"]["sig"])
        if not verify_ed25519(self.peer_identity_pub, ek_pub_peer, sig_peer):
            self.append("[error] Handshake1 signature invalid. Possible MITM."); return
            self.root.after(0, lambda: self.set_chat_controls_enabled(False))

        self.ek_priv = generate_ephemeral()
        ek_pub_bytes = self.ek_priv.public_key().public_bytes_raw()
        sig = sign_ed25519(self.priv, ek_pub_bytes)

        shared = self.ek_priv.exchange(x25519.X25519PublicKey.from_public_bytes(ek_pub_peer))
        self.session_keys = derive_session_keys(shared, initiator=False)
        self.send_counter = 0
        self.recv_counter = 0
        self.append("[info] Handshake complete (responder). You can chat.")
        self.session_status.config(text=f"🔐 Secure session with {self.peer}", fg="green")
        self.root.after(0, lambda: self.set_chat_controls_enabled(True))

        reply = {
            "type": "relay",
            "to": self.peer,
            "from": self.username,
            "nonce": "", "ciphertext": "",
            "meta": {
                "kind": "hs2",
                "ek_pub": b64e(ek_pub_bytes),
                "sig": b64e(sig)
            }
        }
        await self.ws.send(json.dumps(reply))

    async def _on_handshake2(self, msg):
        if not self.ek_priv:
            return
        ek_pub_peer = b64d(msg["meta"]["ek_pub"])
        sig_peer = b64d(msg["meta"]["sig"])
        if not verify_ed25519(self.peer_identity_pub, ek_pub_peer, sig_peer):
            self.append("[error] Handshake2 signature invalid. Possible MITM."); return
            self.root.after(0, lambda: self.set_chat_controls_enabled(False))

        shared = self.ek_priv.exchange(x25519.X25519PublicKey.from_public_bytes(ek_pub_peer))
        self.session_keys = derive_session_keys(shared, initiator=True)
        self.send_counter = 0
        self.recv_counter = 0
        self.append("[info] Handshake complete (initiator). You can chat.")
        self.session_status.config(text=f"🔐 Secure session with {self.peer}", fg="green")
        self.root.after(0, lambda: self.set_chat_controls_enabled(True))

    async def _on_chat(self, msg):
        if not self.session_keys:
            self.append("[warn] Received chat before session established."); return
        try:
            ctr = int(msg["meta"]["ctr"])
            nonce = b64d(msg["nonce"])
            ct = b64d(msg["ciphertext"])
            ad = f"{self.peer}|{self.username}|chat|{ctr}".encode()
            pt = aesgcm_decrypt(self.session_keys.recv_key, nonce, ad, ct).decode()
            self.recv_counter = max(self.recv_counter, ctr + 1)
            self.root.after(0, lambda: self.styled_append(f"{self.peer}: {pt}", sent=False))
        except Exception as e:
            self.root.after(0, lambda: self.append(f"[error] Decrypt failed: {e}"))

    def start_chat(self):
        if not self.peer:
            messagebox.showinfo("No peer selected", "Please select a user to chat with.")
            return
        self.initiator = True
        asyncio.run_coroutine_threadsafe(self._send_chat_request(), self.loop)


    async def _send_chat_request(self):
        await self.ws.send(json.dumps({
            "type": "chat_request",
            "to": self.peer,
            "from": self.username
        }))
        self.append(f"[info] Chat request sent to {self.peer}.")

    async def _send_chat_response(self, peer, accepted):
        await self.ws.send(json.dumps({
            "type": "chat_response",
            "to": peer,
            "from": self.username,
            "accepted": accepted
        }))

    def terminate_chat(self):
        if self.peer:
            async def end_after_notify():
                await self._send_termination_notice()
                self._end_session(local=True)
            asyncio.run_coroutine_threadsafe(end_after_notify(), self.loop)

    def _end_session(self, local=False):
        self.session_keys = None
        self.peer = None
        self.peer_identity_pub = None
        self.ek_priv = None
        self.initiator = False
        self.send_counter = 0
        self.recv_counter = 0
        self.session_status.config(text="🔓 Not connected", fg="red")
        if local:
            self.append("[info] Chat terminated.")
        self.set_start_button_enabled(True)
        self.terminate_chat_btn.config(state=tk.DISABLED)

    async def _send_termination_notice(self):
        await self.ws.send(json.dumps({
            "type": "chat_terminate",
            "from": self.username,
            "to": self.peer
        }))

    def set_chat_controls_enabled(self, enabled: bool):
        state = tk.NORMAL if enabled else tk.DISABLED
        self.send_button.config(state=state)
        self.msg_entry.config(state=state)
        self.terminate_chat_btn.config(state=state)

    def set_start_button_enabled(self, enabled: bool):
        state = tk.NORMAL if enabled else tk.DISABLED
        self.start_chat_btn.config(state=state)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()