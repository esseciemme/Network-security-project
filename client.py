import tkinter as tk
from tkinter import simpledialog, messagebox, font
from threading import Thread
import asyncio, websockets, ssl, json, queue
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
        """Initialize UI and networking."""
        self.root = root
        self.root.title("Secure E2EE Chat Client")
        self.root.geometry("700x650")

        # Prompt for username
        self.username = simpledialog.askstring("Login", "Your username:")
        if not self.username:
            messagebox.showerror("Error", "Username is required.")
            root.destroy()
            return

        self.priv, self.pub = load_or_create_identity(self.username)
        self.peer = None
        self.pending_handshake1 = {}
        self.sessions = {}
        self.active_chat = None
        self.selected_index = None

        self._setup_ui()
        self.ws = None
        self.outq = queue.Queue() # Queue for outgoing messages
        self.loop = asyncio.new_event_loop()
        Thread(target=lambda: self.loop.run_until_complete(self._main_async()), daemon=True).start()
        self.msg_entry.focus()

    def _setup_ui(self):
        """Builds the main UI layout."""
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Identity and session status
        identity_frame = tk.LabelFrame(main_frame, text="Your Identity", padx=10, pady=5)
        identity_frame.pack(fill=tk.X, pady=5)
        username_font = font.Font(family="Helvetica", size=14, weight="bold")
        mono = font.Font(family="Courier", size=12)
        self.username_label = tk.Label(identity_frame, text=f"Username: {self.username}", font=username_font, fg="white")
        self.username_label.pack(anchor="w", pady=(0, 5))
        self.identity_label = tk.Label(identity_frame, text=f"Fingerprint: {fingerprint(self.pub)}", font=mono, fg="white")
        self.identity_label.pack(anchor="w")
        tk.Label(identity_frame, text="Verify fingerprints out-of-band with your peer to defeat MITM.", fg="gray").pack(anchor="w")
        self.session_status = tk.Label(identity_frame, text="🔓 Not connected", fg="red")
        self.session_status.pack(anchor="w", pady=(2, 0))

        # Active users area
        mid_frame = tk.Frame(main_frame)
        mid_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        users_frame = tk.LabelFrame(mid_frame, text="Active Users", padx=5, pady=5)
        users_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        self.user_listbox = tk.Listbox(users_frame, height=15, width=20, font=("Arial", 12))
        self.user_listbox.pack(fill=tk.BOTH, expand=True)
        self.user_listbox.bind("<<ListboxSelect>>", self.on_user_selected)
        self.start_chat_btn = tk.Button(users_frame, text="Start Chat", command=self.start_chat)
        self.start_chat_btn.pack(fill=tk.X, pady=5)
        self.terminate_chat_btn = tk.Button(users_frame, text="End Chat", command=self.terminate_chat)
        self.terminate_chat_btn.pack(fill=tk.X)

        # Chat area
        chat_container = tk.LabelFrame(mid_frame, text="Chat", padx=5, pady=5, fg="white", bg="#2C2F33", font=("Arial", 12, "bold"))
        chat_container.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        chat_frame = tk.Frame(chat_container, bg="#2C2F33")
        chat_frame.pack(fill=tk.BOTH, expand=True)
        self.chat_canvas = tk.Canvas(chat_frame, bg="#2C2F33", highlightthickness=0)
        self.chat_scrollbar = tk.Scrollbar(chat_frame, command=self.chat_canvas.yview)
        self.chat_inner = tk.Frame(self.chat_canvas, bg="#2C2F33")
        self.chat_inner.bind("<Configure>", lambda e: self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all")))
        self.chat_canvas.create_window((0, 0), window=self.chat_inner, anchor="nw")
        self.chat_canvas.configure(yscrollcommand=self.chat_scrollbar.set)
        self.chat_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        input_frame = tk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5)
        self.msg_entry = tk.Entry(input_frame)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.send_button = tk.Button(input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=5)
        self.set_chat_controls_enabled(False)

    def styled_append(self, msg: str, sent: bool = False):
        """Append a message bubble or info to the chat area."""
        is_log = msg.strip().startswith("[")
        frame = tk.Frame(self.chat_inner, bg="#2C2F33")
        if is_log:
            label = tk.Label(frame, text=msg, fg="white", bg="#2C2F33", anchor="w", justify="left", font=("Courier", 14), wraplength=450)
            label.pack(anchor="w", padx=5, pady=2)
            frame.pack(anchor="w", fill="x")
        else:
            bubble_color = "#DCF8C6" if sent else "#FFFFFF"
            align = "e" if sent else "w"
            anchor = "e" if sent else "w"
            padx = (60, 10) if sent else (10, 60)
            bubble = tk.Label(frame, text=msg, bg=bubble_color, fg="black", wraplength=450, justify="left", font=("Arial", 14), padx=10, pady=6, bd=0)
            bubble.pack(anchor=align)
            frame.pack(anchor=anchor, padx=padx, pady=4)
        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)

    def send_message(self):
        """Send a message to the current peer."""
        msg = self.msg_entry.get().strip()
        if not msg or not self.peer:
            return
        sess = self.sessions.get(self.peer)
        if not sess or not sess.get("keys"):
            messagebox.showwarning("No session", "Session not established yet.")
            return
        self.outq.put(("chat", self.peer, msg))
        self.msg_entry.delete(0, tk.END)
        self.add_message_to_session(self.peer, "me", msg)
        if self.active_chat == self.peer:
            self.styled_append(f"You: {msg}", sent=True)

    def on_user_selected(self, event):
        """Handle user selection from the list."""
        selection = event.widget.curselection()
        if not selection:
            return
        idx = selection[0]
        peer = event.widget.get(idx)
        self.peer = peer
        self.active_chat = peer
        self.selected_index = idx
        self.show_chat(peer)
        self.update_session_status()

    def add_message_to_session(self, peer: str, who: str, text: str):
        """Store a message in the session history."""
        sess = self.sessions.setdefault(peer, {
            "keys": None, "send_counter": 0, "recv_counter": 0,
            "messages": [], "peer_identity_pub": None, "ek_priv": None, "initiator": False
        })
        sess["messages"].append((who, text))

    def show_chat(self, peer: str):
        """Display chat history for the selected peer."""
        for child in self.chat_inner.winfo_children():
            child.destroy()
        sess = self.sessions.get(peer)
        if not sess:
            return
        for who, text in sess["messages"]:
            if who == "me":
                self.styled_append(f"You: {text}", sent=True)
            elif who == "them":
                self.styled_append(f"{peer}: {text}", sent=False)
            else:
                self.styled_append(text, sent=False)

    def update_user_list(self, users):
        """Update the user list UI."""
        current_selection = self.user_listbox.curselection()
        selected_user = self.user_listbox.get(current_selection[0]) if current_selection else None
        self.user_listbox.delete(0, tk.END)
        for user in users:
            self.user_listbox.insert(tk.END, user)
        if selected_user and selected_user in users:
            idx = users.index(selected_user)
            self.user_listbox.selection_set(idx)
            self.user_listbox.activate(idx)
            self.selected_index = idx

    async def _main_async(self):
        """Main async loop: connect, register, and start tasks."""
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        try:
            async with websockets.connect(WS_URL, ssl=ssl_ctx, max_size=2**20) as ws:
                self.ws = ws
                await ws.send(json.dumps({"type": "hello", "user": self.username}))
                await ws.recv()
                await ws.send(json.dumps({"type": "register", "user": self.username, "identity_pubkey": b64e(self.pub)}))
                await ws.recv()
                await asyncio.gather(
                    self._recv_loop(ws),
                    self._send_loop(ws),
                    self._poll_user_list(ws)
                )
        except Exception as e:
            self.root.after(0, lambda: self.add_message_to_session("system", "info", f"[error] {e}"))

    async def _send_loop(self, ws):
        """Async send loop for outgoing messages."""
        while True:
            kind, peer, payload = await asyncio.get_event_loop().run_in_executor(None, self.outq.get)
            if kind == "chat" and peer:
                sess = self.sessions.get(peer)
                if not sess or not sess.get("keys"):
                    self.root.after(0, lambda: self.add_message_to_session(peer or "unknown", "info", "[error] Trying to send but no session keys available."))
                    continue
                ctr = sess.get("send_counter", 0)
                ad = f"{self.username}|{peer}|chat|{ctr}".encode()
                nonce, ct = aesgcm_encrypt(sess["keys"].send_key, ctr, ad, payload.encode())
                env = {
                    "type": "relay", "to": peer, "from": self.username,
                    "ciphertext": b64e(ct), "nonce": b64e(nonce),
                    "meta": {"kind": "chat", "ctr": ctr},
                }
                sess["send_counter"] = ctr + 1
                await ws.send(json.dumps(env))

    async def _recv_loop(self, ws):
        """Async receive loop for incoming messages and events."""
        while True:
            text = await ws.recv()
            msg = json.loads(text)
            mtype = msg.get("type")
            if mtype == "pubkey":
                user = msg.get("user")
                if not user:
                    continue
                sess = self.sessions.setdefault(user, {
                    "keys": None, "send_counter": 0, "recv_counter": 0,
                    "messages": [], "peer_identity_pub": None, "ek_priv": None, "initiator": False
                })
                if msg.get("identity_pubkey"):
                    sess["peer_identity_pub"] = b64d(msg["identity_pubkey"])
                    self.root.after(0, lambda u=user: self.add_message_to_session(u, "info", f"[info] Peer {u} fingerprint: {fingerprint(sess['peer_identity_pub'])}"))
                    pending = self.pending_handshake1.pop(user, None)
                    if pending:
                        await self._on_handshake1(pending)
                    if sess.get("initiator") and not sess.get("keys"):
                        await asyncio.sleep(0.05)
                        await self._start_handshake(user)
                else:
                    self.root.after(0, lambda: self.add_message_to_session(user, "info", f"[warn] Peer {user} has not registered yet."))
            elif mtype == "relay":
                sender = msg.get("from")
                if not sender:
                    continue
                meta = msg.get("meta", {}) or {}
                kind = meta.get("kind")
                if kind == "hs1":
                    sess = self.sessions.setdefault(sender, {
                        "keys": None, "send_counter": 0, "recv_counter": 0,
                        "messages": [], "peer_identity_pub": None, "ek_priv": None, "initiator": False
                    })
                    if not sess.get("peer_identity_pub"):
                        self.pending_handshake1[sender] = msg
                        asyncio.run_coroutine_threadsafe(self.request_peer_pubkey(sender), self.loop)
                    else:
                        await self._on_handshake1(msg)
                elif kind == "hs2":
                    await self._on_handshake2(msg)
                elif kind == "chat":
                    if self.active_chat != sender:
                        self.active_chat = sender
                        self.peer = sender
                        self.root.after(0, lambda s=sender: self.show_chat(s))
                    await self._on_chat(msg)
            elif mtype == "user_list":
                users = msg.get("users", [])
                if self.username in users:
                    users.remove(self.username)
                self.root.after(0, lambda: self.update_user_list(users))
            elif mtype == "chat_request" and msg.get("to") == self.username:
                peer = msg.get("from")
                sess = self.sessions.setdefault(peer, {
                    "keys": None, "send_counter": 0, "recv_counter": 0,
                    "messages": [], "peer_identity_pub": None, "ek_priv": None, "initiator": False
                })
                response = messagebox.askyesno("Chat Request", f"{peer} wants to chat. Accept?")
                asyncio.run_coroutine_threadsafe(self._send_chat_response(peer, response), self.loop)
                if response:
                    sess["initiator"] = False
                    asyncio.run_coroutine_threadsafe(self.request_peer_pubkey(peer), self.loop)
                    self.root.after(0, lambda p=peer: (
                        setattr(self, 'peer', p),
                        setattr(self, 'active_chat', p),
                        self.show_chat(p),
                        self.add_message_to_session(p, "info", f"[info] Chat accepted with {p}")
                    ))
            elif mtype == "chat_response" and msg.get("to") == self.username:
                peer = msg.get("from")
                accepted = msg.get("accepted", False)
                if accepted:
                    sess = self.sessions.setdefault(peer, {
                        "keys": None, "send_counter": 0, "recv_counter": 0,
                        "messages": [], "peer_identity_pub": None, "ek_priv": None, "initiator": True
                    })
                    sess["initiator"] = True
                    self.root.after(0, lambda p=peer: (
                        setattr(self, 'peer', p),
                        setattr(self, 'active_chat', p),
                        self.show_chat(p),
                        self.add_message_to_session(p, "info", f"[info] {p} accepted the chat.")
                    ))
                    asyncio.run_coroutine_threadsafe(self.request_peer_pubkey(peer), self.loop)
                else:
                    self.root.after(0, lambda p=peer: self.add_message_to_session(p, "info", f"[info] {p} declined the chat."))
            elif mtype == "chat_terminate" and msg.get("to") == self.username:
                peer_name = msg.get("from", "peer")
                self.root.after(0, lambda pn=peer_name: (
                    self._end_session(pn, local=False),
                    self.add_message_to_session(pn, "info", f"{pn} ended the chat."),
                    self.styled_append(f"{pn} ended the chat.", sent=False),
                    self.set_chat_controls_enabled(False),
                    self.update_session_status()
                ))

    async def _poll_user_list(self, ws):
        """Periodically request the user list."""
        while True:
            await ws.send(json.dumps({"type": "list_users"}))
            await asyncio.sleep(3)

    async def request_peer_pubkey(self, peer: str):
        """Request the public key of a peer."""
        await self.ws.send(json.dumps({"type": "get_pubkey", "user": peer}))

    async def _start_handshake(self, peer: str = None):
        """Initiate handshake with a peer."""
        if not peer:
            peer = self.peer
        if not peer:
            return
        sess = self.sessions.setdefault(peer, {
            "keys": None, "send_counter": 0, "recv_counter": 0,
            "messages": [], "peer_identity_pub": None, "ek_priv": None, "initiator": True
        })
        if sess.get("keys") or not sess.get("peer_identity_pub"):
            return
        ek_priv = generate_ephemeral()
        ek_pub_bytes = ek_priv.public_key().public_bytes_raw()
        sig = sign_ed25519(self.priv, ek_pub_bytes)
        sess["ek_priv"] = ek_priv
        env = {
            "type": "relay", "to": peer, "from": self.username,
            "nonce": "", "ciphertext": "",
            "meta": {"kind": "hs1", "ek_pub": b64e(ek_pub_bytes), "sig": b64e(sig), "initiator": True}
        }
        await self.ws.send(json.dumps(env))
        self.root.after(0, lambda p=peer: self.add_message_to_session(p, "info", "[info] Sent handshake init."))

    async def _on_handshake1(self, msg):
        """Handle handshake step 1 (responder)."""
        sender = msg.get("from")
        if not sender:
            return
        sess = self.sessions.setdefault(sender, {
            "keys": None, "send_counter": 0, "recv_counter": 0,
            "messages": [], "peer_identity_pub": None, "ek_priv": None, "initiator": False
        })
        ek_pub_peer = b64d(msg["meta"]["ek_pub"])
        sig_peer = b64d(msg["meta"]["sig"])
        if not sess.get("peer_identity_pub"):
            self.pending_handshake1[sender] = msg
            asyncio.run_coroutine_threadsafe(self.request_peer_pubkey(sender), self.loop)
            return
        if not verify_ed25519(sess["peer_identity_pub"], ek_pub_peer, sig_peer):
            self.root.after(0, lambda s=sender: self.add_message_to_session(s, "info", "[error] Handshake1 signature invalid. Possible MITM."))
            return
        my_ek = generate_ephemeral()
        ek_pub_bytes = my_ek.public_key().public_bytes_raw()
        sig = sign_ed25519(self.priv, ek_pub_bytes)
        shared = my_ek.exchange(x25519.X25519PublicKey.from_public_bytes(ek_pub_peer))
        keys = derive_session_keys(shared, initiator=False)
        sess.update({"keys": keys, "send_counter": 0, "recv_counter": 0, "ek_priv": my_ek, "initiator": False})
        self.root.after(0, lambda s=sender: (
            self.add_message_to_session(s, "info", "[info] Handshake complete (responder). You can chat."),
            self.set_chat_controls_enabled(True),
            self.update_session_status()
        ))
        reply = {
            "type": "relay", "to": sender, "from": self.username,
            "nonce": "", "ciphertext": "",
            "meta": {"kind": "hs2", "ek_pub": b64e(ek_pub_bytes), "sig": b64e(sig)}
        }
        await self.ws.send(json.dumps(reply))

    async def _on_handshake2(self, msg):
        """Handle handshake step 2 (initiator)."""
        sender = msg.get("from")
        if not sender:
            return
        sess = self.sessions.get(sender)
        if not sess or not sess.get("ek_priv"):
            return
        ek_pub_peer = b64d(msg["meta"]["ek_pub"])
        sig_peer = b64d(msg["meta"]["sig"])
        if not sess.get("peer_identity_pub"):
            asyncio.run_coroutine_threadsafe(self.request_peer_pubkey(sender), self.loop)
            return
        if not verify_ed25519(sess["peer_identity_pub"], ek_pub_peer, sig_peer):
            self.root.after(0, lambda s=sender: self.add_message_to_session(s, "info", "[error] Handshake2 signature invalid. Possible MITM."))
            return
        shared = sess["ek_priv"].exchange(x25519.X25519PublicKey.from_public_bytes(ek_pub_peer))
        keys = derive_session_keys(shared, initiator=True)
        sess.update({"keys": keys, "send_counter": 0, "recv_counter": 0, "initiator": True})
        self.root.after(0, lambda s=sender: (
            self.add_message_to_session(s, "info", "[info] Handshake complete (initiator). You can chat."),
            self.set_chat_controls_enabled(True),
            self.update_session_status()
        ))

    async def _on_chat(self, msg):
        """Handle incoming chat message."""
        sender = msg.get("from")
        if not sender:
            return
        sess = self.sessions.setdefault(sender, {
            "keys": None, "send_counter": 0, "recv_counter": 0,
            "messages": [], "peer_identity_pub": None, "ek_priv": None, "initiator": False
        })
        if not sess.get("keys"):
            self.root.after(0, lambda s=sender: self.add_message_to_session(s, "info", "[warn] Received chat before session established."))
            return
        try:
            ctr = int(msg["meta"]["ctr"])
            nonce = b64d(msg["nonce"])
            ct = b64d(msg["ciphertext"])
            ad = f"{sender}|{self.username}|chat|{ctr}".encode()
            pt = aesgcm_decrypt(sess["keys"].recv_key, nonce, ad, ct).decode()
            sess["recv_counter"] = max(sess.get("recv_counter", 0), ctr + 1)
            self.add_message_to_session(sender, "them", pt)
            if self.active_chat == sender:
                self.root.after(0, lambda s=sender, p=pt: self.styled_append(p, sent=False))
        except Exception as e:
            self.root.after(0, lambda: self.add_message_to_session(sender, "info", f"[error] Decrypt failed: {e}"))

    def start_chat(self):
        """Start a chat session with the selected peer."""
        if not self.peer:
            messagebox.showinfo("No peer selected", "Please select a user to chat with.")
            return
        sess = self.sessions.setdefault(self.peer, {
            "keys": None, "send_counter": 0, "recv_counter": 0,
            "messages": [], "peer_identity_pub": None, "ek_priv": None, "initiator": True
        })
        sess["initiator"] = True
        self.active_chat = self.peer
        asyncio.run_coroutine_threadsafe(self._send_chat_request(), self.loop)

    async def _send_chat_request(self):
        """Send a chat request to the selected peer."""
        await self.ws.send(json.dumps({
            "type": "chat_request", "to": self.peer, "from": self.username
        }))
        self.root.after(0, lambda p=self.peer: self.add_message_to_session(p, "info", f"[info] Chat request sent to {p}."))

    async def _send_chat_response(self, peer, accepted):
        """Send a chat response (accept/decline) to a peer."""
        await self.ws.send(json.dumps({
            "type": "chat_response", "to": peer, "from": self.username, "accepted": accepted
        }))

    def terminate_chat(self):
        """Terminate the current chat session."""
        if self.peer:
            peer = self.peer
            async def end_after_notify():
                await self._send_termination_notice(peer)
                self._end_session(peer, local=True)
            asyncio.run_coroutine_threadsafe(end_after_notify(), self.loop)

    def update_session_status(self):
        """Update the session status label."""
        attivi = [p for p, s in self.sessions.items() if s.get("keys")]
        if not attivi:
            self.session_status.config(text="🔓 Not connected", fg="red")
        elif len(attivi) == 1:
            self.session_status.config(text=f"🔐 Secure session with {attivi[0]}", fg="green")
        else:
            self.session_status.config(text="🔐 Secure session active", fg="green")

    def _end_session(self, peer, local=False):
        """End a session with a peer and update UI."""
        if peer in self.sessions:
            sess = self.sessions[peer]
            sess.update({"keys": None, "send_counter": 0, "recv_counter": 0, "ek_priv": None, "initiator": False})
        if self.active_chat == peer:
            altri = [p for p, s in self.sessions.items() if s.get("keys")]
            if altri:
                nuovo_peer = altri[0]
                self.active_chat = nuovo_peer
                self.peer = nuovo_peer
                self.show_chat(nuovo_peer)
            else:
                self.active_chat = None
                for child in self.chat_inner.winfo_children():
                    child.destroy()
        if local:
            self.add_message_to_session(peer, "info", "[info] Chat terminated.")
        self.set_start_button_enabled(True)
        attivi = [p for p, s in self.sessions.items() if s.get("keys")]
        self.terminate_chat_btn.config(state=tk.NORMAL if attivi else tk.DISABLED)
        self.set_chat_controls_enabled(bool(attivi))
        self.update_session_status()

    async def _send_termination_notice(self, peer):
        """Notify a peer that the chat is terminated."""
        await self.ws.send(json.dumps({
            "type": "chat_terminate", "from": self.username, "to": peer
        }))

    def set_chat_controls_enabled(self, enabled: bool):
        """Enable or disable chat controls."""
        state = tk.NORMAL if enabled else tk.DISABLED
        self.send_button.config(state=state)
        self.msg_entry.config(state=state)
        self.terminate_chat_btn.config(state=state)

    def set_start_button_enabled(self, enabled: bool):
        """Enable or disable the start chat button."""
        state = tk.NORMAL if enabled else tk.DISABLED
        self.start_chat_btn.config(state=state)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()