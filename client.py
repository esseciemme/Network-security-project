import os
import tkinter as tk
from tkinter import simpledialog, messagebox, font
from threading import Thread
import asyncio, websockets, ssl, json, queue
from cryptography.hazmat.primitives.asymmetric import x25519
from common.crypto_utils import (
    load_or_create_identity, fingerprint,
    sign_ed25519, verify_ed25519, generate_ephemeral,
    derive_session_keys, aesgcm_encrypt, aesgcm_decrypt, b64e, b64d, unwrap_secret_with_priv, derive_group_sender_key,
    wrap_secret_for_pub
)

HOST = "127.0.0.1"
PORT = 8443
WS_URL = f"wss://{HOST}:{PORT}"

class ChatClient:
    def __init__(self, root: tk.Tk):
        """Initialize UI and networking."""
        self.root = root
        self.root.title("Secure E2EE Chat Client")
        self.root.geometry("750x720")
        self.root.configure(bg="#2C2F33")

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

        # Broadcast group state
        self.GROUP_ID = "broadcast"
        self.BROADCAST_ITEM = "Broadcast"
        self.group = {
            "joined": False,
            "epoch": 0,
            "epoch_secret": None,  # bytes
            "members": [],  # list[str]
            "my_ecdh": generate_ephemeral(),  # long-lived per-install is fine too
            "send_counter": 0,  # my group message counter
        }

        self.dir_x25519 = {}
        self.dir_ecdh_priv = generate_ephemeral()
        self.dir_ecdh_pub = self.dir_ecdh_priv.public_key().public_bytes_raw()
        self.dir_x25519[self.username] = self.dir_ecdh_pub

        # Show tutorial before setting up the main UI
        self._show_tutorial()

        self._setup_ui()
        self.ws = None
        self.outq = queue.Queue()  # Queue for outgoing messages
        self.loop = asyncio.new_event_loop()
        Thread(target=lambda: self.loop.run_until_complete(self._main_async()), daemon=True).start()
        self.msg_entry.focus()

    def _show_tutorial(self):
        """Display a tutorial dialog explaining how to use the application."""

        tutorial_window = tk.Toplevel(self.root)
        tutorial_window.title("📚 Welcome to Secure Chat")
        tutorial_window.geometry("650x550")
        tutorial_window.configure(bg="#2C2F33")
        tutorial_window.resizable(False, False)
        tutorial_window.transient(self.root)
        tutorial_window.grab_set()
        tutorial_window.update_idletasks()
        width = tutorial_window.winfo_width()
        height = tutorial_window.winfo_height()
        x = (tutorial_window.winfo_screenwidth() // 2) - (width // 2)
        y = (tutorial_window.winfo_screenheight() // 2) - (height // 2)
        tutorial_window.geometry(f'{width}x{height}+{x}+{y}')

        # Main container with padding
        main_container = tk.Frame(tutorial_window, bg="#2C2F33", padx=25, pady=25)
        main_container.pack(fill=tk.BOTH, expand=True)

        # Header
        header_frame = tk.Frame(main_container, bg="#2C2F33")
        header_frame.pack(fill=tk.X, pady=(0, 20))
        icon_label = tk.Label(header_frame, text="🔐", font=("Arial", 48), bg="#2C2F33")
        icon_label.pack(side=tk.LEFT, padx=(0, 15))

        title_frame = tk.Frame(header_frame, bg="#2C2F33")
        title_frame.pack(side=tk.LEFT, fill=tk.Y)
        main_title = tk.Label(title_frame, text="Secure E2EE Chat", font=("Arial", 20, "bold"), fg="white", bg="#2C2F33")
        main_title.pack(anchor="w")
        subtitle = tk.Label(title_frame, text="End-to-End Encrypted Messaging", font=("Arial", 11), fg="#7289DA", bg="#2C2F33")
        subtitle.pack(anchor="w", pady=(2, 0))

        # Content frame with sections
        content_frame = tk.Frame(main_container, bg="#23272A", padx=20, pady=20)
        content_frame.pack(fill=tk.BOTH, expand=True)
        canvas = tk.Canvas(content_frame, bg="#23272A", highlightthickness=0)
        scrollbar = tk.Scrollbar(content_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#23272A")
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        sections = [
            {
                "title": "🔑 Getting Started",
                "content": "Welcome to your secure messaging application! This guide will help you understand how to use all features."
            },
            {
                "title": "👥 Individual Chats",
                "content": "• Select any user from the 'Active Users' list\n• Click 'Start Chat' to initiate a conversation\n• Wait for your peer to accept the request\n• Exchange end-to-end encrypted messages securely\n• Click 'End Chat' to terminate the chat."
            },
            {
                "title": "📢 Broadcast Chat",
                "content": "• Select 'Broadcast' from the user list\n• Click 'Start Chat' to join the group\n• Send messages visible to all group members\n• Click 'End Chat' to leave the group."
            },
            {
                "title": "🛡️ Security Features",
                "content": "• End-to-end encryption protects all messages\n• Unique fingerprints verify user identities\n• X25519 key exchange prevents MITM attacks\n• TLS transport security for network protection"
            }
        ]

        for section in sections:

            title_label = tk.Label(scrollable_frame, text=section["title"], font=("Arial", 14, "bold"), fg="#7289DA", bg="#23272A", anchor="w")
            title_label.pack(fill=tk.X, pady=(0, 8))
            content_label = tk.Label(scrollable_frame, text=section["content"], font=("Arial", 10), fg="white", bg="#23272A", justify="left", wraplength=500, anchor="w")
            content_label.pack(fill=tk.X, pady=(0, 20))

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        button_frame = tk.Frame(main_container, bg="#2C2F33")
        button_frame.pack(fill=tk.X, pady=(20, 0))

        def on_enter(e):
            ok_button.config(bg="#5B6EAE", relief=tk.RAISED, bd=2)

        def on_leave(e):
            ok_button.config(bg="#7289DA", relief=tk.FLAT, bd=0)

        ok_button = tk.Button(button_frame, text="🚀 Start Using the App", command=tutorial_window.destroy, bg="#7289DA", fg="white", activebackground="#5B6EAE", activeforeground="white", font=("Arial", 12, "bold"), padx=30, pady=12, bd=0, relief=tk.FLAT, cursor="hand2")
        ok_button.pack()
        ok_button.bind("<Enter>", on_enter)
        ok_button.bind("<Leave>", on_leave)

        # Footer
        footer_label = tk.Label(main_container, text="Happy chatting! 🎉", font=("Arial", 9), fg="#99AAB5", bg="#2C2F33")
        footer_label.pack(pady=(10, 0))

        self.root.wait_window(tutorial_window)

    def _setup_ui(self):
        """Builds the main UI layout."""
        main_frame = tk.Frame(self.root, bg="#2C2F33")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Identity and session status
        identity_frame = tk.LabelFrame(main_frame, text="Your Identity", padx=10, pady=5, bg="#23272A", fg="white")
        identity_frame.pack(fill=tk.X, pady=5)
        username_font = font.Font(family="Helvetica", size=14, weight="bold")
        mono = font.Font(family="Courier", size=12)
        self.username_label = tk.Label(identity_frame, text=f"Username: {self.username}", font=username_font,fg="white", bg="#23272A")
        self.username_label.pack(anchor="w", pady=(0, 5))
        self.identity_label = tk.Label(identity_frame, text=f"Fingerprint: {fingerprint(self.pub)}", font=mono,fg="white", bg="#23272A")
        self.identity_label.pack(anchor="w")
        tk.Label(identity_frame, text="Verify fingerprints out-of-band with your peer to defeat MITM.", fg="gray",bg="#23272A").pack(anchor="w")
        self.session_status = tk.Label(identity_frame, text="🔓 Not connected", fg="red", bg="#23272A")
        self.session_status.pack(anchor="w", pady=(2, 0))

        # Active users area
        mid_frame = tk.Frame(main_frame, bg="#2C2F33")
        mid_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        users_frame = tk.LabelFrame(mid_frame, text="Active Users", padx=5, pady=5, bg="#23272A", fg="white")
        users_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        self.user_listbox = tk.Listbox(users_frame, height=15, width=20, font=("Arial", 12), bg="#23272A", fg="white",selectbackground="#7289DA", selectforeground="white")
        self.user_listbox.pack(fill=tk.BOTH, expand=True)
        self.user_listbox.bind("<<ListboxSelect>>", self.on_user_selected)
        self.start_chat_btn = tk.Button(users_frame, text="Start Chat", command=self.start_chat, bg="#7289DA", fg="black", activebackground="#5B6EAE", activeforeground="white", bd=0)
        self.start_chat_btn.pack(fill=tk.X, pady=5)
        self.terminate_chat_btn = tk.Button(users_frame, text="End Chat", command=self.terminate_chat, bg="#F04747", fg="black", activebackground="#C03A3A", activeforeground="white", bd=0)
        self.terminate_chat_btn.pack(fill=tk.X)

        # Chat area
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
        input_frame = tk.Frame(main_frame, bg="#2C2F33")
        input_frame.pack(fill=tk.X, pady=5)
        self.msg_entry = tk.Entry(input_frame, bg="#23272A", fg="white", insertbackground="white")
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.send_button = tk.Button(input_frame, text="Send", command=self.send_message, bg="#7289DA", fg="black", activebackground="#99AAB5", activeforeground="white", bd=0, font=("Segoe UI", 10, "bold"), padx=10, pady=5)
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
        """Send a message to the current peer or broadcast."""
        msg = self.msg_entry.get().strip()
        if not msg:
            return
        if self.active_chat == self.BROADCAST_ITEM:
            if not self.group["joined"] or not self.group["epoch_secret"]:
                messagebox.showwarning("Broadcast", "Join the broadcast chat first.")
                return
            # Send broadcast message
            asyncio.run_coroutine_threadsafe(self.group_send(msg), self.loop)
            self.msg_entry.delete(0, tk.END)
            # Persist in session history so reopening shows past messages
            self.add_message_to_session(self.BROADCAST_ITEM, "me", msg)
            self.styled_append(f"You: {msg}", sent=True)
        elif self.peer:
            # Send direct message
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
        if peer == self.BROADCAST_ITEM:
            self.peer = None
            self.active_chat = self.BROADCAST_ITEM
            self.selected_index = idx
            self.show_broadcast()
            self.update_session_status()
            return
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
        self.update_session_status()

    def show_broadcast(self):
        """Display broadcast history/status."""
        for child in self.chat_inner.winfo_children():
            child.destroy()
        joined = self.group["joined"]
        status = "IN" if joined else "NOT IN"
        self.styled_append(f"[broadcast] You are {status} the broadcast chat.", sent=False)
        if joined:
            self.set_chat_controls_enabled(True)
            for who, text in self.sessions.get(self.BROADCAST_ITEM, {}).get("messages", []):
                if who == "me":
                    self.styled_append(f"You: {text}", sent=True)
                elif who == "them":
                    self.styled_append(text, sent=False)
                else:
                    self.styled_append(text, sent=False)
        else:
            self.set_chat_controls_enabled(False)
        self.update_session_status()


    def update_user_list(self, users):
        """Update the user list UI (includes the [Broadcast] pseudo-user)."""
        current_selection = self.user_listbox.curselection()
        selected_user = self.user_listbox.get(current_selection[0]) if current_selection else None

        # Ensure broadcast item is always first
        users = [u for u in users if u != self.username]
        display = [self.BROADCAST_ITEM] + users

        self.user_listbox.delete(0, tk.END)
        for user in display:
            self.user_listbox.insert(tk.END, user)
        if selected_user and selected_user in display:
            idx = display.index(selected_user)
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
                await ws.send(json.dumps({
                    "type": "register",
                    "user": self.username,
                    "identity_pubkey": b64e(self.pub),
                    "x25519_pubkey": b64e(self.dir_ecdh_pub)
                }))
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
                identity_b64 = msg.get("identity_pubkey")
                xpub_b64 = msg.get("x25519_pubkey")
                if identity_b64:
                    sess["peer_identity_pub"] = b64d(identity_b64)
                    self.root.after(0, lambda u=user: self.add_message_to_session(u, "info", f"[info] Peer {u} fingerprint: {fingerprint(sess['peer_identity_pub'])}"))
                    pending = self.pending_handshake1.pop(user, None)
                    if pending:
                        await self._on_handshake1(pending)
                    if sess.get("initiator") and not sess.get("keys"):
                        await asyncio.sleep(0.05)
                        await self._start_handshake(user)
                else:
                    self.root.after(0, lambda: self.add_message_to_session(user, "info", f"[warn] Peer {user} has not registered yet."))
                # Store X25519 directory pubkey independently if present
                if xpub_b64:
                    try:
                        self.dir_x25519[user] = b64d(xpub_b64)
                    except Exception:
                        pass
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
            elif mtype == "group_members":
                members = msg.get("members", [])
                joining = not self.group["joined"]
                if joining:
                    new_members = sorted(list(set(members + [self.username])))
                else:
                    new_members = sorted([u for u in members if u != self.username])
                asyncio.create_task(self._commit_membership(new_members, joining))
            elif mtype == "group_commit":
                if msg.get("group") != self.GROUP_ID:
                    continue
                payload = {k: msg[k] for k in ["type","group","epoch","members","enc_epoch_keys"] if k in msg}
                # For demo purposes we don't strictly verify committer's identity here
                # In a full system, you'd verify against the committer’s identity pubkey. For demo, accept if we can unwrap.
                enc_map = msg.get("enc_epoch_keys", {})
                blob = enc_map.get(self.username)
                if blob:
                    try:
                        new_secret = unwrap_secret_with_priv(blob, self.dir_ecdh_priv)
                        self.group["epoch_secret"] = new_secret
                        self.group["epoch"] = int(msg.get("epoch", self.group["epoch"] + 1))
                        self.group["members"] = msg.get("members", self.group["members"])
                        self.group["joined"] = (self.username in self.group["members"])
                        self.group["send_counter"] = 0
                        if self.active_chat == self.BROADCAST_ITEM:
                            self.root.after(0, lambda: self.styled_append(
                                f"[broadcast] New epoch: {self.group['epoch']} (members: {', '.join(self.group['members'])})", sent=False
                            ))
                    except Exception as e:
                        # Not for us or unwrap failed; ignore
                        pass

            elif mtype == "group_message":
                if msg.get("group") != self.GROUP_ID:
                    continue
                sender = msg.get("from")
                if not self.group["joined"] or not self.group["epoch_secret"]:
                    continue
                try:
                    ctr = int(msg["ctr"])
                    nonce = b64d(msg["nonce"])
                    ct = b64d(msg["ciphertext"])
                    key = derive_group_sender_key(self.group["epoch_secret"], self.GROUP_ID, sender)
                    ad = f"{self.GROUP_ID}|{sender}|{ctr}".encode()
                    pt = aesgcm_decrypt(key, nonce, ad, ct).decode()
                    self.add_message_to_session(self.BROADCAST_ITEM, "them", f"{sender}: {pt}")
                    if self.active_chat == self.BROADCAST_ITEM:
                        self.root.after(0, lambda p=pt, s=sender: self.styled_append(f"{s}: {p}", sent=False))
                except Exception as e:
                    self.root.after(0, lambda: self.styled_append(f"[broadcast] decrypt error: {e}", sent=False))

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
        """Start a chat session with the selected peer or join the broadcast chat."""
        if not self.peer and self.active_chat == self.BROADCAST_ITEM:
            # Join the broadcast chat
            asyncio.run_coroutine_threadsafe(self.group_join(), self.loop)
            self.add_message_to_session(self.BROADCAST_ITEM, "info", "[info] Joined the broadcast chat.")
            self.show_broadcast()
            return

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
        """Terminate the current chat session or leave the broadcast chat."""
        if self.active_chat == self.BROADCAST_ITEM:
            # Leave the broadcast chat
            asyncio.run_coroutine_threadsafe(self.group_leave(), self.loop)
            self.add_message_to_session(self.BROADCAST_ITEM, "info", "[info] Left the broadcast chat.")
            self.show_broadcast()
            return

        if self.peer:
            peer = self.peer

            async def end_after_notify():
                await self._send_termination_notice(peer)
                self._end_session(peer, local=True)

            asyncio.run_coroutine_threadsafe(end_after_notify(), self.loop)

    def update_session_status(self):
        """Update the session status label."""
        if self.active_chat == self.BROADCAST_ITEM:
            if self.group["joined"]:
                self.session_status.config(text="🔐 Connected to the broadcast chat", fg="green")
            else:
                self.session_status.config(text="🔓 Not connected to broadcast", fg="red")
        elif self.active_chat:
            sess = self.sessions.get(self.active_chat)
            if sess and sess.get("keys"):
                self.session_status.config(text=f"🔐 Secure session with {self.active_chat}", fg="green")
            else:
                self.session_status.config(text="🔓 Not connected", fg="red")
        else:
            self.session_status.config(text="🔓 Not connected", fg="red")

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

    async def _ensure_x25519_directory_published(self):
        # Already published at login; nothing to do here, kept for symmetry
        return

    async def _send_termination_notice(self, peer):
        """Notify a peer that the chat is terminated."""
        await self.ws.send(json.dumps({
            "type": "chat_terminate", "from": self.username, "to": peer
        }))

    async def _commit_membership(self, new_members: list[str], joining: bool):
        """
        Build and send a group_commit while allowing the recv loop to process
        pubkey responses in parallel. Updates local state optimistically.
        """
        await self._ensure_x25519_directory_published()

        # Require directory keys for all existing members so everyone can decrypt immediately
        if joining:
            required = [u for u in new_members if u != self.username]
        else:
            required = list(new_members)
        payload, epoch_secret = await self._make_epoch_commit(new_members, require_all_of=required)

        # Update local state before sending so we can send/receive immediately
        self.group["epoch"] = payload["epoch"]
        self.group["epoch_secret"] = epoch_secret
        self.group["members"] = new_members
        self.group["joined"] = joining
        self.group["send_counter"] = 0

        try:
            await self.ws.send(json.dumps(payload))
        except Exception:
            pass
        self.root.after(0, lambda: self.styled_append(
            f"[broadcast] {'Joined' if joining else 'Left'}; epoch -> {payload['epoch']}", sent=False
        ))
        if self.active_chat == self.BROADCAST_ITEM:
            self.set_chat_controls_enabled(joining)

    async def group_join(self):
        """
        Join flow:
          1) Ask server for current members.
          2) Act as committer: generate new epoch_secret, include ourselves, and send GROUP_COMMIT
             with epoch_secret wrapped to each member (including us).
        """
        await self.ws.send(json.dumps({"type": "group_join"}))

    async def group_leave(self):
        """
        Leave flow:
          1) Ask server for current members.
          2) Act as committer to exclude ourselves and rekey remaining members.
        """
        await self.ws.send(json.dumps({"type": "group_leave"}))

    async def _make_epoch_commit(self, members: list[str], require_all_of: list[str] | None = None):
        """
        Create a GROUP_COMMIT message:
          - generate epoch_secret
          - ensure peers' X25519 directory keys are available (request + brief wait)
          - wrap to each member's X25519 pubkey
          - sign the commit envelope with our Ed25519 identity (authenticity)
        Returns (payload, epoch_secret).
        """
        epoch_secret = os.urandom(32)
        enc_epoch_keys = {}

        # Ensure session entries exist
        for u in members:
            self.sessions.setdefault(u, {
                "keys": None, "send_counter": 0, "recv_counter": 0,
                "messages": [], "peer_identity_pub": None, "ek_priv": None, "initiator": False
            })

        # Request missing X25519 directory pubkeys and wait briefly
        targets = require_all_of if require_all_of is not None else members
        missing = [u for u in targets if u not in self.dir_x25519]
        if missing:
            for u in missing:
                try:
                    await self.ws.send(json.dumps({"type": "get_pubkey", "user": u}))
                except Exception:
                    pass
            # Wait up to ~1s for directory replies
            for _ in range(20):
                await asyncio.sleep(0.05)
                missing = [u for u in targets if u not in self.dir_x25519]
                if not missing:
                    break

        # Build enc map for known users only (others will be included in a future epoch)
        for u in members:
            xpub = self.dir_x25519.get(u)
            if not xpub:
                continue
            enc_epoch_keys[u] = wrap_secret_for_pub(epoch_secret, xpub)

        payload = {
            "type": "group_commit",
            "group": self.GROUP_ID,
            "epoch": self.group["epoch"] + 1,
            "members": members,
            "enc_epoch_keys": enc_epoch_keys
        }
        to_sign = json.dumps(payload, sort_keys=True).encode()
        payload["sig"] = b64e(sign_ed25519(self.priv, to_sign))
        return payload, epoch_secret

    async def group_send(self, text: str):
        """Encrypt and send a broadcast message to all current members via the server."""
        key = derive_group_sender_key(self.group["epoch_secret"], self.GROUP_ID, self.username)
        ctr = self.group["send_counter"]
        ad = f"{self.GROUP_ID}|{self.username}|{ctr}".encode()
        nonce, ct = aesgcm_encrypt(key, ctr, ad, text.encode())
        self.group["send_counter"] += 1
        env = {
            "type": "group_message",
            "group": self.GROUP_ID,
            "from": self.username,
            "ctr": ctr,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ct),
        }
        await self.ws.send(json.dumps(env))

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
