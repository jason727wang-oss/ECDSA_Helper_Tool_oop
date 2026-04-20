import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import os, re
import crypto_utils as cu  # 確保你的 cu 模組功能正確
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization


class ECTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding="10")
        self.last_cleared = None
        self.init_ui()

    def init_ui(self):
        # 設定三欄比例
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=1)

        # ==========================================
        # 第一欄 (左)：Key Management
        # ==========================================
        col1 = ttk.Frame(self)
        col1.grid(row=0, column=0, sticky="nsew", padx=10)

        curve_f = ttk.LabelFrame(col1, text="Curve & Basic Settings", padding="10")
        curve_f.pack(fill="x", pady=5)
        self.curve_var = tk.StringVar(value="P-384")
        self.curve_combo = ttk.Combobox(curve_f, textvariable=self.curve_var, values=["P-384", "P-256"],
                                        state="readonly")
        self.curve_combo.pack(fill="x", pady=5)

        tk.Button(curve_f, text="Generate New Key Pair", bg='#FFC003', command=self.generate_key).pack(fill="x")

        key_f = ttk.LabelFrame(col1, text="Key Management", padding="10")
        key_f.pack(fill="both", expand=True, pady=5)

        # PEM Private Key 區塊，增加綁定事件
        tk.Label(key_f, text="PEM Private Key").pack(anchor="w")
        self.pem_text = scrolledtext.ScrolledText(key_f, height=10, font=('Courier', 10))
        self.pem_text.pack(fill="x", pady=(0, 5))
        self.pem_text.bind("<<Paste>>", self.on_pem_paste)  # 核心功能：貼上自動解析

        tk.Label(key_f, text="Private Key (hex)").pack(anchor="w", pady=(10, 0))
        self.priv_text = scrolledtext.ScrolledText(key_f, height=5, font=('Courier', 10))
        self.priv_text.pack(fill="x", pady=(0, 15))
        self.priv_text.bind("<<Paste>>", self.on_paste_event)

        tk.Label(key_f, text="Public Key (X||Y hex)").pack(anchor="w")
        self.pub_text = scrolledtext.ScrolledText(key_f, height=5, font=('Courier', 10))
        self.pub_text.pack(fill="x", pady=(0, 5))
        self.pub_text.bind("<<Paste>>", self.on_paste_event)

        # ==========================================
        # 第二欄 (中)：Message & Signature
        # ==========================================
        col2 = ttk.Frame(self)
        col2.grid(row=0, column=1, sticky="nsew", padx=10)

        msg_f = ttk.LabelFrame(col2, text="Message & Hash Calculation", padding="10")
        msg_f.pack(fill="x", pady=5)

        m_sel = ttk.Frame(msg_f)
        m_sel.pack(anchor="w")
        self.msg_mode = tk.StringVar(value="Hex")
        ttk.Radiobutton(m_sel, text="Hex Mode", variable=self.msg_mode, value="Hex", command=self.clear_msg).pack(
            side="left")
        ttk.Radiobutton(m_sel, text="Text Mode", variable=self.msg_mode, value="Text", command=self.clear_msg).pack(
            side="left", padx=10)

        self.msg_text = scrolledtext.ScrolledText(msg_f, height=8, font=('Courier', 10))
        self.msg_text.pack(fill="x", pady=5)
        self.msg_text.bind("<Key>", self.filter_hex_input)
        self.msg_text.bind("<KeyRelease>", lambda e: self.update_tbs())
        self.msg_text.bind("<<Paste>>", self.on_paste_event)

        tk.Button(msg_f, text="Hash Large File", bg='#9FFFFB', command=self.calc_file_hash).pack(fill="x", pady=2)

        tk.Label(msg_f, text="TBS Hash (To Be Signed)").pack(anchor="w")
        self.tbs_text = scrolledtext.ScrolledText(msg_f, height=4, font=('Courier', 10))
        self.tbs_text.pack(fill="x", pady=(0, 5))
        self.tbs_text.bind("<<Paste>>", self.on_paste_event)

        sig_f = ttk.LabelFrame(col2, text="Signature Result", padding="10")
        sig_f.pack(fill="both", expand=True, pady=5)

        self.sig_fmt = tk.StringVar(value="RS Raw")
        fmt_f = ttk.Frame(sig_f)
        fmt_f.pack(fill="x")
        ttk.Radiobutton(fmt_f, text="RS Raw", variable=self.sig_fmt, value="RS Raw",
                        command=self.on_sig_fmt_change).pack(side="left")
        ttk.Radiobutton(fmt_f, text="DER Hex", variable=self.sig_fmt, value="DER Hex",
                        command=self.on_sig_fmt_change).pack(side="left", padx=10)

        self.sig_text = scrolledtext.ScrolledText(sig_f, height=6, font=('Courier', 10))
        self.sig_text.pack(fill="x", pady=5)
        self.sig_text.bind("<<Paste>>", self.on_paste_event)

        ctrl_f = ttk.Frame(col2)
        ctrl_f.pack(fill="x", pady=10)
        tk.Button(ctrl_f, text="SIGN", font=('Helvetica', 10, 'bold'), bg='#02FF83', height=2,
                  command=self.sign_data).pack(side="left", expand=True, fill="x", padx=2)
        tk.Button(ctrl_f, text="VERIFY", font=('Helvetica', 10, 'bold'), bg='#04D5FF', height=2,
                  command=self.verify_data).pack(side="left", expand=True, fill="x", padx=2)

        # ==========================================
        # 第三欄 (右)：Output Console
        # ==========================================
        col3 = ttk.Frame(self)
        col3.grid(row=0, column=2, sticky="nsew", padx=10)

        action_f = ttk.LabelFrame(col3, text="Quick Actions", padding="10")
        action_f.pack(fill="x", pady=5)
        tk.Button(action_f, text="Clean All Fields / Undo", bg='#F0F0F0', command=self.clean_all).pack(fill="x")

        log_f = ttk.LabelFrame(col3, text="Output Console", padding="10")
        log_f.pack(fill="both", expand=True, pady=5)
        self.out_text = scrolledtext.ScrolledText(log_f, state="disabled", font=('Courier', 10), bg="#1E1E1E",
                                                  fg="#FFFFFF")
        self.out_text.pack(fill="both", expand=True)

    # --- Logic Functions ---
    def on_pem_paste(self, event):
        """處理 PEM 貼上事件：自動辨識曲線、填寫 Hex"""
        self.after(100, self.parse_pem_and_sync_ui)

    def parse_pem_and_sync_ui(self):
        pem_str = self.pem_text.get("1.0", tk.END).strip()
        if not pem_str: return

        try:
            # 1. 載入金鑰
            private_key = serialization.load_pem_private_key(pem_str.encode(), password=None)

            # 2. 辨識曲線
            curve_obj = private_key.curve
            detected_curve = ""
            if isinstance(curve_obj, ec.SECP384R1):
                detected_curve = "P-384"
            elif isinstance(curve_obj, ec.SECP256R1):
                detected_curve = "P-256"

            if detected_curve:
                self.curve_var.set(detected_curve)
                self.out_print(f"💡 Auto-detected Curve: {detected_curve}")
            else:
                self.out_print("⚠️ Unknown Curve Type in PEM")
                return

            # 3. 更新介面 Hex
            _, _, bl = cu.get_curve_settings(detected_curve)
            priv_val = private_key.private_numbers().private_value
            self.priv_text.delete("1.0", tk.END)
            self.priv_text.insert(tk.END, f"{priv_val:0{bl * 2}x}")

            pub = private_key.public_key().public_numbers()
            self.pub_text.delete("1.0", tk.END)
            self.pub_text.insert(tk.END, f"{pub.x:0{bl * 2}x}{pub.y:0{bl * 2}x}")

            self.out_print(f"✅ PEM loaded for {detected_curve}")
            self.update_tbs()  # 連動更新 Hash

        except Exception as e:
            self.out_print(f"❌ PEM Parse Error: {e}")

    def out_print(self, msg):
        self.out_text.configure(state="normal")
        self.out_text.insert(tk.END, msg + "\n")
        tag = "green" if "✅" in msg else "red" if "❌" in msg else "yellow" if "💡" in msg else "white"
        self.out_text.tag_add(tag, "end-2c linestart", "end-2c lineend")
        self.out_text.tag_config("green", foreground="#00FF00")
        self.out_text.tag_config("red", foreground="#FF4444")
        self.out_text.tag_config("yellow", foreground="#FFFF00")
        self.out_text.tag_config("white", foreground="#FFFFFF")
        self.out_text.see(tk.END)
        self.out_text.configure(state="disabled")

    def filter_hex_input(self, event):
        if self.msg_mode.get() == "Hex":
            if event.keysym in ("BackSpace", "Delete", "Left", "Right", "Tab", "Return"): return None
            if event.state & 0x4: return None  # Ctrl
            if not re.match(r'[0-9a-fA-F]', event.char): return "break"

    def on_paste_event(self, event):
        if event.widget == self.msg_text and self.msg_mode.get() == "Text": return None
        try:
            cb = self.master.clipboard_get()
            clean = "".join(cb.split())
            event.widget.insert(tk.INSERT, clean)
            if event.widget == self.msg_text: self.update_tbs()
            return "break"
        except:
            pass

    def clear_msg(self):
        self.msg_text.delete("1.0", tk.END)
        self.tbs_text.delete("1.0", tk.END)

    def update_tbs(self):
        try:
            raw = self.msg_text.get("1.0", tk.END).strip()
            if not raw: self.tbs_text.delete("1.0", tk.END); return
            curve, h, _ = cu.get_curve_settings(self.curve_var.get())
            d = hashes.Hash(h)
            data = bytes.fromhex(cu.only_hex_filter(raw)) if self.msg_mode.get() == "Hex" else raw.encode()
            d.update(data)
            self.tbs_text.delete("1.0", tk.END)
            self.tbs_text.insert(tk.END, d.finalize().hex())
        except:
            pass

    def calc_file_hash(self):
        path = filedialog.askopenfilename(filetypes=[("Files", "*.hex;*.txt")])
        if not path: return
        try:
            _, h, _ = cu.get_curve_settings(self.curve_var.get())

            # 檢查副檔名
            is_hex = path.lower().endswith(('.hex'))

            if is_hex:
                # --- 處理文字格式的 Hex 檔案 ---
                with open(path, "r", encoding="utf-8") as f:
                    # 讀取全文，並移除換行、空白（這對從 Log 貼出來的資料很重要）
                    hex_string = f.read().replace(" ", "").replace("\n", "").replace("\r", "").strip()

                    # 確保長度是偶數，否則 bytes.fromhex 會報錯
                    if len(hex_string) % 2 != 0:
                        hex_string = hex_string[:-1]  # 或者補 '0'，視你的需求而定

                    file_data = bytes.fromhex(hex_string)

                # 直接計算 Hash
                d = hashes.Hash(h)
                d.update(file_data)
                final_digest = d.finalize().hex()
            else:
                # (.txt) ---
                d = hashes.Hash(h)
                with open(path, "rb") as f:
                    while chunk := f.read(2 * 1024 * 1024):
                        d.update(chunk)
                final_digest = d.finalize().hex()

            # 更新 UI
            self.tbs_text.delete("1.0", tk.END)
            self.tbs_text.insert(tk.END, final_digest)
            self.out_print(
                f"✅ Hash Calculation Complete ({'Hex' if is_hex else 'Text'}): {os.path.basename(path)}")

        except Exception as e:
            self.out_print(f"❌ Error during Hash: {e}")

    def generate_key(self):
        curve, _, bl = cu.get_curve_settings(self.curve_var.get())
        pk = ec.generate_private_key(curve)
        pem = pk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                               serialization.NoEncryption())
        self.pem_text.delete("1.0", tk.END)
        self.pem_text.insert(tk.END, pem.decode())
        self.priv_text.delete("1.0", tk.END)
        self.priv_text.insert(tk.END, f"{pk.private_numbers().private_value:0{bl * 2}x}")
        pub = pk.public_key().public_numbers()
        self.pub_text.delete("1.0", tk.END)
        self.pub_text.insert(tk.END, f"{pub.x:0{bl * 2}x}{pub.y:0{bl * 2}x}")
        self.out_print(f"✅ New {self.curve_var.get()} Key Pair Generated")

    def on_sig_fmt_change(self):
        curr = self.sig_text.get("1.0", tk.END).strip()
        if not curr: return
        try:
            new_val = cu.convert_sig(curr, self.sig_fmt.get(), self.curve_var.get())
            self.sig_text.delete("1.0", tk.END)
            self.sig_text.insert(tk.END, new_val)
            self.out_print("💡 Signature format converted.")
        except:
            self.sig_text.delete("1.0", tk.END)
            self.out_print("❌ Invalid format for conversion, cleared.")

    def sign_data(self):
        try:
            priv_hex = cu.only_hex_filter(self.priv_text.get("1.0", tk.END))
            tbs_hex = cu.only_hex_filter(self.tbs_text.get("1.0", tk.END))
            curve, h, bl = cu.get_curve_settings(self.curve_var.get())
            key = ec.derive_private_key(int(priv_hex, 16), curve)
            sig = key.sign(bytes.fromhex(tbs_hex), ec.ECDSA(utils.Prehashed(h)))
            if self.sig_fmt.get() == "RS Raw":
                r, s = utils.decode_dss_signature(sig)
                sig = r.to_bytes(bl, "big") + s.to_bytes(bl, "big")
            self.sig_text.delete("1.0", tk.END)
            self.sig_text.insert(tk.END, sig.hex())
            self.out_print("✅ Sign Successful")
        except Exception as e:
            self.out_print(f"❌ Sign Error: {e}")

    def verify_data(self):
        try:
            pub_hex = cu.only_hex_filter(self.pub_text.get("1.0", tk.END))
            sig_hex = cu.only_hex_filter(self.sig_text.get("1.0", tk.END))
            tbs_hex = cu.only_hex_filter(self.tbs_text.get("1.0", tk.END))
            curve, h, bl = cu.get_curve_settings(self.curve_var.get())
            pk = ec.EllipticCurvePublicNumbers(int(pub_hex[:bl * 2], 16), int(pub_hex[bl * 2:], 16), curve).public_key()
            sig = bytes.fromhex(sig_hex)
            if self.sig_fmt.get() == "RS Raw":
                sig = utils.encode_dss_signature(int.from_bytes(sig[:bl], "big"), int.from_bytes(sig[bl:], "big"))
            pk.verify(sig, bytes.fromhex(tbs_hex), ec.ECDSA(utils.Prehashed(h)))
            self.out_print("✅ Signature Valid")
        except:
            self.out_print("❌ Signature Invalid")

    def clean_all(self):
        widgets = [self.pem_text, self.priv_text, self.pub_text, self.msg_text, self.tbs_text, self.sig_text]
        if not any(w.get("1.0", tk.END).strip() for w in widgets) and self.last_cleared:
            for w, content in zip(widgets, self.last_cleared): w.insert(tk.END, content)
            self.last_cleared = None
            self.out_print("✅ Undo Successful")
        else:
            self.last_cleared = [w.get("1.0", tk.END) for w in widgets]
            for w in widgets: w.delete("1.0", tk.END)
            self.out_text.configure(state="normal")
            self.out_text.delete("1.0", tk.END)
            self.out_text.configure(state="disabled")
            self.out_print("Input cleared. Click again to Undo.")