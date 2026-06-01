import hashlib
import os
import re
import shutil
import subprocess
import sys
import configparser
from datetime import datetime, timezone
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog

# 確保已安裝 cryptography 庫：pip install cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448

CONFIG_FILE = "config.ini"


class SPDMParserTab(ttk.Frame):

    def __init__(self, notebook):
        super().__init__(notebook)
        self.pack(fill="both", expand=True)

        # 💡 載入設定檔
        self.config = configparser.ConfigParser()
        self.load_config()

        self._create_widgets()

    def load_config(self):
        """讀取或初始化設定檔"""
        if os.path.exists(CONFIG_FILE):
            try:
                self.config.read(CONFIG_FILE, encoding="utf-8")
            except:
                pass

        if 'Paths' not in self.config:
            self.config['Paths'] = {
                'source': r"C:\Users\jason\PycharmProjects\ft4222_as_host_cnfmod2_cli\dist\spdm.log",
                'target': os.path.abspath("spdm.log")
            }

    def save_config(self):
        """將目前 UI 上的路徑存入 config.ini"""
        src = self.ent_src_path.get().strip()
        dst = self.ent_dst_path.get().strip()
        if 'Paths' not in self.config:
            self.config['Paths'] = {}
        self.config['Paths']['source'] = src
        self.config['Paths']['target'] = dst
        with open(CONFIG_FILE, 'w', encoding="utf-8") as f:
            self.config.write(f)

    def _create_widgets(self):
        # --- 💡 頂部路徑設定區 (新增) ---
        path_frame = ttk.LabelFrame(self, text="File Path Settings (Memory Mode)")
        path_frame.pack(fill="x", padx=10, pady=10)

        # 來源路徑
        ttk.Label(path_frame, text="Source Log:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.ent_src_path = ttk.Entry(path_frame)
        self.ent_src_path.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.ent_src_path.insert(0, self.config['Paths']['source'])

        btn_browse_src = ttk.Button(path_frame, text="Browse", command=lambda: self.browse_file(self.ent_src_path))
        btn_browse_src.grid(row=0, column=2, padx=5, pady=5)

        # 目的路徑
        ttk.Label(path_frame, text="Target (Local):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.ent_dst_path = ttk.Entry(path_frame)
        self.ent_dst_path.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.ent_dst_path.insert(0, self.config['Paths']['target'])

        btn_browse_dst = ttk.Button(path_frame, text="Browse",
                                    command=lambda: self.browse_file(self.ent_dst_path, save=True))
        btn_browse_dst.grid(row=1, column=2, padx=5, pady=5)

        path_frame.columnconfigure(1, weight=1)

        # --- 按鈕操作區 (原本的功能) ---
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=5)

        self.btn_open_log = ttk.Button(btn_frame, text="Open spdm.log", command=self.handle_open_log)
        self.btn_open_log.pack(side="left", padx=2)

        self.btn_open_raw_tbs = ttk.Button(btn_frame, text="Open raw_tbs.hex",
                                           command=lambda: self.open_file("raw_tbs.hex"))
        self.btn_open_raw_tbs.pack(side="left", padx=2)

        for i in range(4):
            btn = ttk.Button(btn_frame, text=f"Cert{i}.pem", command=lambda idx=i: self.open_file(f"cert{idx}.pem"))
            btn.pack(side="left", padx=2)

        self.btn_analyze = tk.Button(
            btn_frame, text="Log Parser & Verify", command=self.process_log,
            bg="#ADD8E6", fg="black", activebackground="#87CEEB", relief="raised",
            borderwidth=2, padx=12, pady=2, font=("Microsoft JhengHei", 9, "bold"), cursor="hand2"
        )
        self.btn_analyze.pack(side="left", padx=15)

        self.btn_clear = tk.Button(
            btn_frame, text="Clear Results", command=self.clear_log,
            bg="#F5F5F5", fg="#333333", activebackground="#E0E0E0", relief="raised",
            borderwidth=2, padx=10, pady=2, cursor="hand2"
        )
        self.btn_clear.pack(side="left", padx=2)

        self.btn_replace_log = tk.Button(
            btn_frame, text="Replace spdm.log", command=self.handle_copy_log,
            bg="#FFE4B5", fg="#8B4513", activebackground="#F4A460", relief="raised",
            borderwidth=2, padx=10, pady=2, cursor="hand2"
        )
        self.btn_replace_log.pack(side="left", padx=2)

        self.btn_help = ttk.Button(btn_frame, text="Help / Info", command=self.show_help)
        self.btn_help.pack(side="right", padx=10)

        # --- 顯示區 ---
        self.display = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Consolas", 10), bg="#F8F9FA", padx=10,
                                                 pady=10)
        self.display.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # 顏色配置 (完全恢復)
        self.display.tag_config("header", foreground="#0000FF", font=("Consolas", 10, "bold"))
        self.display.tag_config("pass", foreground="#28A745", font=("Consolas", 10, "bold"))
        self.display.tag_config("fail", foreground="#DC3545", font=("Consolas", 10, "bold"))
        self.display.tag_config("info", foreground="#666666")
        self.display.tag_config("header_data", foreground="#00008B", background="#E6E6FA",
                                font=("Consolas", 10, "bold"))
        self.display.tag_config("roothash_data", foreground="#800080", background="#FFF0F5", font=("Consolas", 10))
        self.display.tag_config("warning", foreground="#FD7E14", font=("Consolas", 10, "bold"))

    def browse_file(self, entry_widget, save=False):
        if save:
            filename = filedialog.asksaveasfilename(defaultextension=".log", initialfile="spdm.log")
        else:
            filename = filedialog.askopenfilename(filetypes=[("Log files", "*.log"), ("All files", "*.*")])
        if filename:
            path = os.path.normpath(filename)
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, path)
            self.save_config()

    def handle_copy_log(self):
        src = self.ent_src_path.get().strip()
        dst = self.ent_dst_path.get().strip()
        if not os.path.exists(src):
            messagebox.showerror("Error", f"Source file not found:\n{src}")
            return
        try:
            shutil.copy2(src, dst)
            self.save_config()
            self.log_msg(f"✅ 成功複製並取代 spdm.log！", "pass")
            self.log_msg(f"   ↳ 來源: {src}", "info")
            self.log_msg(f"   ↳ 目的: {dst}", "info")
            messagebox.showinfo("Success", "spdm.log has been replaced.")
        except Exception as e:
            messagebox.showerror("Error", f"Copy failed: {e}")

    def handle_open_log(self):
        path = self.ent_dst_path.get().strip()
        file_path = os.path.abspath(path)
        if os.path.exists(file_path):
            file_time = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
            os.startfile(file_path)
            self.log_msg(f"✅ 已開啟檔案: {file_path} (修改時間: {file_time})", "info")
        else:
            messagebox.showwarning("Warning", "File not found.")

    def open_file(self, path):
        if os.path.exists(path):
            os.startfile(path)
        else:
            messagebox.showwarning("Warning", f"File not found: {path}")

    def log_msg(self, msg, tag=None):
        self.display.insert(tk.END, msg + "\n", tag)
        self.display.see(tk.END)

    def clear_log(self):
        if messagebox.askyesno("Confirm", "Clear results?"):
            self.display.delete(1.0, tk.END)

    def verify_signature(self, parent_cert, child_cert):
        parent_pub = parent_cert.public_key()
        try:
            if isinstance(parent_pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                parent_pub.verify(child_cert.signature, child_cert.tbs_certificate_bytes)
            else:
                parent_pub.verify(child_cert.signature, child_cert.tbs_certificate_bytes,
                                  ec.ECDSA(child_cert.signature_hash_algorithm))
            return True, "OK"
        except Exception as e:
            return False, str(e)

    def process_log(self):
        self.display.delete(1.0, tk.END)
        file_path = self.ent_dst_path.get().strip()
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "spdm.log not found.")
            return

        self.save_config()

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        pattern = re.compile(r"cert(\d):.*?(\-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)", re.DOTALL)
        matches = pattern.findall(content)
        if not matches:
            self.log_msg("[!] No certificate patterns detected.", "fail")
            return

        certs, raw_ders = [], []
        now = datetime.now(timezone.utc)
        self.log_msg(f"=== SPDM Analysis Log ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ===", "header")

        for idx, text in matches:
            try:
                cert_data_str = text.strip()
                c = x509.load_pem_x509_certificate(cert_data_str.encode(), default_backend())
                certs.append(c)
                der_data = c.public_bytes(encoding=serialization.Encoding.DER)
                raw_ders.append(der_data)

                # 提取公鑰資訊
                pub_key = c.public_key()
                pub_key_raw_hex = "N/A"
                pub_key_type = "Unknown"

                if isinstance(pub_key, ec.EllipticCurvePublicKey):
                    pub_key_type = f"ECC ({pub_key.curve.name})"
                    pub_key_bytes = pub_key.public_bytes(encoding=serialization.Encoding.X962,
                                                         format=serialization.PublicFormat.UncompressedPoint)
                    pub_key_raw_hex = pub_key_bytes[1:].hex().upper() if pub_key_bytes[
                                                                             0] == 0x04 else pub_key_bytes.hex().upper()
                elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                    pub_key_type = "Ed25519"
                    pub_key_raw_hex = pub_key.public_bytes(serialization.Encoding.Raw,
                                                           serialization.PublicFormat.Raw).hex().upper()

                not_before = c.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")
                not_after = c.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")
                status_tag = "info"
                expiry_status = " [✅ Valid]"
                if now < c.not_valid_before_utc or now > c.not_valid_after_utc:
                    status_tag = "fail";
                    expiry_status = " [❌ EXPIRED]"

                # 完整顯示 Subject 與 Issuer (恢復)
                self.log_msg(f"\n[Cert{idx}] Subject: {c.subject.rfc4514_string()}", "info")
                self.log_msg(f"   - Issuer:  {c.issuer.rfc4514_string()}", "info")
                self.log_msg(f"   - Type: {pub_key_type}", "info")
                self.log_msg(f"   - Validity: {not_before} to {not_after}{expiry_status}", status_tag)
                self.log_msg(f"   - Public Key Hex (Raw X+Y): {pub_key_raw_hex}", "info")

                with open(f"cert{idx}.pem", "w", encoding="utf-8") as f_out:
                    f_out.write(cert_data_str)
            except Exception as e:
                self.log_msg(f"   ❌ Error parsing cert{idx}: {e}", "fail")

        # --- Chain Verification (恢復) ---
        if len(certs) > 1:
            self.log_msg("\n" + "-" * 60, "header")
            self.log_msg("=== Chain of Trust Verification ===", "header")
            for i in range(1, len(certs)):
                success, error_msg = self.verify_signature(certs[i - 1], certs[i])
                tag = "pass" if success else "fail"
                self.log_msg(f"Verify [Cert{i - 1} -> Cert{i}]: {'✅ PASS' if success else f'❌ FAIL: {error_msg}'}", tag)

        # --- Digest Components (完整恢復) ---
        if raw_ders:
            self.log_msg("\n" + "-" * 60, "header")
            self.log_msg("=== SPDM Certificate Chain Digest Components ===", "header")
            try:
                root_hash_bin = hashlib.sha384(raw_ders[0]).digest()
                all_certs_bin = b"".join(raw_ders)
                total_len = len(root_hash_bin) + len(all_certs_bin) + 4
                header_bin = total_len.to_bytes(2, byteorder="little") + b"\x00\x00"

                self.log_msg(f" 1. Header [Length] (4 bytes, Little Endian):", "info")
                self.display.insert(tk.END, f"    {header_bin.hex().upper()}\n", "header_data")
                self.log_msg(f" 2. RootHash (48 bytes, SHA384 of Cert0):", "info")
                self.display.insert(tk.END, f"    {root_hash_bin.hex().upper()}\n", "roothash_data")
                self.log_msg(f" 3. All Certs [DER] Cet0+Cet1+Cet2+Cet3 ({len(all_certs_bin)} bytes):", "info")
                self.log_msg(f" >> ***skip***", "pass")

                cert_chain_digest = hashlib.sha384(header_bin + root_hash_bin + all_certs_bin).hexdigest().upper()
                self.log_msg("\n" + "-" * 60, "header")
                self.log_msg(f" [Summary] Total Binary Size: {len(header_bin + root_hash_bin + all_certs_bin)} bytes",
                             "pass")
                self.log_msg(f" Cert Chain Digest (SHA384):", "header")
                self.log_msg(f" >> {cert_chain_digest}", "pass")

                # Signature / TBS Verify (完整恢復)
                sig_match = re.search(r"Challenge Signature:\s*([0-9A-Fa-f]+)", content)
                tbs_match = re.search(r"Leo challenge_msg\(TBS\):\s*([0-9A-Fa-f]+)", content)

                if tbs_match and sig_match:
                    self.log_msg("\n" + "-" * 60, "header")
                    full_tbs_hex = tbs_match.group(1).upper()
                    tbs_bin = bytes.fromhex(full_tbs_hex)
                    with open("raw_tbs.hex", "w", encoding="utf-8") as f_hex:
                        f_hex.write(full_tbs_hex)

                    self.log_msg(f" challenge_msg(TBS) = SPDM Response + Nonce + All Cert Chain + Padding", "pass")
                    self.log_msg(f" [Digest] SHA-384: {hashlib.sha384(tbs_bin).hexdigest().upper()}", "header")

                    # Verify
                    leaf_pub = certs[-1].public_key()
                    sig_bin = bytes.fromhex(sig_match.group(1))
                    r, s = int.from_bytes(sig_bin[:48], "big"), int.from_bytes(sig_bin[48:], "big")
                    from cryptography.hazmat.primitives.asymmetric import utils
                    der_sig = utils.encode_dss_signature(r, s)
                    leaf_pub.verify(der_sig, tbs_bin, ec.ECDSA(hashes.SHA384()))
                    self.log_msg("\n ✅ Verification SUCCESS! (With Padding)", "pass")
                else:
                    self.log_msg("\n  ⚠️ Missing Leo challenge_msg(TBS) in log.", "warning")

                # CEC1736 Measurement Guide (恢復)
                guide_text = (
                        "\n" + "=" * 60 + "\n"
                                          "【CEC1736  SPDM Measurements 】\n" + "-" * 60 + "\n"
                                                                                         f"{'Block 1':<10} | {'ROM':<15} | 硬體身分：出廠固定，不應變動。\n"
                                                                                         f"{'Block 2':<10} | {'Mutable FW':<15} | 韌體版本：對應 v.1.5.1(1203)，改 Code 即變。\n"
                                                                                         f"{'Block 3':<10} | {'HW Config':<15} | 硬體設定：Pin 腳、Strapping 參數。\n"
                                                                                         f"{'Block 4':<10} | {'FW Config':<15} | 韌體設定：Key 設定與安全原則 (Policies)。\n"
                                                                                         f"{'Block 5':<10} | {'Manifest':<15} | 標準答案卷：包含以上項目的預期 Hash。\n"
                )
                self.log_msg(guide_text)
            except Exception as e:
                self.log_msg(f"   ❌ Error: {e}", "fail")

    def show_help(self):
        help_text = (
                r"1. Modify \tpds\cec_utilities\spdmspdm_cmds.py" + "\n"
                + 'logging.info(f"Challenge Signature: {signature.hex().upper()}")\n'
                + '=>logging.info(f"Leo challenge_msg(TBS): {challenge_msg.hex().upper()}")\n\n'
                + "2. Tool will save paths in config.ini automatically.\n"
        )
        messagebox.showinfo("SPDM Info", help_text)


if __name__ == "__main__":
    root = tk.Tk()
    root.title("SPDM Log Analyzer v2.2")
    root.geometry("1100x900")
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)
    tab = SPDMParserTab(notebook)
    root.mainloop()