import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import re
import os
import subprocess
import sys
import hashlib
from datetime import datetime, timezone

# 確保已安裝 cryptography 庫：pip install cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448
from cryptography.hazmat.primitives import hashes, serialization


class SPDMParserTab(ttk.Frame):
    def __init__(self, notebook):
        super().__init__(notebook)
        self.pack(fill="both", expand=True)
        self._create_widgets()

    def _create_widgets(self):
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=10)

        # self.btn_open_log = ttk.Button(btn_frame, text="Open spdm.log", command=lambda: self.open_file("spdm.log"))
        self.btn_open_log = ttk.Button(
            btn_frame,
            text="Open spdm.log",
            command=self.handle_open_log  # 直接指向 method 名稱
        )
        self.btn_open_log.pack(side="left", padx=2)

        self.btn_open_log = ttk.Button(btn_frame, text="Open raw_tbs.hex", command=lambda: self.open_file("raw_tbs.hex"))
        self.btn_open_log.pack(side="left", padx=2)

        for i in range(4):
            btn = ttk.Button(btn_frame, text=f"Open Cert{i}.pem",
                             command=lambda idx=i: self.open_file(f"cert{idx}.pem"))
            btn.pack(side="left", padx=2)

        self.btn_analyze = tk.Button(
            btn_frame, text="Log Parser & Verify", command=self.process_log,
            bg="#ADD8E6", fg="black", activebackground="#87CEEB",
            relief="raised", borderwidth=2, padx=12, pady=2,
            font=("Microsoft JhengHei", 9, "bold"), cursor="hand2"
        )
        self.btn_analyze.pack(side="left", padx=15)

        self.btn_clear = tk.Button(
            btn_frame, text="Clear Results", command=self.clear_log,
            bg="#F5F5F5", fg="#333333", activebackground="#E0E0E0",
            relief="raised", borderwidth=2, padx=10, pady=2, cursor="hand2"
        )
        self.btn_clear.pack(side="left", padx=2)

        # 新增 Help 按鈕
        self.btn_help = ttk.Button(btn_frame, text="Help / Info", command=self.show_help)
        self.btn_help.pack(side="right", padx=10)

        self.display = scrolledtext.ScrolledText(
            self, wrap=tk.WORD, font=("Consolas", 10), bg="#F8F9FA", padx=10, pady=10
        )
        self.display.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # 顏色配置
        self.display.tag_config("header", foreground="#0000FF", font=("Consolas", 10, "bold"))
        self.display.tag_config("pass", foreground="#28A745", font=("Consolas", 10, "bold"))
        self.display.tag_config("fail", foreground="#DC3545", font=("Consolas", 10, "bold"))
        self.display.tag_config("info", foreground="#666666")

        # 數據視覺化顏色配置
        self.display.tag_config("header_data", foreground="#00008B", background="#E6E6FA",
                                font=("Consolas", 10, "bold"))
        self.display.tag_config("roothash_data", foreground="#800080", background="#FFF0F5", font=("Consolas", 10))
        self.display.tag_config("cert_data", foreground="#555555")

        # 新增橘色警告配置
        self.display.tag_config("warning", foreground="#FD7E14", font=("Consolas", 10, "bold"))

    def handle_open_log(self):
        """處理開啟 spdm.log 的邏輯，若不存在則開啟目錄"""
        target_file = "spdm.log"
        file_path = os.path.abspath(target_file)
        file_dir = os.path.dirname(file_path)

        if os.path.exists(file_path):
            # 情況 A: 檔案存在，直接用系統預設程式開啟
            try:
                os.startfile(file_path)
                self.log_msg(f"✅ 已開啟檔案: {target_file}", "info")
            except Exception as e:
                self.log_msg(f"❌ 無法開啟檔案: {e}", "fail")
        else:
            # 情況 B: 檔案不存在，開啟該檔案應存在的目錄
            if os.path.exists(file_dir):
                self.log_msg(f"⚠️ 找不到 {target_file}，正在開啟檔案夾...", "fail")
                try:
                    # 開啟檔案總管並定位到該目錄
                    os.startfile(file_dir)
                except Exception as e:
                    self.log_msg(f"❌ 無法開啟目錄: {e}", "fail")
            else:
                self.log_msg(f"❌ 找不到目錄路徑: {file_dir}", "fail")
    def show_help(self):
        """ 顯示 SPDM 驗證邏輯說明視窗 """
        help_text = (
            "1. Modify \tpds\cec_utilities\spdmspdm_cmds.py\n"
            "logging.info(f\"Challenge Signature: {signature.hex().upper()}\")\n"
			"=>logging.info(f\"Leo challenge_msg(TBS): {challenge_msg.hex().upper()}\")\n\n"
			"2. Run ft4222_as_host_cnfmod2_cl\n"
            "3. Enter Cmd (or 'exit' to quit or 'help'): spdm\n"
            "4. Copy spdm.log to the folder ECDSA_Helper_Tool\n"
        )
        messagebox.showinfo("SPDM Info", help_text)

    def open_file(self, file_path):
        if os.path.exists(file_path):
            try:
                if os.name == 'nt':
                    os.startfile(file_path)
                else:
                    subprocess.call(('open' if sys.platform == 'darwin' else 'xdg-open', file_path))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open {file_path}: {e}")
        else:
            messagebox.showwarning("Warning", f"File not found: {file_path}")

    def log_msg(self, msg, tag=None):
        self.display.insert(tk.END, msg + "\n", tag)
        self.display.see(tk.END)

    def clear_log(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to clear the logs?"):
            self.display.delete(1.0, tk.END)

    def verify_signature(self, parent_cert, child_cert):
        parent_pub = parent_cert.public_key()
        try:
            if isinstance(parent_pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                parent_pub.verify(child_cert.signature, child_cert.tbs_certificate_bytes)
            else:
                parent_pub.verify(
                    child_cert.signature, child_cert.tbs_certificate_bytes,
                    ec.ECDSA(child_cert.signature_hash_algorithm)
                )
            return True, "OK"
        except Exception as e:
            return False, str(e)

    def process_log(self):
        self.display.delete(1.0, tk.END)
        file_path = "spdm.log"
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "spdm.log not found.")
            return

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        pattern = re.compile(r'cert(\d):.*?(\-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)', re.DOTALL)
        matches = pattern.findall(content)
        if not matches:
            self.log_msg("[!] No certificate patterns detected.", "fail")
            return

        certs = []
        raw_ders = []
        now = datetime.now(timezone.utc)
        self.log_msg(f"=== SPDM Analysis Log ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ===", "header")

        for idx, text in matches:
            try:
                cert_data_str = text.strip()
                c = x509.load_pem_x509_certificate(cert_data_str.encode(), default_backend())
                certs.append(c)
                der_data = c.public_bytes(encoding=serialization.Encoding.DER)
                raw_ders.append(der_data)

                # --- 提取公鑰與日期資訊 (已優化顯示) ---
                pub_key = c.public_key()
                pub_key_hex = "N/A"
                pub_key_type = "Unknown"

                # 提取 ECC 公鑰的 Hex Value (針對 CEC1736 的 P-384)
                if isinstance(pub_key, ec.EllipticCurvePublicKey):
                    pub_key_type = f"ECC ({pub_key.curve.name})"
                    # 使用 X9.62 Uncompressed 格式 (04 + X + Y)
                    pub_key_bytes = pub_key.public_bytes(
                        encoding=serialization.Encoding.X962,
                        format=serialization.PublicFormat.UncompressedPoint
                    )

                    # --- [關鍵修改]：拿掉開頭的 04 ---
                    # 如果開頭是 0x04 (Uncompressed)，則取第 1 個 byte 之後的資料
                    if pub_key_bytes[0] == 0x04:
                        pub_key_raw_hex = pub_key_bytes[1:].hex().upper()
                    else:
                        pub_key_raw_hex = pub_key_bytes.hex().upper()
                    # -----------------------------------

                elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                    pub_key_type = "Ed25519"
                    pub_key_bytes = pub_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                    pub_key_raw_hex = pub_key_bytes.hex().upper()

                # 取得有效期
                not_before = c.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S')
                not_after = c.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S')

                # 檢查是否過期
                status_tag = "info"
                expiry_status = " [✅ Valid]"
                if now < c.not_valid_before_utc or now > c.not_valid_after_utc:
                    status_tag = "fail"
                    expiry_status = " [❌ EXPIRED]"

                # 1. 取得 Subject (持有者) 與 Issuer (核發者)
                subject_str = c.subject.rfc4514_string()
                issuer_str = c.issuer.rfc4514_string()

                # 2. 判定是否為 Root (自簽署：自己發給自己)
                is_self_signed = " [Root CA]" if subject_str == issuer_str else ""

                # --- 顯示資訊到介面 (純文字，拿掉顏色 Tag，方便 Double-click 全選) ---
                self.log_msg(f"\n[Cert{idx}] Subject: {c.subject.rfc4514_string()}", "info")
                self.log_msg(f"   - Issuer:  {issuer_str}", "info")  # <--- 新增這一行
                self.log_msg(f"   - Type: {pub_key_type}", "info")
                self.log_msg(f"   - Validity: {not_before} to {not_after}{expiry_status}", status_tag)

                # 印出 Public Key Hex (拿掉 04，使用 info 一般文字)
                self.log_msg(f"   - Public Key Hex (Raw X+Y): {pub_key_raw_hex}", "info")
                # -------------------------------------------------------------

                with open(f"cert{idx}.pem", "w", encoding="utf-8") as f_out:
                    f_out.write(cert_data_str)
            except Exception as e:
                self.log_msg(f"   ❌ Error parsing cert{idx}: {e}", "fail")

        # --- Chain Verification ---
        if len(certs) > 1:
            self.log_msg("\n" + "-" * 60, "header")
            self.log_msg("=== Chain of Trust Verification ===", "header")
            for i in range(1, len(certs)):
                success, error_msg = self.verify_signature(certs[i - 1], certs[i])
                tag = "pass" if success else "fail"
                self.log_msg(f"Verify [Cert{i - 1} -> Cert{i}]: {'✅ PASS' if success else f'❌ FAIL: {error_msg}'}", tag)

        # --- SPDM 1.1+ Certificate Chain Digest ---
        if raw_ders:
            self.log_msg("\n" + "-" * 60, "header")
            self.log_msg("=== SPDM Certificate Chain Digest Components ===", "header")
            try:
                # 1. 計算各組件
                root_hash_bin = hashlib.sha384(raw_ders[0]).digest()
                all_certs_bin = b"".join(raw_ders)

                total_len = len(root_hash_bin) + len(all_certs_bin) + 4
                header_bin = total_len.to_bytes(2, byteorder='little') + b"\x00\x00"

                # 2. 列印各個部分
                self.log_msg(f" 1. Header [Length] (4 bytes, Little Endian):", "info")
                self.display.insert(tk.END, f"    {header_bin.hex().upper()}\n", "header_data")

                self.log_msg(f" 2. RootHash (48 bytes, SHA384 of Cert0):", "info")
                rh_hex = root_hash_bin.hex().upper()
                self.display.insert(tk.END, f"    {rh_hex}\n", "roothash_data")

                cert_len = len(all_certs_bin)
                self.log_msg(f" 3. All Certs [DER] Cet0+Cet1+Cet2+Cet3 ({cert_len} bytes):", "info")
                # self.display.insert(tk.END, f"    {all_certs_bin.hex().upper()}\n", "cert_data")
                self.log_msg(f" >> ***skip***", "pass")

                # 3. 計算最終 Digest
                total_data_bin = header_bin + root_hash_bin + all_certs_bin
                cert_chain_digest = hashlib.sha384(total_data_bin).hexdigest().upper()

                self.log_msg("\n" + "-" * 60, "header")
                self.log_msg(f" [Summary] Total Binary Size: {len(total_data_bin)} bytes (0x{len(total_data_bin):X})",
                             "pass")
                self.log_msg(f" Cert Chain Digest (SHA384):", "header")
                self.log_msg(f" >> {cert_chain_digest}", "pass")

                # 5. 提取 Challenge Signature 與 TBS (challenge_msg)
                sig_match = re.search(r'Challenge Signature:\s*([0-9A-Fa-f]+)', content)
                tbs_match = re.search(r'Leo challenge_msg\(TBS\):\s*([0-9A-Fa-f]+)', content)

                if sig_match:
                    # 使用 .group(1) 提取括號內的 Hex 字串
                    actual_sig = sig_match.group(1)
                    self.log_msg(f"實際 Signature 長度: {len(actual_sig)}")
                    self.log_msg(f"Signature 內容: {actual_sig}")

                if tbs_match:
                    self.log_msg("\n" + "-" * 60, "header")
                    try:
                        # --- A. 取得原始 TBS (保留所有 00) ---
                        # 直接使用 group(1)，只轉大寫，不處理結尾
                        full_tbs_hex = tbs_match.group(1).upper()

                        # 確保 Hex 格式正確 (如果是從 Log 抓出，通常已經是偶數)
                        if len(full_tbs_hex) % 2 != 0:
                            full_tbs_hex += '0'

                        tbs_bin = bytes.fromhex(full_tbs_hex)

                        # --- B. 存檔與顯示 (此時長度應為 8332) ---
                        with open("raw_tbs.hex", "w", encoding="utf-8") as f_hex:
                            f_hex.write(full_tbs_hex)

                        self.log_msg(f" challenge_msg(TBS) = SPDM Response + Responder Nonce + All Cert Chain + Padding", "pass")
                        self.log_msg(f" [File] raw_tbs.hex saved (Length: {len(full_tbs_hex)} chars)", "pass")

                        # --- C. 計算並印出 Digest ---
                        tbs_digest = hashlib.sha384(tbs_bin).hexdigest().upper()
                        self.log_msg(f" [Digest] SHA-384: {tbs_digest}", "header")

                        # --- D. 準備公鑰與簽名 ---
                        leaf_cert = certs[3]
                        public_key = leaf_cert.public_key()

                        raw_sig_hex = sig_match.group(1).upper()
                        sig_bin = bytes.fromhex(raw_sig_hex)

                        # R+S 轉 DER
                        from cryptography.hazmat.primitives.asymmetric import utils
                        r = int.from_bytes(sig_bin[:48], 'big')
                        s = int.from_bytes(sig_bin[48:], 'big')
                        der_sig = utils.encode_dss_signature(r, s)

                        self.log_msg("\n Use PublicKey of to verify der_sig with tbs_digest", "info")
                        # --- E. 執行驗證 ---
                        public_key.verify(
                            der_sig,
                            tbs_bin,
                            ec.ECDSA(hashes.SHA384())
                        )

                        self.log_msg("\n ✅ Verification SUCCESS! (With Padding)", "pass")

                    except Exception as e:
                        self.log_msg(f"\n ❌ Verification FAILED: {type(e).__name__}", "fail")
                        self.log_msg(f" Error: {str(e)}", "fail")

                else:
                    self.log_msg("\n  ⚠️ Please check the \\cec_utilities\\spdm\\__main__.py line 118", "warning")
                    self.log_msg("\n  ⚠️ Add challenge_msg(TBS)", "warning")

                """ 顯示 SPDM 驗證邏輯說明視窗 """
                guide_text = (
                        "\n" + "=" * 60 + "\n"
                        "【CEC1736  SPDM Measurements 】\n" + "-" * 60 + "\n"
                        f"{'項目':<10} | {'名稱':<15} | {' (解讀方式)':<30}\n" + "-" * 60 + "\n"
                        f"{'Block 1':<10} | {'ROM':<15} | 硬體身分：出廠固定，不應變動。\n"
                        f"{'Block 2':<10} | {'Mutable FW':<15} | 韌體版本：對應 v.1.5.1(1203)，改 Code 即變。\n"
                        f"{'Block 3':<10} | {'HW Config':<15} | 硬體設定：Pin 腳、Strapping 參數。\n"
                        f"{'Block 4':<10} | {'FW Config':<15} | 韌體設定：Key 設定與安全原則 (Policies)。\n"
                        f"{'Block 5':<10} | {'Manifest':<15} | 標準答案卷：包含以上項目的預期 Hash。\n"
                )
                self.log_msg(guide_text)

                # # --- 1. 準備資料 ---
                # # 這是你剛才格式化後的公鑰 (Raw X+Y, 96 bytes for secp384r1)
                # pub_key_hex = "D132D9E090BE969A293FFE1F8793CCC21CE1AB53CCC646B2DA5D9EB30F702F2F2AEFE9E03CA19D72AE515020B552895F37FD08FA9A1443581D9EBE243ED96B6F48C6B41A9E8CEC2B46874F9908CF72672ACB8AC42C78C0714DFE91A9BF12079A"
                #
                # # 請替換成你抓到的 Challenge Signature (通常是 R + S 拼接)
                # sig_hex = "f2143e9eb0e80e3cc9d0fa0b14d3188d67ba18060362dc009464171103bfbeccb068613f8294e81394eae4994e2b70d2"
                #
                # # 這是 Challenge 的原始訊息 (Raw Challenge data)
                # message_hex = "f2143e9eb0e80e3cc9d0fa0b14d3188d67ba18060362dc009464171103bfbeccb068613f8294e81394eae4994e2b70d2"
                #
                # try:
                #     # --- 2. 重構公鑰物件 ---
                #     # secp384r1 的 Raw 公鑰是 X (48 bytes) + Y (48 bytes)
                #     # 我們需要加上開頭字節 0x04 表示非壓縮格式 (Uncompressed point)
                #     public_key_bytes = bytes.fromhex("04" + pub_key_hex)
                #
                #     # 載入公鑰
                #     public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), public_key_bytes)
                #
                #     # --- 3. 執行驗證 ---
                #     # 假設簽章是 Raw 格式 (R+S)，cryptography 庫通常需要 DER 編碼
                #     # 如果驗證失敗，通常是因為簽章格式不對或訊息不匹配
                #     signature = bytes.fromhex(sig_hex)
                #     message = bytes.fromhex(message_hex)
                #
                #     # 進行驗證 (secp384r1 搭配 SHA384)
                #     public_key.verify(
                #         signature,
                #         message,
                #         ec.ECDSA(hashes.SHA384())
                #     )
                #     print("✅ 驗證成功！Challenge Signature 與 Cert3 公鑰匹配。")
                #
                # except Exception as e:
                #     print(f"❌ 驗證失敗: {e}")

            except Exception as e:
                self.log_msg(f"   ❌ Digest Calculation Failed: {e}", "fail")


if __name__ == "__main__":
    root = tk.Tk()
    root.title("SPDM Log Analyzer")
    root.geometry("1100x800")
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)
    tab = SPDMParserTab(notebook)
    root.mainloop()