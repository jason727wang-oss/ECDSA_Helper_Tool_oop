import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

class CertTab(ttk.Frame):
    def __init__(self, parent, ec_tab):
        super().__init__(parent, padding="10")
        self.ec_tab = ec_tab
        self.extracted_pub = tk.StringVar()
        self.init_ui()

    def init_ui(self):
        tk.Label(self, text="Certificate PEM or DER:").pack(anchor="w")
        self.cert_in = scrolledtext.ScrolledText(self, height=18)
        self.cert_in.pack(fill="x", pady=5)

        # 預設憑證內容
        default_cert = """-----BEGIN CERTIFICATE-----
MIICRTCCAcqgAwIBAgIIbbIi4obcUpowCgYIKoZIzj0EAwMwVjEhMB8GA1UECgwY
TWljcm9jaGlwIFRlY2hub2xvZ3kgSW5jMRYwFAYDVQQDDA1DUEcgUm9vdCBDQSAx
MQwwCgYDVQQLDANDUEcxCzAJBgNVBAYTAlVTMCAXDTIzMTIwOTEzMjIzM1oYDzk5
OTkxMjMxMjM1OTU5WjBWMSEwHwYDVQQKDBhNaWNyb2NoaXAgVGVjaG5vbG9neSBJ
bmMxFjAUBgNVBAMMDUNQRyBSb290IENBIDExDDAKBgNVBAsMA0NQRzELMAkGA1UE
BhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARwfDwEVyn/Pd8EMuK0KUmIH5pu
1h8M57B3gG5y9RRKnizW5MAlvjQjgBYYYiFc8Nk0j+tyrwWY4Ehq+P7LZ0En/ChS
hngcXwrDr2aa4bzIo/r4HrLb0eLMkNEWSBHAPnajYzBhMA4GA1UdDwEB/wQEAwIC
BDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRZi+U0nBdZ/JaLD48YTPFwSgE2
CjAfBgNVHSMEGDAWgBRZi+U0nBdZ/JaLD48YTPFwSgE2CjAKBggqhkjOPQQDAwNp
ADBmAjEAtn/BkIWefSIs1tRcL+IdWga6OD3PC3WPkmqK+GHrF2GIQaOIwCkw8azO
hfFGR/y6AjEAt3TqnssaJyxtXNNhNNiILgpoFlbm/VbCo3dvtA0GvKiVYGhRB33F
0n7GQvp8PZjj
-----END CERTIFICATE-----"""
        self.cert_in.insert("1.0", default_cert)

        btn_f = ttk.Frame(self);
        btn_f.pack(fill="x")
        ttk.Button(btn_f, text="Decode Certificate", command=self.decode_cert).pack(side="left", padx=5)
        ttk.Button(btn_f, text="Copy Public Key to EC Tab", command=self.copy_to_ec).pack(side="left")

        self.cert_out = scrolledtext.ScrolledText(self, height=12, bg="#F5F5DC")
        self.cert_out.pack(fill="both", expand=True, pady=10)

    #v2.3.0
    #Add decode_cert suppport pem and der formate.
    def decode_cert(self):
        try:
            # 1. 取得輸入並整理（去除首尾空白）
            raw_input_str = self.cert_in.get("1.0", tk.END).strip()

            # 判斷輸入是 Base64(PEM) 還是 Hex 字串(DER)
            # 如果包含 BEGIN CERTIFICATE，通常是 PEM
            if "-----BEGIN CERTIFICATE-----" in raw_input_str:
                input_bytes = raw_input_str.encode()
                cert = x509.load_pem_x509_certificate(input_bytes)
                input_format = "PEM"
            else:
                # 嘗試將輸入視為 Hex 字串轉回二進位 DER
                try:
                    # 去除可能的空白或冒號
                    clean_hex = "".join(filter(str.isalnum, raw_input_str))
                    input_bytes = bytes.fromhex(clean_hex)
                    cert = x509.load_der_x509_certificate(input_bytes)
                    input_format = "DER"
                except Exception:
                    # 如果 Hex 轉換失敗，嘗試直接讀取原始 bytes (處理 binary 貼上的情況)
                    input_bytes = raw_input_str.encode('latin-1')
                    cert = x509.load_der_x509_certificate(input_bytes)
                    input_format = "DER"

            # 2. 準備轉換資料
            der_bytes = cert.public_bytes(serialization.Encoding.DER)
            pem_bytes = cert.public_bytes(serialization.Encoding.PEM)

            # 3. 取得公鑰資訊
            pk = cert.public_key()
            if isinstance(pk, ec.EllipticCurvePublicKey):
                curve_size = pk.curve.key_size
                chosen_hash = hashes.SHA256() if curve_size <= 256 else hashes.SHA384()
            else:
                chosen_hash = hashes.SHA256()

            # 4. 計算 Fingerprint
            der_hash_hex = cert.fingerprint(chosen_hash).hex().upper()

            # 5. 組合 UI 顯示資訊
            res = f"Detected Format: {input_format}\n"
            res += f"Subject: {cert.subject.rfc4514_string()}\n"
            res += f"Issuer: {cert.issuer.rfc4514_string()}\n"
            res += f"Curve: {pk.curve.name if hasattr(pk, 'curve') else 'N/A'}\n"
            res += f"Hash Algo: {chosen_hash.name.upper()}\n"

            res += "\n[1. Certificate Fingerprint]:\n" + der_hash_hex + "\n"

            # 提取 EC 公鑰坐標 (X||Y)
            if isinstance(pk, ec.EllipticCurvePublicKey):
                bl = pk.curve.key_size // 8
                pn = pk.public_numbers()
                pub_hex = f"{pn.x:0{bl * 2}x}{pn.y:0{bl * 2}x}"
                res += f"\n[2. Public Key (X||Y)]:\n{pub_hex}"
                self.extracted_pub.set(pub_hex)

            # --- 新增區塊 3: Signature (解析為 Raw R+S 格式) ---
            from cryptography.hazmat.primitives.asymmetric import utils

            sig_data = cert.signature
            try:
                # 嘗試將 DER 格式解碼為 R, S 數值
                r, s = utils.decode_dss_signature(sig_data)

                # 根據曲線決定單個分量的長度 (P-384 為 48B, P-256 為 32B)
                # 如果 pk 是 ec.EllipticCurvePublicKey
                if isinstance(pk, ec.EllipticCurvePublicKey):
                    field_size = (pk.curve.key_size + 7) // 8
                    # 拼合成 Raw 格式 (R||S)
                    raw_sig = r.to_bytes(field_size, 'big') + s.to_bytes(field_size, 'big')
                    res += f"\n[3. Certificate Signature (Raw R+S {len(raw_sig)}B)]:\n" + raw_sig.hex().upper() + "\n"
                else:
                    # 非 EC 憑證則顯示原始 DER
                    res += f"\n[3. Certificate Signature (DER {len(sig_data)}B)]:\n" + sig_data.hex().upper() + "\n"
            except Exception:
                # 如果解碼失敗，回退顯示原始數據
                res += f"\n[3. Certificate Signature (Raw R+S {len(sig_data)}B)]:\n" + sig_data.hex().upper() + "\n"

            # 根據輸入格式決定區塊 4 的內容
            if input_format == "PEM":
                res += "\n[4. Raw Certificate DER (Hex)]:\n" + der_bytes.hex().upper() + "\n"
            else:
                res += "\n[4. Certificate PEM Format]:\n" + pem_bytes.decode() + "\n"





            # 6. 更新 UI
            self.cert_out.delete("1.0", tk.END)
            self.cert_out.insert(tk.END, res)

        except Exception as e:
            messagebox.showerror("Error", f"解析失敗: 格式不正確或非有效憑證\n{str(e)}")
    def copy_to_ec(self):
        val = self.extracted_pub.get()
        if val:
            self.ec_tab.pub_text.delete("1.0", tk.END);
            self.ec_tab.pub_text.insert(tk.END, val)
            self.master.select(0)
            self.ec_tab.out_print("✅ Public Key copied from Certificate")