# ECDSA_Helper_Tool_oop


A professional-grade cryptography utility built with Python and Tkinter. This tool is specifically designed to streamline ECDSA signature development, hash calculations, and X.509 certificate parsing.

🚀 Key Modules and Features
1. EC Cryptography Core (EC Tab)
This module handles asymmetric key generation, signing, and verification logic.

Curve Support
Built-in support for NIST standard curves: P-256 (secp256r1) and P-384 (secp384r1).

Key Management
Paste a PEM private key to automatically extract the curve type, Private Key (hex), and Public Key (hex). You can also generate new standard-compliant EC key pairs with one click.

Signature Tools
Supports seamless conversion between RS Raw (concatenated) and DER Hex (ASN.1) formats. It provides dedicated functions for SIGN and VERIFY.

Hash Calculation (TBS)
Automatically converts messages or files into To-Be-Signed (TBS) hashes. It also supports loading external .txt or .hex files for direct computation.

2. Certificate Decoder (Certificate Tab)
This module is designed to extract critical cryptographic metadata from X.509 certificates.

Format Autodetect
Automatically recognizes and parses PEM (Base64) or DER (Hex/Binary) inputs.

Information Extraction

Fingerprint: Computes the unique certificate fingerprint.

Public Key: Extracts X and Y coordinates with one-click synchronization to the EC Tab.

Format Swap: Automatically generates the raw DER Hex or PEM string.

Signature: Displays the raw Certificate Signature Value.

🛠 Installation
This tool is developed with native Python 3 and requires the cryptography library.

Bash
pip install cryptography
💡 Usage Tips
Clean and Undo
Use the "Clean All" button to wipe all fields. If you delete something by mistake, click it again to Undo and restore your data.

Zero-Processing Input
The input fields automatically filter out spaces, colons, and newlines. You can paste raw logs directly from your terminal or serial monitor without manual cleaning.

Workflow Example
First, parse a certificate in the Cert Tab. Then, click "Copy Public Key to EC Tab". Finally, switch to the EC Tab, paste your message and signature, and click VERIFY.

⚖ Disclaimer
This tool is provided for development, debugging, and educational purposes only. Always follow security best practices when handling production private keys.

這是一個基於 Python Tkinter 開發的專業級密碼學輔助工具。
旨在簡化 ECDSA 簽章開發、雜湊計算及 X.509 憑證解析的繁瑣流程。

---

## 🚀 核心功能模組

### 1. EC 密碼學核心 (EC Tab)
處理非對稱金鑰的生成、簽章與驗證邏輯。

* **曲線支持**：內建 NIST `P-256` 與 `P-384` 曲線標準。
* **金鑰管理**：
    * 支持 **PEM 格式自動解析**：貼上 PEM 即可自動填入私鑰與公鑰 Hex。
    * 支持 **一鍵生成**：快速產出符合標準的新金鑰對。
* **簽章工具**：
    * **格式轉換**：支持 `RS Raw` (拼接格式) 與 `DER Hex` (ASN.1 格式) 互轉。
    * **雙向運算**：提供 SIGN (簽署) 與 VERIFY (驗證) 功能。
* **雜湊計算 (TBS)**：
    * 自動將 Message 轉換為 To-Be-Signed (TBS) 雜湊值。
    * **大檔案支持**：可直接載入外部檔案進行 Hash 計算。

---

### 2. 憑證解析工具 (Certificate Tab)
專為處理 X.509 憑證設計，方便從現有憑證提取關鍵資訊。

* **多格式辨識**：自動判別並解析 **PEM** 或 **DER (Hex)** 輸入。
* **四大解析區塊**：
    1.  **Fingerprint**：計算憑證唯一指紋。
    2.  **Public Key**：提取公鑰 $X||Y$ 座標，支持一鍵同步至 EC 頁面。
    3.  **Format Swap**：自動產出對應的 DER 或 PEM 原始資料。
    4.  **Signature**：顯示憑證本身的簽章內容 (Certificate Signature)。

---

## 🛠 安裝與需求

本工具使用原生 Python 3 開發，僅需安裝 `cryptography` 套件：

```bash
pip install cryptography