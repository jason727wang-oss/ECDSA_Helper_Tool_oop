# pyinstaller --noconsole --onefile -i ecdsa.ico --name "ECDSA_Helper_Tool" main.py
# pyinstaller --noconsole --onedir -i ecdsa.ico --name "ECDSA_Helper_Tool" main.py
import tkinter as tk
from tkinter import ttk
import os
import sys
import configparser
from tab_ec import ECTab
from tab_cert import CertTab
from tab_spdm_parser import SPDMParserTab
from tab_about import AboutTab

CONFIG_FILE = "gui_config.ini"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ECDSA Helper Tool - Modular Version")

        # 1. 處理視窗大小與位置 (由 App 自己管理)
        self.load_config()

        try:
            base_path = getattr(sys, '_MEIPASS', os.path.abspath("."))
            icon_path = os.path.join(base_path, "ecdsa.ico")
            self.iconbitmap(icon_path)
        except:
            pass

        self.configure(bg='#E0E0E0')

        style = ttk.Style()
        try:
            style.theme_use('clam')
        except:
            pass

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # 2. 初始化各個分頁 (只傳 notebook 過去，讓分頁乖乖待著)
        self.tab_ec = ECTab(self.notebook)
        self.tab_cert = CertTab(self.notebook, self.tab_ec)
        self.tab_spdm = SPDMParserTab(self.notebook) # <-- 修正：移除後面的 self
        self.tab_about = AboutTab(self.notebook)

        self.notebook.add(self.tab_ec, text="EC Sign / Verify")
        self.notebook.add(self.tab_cert, text="Certificate Decoder")
        self.notebook.add(self.tab_spdm, text="SPDM Log Parser")
        self.notebook.add(self.tab_about, text="About")

        # 3. 綁定關閉事件：App 負責記住位置
        self.protocol("WM_DELETE_WINDOW", self.save_config)

    def load_config(self):
        config = configparser.ConfigParser()
        # 預設起始位置
        default_geom = "1400x700+100+100"

        if os.path.exists(CONFIG_FILE):
            try:
                config.read(CONFIG_FILE)
                geom = config.get('Window', 'geometry', fallback=default_geom)

                # --- 新增：防呆檢查 ---
                # 格式通常是 "寬x高+X+Y"
                parts = geom.replace('x', '+').split('+')
                if len(parts) == 4:
                    win_x = int(parts[2])
                    win_y = int(parts[3])

                    # 取得目前「主螢幕」的寬高 (簡單檢查)
                    screen_w = self.winfo_screenwidth()
                    screen_h = self.winfo_screenheight()

                    # 如果 X 或 Y 座標遠大於目前螢幕，或是負數太嚴重
                    # 就重置回 +100+100，避免視窗開在螢幕外
                    if win_x > screen_w or win_y > screen_h or win_x < -screen_w:
                        geom = "1400x700+100+100"

                self.geometry(geom)
            except:
                self.geometry(default_geom)
        else:
            self.geometry(default_geom)

    def save_config(self):
        """關閉時儲存位置並退出"""
        try:
            # 強制更新視窗狀態，確保抓到最新坐標
            self.update_idletasks()
            current_geometry = self.winfo_geometry()

            # 偵測是否抓到無效值 (例如 1x1+0+0)，如果是就不存
            if "+0+0" in current_geometry and "1x1" in current_geometry:
                self.destroy()
                return

            config = configparser.ConfigParser()
            config['Window'] = {'geometry': current_geometry}

            # 使用絕對路徑確保檔案存在 .exe 同級目錄
            base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            config_path = os.path.join(base_dir, CONFIG_FILE)

            with open(config_path, 'w', encoding='utf-8') as f:
                config.write(f)
        except Exception as e:
            print(f"Save config failed: {e}")

        self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()