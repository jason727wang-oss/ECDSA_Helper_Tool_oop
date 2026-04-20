import tkinter as tk
from tkinter import ttk
import webbrowser

class AboutTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding="10")
        self.box = tk.Text(self, font=('Courier', 11), bg='#F0F0F0', padx=10, pady=10)
        self.box.pack(fill="both", expand=True)
        self.render_content()

    def add_link(self, label, url):
        start = self.box.index(tk.INSERT)
        self.box.insert(tk.INSERT, label + "\n")
        end = self.box.index(f"{start} lineend")
        tag = f"link_{label.replace(' ', '')}"
        self.box.tag_add(tag, start, end)
        self.box.tag_config(tag, foreground="blue", underline=True)
        self.box.tag_bind(tag, "<Button-1>", lambda e: webbrowser.open_new(url))
        self.box.tag_bind(tag, "<Enter>", lambda e: self.box.config(cursor="hand2"))
        self.box.tag_bind(tag, "<Leave>", lambda e: self.box.config(cursor="arrow"))

    def render_content(self):
        self.box.insert(tk.END, " /\\_/\\ \n( 0.0 )\n (_ _)~\nECDSA Helper Tool v2.3.0 (Modular)\n\n")
        self.box.insert(tk.END, "Author: LeoWang/Weikeng\nEmail: leowang@weikeng.com.tw\n\nLinks:\n")
        self.add_link("JS ECDSA Online Sample", "https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html")
        self.add_link("ASN.1 Online Decoder", "https://lapo.it/asn1js/")
        self.add_link("SHA-384 Online Tool", "https://emn178.github.io/online-tools/sha384.html")
        self.box.config(state="disabled")