import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import sys
import threading
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from config import KEYS_DIR
from src.utils.key_manager import KeyManager
from src.core.hybrid_crypto import HybridCrypto

class EncryptionToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Hybrid File Encryption Tool")
        self.root.geometry("850x650")
        
        # Use standard theme - clean and reliable
        self.style = ttk.Style()
        self.style.theme_use('default') 
        
        # Configure a clean font for everything
        self.default_font = ("Segoe UI", 10)
        self.style.configure(".", font=self.default_font)
        self.style.configure("TLabel", font=self.default_font)
        self.style.configure("TButton", font=self.default_font, padding=5)
        
        # Header Style
        self.style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground="#333333")

        # --- LAYOUT ---
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill='both', expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill='x', pady=(0, 20))
        ttk.Label(header_frame, text="🛡️ Hybrid File Encryption System", style="Header.TLabel").pack(side='left')
        ttk.Label(header_frame, text="v1.0 (RSA-4096 + AES-256)", foreground="#666666").pack(side='left', padx=15, anchor='s', pady=(0, 5))

        # Notebook (Tabs)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill='both', expand=True)
        
        self.create_key_tab()
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor='w', padx=10, pady=5)
        self.status_bar.pack(side='bottom', fill='x')

        # Load users immediately
        self.update_user_lists()

    # --- HELPERS ---
    def log(self, widget, msg):
        """Simple logging helper"""
        widget.config(state='normal')
        timestamp = time.strftime('%H:%M:%S')
        widget.insert(tk.END, f"[{timestamp}] {msg}\n")
        widget.see(tk.END)
        widget.config(state='disabled')

    def toggle_inputs(self, state):
        """Disable buttons while processing"""
        for child in self.root.winfo_children():
            if isinstance(child, ttk.Button): child.configure(state=state)

    # ==========================================
    # TAB 1: KEY GENERATION
    # ==========================================
    def create_key_tab(self):
        tab = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(tab, text="Generate Keys")
        
        # Input Section
        panel = ttk.LabelFrame(tab, text="Create New User Identity", padding=15)
        panel.pack(fill='x', pady=(0, 15))
        
        frame = ttk.Frame(panel)
        frame.pack(fill='x')
        
        ttk.Label(frame, text="Username:").pack(side='left', padx=(0, 10))
        self.user_entry = ttk.Entry(frame, width=30)
        self.user_entry.pack(side='left', padx=(0, 20))
        
        ttk.Button(frame, text="Generate Keys", command=self.start_keygen).pack(side='left')
        
        # Progress Bar (Hidden by default)
        self.key_progress = ttk.Progressbar(panel, mode='indeterminate')
        self.key_progress.pack(fill='x', pady=(15, 0))
        
        # Log Section
        log_lbl = ttk.Label(tab, text="System Log:", font=("Segoe UI", 9, "bold"))
        log_lbl.pack(anchor='w', pady=(10, 5))
        
        self.key_log = scrolledtext.ScrolledText(tab, height=10, state='disabled', font=("Consolas", 9))
        self.key_log.pack(fill='both', expand=True)

    def start_keygen(self):
        user = self.user_entry.get().strip()
        if not user: return messagebox.showerror("Error", "Username is required.")
        
        self.key_progress.start(10)
        self.status_var.set(f"Generating keys for {user}...")
        threading.Thread(target=self.run_keygen, args=(user,), daemon=True).start()

    def run_keygen(self, user):
        try:
            # FIX: Explicitly using KEYS_DIR
            res = KeyManager.generate_user_keys(user, keys_dir=KEYS_DIR)
            self.root.after(0, lambda: self.finish_keygen(True, res))
        except Exception as e:
            self.root.after(0, lambda: self.finish_keygen(False, str(e)))

    def finish_keygen(self, success, res):
        self.key_progress.stop()
        if success:
            self.log(self.key_log, f"✅ Success: Keys generated for '{res['username']}'")
            self.log(self.key_log, f"   Location: {KEYS_DIR}")
            self.status_var.set("Ready")
            self.update_user_lists()
            messagebox.showinfo("Success", f"Keys created for {res['username']}!")
        else:
            self.log(self.key_log, f"❌ Error: {res}")
            messagebox.showerror("Error", res)

    # ==========================================
    # TAB 2: ENCRYPTION
    # ==========================================
    def create_encrypt_tab(self):
        tab = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(tab, text="Encrypt File")
        
        # File Selection
        panel = ttk.LabelFrame(tab, text="Encryption Details", padding=15)
        panel.pack(fill='x', pady=(0, 15))
        panel.columnconfigure(1, weight=1)
        
        # Row 0: Input File
        ttk.Label(panel, text="Input File:").grid(row=0, column=0, sticky='w', pady=5)
        self.enc_file = ttk.Entry(panel)
        self.enc_file.grid(row=0, column=1, sticky='ew', padx=10)
        ttk.Button(panel, text="Browse...", command=lambda: self.browse_file(self.enc_file)).grid(row=0, column=2)
        
        # Row 1: Recipient
        ttk.Label(panel, text="Recipient:").grid(row=1, column=0, sticky='w', pady=5)
        self.rec_var = tk.StringVar()
        self.rec_combo = ttk.Combobox(panel, textvariable=self.rec_var, state='readonly')
        self.rec_combo.grid(row=1, column=1, sticky='ew', padx=10)
        
        # Row 2: Output File
        ttk.Label(panel, text="Save As:").grid(row=2, column=0, sticky='w', pady=5)
        self.enc_out = ttk.Entry(panel)
        self.enc_out.insert(0, "data/output/encrypted_file.bin")
        self.enc_out.grid(row=2, column=1, sticky='ew', padx=10)
        ttk.Button(panel, text="Browse...", command=lambda: self.save_file(self.enc_out)).grid(row=2, column=2)
        
        # Action Button & Progress
        self.enc_progress = ttk.Progressbar(panel, mode='indeterminate')
        self.enc_progress.grid(row=3, column=0, columnspan=3, sticky='ew', pady=(15, 0))
        
        btn = ttk.Button(panel, text="🔒 Encrypt File", command=self.start_enc)
        btn.grid(row=4, column=0, columnspan=3, sticky='ew', pady=(10, 0))
        
        # Log
        self.enc_log = scrolledtext.ScrolledText(tab, height=8, state='disabled', font=("Consolas", 9))
        self.enc_log.pack(fill='both', expand=True)

    def start_enc(self):
        if not self.enc_file.get() or not self.rec_var.get(): 
            return messagebox.showwarning("Missing Info", "Please select a file and a recipient.")
        
        self.enc_progress.start(10)
        self.status_var.set("Encrypting file...")
        threading.Thread(target=self.run_enc, daemon=True).start()

    def run_enc(self):
        try:
            inp = self.enc_file.get()
            rec = self.rec_var.get()
            out = self.enc_out.get()
            
            # FIX: Explicitly using KEYS_DIR
            keys = KeyManager.get_user_keys(rec, keys_dir=KEYS_DIR)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            
            res = HybridCrypto.encrypt_file(inp, keys['public_key'], out)
            self.root.after(0, lambda: self.finish_enc(True, res))
        except Exception as e:
            self.root.after(0, lambda: self.finish_enc(False, str(e)))

    def finish_enc(self, success, res):
        self.enc_progress.stop()
        if success:
            self.log(self.enc_log, f"✅ Encrypted file for user: {self.rec_var.get()}")
            self.log(self.enc_log, f"   Original Size: {res['original_size']} bytes")
            self.log(self.enc_log, f"   Encrypted Size: {res['encrypted_size']} bytes")
            self.status_var.set("Encryption complete")
            messagebox.showinfo("Success", "File Encrypted Successfully!")
        else:
            self.log(self.enc_log, f"❌ Error: {res}")
            messagebox.showerror("Error", res)

    # ==========================================
    # TAB 3: DECRYPTION
    # ==========================================
    def create_decrypt_tab(self):
        tab = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(tab, text="Decrypt File")
        
        panel = ttk.LabelFrame(tab, text="Decryption Details", padding=15)
        panel.pack(fill='x', pady=(0, 15))
        panel.columnconfigure(1, weight=1)
        
        # Row 0: Input
        ttk.Label(panel, text="Encrypted File:").grid(row=0, column=0, sticky='w', pady=5)
        self.dec_file = ttk.Entry(panel)
        self.dec_file.grid(row=0, column=1, sticky='ew', padx=10)
        ttk.Button(panel, text="Browse...", command=lambda: self.browse_file(self.dec_file)).grid(row=0, column=2)
        
        # Row 1: User Identity
        ttk.Label(panel, text="I am User:").grid(row=1, column=0, sticky='w', pady=5)
        self.dec_user_var = tk.StringVar()
        self.dec_user_combo = ttk.Combobox(panel, textvariable=self.dec_user_var, state='readonly')
        self.dec_user_combo.grid(row=1, column=1, sticky='ew', padx=10)
        
        # Row 2: Output Folder
        ttk.Label(panel, text="Output Folder:").grid(row=2, column=0, sticky='w', pady=5)
        self.dec_out = ttk.Entry(panel)
        self.dec_out.insert(0, "data/decrypted/")
        self.dec_out.grid(row=2, column=1, sticky='ew', padx=10)
        ttk.Button(panel, text="Browse...", command=lambda: self.browse_dir(self.dec_out)).grid(row=2, column=2)
        
        # Action
        self.dec_progress = ttk.Progressbar(panel, mode='indeterminate')
        self.dec_progress.grid(row=3, column=0, columnspan=3, sticky='ew', pady=(15, 0))
        
        btn = ttk.Button(panel, text="🔓 Decrypt File", command=self.start_dec)
        btn.grid(row=4, column=0, columnspan=3, sticky='ew', pady=(10, 0))
        
        # Log
        self.dec_log = scrolledtext.ScrolledText(tab, height=8, state='disabled', font=("Consolas", 9))
        self.dec_log.pack(fill='both', expand=True)

    def start_dec(self):
        if not self.dec_file.get() or not self.dec_user_var.get():
            return messagebox.showwarning("Missing Info", "Please select the encrypted file and your username.")
        
        self.dec_progress.start(10)
        self.status_var.set("Decrypting...")
        threading.Thread(target=self.run_dec, daemon=True).start()

    def run_dec(self):
        try:
            inp = self.dec_file.get()
            user = self.dec_user_var.get()
            out_dir = self.dec_out.get()
            
            # FIX: Explicitly using KEYS_DIR
            keys = KeyManager.get_user_keys(user, keys_dir=KEYS_DIR)
            
            if not os.path.exists(out_dir): os.makedirs(out_dir)
            
            # Create a dummy path so logic works; real filename is extracted from metadata
            dummy_path = os.path.join(out_dir, "placeholder")
            
            res = HybridCrypto.decrypt_file(inp, keys['private_key'], dummy_path)
            self.root.after(0, lambda: self.finish_dec(True, res))
        except Exception as e:
            self.root.after(0, lambda: self.finish_dec(False, str(e)))

    def finish_dec(self, success, res):
        self.dec_progress.stop()
        if success:
            filename = os.path.basename(res['output_file'])
            self.log(self.dec_log, f"✅ File Restored Successfully")
            self.log(self.dec_log, f"   Saved as: {filename}")
            self.status_var.set("Ready")
            messagebox.showinfo("Success", f"File restored: {filename}")
        else:
            self.log(self.dec_log, f"❌ Decryption Failed: {res}")
            messagebox.showerror("Error", f"Decryption Failed.\n{res}")

    # --- COMMON UTILS ---
    def browse_file(self, entry):
        f = filedialog.askopenfilename()
        if f: 
            entry.delete(0, tk.END)
            entry.insert(0, f)
            
    def save_file(self, entry):
        f = filedialog.asksaveasfilename(defaultextension=".bin")
        if f:
            entry.delete(0, tk.END)
            entry.insert(0, f)

    def browse_dir(self, entry):
        f = filedialog.askdirectory()
        if f:
            entry.delete(0, tk.END)
            entry.insert(0, f)

    def update_user_lists(self):
        # FIX: Explicitly using KEYS_DIR
        users = KeyManager.list_users(keys_dir=KEYS_DIR)
        if users:
            self.rec_combo['values'] = users
            self.dec_user_combo['values'] = users
            if not self.rec_var.get(): self.rec_combo.current(0)
            if not self.dec_user_var.get(): self.dec_user_combo.current(0)
        else:
            msg = ["No keys found"]
            self.rec_combo['values'] = msg
            self.dec_user_combo['values'] = msg

def main():
    root = tk.Tk()
    app = EncryptionToolGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()