import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config import KEYS_DIR, DATA_DIR
from src.utils.key_manager import KeyManager
from src.core.hybrid_crypto import HybridCrypto
from src.core.signature import SignatureHandler


class EncryptionToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Hybrid File Encryption Tool")
        self.root.geometry("800x650")
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_key_gen_tab()
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        
        # Status bar
        self.status_frame = tk.Frame(self.root, bg="#333333", height=30)
        self.status_frame.pack(side='bottom', fill='x')
        
        self.status_label = tk.Label(
            self.status_frame, text="Ready", bg="#333333", fg="white", anchor='w', padx=10
        )
        self.status_label.pack(fill='x')
    
    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update()
    
    # TAB 1: KEY GENERATION
    def create_key_gen_tab(self):
        tab = tk.Frame(self.notebook)
        self.notebook.add(tab, text="🔑 Generate Keys")
        
        tk.Label(tab, text="Generate RSA Key Pair", font=("Arial", 16, "bold")).pack(pady=20)
        
        # Username
        frame = tk.Frame(tab)
        frame.pack(pady=10)
        tk.Label(frame, text="Username:", font=("Arial", 12)).pack(side='left', padx=5)
        self.username_entry = tk.Entry(frame, font=("Arial", 12), width=30)
        self.username_entry.pack(side='left', padx=5)
        
        # Key size
        frame2 = tk.Frame(tab)
        frame2.pack(pady=10)
        tk.Label(frame2, text="Key Size:", font=("Arial", 12)).pack(side='left', padx=5)
        self.keysize_var = tk.StringVar(value="4096")
        ttk.Combobox(frame2, textvariable=self.keysize_var, values=["2048", "4096"], 
                     state='readonly', width=10).pack(side='left', padx=5)
        
        # Generate button
        tk.Button(tab, text="Generate Keys", font=("Arial", 12, "bold"), 
                 bg="#2196F3", fg="white", padx=20, pady=10,
                 command=self.generate_keys).pack(pady=20)
        
        # Output
        tk.Label(tab, text="Output:", font=("Arial", 12, "bold")).pack(pady=5)
        self.keygen_log = scrolledtext.ScrolledText(tab, height=12, width=80, font=("Courier", 10))
        self.keygen_log.pack(pady=10, padx=20)
    
    def generate_keys(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Please enter a username!")
            return
        
        try:
            self.update_status("Generating keys...")
            self.keygen_log.delete(1.0, tk.END)
            
            keysize = int(self.keysize_var.get())
            self.keygen_log.insert(tk.END, f"🔑 Generating {keysize}-bit keys for '{username}'...\n\n")
            self.root.update()
            
            result = KeyManager.generate_user_keys(username, key_size=keysize)
            
            self.keygen_log.insert(tk.END, f"✅ Keys generated!\n\n")
            self.keygen_log.insert(tk.END, f"Private Key: {result['private_key']}\n")
            self.keygen_log.insert(tk.END, f"Public Key: {result['public_key']}\n")
            self.keygen_log.insert(tk.END, f"Key Size: {result['key_size']} bits\n")
            
            self.update_status(f"Keys generated for {username}")
            self.update_user_lists()
            messagebox.showinfo("Success", f"Keys generated for {username}!")
            
        except Exception as e:
            self.keygen_log.insert(tk.END, f"\n❌ ERROR: {str(e)}\n")
            self.update_status("Error")
            messagebox.showerror("Error", str(e))
    
    # TAB 2: ENCRYPT
    def create_encrypt_tab(self):
        tab = tk.Frame(self.notebook)
        self.notebook.add(tab, text="🔒 Encrypt File")
        
        tk.Label(tab, text="Encrypt File", font=("Arial", 16, "bold")).pack(pady=20)
        
        # Input file
        frame = tk.Frame(tab)
        frame.pack(pady=10, fill='x', padx=20)
        tk.Label(frame, text="Input File:", font=("Arial", 11)).pack(anchor='w')
        
        frame2 = tk.Frame(frame)
        frame2.pack(fill='x', pady=5)
        self.encrypt_input_entry = tk.Entry(frame2, font=("Arial", 10), width=60)
        self.encrypt_input_entry.pack(side='left', padx=(0, 5))
        tk.Button(frame2, text="Browse", command=self.browse_encrypt_input).pack(side='left')
        
        # Recipient
        frame3 = tk.Frame(tab)
        frame3.pack(pady=10, fill='x', padx=20)
        tk.Label(frame3, text="Recipient:", font=("Arial", 11)).pack(anchor='w')
        self.recipient_var = tk.StringVar()
        self.recipient_combo = ttk.Combobox(frame3, textvariable=self.recipient_var, width=30)
        self.recipient_combo.pack(anchor='w', pady=5)
        
        # Output file
        frame4 = tk.Frame(tab)
        frame4.pack(pady=10, fill='x', padx=20)
        tk.Label(frame4, text="Output File:", font=("Arial", 11)).pack(anchor='w')
        
        frame5 = tk.Frame(frame4)
        frame5.pack(fill='x', pady=5)
        self.encrypt_output_entry = tk.Entry(frame5, font=("Arial", 10), width=60)
        self.encrypt_output_entry.pack(side='left', padx=(0, 5))
        self.encrypt_output_entry.insert(0, "data/output/encrypted_file.bin")
        tk.Button(frame5, text="Browse", command=self.browse_encrypt_output).pack(side='left')
        
        # Encrypt button
        tk.Button(tab, text="🔒 Encrypt File", font=("Arial", 12, "bold"),
                 bg="#4CAF50", fg="white", padx=20, pady=10,
                 command=self.encrypt_file).pack(pady=20)
        
        # Output
        tk.Label(tab, text="Output:", font=("Arial", 11, "bold")).pack(pady=5)
        self.encrypt_log = scrolledtext.ScrolledText(tab, height=8, width=80, font=("Courier", 9))
        self.encrypt_log.pack(pady=10, padx=20)
    
    def browse_encrypt_input(self):
        filename = filedialog.askopenfilename(title="Select file to encrypt")
        if filename:
            self.encrypt_input_entry.delete(0, tk.END)
            self.encrypt_input_entry.insert(0, filename)
    
    def browse_encrypt_output(self):
        filename = filedialog.asksaveasfilename(
            title="Save as", defaultextension=".bin",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        if filename:
            self.encrypt_output_entry.delete(0, tk.END)
            self.encrypt_output_entry.insert(0, filename)
    
    def encrypt_file(self):
        input_file = self.encrypt_input_entry.get().strip()
        recipient = self.recipient_var.get().strip()
        output_file = self.encrypt_output_entry.get().strip()
        
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("Error", "Please select a valid input file!")
            return
        if not recipient:
            messagebox.showerror("Error", "Please select a recipient!")
            return
        if not output_file:
            messagebox.showerror("Error", "Please specify output file!")
            return
        
        try:
            self.update_status("Encrypting...")
            self.encrypt_log.delete(1.0, tk.END)
            
            recipient_keys = KeyManager.get_user_keys(recipient)
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            self.encrypt_log.insert(tk.END, f"🔐 Encrypting for {recipient}...\n\n")
            self.root.update()
            
            result = HybridCrypto.encrypt_file(
                input_path=input_file,
                recipient_public_key_path=recipient_keys['public_key'],
                output_path=output_file
            )
            
            self.encrypt_log.insert(tk.END, f"✅ File encrypted!\n\n")
            self.encrypt_log.insert(tk.END, f"Output: {result['output_file']}\n")
            self.encrypt_log.insert(tk.END, f"Size: {result['encrypted_size']:,} bytes\n")
            
            self.update_status("Encryption complete")
            messagebox.showinfo("Success", "File encrypted successfully!")
            
        except Exception as e:
            self.encrypt_log.insert(tk.END, f"\n❌ ERROR: {str(e)}\n")
            self.update_status("Error")
            messagebox.showerror("Error", str(e))
    
    # TAB 3: DECRYPT
    def create_decrypt_tab(self):
        tab = tk.Frame(self.notebook)
        self.notebook.add(tab, text="🔓 Decrypt File")
        
        tk.Label(tab, text="Decrypt File", font=("Arial", 16, "bold")).pack(pady=20)
        
        # Input file
        frame = tk.Frame(tab)
        frame.pack(pady=10, fill='x', padx=20)
        tk.Label(frame, text="Encrypted File:", font=("Arial", 11)).pack(anchor='w')
        
        frame2 = tk.Frame(frame)
        frame2.pack(fill='x', pady=5)
        self.decrypt_input_entry = tk.Entry(frame2, font=("Arial", 10), width=60)
        self.decrypt_input_entry.pack(side='left', padx=(0, 5))
        tk.Button(frame2, text="Browse", command=self.browse_decrypt_input).pack(side='left')
        
        # User
        frame3 = tk.Frame(tab)
        frame3.pack(pady=10, fill='x', padx=20)
        tk.Label(frame3, text="You are:", font=("Arial", 11)).pack(anchor='w')
        self.decrypt_user_var = tk.StringVar()
        self.decrypt_user_combo = ttk.Combobox(frame3, textvariable=self.decrypt_user_var, width=30)
        self.decrypt_user_combo.pack(anchor='w', pady=5)
        
        # Output file
        frame4 = tk.Frame(tab)
        frame4.pack(pady=10, fill='x', padx=20)
        tk.Label(frame4, text="Output File:", font=("Arial", 11)).pack(anchor='w')
        
        frame5 = tk.Frame(frame4)
        frame5.pack(fill='x', pady=5)
        self.decrypt_output_entry = tk.Entry(frame5, font=("Arial", 10), width=60)
        self.decrypt_output_entry.pack(side='left', padx=(0, 5))
        self.decrypt_output_entry.insert(0, "data/decrypted/")
        tk.Button(frame5, text="Browse", command=self.browse_decrypt_output).pack(side='left')
        
        # Decrypt button
        tk.Button(tab, text="🔓 Decrypt File", font=("Arial", 12, "bold"),
                 bg="#FF9800", fg="white", padx=20, pady=10,
                 command=self.decrypt_file).pack(pady=20)
        
        # Output
        tk.Label(tab, text="Output:", font=("Arial", 11, "bold")).pack(pady=5)
        self.decrypt_log = scrolledtext.ScrolledText(tab, height=8, width=80, font=("Courier", 9))
        self.decrypt_log.pack(pady=10, padx=20)
    
    def browse_decrypt_input(self):
        filename = filedialog.askopenfilename(
            title="Select encrypted file",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        if filename:
            self.decrypt_input_entry.delete(0, tk.END)
            self.decrypt_input_entry.insert(0, filename)
    
    def browse_decrypt_output(self):
        filename = filedialog.asksaveasfilename(title="Save decrypted file as",
            defaultextension=".*",
        filetypes=[
            ("All files", "*.*"),
            ("Text files", "*.txt"),
            ("PDF files", "*.pdf"),
            ("Word files", "*.docx"),
            ("Excel files", "*.xlsx"),
            ("Images", "*.png *.jpg *.jpeg"),  
            ]
        )                                      
        if filename:
            self.decrypt_output_entry.delete(0, tk.END)
            self.decrypt_output_entry.insert(0, filename)
    
    def decrypt_file(self):
        input_file = self.decrypt_input_entry.get().strip()
        user = self.decrypt_user_var.get().strip()
        output_file = self.decrypt_output_entry.get().strip()
        
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("Error", "Please select a valid encrypted file!")
            return
        if not user:
            messagebox.showerror("Error", "Please select your username!")
            return
        if not output_file:
            messagebox.showerror("Error", "Please specify output file!")
            return
        
        try:
            self.update_status("Decrypting...")
            self.decrypt_log.delete(1.0, tk.END)
            
            user_keys = KeyManager.get_user_keys(user)
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            self.decrypt_log.insert(tk.END, f"🔓 Decrypting...\n\n")
            self.root.update()
            
            result = HybridCrypto.decrypt_file(
                input_path=input_file,
                recipient_private_key_path=user_keys['private_key'],
                output_path=output_file
            )
            
            self.decrypt_log.insert(tk.END, f"✅ File decrypted!\n\n")
            self.decrypt_log.insert(tk.END, f"Output: {result['output_file']}\n")
            self.decrypt_log.insert(tk.END, f"Size: {result['decrypted_size']:,} bytes\n")
            
            self.update_status("Decryption complete")
            messagebox.showinfo("Success", "File decrypted successfully!")
            
        except Exception as e:
            self.decrypt_log.insert(tk.END, f"\n❌ ERROR: {str(e)}\n")
            self.update_status("Error")
            messagebox.showerror("Error", str(e))
    
    def update_user_lists(self):
        users = KeyManager.list_users(keys_dir=KEYS_DIR) 
    
        if users:
            self.recipient_combo['values'] = users
            self.decrypt_user_combo['values'] = users
            
            # Optionally set the first user as the default selected user
            if not self.decrypt_user_var.get():
                self.decrypt_user_var.set(users[0])
            if not self.recipient_var.get():
                self.recipient_var.set(users[0])
        else:
            self.recipient_combo['values'] = ['Generate keys first']
            self.decrypt_user_combo['values'] = ['Generate keys first']

def main():
    root = tk.Tk()
    app = EncryptionToolGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()