# 🔐 Hybrid File Encryption Tool

A secure file encryption application that combines **RSA-4096** and **AES-256** encryption algorithms to provide security for file sharing.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Security](#security)
- [Technologies](#technologies)
- [Contributing](#contributing)

## 🎯 Overview

This project implements a **hybrid encryption system** that securely encrypts files for transmission over insecure channels. It uses:
- **RSA-4096** for secure key exchange
- **AES-256-GCM** for fast file encryption
- **SHA-256** for digital signatures

Perfect for securely sharing confidential documents, images, or any file type over email, cloud storage, or USB drives.

## ✨ Features

- 🔒 **Hybrid Encryption**: Combines RSA and AES for optimal security and performance
- 🖥️ **User-Friendly GUI**: Easy-to-use graphical interface built with Tkinter
- 🔑 **Key Management**: Generate and manage RSA key pairs for multiple users
- ✍️ **Digital Signatures**: Verify file authenticity and integrity
- 📁 **All File Types**: Encrypt any file format (PDF, DOCX, images, videos, etc.)
- 🚀 **Fast Performance**: AES ensures quick encryption of large files

## 🔐 How It Works

### Encryption Process
```
1. User selects a file to encrypt
2. System generates a random AES-256 session key
3. File content is encrypted with AES (fast)
4. AES key is encrypted with recipient's RSA public key
5. Encrypted package is created and can be safely transmitted
```

### Decryption Process
```
1. Recipient receives encrypted package
2. Recipient's RSA private key decrypts the AES key
3. AES key decrypts the file content
4. Original file is restored
```

### Why Hybrid Encryption?

| Algorithm | Strength | Speed | Best For |
|-----------|----------|-------|----------|
| **RSA** | Very High | Slow | Small data (keys) |
| **AES** | Very High | Fast | Large data (files) |
| **Hybrid** | Very High | Fast | Everything! ✅ |

## 🚀 Installation

### Prerequisites

- Python install -r requirements.txt

### Step 1: Clone the Repository
```bash
git clone https://github.com/Narin-Chhorn/Hybrid-File-Encryption-Tool.git
cd Hybrid-File-Encryption-Tool
```

### Step 2: Create Virtual Environment (Recommended)
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run the Application
```bash
python gui_app.py
```

## 📖 Usage

### 1. Generate Keys

Before encrypting files, generate RSA key pairs for users:
```
1. Open the application
2. Go to "🔑 Generate Keys" tab
3. Enter username (e.g., "alice", "bob")
4. Select key size (4096-bit recommended)
5. Click "Generate Keys"
```

**Important:** Keep private keys secure! Never share them.

### 2. Encrypt a File
```
1. Go to "🔒 Encrypt File" tab
2. Click "Browse" and select the file to encrypt
3. Select recipient from dropdown
4. Choose output location
5. Click "🔒 Encrypt File"
6. Share the encrypted file via email, USB, cloud, etc.
```

### 3. Decrypt a File
```
1. Go to "🔓 Decrypt File" tab
2. Click "Browse" and select encrypted file
3. Select your username from dropdown
4. Choose where to save decrypted file
5. Click "🔓 Decrypt File"
6. Original file is restored!
```

## 📁 Project Structure
```
Hybrid-File-Encryption-Tool/
│
├── gui_app.py                 # Main GUI application
├── config.py                  # Configuration settings
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
├── .gitignore                 # Git ignore rules
│
├── keys/                      # RSA key storage
│
├── data/                      # File storage
│   ├── input/                # Files to encrypt
│   ├── output/               # Encrypted files
│   └── decrypted/            # Decrypted files
│
└── src/                       # Source code
    ├── core/                 # Core encryption modules
    │   ├── rsa_handler.py    # RSA operations
    │   ├── aes_handler.py    # AES operations
    │   ├── hybrid_crypto.py  # Hybrid encryption logic
    │   └── signature.py      # Digital signatures
    └── utils/                # Utility modules
        └── key_manager.py    # Key generation and management
```

## 🔒 Security

### Encryption Specifications

|    Component       |      Specification        |
|--------------------|---------------------------|
| **RSA Key Size**   | 4096-bit                  |
| **AES Key Size**   | 256-bit                   |
| **AES Mode**       | GCM (Galois/Counter Mode) |
| **Hash Function**  | SHA-256                   |
| **Security Level** | Military Grade            |

### Security Features

✅ **End-to-End Encryption**: Only the recipient can decrypt files   
✅ **Digital Signatures**: Verify sender authenticity  
✅ **Key Isolation**: Private keys never transmitted  
✅ **Forward Secrecy**: Each encryption uses new session key  

### Security Best Practices

1. ⚠️ **Never share your private key**
2. ⚠️ **Use 4096-bit RSA keys** for maximum security
3. ⚠️ **Verify digital signatures** when receiving files
4. ⚠️ **Keep software updated** with latest security patches
5. ⚠️ **Use strong passwords** if adding key encryption

## 🛠️ Technologies

- **Python 3.8+**: Core programming language
- **PyCryptodome**: Cryptography library
- **Tkinter**: GUI framework
- **RSA-4096**: Asymmetric encryption
- **AES-256-GCM**: Symmetric encryption

## 👤 Author

**Narin Chhorn Bachelor of Telecom and Networking Specialization: Cybersecurity**
**Course: Cryptography**

- GitHub: [@Narin-Chhorn](https://github.com/Narin-Chhorn)
- Project Link: [Hybrid-File-Encryption-Tool](https://github.com/Narin-Chhorn/Hybrid-File-Encryption-Tool)

## 🙏 Acknowledgments

- PyCryptodome for excellent cryptography library
- Anthropic's Claude for development assistance
- Open source community for inspiration

## 📚 Resources

- [RSA Encryption](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [AES Encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [Hybrid Cryptosystems](https://en.wikipedia.org/wiki/Hybrid_cryptosystem)
- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/)


## 🔮 Future Enhancements

- [ ] Add support for multiple recipients
- [ ] Implement key expiration
- [ ] Add file compression before encryption
- [ ] Create command-line interface (CLI)
- [ ] Add batch file encryption
- [ ] Implement key backup and recovery
- [ ] Add progress bar for large files

## ⚡ Quick Start Example
```python
from src.utils.key_manager import KeyManager
from src.core.hybrid_crypto import HybridCrypto

# Generate keys
KeyManager.generate_user_keys('alice', key_size=4096)
KeyManager.generate_user_keys('bob', key_size=4096)

# Encrypt file
HybridCrypto.encrypt_file(
    input_path='document.pdf',
    recipient_public_key_path='keys/bob/public_key.pem',
    output_path='encrypted.bin'
)

# Decrypt file
HybridCrypto.decrypt_file(
    input_path='encrypted.bin',
    recipient_private_key_path='keys/bob/private_key.pem',
    output_path='decrypted.pdf'
)

