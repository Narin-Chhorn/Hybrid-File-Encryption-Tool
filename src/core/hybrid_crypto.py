import struct
import os
from .rsa_handler import RSAHandler
from .aes_handler import AESHandler

class HybridCrypto:
    @staticmethod
    def encrypt_file(input_path, recipient_public_key_path, output_path):
        # 1. Get the full original filename (e.g., 'document.pdf') to save in header
        original_filename = os.path.basename(input_path).encode('utf-8')
        filename_len = len(original_filename)

        # 2. Generate AES key and encrypt content
        aes_key = AESHandler.generate_key(32)
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        
        nonce, ciphertext, tag = AESHandler.encrypt_data(plaintext, aes_key)

        # 3. Encrypt AES key with Recipient's RSA Public Key
        recipient_public_key = RSAHandler.load_key(recipient_public_key_path)
        encrypted_aes_key = RSAHandler.encrypt(aes_key, recipient_public_key)

        # 4. Save everything into one package
        # Format: [Filename_Len(4)] + [Filename_Bytes] + [Key_Len(4)] + [Key] + [Nonce] + [Tag] + [Ciphertext]
        with open(output_path, 'wb') as f:
            # Write Original Filename metadata
            f.write(struct.pack('I', filename_len))
            f.write(original_filename)
            
            # Write encryption data
            f.write(struct.pack('I', len(encrypted_aes_key)))
            f.write(encrypted_aes_key)
            f.write(nonce)
            f.write(tag)
            f.write(ciphertext)

        return {
            'original_size': len(plaintext),
            'encrypted_size': os.path.getsize(output_path),
            'output_file': output_path
        }

    @staticmethod
    def decrypt_file(input_path, recipient_private_key_path, output_path):
        with open(input_path, 'rb') as f:
            # 1. Read Original Filename Metadata
            # Read 4 bytes for the length of the filename string
            filename_len = struct.unpack('I', f.read(4))[0] 
            # Read the original filename bytes (e.g., b'document.pdf')
            original_filename = f.read(filename_len).decode('utf-8')

            # 2. Read Encrypted AES Key
            key_size = struct.unpack('I', f.read(4))[0]
            encrypted_aes_key = f.read(key_size)

            # 3. Read AES components
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        # 4. Decrypt AES key with RSA
        recipient_private_key = RSAHandler.load_key(recipient_private_key_path)
        aes_key = RSAHandler.decrypt(encrypted_aes_key, recipient_private_key)

        # 5. Decrypt file content
        plaintext = AESHandler.decrypt_data(nonce, ciphertext, tag, aes_key)

        # 6. Construct the final output path using the original filename
        
        # Get the directory (e.g., 'data/decrypted') from the user-provided output_path
        output_dir = os.path.dirname(output_path)
        
        # Construct the final path: directory + original filename
        final_output_path = os.path.join(output_dir, original_filename)

        with open(final_output_path, 'wb') as f:
            f.write(plaintext)

        return {
            'decrypted_size': len(plaintext),
            'output_file': final_output_path
        }