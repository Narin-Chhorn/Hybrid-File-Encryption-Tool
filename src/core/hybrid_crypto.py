import struct
import os
from .rsa_handler import RSAHandler
from .aes_handler import AESHandler

# Define constants instead of using "Magic Numbers"
AES_NONCE_SIZE = 16
AES_TAG_SIZE = 16
AES_KEY_SIZE = 32
FILENAME_LEN_SIZE = 4
KEY_LEN_SIZE = 4

class HybridCrypto:
    @staticmethod
    def encrypt_file(input_path, recipient_public_key_path, output_path):
        # Security: Strip any directory paths to get just the filename
        # This prevents "confused deputy" attacks with paths
        filename_str = os.path.basename(input_path)
        original_filename = filename_str.encode('utf-8')
        filename_len = len(original_filename)

        # 2. Generate AES key and encrypt content
        aes_key = AESHandler.generate_key(AES_KEY_SIZE)
        
        with open(input_path, 'rb') as f:
            plaintext = f.read() # Warning: Still reads full file into RAM
        
        # Pass original_filename as associated_data
        # This "signs" the filename. If a hacker changes it, decryption fails.
        nonce, ciphertext, tag = AESHandler.encrypt_data(plaintext, aes_key, associated_data=original_filename)

        # 3. Encrypt AES key with Recipient's RSA Public Key
        recipient_public_key = RSAHandler.load_key(recipient_public_key_path)
        encrypted_aes_key = RSAHandler.encrypt(aes_key, recipient_public_key)

        # 4. Save everything into one package
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
            filename_len = struct.unpack('I', f.read(FILENAME_LEN_SIZE))[0] 
            
            # Read the original filename bytes
            original_filename_bytes = f.read(filename_len)
            original_filename = original_filename_bytes.decode('utf-8')

            # 2. Read Encrypted AES Key
            key_size = struct.unpack('I', f.read(KEY_LEN_SIZE))[0]
            encrypted_aes_key = f.read(key_size)

            # 3. Read AES components using constants
            nonce = f.read(AES_NONCE_SIZE)
            tag = f.read(AES_TAG_SIZE)
            ciphertext = f.read()

        # 4. Decrypt AES key with RSA
        recipient_private_key = RSAHandler.load_key(recipient_private_key_path)
        aes_key = RSAHandler.decrypt(encrypted_aes_key, recipient_private_key)

        # 5. Decrypt file content
        # Pass the filename bytes as associated_data for verification
        try:
            plaintext = AESHandler.decrypt_data(nonce, ciphertext, tag, aes_key, associated_data=original_filename_bytes)
        except ValueError:
             # This happens if the Tag doesn't match (meaning content OR filename was tampered with)
            raise ValueError("Integrity Check Failed! The file or filename has been modified.")

        # 6. Construct the final output path
        # Even if the tag matches, we never trust file paths from external sources.
        safe_filename = os.path.basename(original_filename)
        
        output_dir = os.path.dirname(output_path)
        final_output_path = os.path.join(output_dir, safe_filename)

        with open(final_output_path, 'wb') as f:
            f.write(plaintext)

        return {
            'decrypted_size': len(plaintext),
            'output_file': final_output_path
        }