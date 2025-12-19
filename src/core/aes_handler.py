from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class AESHandler:
    @staticmethod
    def generate_key(key_size=32):
        return get_random_bytes(key_size)
    
    @staticmethod
    def encrypt_data(data, key):
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce, ciphertext, tag
    
    @staticmethod
    def decrypt_data(nonce, ciphertext, tag, key):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext