from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

class RSAHandler:
    @staticmethod
    def generate_keypair(key_size=4096):
        key = RSA.generate(key_size)
        return key, key.publickey()
    
    @staticmethod
    def save_key(key, filepath):
        with open(filepath, 'wb') as f:
            f.write(key.export_key('PEM'))
    
    @staticmethod
    def load_key(filepath):
        with open(filepath, 'rb') as f:
            return RSA.import_key(f.read())
    
    @staticmethod
    def encrypt(data, public_key):
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(data)
    
    @staticmethod
    def decrypt(encrypted_data, private_key):
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(encrypted_data)