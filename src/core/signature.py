from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from .rsa_handler import RSAHandler

class SignatureHandler:
    @staticmethod
    def sign_file(file_path, private_key_path):
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        hash_obj = SHA256.new(file_data)
        private_key = RSAHandler.load_key(private_key_path)
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        return signature
    
    @staticmethod
    def verify_signature(file_path, signature, public_key_path):
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            hash_obj = SHA256.new(file_data)
            public_key = RSAHandler.load_key(public_key_path)
            pkcs1_15.new(public_key).verify(hash_obj, signature)
            return True
        except:
            return False