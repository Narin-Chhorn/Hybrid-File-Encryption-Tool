import os
from ..core.rsa_handler import RSAHandler

# --- CRITICAL FIX: Ensure the absolute path is loaded from config ---
# Use an import statement to bring in the absolute path variable.
try:
    # Attempt to load the absolute path defined in your config.py
    from config import KEYS_DIR
    DEFAULT_KEYS_DIR = KEYS_DIR
except ImportError:
    # Fallback to the relative path if the config file can't be imported 
    # (this should only happen in very specific environments, but is safe).
    DEFAULT_KEYS_DIR = 'keys'


class KeyManager:
    @staticmethod
    def generate_user_keys(username, keys_dir=DEFAULT_KEYS_DIR, key_size=4096):
        # The key size is 4096 by default [cite: 42, 50, 158]
        user_dir = os.path.join(keys_dir, username)
        os.makedirs(user_dir, exist_ok=True)
        
        private_key, public_key = RSAHandler.generate_keypair(key_size)
        
        private_key_path = os.path.join(user_dir, 'private_key.pem')
        public_key_path = os.path.join(user_dir, 'public_key.pem')
        
        RSAHandler.save_key(private_key, private_key_path)
        RSAHandler.save_key(public_key, public_key_path)
        
        return {
            'username': username,
            'private_key': private_key_path,
            'public_key': public_key_path,
            'key_size': key_size
        }

    @staticmethod
    def get_user_keys(username, keys_dir=DEFAULT_KEYS_DIR):
        user_dir = os.path.join(keys_dir, username)
        return {
            'private_key': os.path.join(user_dir, 'private_key.pem'),
            'public_key': os.path.join(user_dir, 'public_key.pem')
        }

    @staticmethod
    def list_users(keys_dir=DEFAULT_KEYS_DIR):
        # This function now uses the absolute path loaded from config.py by default
        if not os.path.exists(keys_dir):
            return []
            
        return [d for d in os.listdir(keys_dir) 
                if os.path.isdir(os.path.join(keys_dir, d))]