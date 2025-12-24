import os
import re  # Added regex for validation
from ..core.rsa_handler import RSAHandler

try:
    from config import KEYS_DIR
    DEFAULT_KEYS_DIR = KEYS_DIR
except ImportError:
    DEFAULT_KEYS_DIR = 'keys'

class KeyManager:
    @staticmethod
    def _validate_username(username):
        # Allow only alphanumeric, underscores, and dashes.
        # This prevents users from entering "../../windows"
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            raise ValueError("Invalid username. Use only letters, numbers, _, or -")

    @staticmethod
    def generate_user_keys(username, keys_dir=DEFAULT_KEYS_DIR, key_size=4096):
        KeyManager._validate_username(username) # Check input
        
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
        KeyManager._validate_username(username) # Check input
        user_dir = os.path.join(keys_dir, username)
        return {
            'private_key': os.path.join(user_dir, 'private_key.pem'),
            'public_key': os.path.join(user_dir, 'public_key.pem')
        }

    @staticmethod
    def list_users(keys_dir=DEFAULT_KEYS_DIR):
        if not os.path.exists(keys_dir):
            return []
            
        return [d for d in os.listdir(keys_dir) 
                if os.path.isdir(os.path.join(keys_dir, d))]