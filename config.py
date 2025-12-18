import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) 

KEYS_DIR = os.path.join(BASE_DIR, 'keys')
DATA_DIR = os.path.join(BASE_DIR, 'data')

RSA_KEY_SIZE = 4096
AES_KEY_SIZE = 32