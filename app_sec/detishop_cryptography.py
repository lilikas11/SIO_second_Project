import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import logging
import hmac
import hashlib

# Logging config
logging.basicConfig(filename='app.log', level=logging.INFO)

def encrypt(key, plaintext):
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        return b64encode(iv + ciphertext).decode('utf-8')
    except Exception as e:
        logging.error(f"Encryption error: {e}")
        logging.exception("An exception occurred during encryption:")
        raise

def decrypt(key, ciphertext):
    try:
        ciphertext = b64decode(ciphertext)
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        logging.exception("An exception occurred during decryption:")
        raise

def generate_key():
    return os.urandom(32)

def encrypt_with_hmac(key, plaintext, hmac_key):
    try:
        ciphertext = encrypt(key, plaintext)
        hmac_digest = hmac.new(hmac_key, ciphertext.encode(), hashlib.sha256).hexdigest()
        return ciphertext + ':' + hmac_digest 
    except Exception as e:
        logging.error(f"Hashing error: {e}")
        logging.exception("An exception occurred during hashing:")
        raise

def decrypt_with_hmac(key, hmac_key, hmac_ciphertext):
    ciphertext, hmac_digest = hmac_ciphertext.rsplit(':', 1)
    if hmac.new(hmac_key, ciphertext.encode(), hashlib.sha256).hexdigest() != hmac_digest:
        raise ValueError("Ciphertext integrity check failed")
    return decrypt(key, ciphertext)
