from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(text: str, password: str) -> str:
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return urlsafe_b64encode(salt + iv + ciphertext).decode('utf-8')

def decrypt(enc_data: str, password: str) -> str:
    enc_data_bytes = urlsafe_b64decode(enc_data.encode('utf-8'))
    salt = enc_data_bytes[:16]
    iv = enc_data_bytes[16:32]
    ciphertext = enc_data_bytes[32:]

    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode('utf-8')

def main():
    action = input("Do you want to encrypt or decrypt a message? (enter 'encrypt' or 'decrypt'): ").strip().lower()

    if action == 'encrypt':
        message = input("Please enter the message to encrypt: ").strip()
        key = input("Please enter the encryption key: ").strip()
        encrypted_data = encrypt(message, key)
        print("Encrypted Data:")
        print(encrypted_data)
    elif action == 'decrypt':
        ciphertext = input("Please enter the encrypted message: ").strip()
        key = input("Please enter the decryption key: ").strip()
        try:
            decrypted_message = decrypt(ciphertext, key)
            print(f"Decrypted Message: {decrypted_message}")
        except Exception as e:
            print(f"An error occurred during decryption: {e}")
    else:
        print("Invalid action. Please enter 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()
