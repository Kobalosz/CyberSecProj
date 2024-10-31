from cryptography.fernet import Fernet
from passgen import TestVar, Username
import secrets
import string
import json
import os
import re


def manage_crypto(password, username=None, data_dir="my_data"):
    """
    Manages encryption and decryption of a message.

    Args:
        message (str): The message to be processed.

    Returns:
        tuple: A tuple containing the encrypted and decrypted messages.
    """

    def generate_key():
        """Generates a new encryption key."""
        key = Fernet.generate_key()
        return key

    def encrypt_pass(password, key):
        """Encrypts the message using the provided key."""
        f = Fernet(key)
        encrypted_pass = f.encrypt(password.encode())
        return encrypted_pass
    

    def decrypt_pass(encrypted_pass, key):
        """Decrypts the encrypted message using the provided key."""
        f = Fernet(key)
        decrypted_pass = f.decrypt(encrypted_pass).decode()
        return decrypted_pass
     
    # Create the data directory if it doesn't exist
    os.makedirs(data_dir, exist_ok=True)

    # --- Key Storage ---
    key_store_filename = os.path.join(data_dir, "key_store.json")
    if os.path.exists(key_store_filename):
        with open(key_store_filename, "r") as f:
            try:
                key_data = json.load(f)
            except json.JSONDecodeError:
                key_data = {}
    else:
        key_data = {}

    # Generate a new key if not already present
    key_id = len(key_data)
    if key_id not in key_data:
        key = generate_key()  # Call the nested generate_key function
        key_data[key_id] = key.decode()

        with open(key_store_filename, "w") as f:
            json.dump(key_data, f, indent=4)

    key = key_data[key_id].encode()

    # Encrypt the password
    encrypted_pass = encrypt_pass(password, key)  # Call the nested encrypt_pass function

    # --- Password Storage ---
    password_data = {
        "password": encrypted_pass.decode(),
        "username": username,
    }

    password_store_filename = os.path.join(data_dir, "password_store.json")
    if os.path.exists(password_store_filename):
        with open(password_store_filename, "r") as f:
            try:
                existing_data = json.load(f)
            except json.JSONDecodeError:
                existing_data = []
    else:
        existing_data = []

    existing_data.append(password_data)

    with open(password_store_filename, "w") as f:
        json.dump(existing_data, f, indent=4)

    return encrypted_pass, key_id

# Example usage:
encrypted_pass, key_id = manage_crypto(
    "mypassword", username="user123", website="example.com", data_dir="my_passwords"
)

print("Encrypted password:", encrypted_pass)
print("Key ID:", key_id)
# Example usage

