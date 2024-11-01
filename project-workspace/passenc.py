import os
import json
import base64
import re
import secrets
import string
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey

class PasswordGenerator:
    """
    Secure password generation with comprehensive strength validation.
    """
    def __init__(self, 
                 min_length: int = 12, 
                 max_length: int = 32,
                 require_lowercase: bool = True,
                 require_uppercase: bool = True,
                 require_digits: bool = True,
                 require_special: bool = True):
        self.min_length = min_length
        self.max_length = max_length
        self.excluded_chars = set("|`¬¦~")
        
        self.validation_rules = {
            'lowercase': require_lowercase,
            'uppercase': require_uppercase,
            'digits': require_digits,
            'special': require_special
        }

    def generate_password(self, length: Optional[int] = None) -> str:
        """
        Generate a cryptographically secure password.
        
        Args:
            length (int, optional): Desired password length. 
                                    Defaults to midpoint between min and max.
        
        Returns:
            str: Generated password meeting strength criteria
        """
        if length is None:
            length = (self.min_length + self.max_length) // 2

        # Validate length before generation
        if not self.min_length <= length <= self.max_length:
            raise ValueError(f"Length must be between {self.min_length} and {self.max_length}")

        # Define character sets
        chars = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'special': string.punctuation
        }

        # Prepare password generation based on validation rules
        password_chars = []
        
        # Add required character types
        for char_type, required in self.validation_rules.items():
            if required:
                password_chars.append(secrets.choice(chars[char_type]))

        # Fill remaining characters
        all_chars = ''.join(chars.values())
        password_chars.extend(
            secrets.choice(all_chars) 
            for _ in range(length - len(password_chars))
        )

        # Shuffle and convert to string, removing excluded characters
        secrets.SystemRandom().shuffle(password_chars)
        return ''.join(char for char in password_chars if char not in self.excluded_chars)

    def validate_password(self, password: str) -> Dict[str, bool]:
        """
        Comprehensive password strength validation.
        
        Args:
            password (str): Password to validate
        
        Returns:
            Dict[str, bool]: Validation results for each criteria
        """
        validation_results = {
            'length': len(password) >= self.min_length,
            'lowercase': not self.validation_rules['lowercase'] or bool(re.search(r'[a-z]', password)),
            'uppercase': not self.validation_rules['uppercase'] or bool(re.search(r'[A-Z]', password)),
            'digits': not self.validation_rules['digits'] or bool(re.search(r'\d', password)),
            'special': not self.validation_rules['special'] or bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }

        return validation_results

    def is_password_strong(self, password: str) -> bool:
        """
        Check if password meets all validation criteria.
        
        Args:
            password (str): Password to check
        
        Returns:
            bool: Whether password is strong
        """
        results = self.validate_password(password)
        return all(results.values())


class SecurePasswordManager:
    """
    A comprehensive password management system integrating generation and secure storage.
    """
    
    def __init__(self, 
                 workspace_dir: str = "project-workspace", 
                 username: Optional[str] = None):
        """
        Initialize the password manager with secure storage paths.
        
        Args:
            workspace_dir (str): Directory for storing project-related data
            username (str, optional): Primary username for the vault
        """
        # Ensure the workspace directory exists
        self.workspace_dir = os.path.abspath(workspace_dir)
        os.makedirs(self.workspace_dir, exist_ok=True)
        
        # Components
        self.password_generator = PasswordGenerator()
        
        # Vault configuration with workspace-relative paths
        self.username = username
        self.salt_path = os.path.join(self.workspace_dir, "master_salt.key")
        self.password_store_path = os.path.join(self.workspace_dir, "password_store.json")
        
        # Initialize master salt
        self._master_salt = self._get_or_generate_salt()
    
    def _get_or_generate_salt(self) -> bytes:
        """
        Generate or retrieve a master salt for key derivation.
        
        Returns:
            bytes: Cryptographically secure salt
        """
        if not os.path.exists(self.salt_path):
            salt = os.urandom(16)
            with open(self.salt_path, 'wb') as f:
                f.write(salt)
            return salt
        
        with open(self.salt_path, 'rb') as f:
            return f.read()
    
    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        """
        Derive a secure encryption key using PBKDF2.
        
        Args:
            master_password (str): Master password
            salt (bytes): Cryptographic salt
        
        Returns:
            bytes: Derived encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    
    def generate_and_store_password(self, 
                                    master_password: str, 
                                    service: str, 
                                    length: Optional[int] = None) -> Dict[str, Any]:
        """
        Generate a secure password and store it encrypted.
        
        Args:
            master_password (str): User's master password
            service (str): Service/website name
            length (int, optional): Desired password length
        
        Returns:
            Dict[str, Any]: Generated password details
        """
        # Generate password
        password = self.password_generator.generate_password(length)
        
        # Validate password strength
        if not self.password_generator.is_password_strong(password):
            raise ValueError("Generated password does not meet strength requirements")
        
        # Encrypt and store
        encrypted_entry = self._encrypt_password(master_password, service, password)
        
        return {
            "service": service,
            "password_strength": self.password_generator.validate_password(password),
            "encrypted_entry": encrypted_entry
        }
    
    def _encrypt_password(self, 
                          master_password: str, 
                          service: str, 
                          password: str) -> Dict[str, str]:
        """
        Encrypt a password for a specific service.
        
        Args:
            master_password (str): User's master password
            service (str): Service/website name
            password (str): Password to encrypt
        
        Returns:
            Dict[str, str]: Encrypted password metadata
        """
        derived_key = self._derive_key(master_password, self._master_salt)
        fernet = Fernet(derived_key)
        
        encrypted_pass = fernet.encrypt(password.encode())
        
        # Prepare storage metadata
        password_entry = {
            "service": service,
            "username": self.username,
            "encrypted_password": base64.b64encode(encrypted_pass).decode(),
            "timestamp": str(datetime.now())
        }
        
        # Thread-safe file update
        self._atomic_json_update(self.password_store_path, password_entry)
        
        return password_entry
    
    def decrypt_password(self, 
                         master_password: str, 
                         service: str) -> Optional[str]:
        """
        Decrypt a password for a specific service.
        
        Args:
            master_password (str): User's master password
            service (str): Service/website name
        
        Returns:
            Optional[str]: Decrypted password or None if not found
        """
        try:
            derived_key = self._derive_key(master_password, self._master_salt)
            fernet = Fernet(derived_key)
            
            # Read password store
            with open(self.password_store_path, 'r') as f:
                passwords = json.load(f)
            
            # Find matching service
            for entry in passwords:
                if entry['service'] == service:
                    encrypted_pass = base64.b64decode(entry['encrypted_password'])
                    return fernet.decrypt(encrypted_pass).decode()
            
            return None
        
        except (FileNotFoundError, InvalidKey, json.JSONDecodeError):
            return None
    
    def _atomic_json_update(self, filepath: str, new_entry: Dict[str, Any]):
        """
        Safely update JSON file with a new entry.
        
        Args:
            filepath (str): Path to JSON file
            new_entry (Dict[str, Any]): New entry to add
        """
        import fcntl
        
        try:
            with open(filepath, 'r+') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = []
                
                data.append(new_entry)
                
                f.seek(0)
                json.dump(data, f, indent=4)
                f.truncate()
        
        except FileNotFoundError:
            with open(filepath, 'w') as f:
                json.dump([new_entry], f, indent=4)

    def list_services(self) -> List[str]:
        """
        List all services with stored passwords.
        
        Returns:
            List[str]: List of service names
        """
        try:
            with open(self.password_store_path, 'r') as f:
                passwords = json.load(f)
                return [entry['service'] for entry in passwords]
        except (FileNotFoundError, json.JSONDecodeError):
            return []


def main():
    print("🔐 Secure Password Management System 🔐")
    
    # Create workspace directory if it doesn't exist
    workspace_dir = "project-workspace"
    os.makedirs(workspace_dir, exist_ok=True)
    
    # Get username
    username = input("Enter your username: ")
    
    # Initialize password manager with workspace directory
    vault = SecurePasswordManager(
        workspace_dir=workspace_dir, 
        username=username
    )
    
    while True:
        print("\nChoose an option:")
        print("1. Generate and Store New Password")
        print("2. Retrieve Stored Password")
        print("3. List Stored Services")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ")
        
        try:
            if choice == '1':
                # Master password for encryption
                master_pass = input("Enter master password for vault: ")
                
                # Service details
                service = input("Enter service/website name: ")
                
                # Optional custom length
                length_input = input("Enter desired password length (press Enter for default): ")
                length = int(length_input) if length_input.strip() else None
                
                # Generate and store password
                result = vault.generate_and_store_password(
                    master_password=master_pass, 
                    service=service, 
                    length=length
                )
                
                print("\n--- Password Generation Result ---")
                print(f"Service: {result['service']}")
                print("Password Strength:")
                for criteria, passed in result['password_strength'].items():
                    print(f"- {criteria.capitalize()}: {'✓' if passed else '✗'}")
                print("Password stored successfully!")
            
            elif choice == '2':
                master_pass = input("Enter master password for vault: ")
                service = input("Enter service name: ")
                
                decrypted_pass = vault.decrypt_password(master_pass, service)
                if decrypted_pass:
                    print(f"Decrypted password: {decrypted_pass}")
                else:
                    print("Password not found or decryption failed.")
            
            elif choice == '3':
                services = vault.list_services()
                print("Stored Services:", services)
            
            elif choice == '4':
                print("Exiting Secure Password Manager. Goodbye!")
                break
            
            else:
                print("Invalid option. Please try again.")
        
        except Exception as e:
            print(f"An error occurred: {e}")
            print("Please try again.")

if __name__ == "__main__":
    main()