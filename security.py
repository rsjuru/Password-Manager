import base64
import hashlib
import re
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
import string


"""
Generate a random password with the specified length.

Args:
    length (int, optional): The length of the password. Defaults to 12.

Returns:
    str: The randomly generated password.
"""
def generate_password(length=12):

    # Define character sets for different types of characters
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase
    digits = string.digits
    special_characters = string.punctuation

    # Combine all character sets
    all_characters = lowercase_letters + uppercase_letters + digits + special_characters

    # Ensure at least one character from each set
    password = random.choice(lowercase_letters)
    password += random.choice(uppercase_letters)
    password += random.choice(digits)
    password += random.choice(special_characters)

    # Fill the rest of the password with random characters
    password += ''.join(random.choice(all_characters) for _ in range(length - 4))

    # Shuffle the password to ensure randomness
    password_list = list(password)
    random.shuffle(password_list)
    password = ''.join(password_list)

    return password


"""
Hash the password using the SHA-256 algorithm.

Args:
    password (str): The password to be hashed.

Returns:
    str: The hashed password.
"""
def hash_password(password):
    # Hash the password using SHA-256
    return hashlib.sha256(password.encode()).hexdigest()


"""
Validate the input string to prevent SQL injection and cross-site scripting (XSS) attacks.

Args:
    input_string (str): The input string to be validated.

Returns:
    str or None: Error message if the input is invalid, otherwise None.
"""
def validate_input(input_string):
    # Prevent SQL injection
    if re.search(r'[;<>\'"]', input_string):
        return "Input contains invalid characters."

    # Prevent cross-site scripting (XSS)
    if re.search(r'<(script|iframe|img|svg)', input_string, flags=re.IGNORECASE):
        return "Input contains potentially dangerous HTML tags."

    return None


"""
Validate the username.

Args:
    username (str): The username to be validated.

Returns:
    str or None: Error message if the username is invalid, otherwise None.
"""
def validate_username(username):
    # Checking if username is between 3 and 20 characters
    if len(username) < 3 or len(username) > 20:
        return "Username must be between 3 and 20 characters"

    # Username should only contain alphanumeric characters and underscores
    if not re.match("[a-zA-Z0-9_]+$",username):
        return "Username can only contain letters, numbers, and underscores"

    return None


"""
Validate the password.

Args:
    password (str): The password to be validated.

Returns:
    str or None: Error message if the password is invalid, otherwise None.
"""
def validate_password(password):
    # Check if the password is at least 12 characters long
    if len(password) < 12:
        return "Password must be at least 12 characters long."

    # Check if the password contains mixed-case letters, numbers, and symbols
    if not (re.search(r'[a-z]', password) and re.search(r'[A-Z]', password) and
            re.search(r'\d', password) and re.search(r'[!@#$%^&*()_+{}|:"<>?]', password)):
        return "Password must contain at least one lowercase letter, one uppercase letter, one digit, and one symbol."

    return None


"""
Generate a random salt.

Returns:
    bytes: Randomly generated salt.
"""
def generate_salt():
    # 16 bytes (128 bits) salt
    return os.urandom(16)


"""
Derive a cryptographic key from the master password and salt using PBKDF2.

Args:
    master_password (str): The master password.
    salt (bytes): The salt used for key derivation.

Returns:
    bytes: The derived cryptographic key.
"""
def derive_key(master_password, salt):

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes key length for AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode('utf-8'))


"""
Encrypt a password using AES in CBC mode.

Args:
    password (str): The password to encrypt.
    key (bytes): The cryptographic key.

Returns:
    tuple: A tuple containing the base64-encoded encrypted password and IV.
"""
def encrypt_password(password, key):
    #Generate a random initialization vector (IV)
    iv = os.urandom(16)

    # Pad the password to match the block size of AES
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(password.encode()) + padder.finalize()

    # Create an AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Encrypt the password
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the encrypted password and IV as base64-encoded strings
    return base64.b64encode(ciphertext), base64.b64encode(iv)


"""
Decrypt an encrypted password using AES in CBC mode.

Args:
    encrypted_password (bytes): The base64-encoded encrypted password.
    iv (bytes): The base64-encoded initialization vector (IV).
    key (bytes): The cryptographic key.

Returns:
    str: The decrypted password.
"""
def decrypt_password(encrypted_password, iv, key):
    # Initialize AES cipher with CBC mode and IV
    cipher = Cipher(algorithms.AES(key),modes.CBC(base64.b64decode(iv)),backend=default_backend())

    # Decrypt the password
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(base64.b64decode(encrypted_password)) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Return the decrypted password
    return unpadded_data.decode()
