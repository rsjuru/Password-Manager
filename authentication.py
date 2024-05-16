import sqlite3
from security import encrypt_password, hash_password,generate_password, generate_salt, derive_key
import os


"""
Function to create a SQLite database and initialize the tables.

The function connects to the SQLite database 'pw_manager.db' and creates two tables:
- 'users': to store user information including their usernames and hashed passwords.
- 'passwords': to store passwords for each user, along with additional encryption-related information.

If the tables already exist, the function will not recreate them.

Returns:
    None
"""
def create_database():
    conn = sqlite3.connect('pw_manager.db')
    cursor = conn.cursor()

    # Create a table to store user information
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                    )''')

    # Create a table to store passwords for each user
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        website_name TEXT NOT NULL,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        iv TEXT NOT NULL,
                        user_iv TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(id))''')

    conn.commit()
    conn.close()


"""
Function to register a new user in the password manager system.

Args:
    username (str): The username of the new user.
    password (str): The password of the new user.

Returns:
    str or None: Returns None if registration is successful. Otherwise, returns a string indicating the error.
"""
def register_user(username, password):

    # Create the database tables if they don't exist
    create_database()

    # Connecting to the database
    conn = sqlite3.connect('pw_manager.db')
    cursor = conn.cursor()

    # Hash the password
    password_hash = hash_password(password)

    try:
        # Insert the user data into the 'users' table
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?,?)'
                       , (username, password_hash))
        user_id = cursor.lastrowid

        # Commit the transaction
        conn.commit()
    except sqlite3.IntegrityError:
        # If username already exists, rollback and close the connection
        conn.rollback()
        conn.close()
        return "Username already taken."

    conn.close()
    return None


"""
Function to authenticate a user in the password manager system.

Args:
    username (str): The username of the user.
    password (str): The password of the user.

Returns:
    str: Returns a string indicating the result of the authentication.
"""
def authenticate_user(username, password):

    # Create the database tables if they don't exist
    create_database()

    # Connecting to the database
    conn = sqlite3.connect('pw_manager.db')
    cursor = conn.cursor()

    # Hashing the provided password
    password_hash = hash_password(password)

    # Query the 'users' table for the user's password hash
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()

    if result is not None:
        stored_password_hash = result[0]
        if password_hash == stored_password_hash:
            conn.close()
            return "Login succesful!"
        else:
            conn.close()
            return "Incorrect Password."
    else:
        conn.close()
        return "User not found."
