import security
import sqlite3

"""
Add a new password entry to the database for the given user.

Args:
    user_id (int): The user's ID.
    website_name (str): The name of the website or service.
    username (str): The username associated with the account.
    password (str): The password for the account.
    master_password (str): The user's master password.
    
Raises:
    sqlite3.Error: If there is an error executing the SQL query.
"""


def add_password(user_id, website_name, username, password, master_password):
    # Connect to the database
    conn = sqlite3.connect('pw_manager.db')
    cursor = conn.cursor()

    # Generate a salt and derive a key from the master password
    salt = security.generate_salt()
    key = security.derive_key(master_password, salt)

    # Encrypt the username and password
    encrypted_username, user_iv = security.encrypt_password(username, key)
    encrypted_password, iv = security.encrypt_password(password, key)

    # Insert the encrypted values into the database
    try:
        cursor.execute('''INSERT INTO passwords (user_id, website_name, username, password, salt, iv, user_iv)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''', (user_id, website_name, encrypted_username,
                                                                encrypted_password, salt, iv, user_iv))
        conn.commit()
    except sqlite3.Error as e:
        print("Error adding password:", e)
        conn.rollback()  # Roll back the transaction in case of error
    finally:
        # Close the database connection
        conn.close()


"""
Delete a password entry from the database.

Args:
    password_id (int): The ID of the password entry to be deleted.

Raises:
    sqlite3.Error: If there is an error executing the SQL query.
"""


def delete_password(password_id):
    # Connect to the database
    conn = sqlite3.connect('pw_manager.db')
    cursor = conn.cursor()

    # Delete the password entry with the given ID
    try:
        cursor.execute('''DELETE FROM passwords WHERE id = ?''', (password_id,))
        conn.commit()
    except sqlite3.Error as e:
        print("Error deleting password:", e)
        conn.rollback()  # Roll back the transaction in case of error
    finally:
        # Close the database connection
        conn.close()


"""
Modify the password for a given password ID.

Args:
    password_id (int): The ID of the password entry to be modified.
    new_password (str): The new password to be set.
    master_password (str): The master password used for encryption.

Raises:
    sqlite3.Error: If there is an error executing the SQL query.
"""


def modify_password(password_id, new_password, master_password):
    # Connect to the database
    conn = sqlite3.connect('pw_manager.db')
    cursor = conn.cursor()

    try:
        # Fetch the salt associated with the password ID
        cursor.execute('''SELECT salt FROM passwords WHERE id=?''', (password_id,))
        result = cursor.fetchone()
        salt = result[0]

        # Derive the encryption key using the master password and salt
        key = security.derive_key(master_password, salt)

        # Encrypt the new password
        encrypted_password, iv = security.encrypt_password(new_password, key)

        # Update the password and IV in the database
        cursor.execute('''UPDATE passwords SET password = ?, iv = ? WHERE id = ?''',
                       (encrypted_password, iv, password_id))

        conn.commit()
    except sqlite3.Error as e:
        print("Error modifying password:", e)
        conn.rollback()  # Roll back the transaction in case of error
    finally:
        # Close the database connection
        conn.close()


"""
Fetch the decrypted username and password for a given password ID.

Args:
    pw_id (int): The ID of the password entry to fetch.
    master_pw (str): The master password used for decryption.

Returns:
    tuple: A tuple containing the decrypted username and password.
"""


def fetch_password(pw_id, master_pw):
    conn = sqlite3.connect('pw_manager.db')
    cursor = conn.cursor()

    try:
        # Fetch the encrypted username, password, salt, IV, and user IV from the database
        cursor.execute('''SELECT username, password, salt, iv, user_iv FROM passwords WHERE id = ?''', (pw_id,))
        result = cursor.fetchone()

        # Derive the encryption key using the master password and salt
        key = security.derive_key(master_pw, result[2])

        # Decrypt the password and username using the encryption key and IV
        decrypted_pw = security.decrypt_password(result[1], result[3], key)
        decrypted_username = security.decrypt_password(result[0], result[4], key)

        return decrypted_username, decrypted_pw
    except sqlite3.Error as e:
        print("Error fetching password:", e)
    finally:
        # Close the database connection
        conn.close()


"""
Fetch all passwords associated with a given user ID.

Args:
    user_id (int): The ID of the user whose passwords are to be fetched.

Returns:
    list: A list of tuples containing password information (id, website_name, username).
"""


def fetch_passwords(user_id):
    conn = sqlite3.connect('pw_manager.db')
    cursor = conn.cursor()
    try:
        # Select passwords associated with the user ID from the database
        cursor.execute('SELECT id, website_name, username FROM passwords WHERE user_id = ?', (user_id,))
        passwords = cursor.fetchall()
        return passwords
    except sqlite3.Error as e:
        print("Error fetching passwords:", e)
    finally:
        # Close the database connection
        conn.close()


"""
Update passwords associated with a user to reflect a change in master password.

Args:
    user_id (int): The ID of the user whose passwords are to be updated.
    old_master_pw (str): The old master password.
    master_pw (str): The new master password.
"""


def update_passwords(user_id, old_master_pw, master_pw):
    # Connect to the database
    conn = sqlite3.connect('pw_manager.db')
    cursor = conn.cursor()

    # Fetch passwords associated with the user
    cursor.execute('SELECT id, username, password, salt, iv, user_iv FROM passwords WHERE user_id = ?', (user_id,))
    information = cursor.fetchall()

    # Iterate over each password and update it
    for password in information:
        pw_id = password[0]
        username = password[1]
        pw = password[2]
        salt = password[3]
        iv = password[4]
        user_iv = password[5]

        # Derive key using old master password and salt
        key = security.derive_key(old_master_pw, salt)

        # Decrypt password and username using old key
        decrypted_pw = security.decrypt_password(pw, iv, key)
        decrypted_username = security.decrypt_password(username, user_iv, key)

        # Generate new salt and key using new master password
        new_salt = security.generate_salt()
        new_key = security.derive_key(master_pw, new_salt)

        # Encrypt password and username using new key
        new_pw, new_iv = security.encrypt_password(decrypted_pw, new_key)
        new_username, new_user_iv = security.encrypt_password(decrypted_username, new_key)

        # Update password information in the database
        cursor.execute(
            '''UPDATE passwords SET username = ?, password = ?, salt = ?, iv = ?, user_iv = ? WHERE id = ?''',
            (new_username, new_pw, new_salt, new_iv, new_user_iv, pw_id))

    # Commit changes and close connection
    conn.commit()
    conn.close()


"""
Retrieve the user ID associated with a given username.

Args:
    username (str): The username for which to retrieve the user ID.

Returns:
    int or None: The user ID if the username is found, else None.
"""


def get_user_id(username):
    # Connect to the database
    conn = sqlite3.connect('pw_manager.db')
    cursor = conn.cursor()

    # Query the database for the user ID
    cursor.execute('''SELECT id FROM users WHERE username = ?''', (username,))
    result = cursor.fetchone()

    # Close the connection
    conn.close()

    # Return the user ID if found, else None
    if result:
        return result[0]
    else:
        return None


"""
Change the password for a user.

Args:
    user_id (int): The ID of the user whose password is to be changed.
    old_pw (str): The old password of the user.
    new_pw (str): The new password to be set.

Returns:
    None
"""


def change_user_password(user_id, old_pw, new_pw):
    conn = sqlite3.connect('pw_manager.db')
    cursor = conn.cursor()

    password_hash = security.hash_password(new_pw)

    # Insert the user data into the 'users' table
    cursor.execute('''UPDATE users SET password_hash = ? WHERE id = ?'''
                   , (password_hash, user_id))

    # Commit the transaction
    conn.commit()
    conn.close()

    update_passwords(user_id, old_pw, new_pw)
    return


"""
Delete a user and associated passwords from the database.

Args:
    user_id (int): The ID of the user to be deleted.

Returns:
    None
"""


def delete_user(user_id):
    conn = sqlite3.connect('pw_manager.db')
    cursor = conn.cursor()

    try:
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        # Delete passwords associated with the user from the 'passwords' table
        cursor.execute('DELETE FROM passwords WHERE user_id = ?', (user_id,))

        # Commit the transaction
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
    finally:
        conn.close()
