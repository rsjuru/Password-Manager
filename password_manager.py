import authentication
import security
import data_access as da
import tkinter as tk


"""
Check if the provided username is valid.

Args:
    username (str): The username to be validated.
    label_error (tkinter.Label): The label widget to display error messages.

Returns:
    bool: True if the username is valid, False otherwise.
"""
def check_username(username, label_error):

    # Check for SQL injection and XSS vulnerabilies in the given value
    injection_error = security.validate_input(username)
    value_error = security.validate_username(username)

    # Display error messages if any vulnerabilities in the username
    if injection_error:
        label_error.config(text=injection_error)
        return False

    if value_error:
        label_error.config(text=value_error)
        return False

    return True


"""
Check if the provided password meets the required criteria.

Args:
    password (str): The password to be validated.
    label_error (tkinter.Label): The label widget to display error messages.

Returns:
    bool: True if the password is valid, False otherwise.
"""
def check_password(password, label_error):
    # Check for SQL injection and XSS vulnerabilities in the password
    injection_error = security.validate_input(password)
    value_error = security.validate_password(password)

    # Display error messages if any vulnerability is found
    if injection_error:
        label_error.config(text=injection_error)
        return False

    if value_error:
        label_error.config(text=value_error)
        return False

    return True


"""
Register a new user with the provided username and password.

Args:
    user_entry (str): The username entered by the user.
    password_entry (str): The password entered by the user.
    confirm_entry (str): The password confirmation entered by the user.
    error (tkinter.Label): The label widget to display error messages.

Returns:
    bool: True if registration is successful, False otherwise.
"""
def register_user(user_entry, password_entry, confirm_entry, error):

    # Validate username, password, and confirmation password
    if not check_username(user_entry, error):
        return False

    if not check_password(password_entry, error):
        return False

    if not check_password(confirm_entry, error):
        return False

    # Check if passwords match
    if password_entry != confirm_entry:
        error.config(text="Passwords do not match.")
        return False

    # Attempt to register the user
    authentication_error = authentication.register_user(user_entry, password_entry)
    if authentication_error:
        error.config(text=authentication_error)
        return False
    else:
        return True


"""
Authenticate a user with the provided username and password.

Args:
    user_entry (str): The username entered by the user.
    password_entry (str): The password entered by the user.
    error (tkinter.Label): The label widget to display error messages.

Returns:
    bool: True if authentication is successful, False otherwise.
"""
def user_login(user_entry, password_entry, error):
    global MASTER_PASSWORD, USER_ID
    # validate username
    if not check_username(user_entry, error):
        return False

    # validate password for injection attacks
    password_injection_error = security.validate_input(password_entry)
    if password_injection_error:
        error.config(text=password_injection_error)
        return False

    # Authenticate user
    authentication_error = authentication.authenticate_user(user_entry, password_entry)
    if authentication_error == "Login succesful!":
        #Retrieve user ID
        USER_ID = da.get_user_id(user_entry)
        # Store master password
        MASTER_PASSWORD = password_entry
        return True
    else:
        error.config(text=authentication_error)
        return False


"""
Toggle the visibility of the password in the password entry widget.

Args:
    show_password (tkinter.BooleanVar): A boolean variable indicating whether the password should be visible.
    password_entry (tkinter.Entry): The password entry widget.

Returns:
    None
"""
def toggle_password_visibility(show_password, password_entry):
    # If show_password is True, reveal the password
    if show_password.get():
        password_entry.config(show="")
    else:
        # If show_password is False, hide the password
        password_entry.config(show="*")


"""
Filter passwords based on a search text.

Args:
    search_text (str): The text to search for in website names.

Returns:
    list: A list of passwords matching the search criteria.
"""
def filter_passwords(search_text):
    # Retrieve all passwords for the current user
    passwords = da.fetch_passwords(USER_ID)

    # Initialize a list to store filtered passwords
    filtered_passwords = []

    # Iterate thrpugh each password
    for password in passwords:
        #Extract website name from the password data
        website_name = password[1]

        # Check is the search text is present in the website name (case-insensitive)
        if search_text.lower() in website_name.lower():
            # If the search text matches the website name, add the password to the filtered list
            filtered_passwords.append(password)

    return filtered_passwords


"""
Generate a new password and insert it into the given entry widget.

Args:
    entry (tk.Entry): The entry widget where the new password will be inserted.

Returns:
    str: The generated password.
"""
def regenerate_password(entry):
    # Generate a new password
    new_password = security.generate_password()

    # Insert the new password into the entry widget
    entry.delete(0, tk.END) # Clear any existing text in the entry
    entry.insert(0, new_password) # Insert the new password at the beginning of the entry
    return


"""
Show or hide the password for a given password entry.

Args:
    pw_id (int): The ID of the password entry.
    username_label (tk.Label): The label widget where the username will be displayed.
    pw_label (tk.Label): The label widget where the password will be displayed.
    button (tk.Button): The button widget used to toggle between showing and hiding the password.
"""
def show_password(pw_id,username_label, pw_label, button):
    # Get the current text of the button
    button_label = button.cget("text")

    # If the button is currently labeled as "Hide", hide the password
    if button_label == "Hide":
        # Hide both username and password by displaying asterisk
        username_label.config(text="Username: ********")
        pw_label.config(text="Password: ********")
        button.config(text="Show") # Change tge button label to "Show"
        return

    # If the button is currently labeled as "Show", show the password
    username, pw = da.fetch_password(pw_id, MASTER_PASSWORD) # Fetch username and password
    username_label.config(text=f"Username: {username}") # Display the username
    pw_label.config(text=f"Password: {pw}") # Display the password
    button.config(text="Hide") # Change the button label to "Hide"
    return


"""
Change the password for a given password entry.

Args:
    pw_id (int): The ID of the password entry.
    old_pw (str): The old password.
    new_pw (str): The new password.
    confirm_pw (str): The confirmation of the new password.
    error (tk.Label): The label widget used to display error messages.

Returns:
    bool: True if the password change is successful, False otherwise.
"""
def change_password(pw_id, old_pw, new_pw, confirm_pw, error):
    # Validate the input for old password
    old_error = security.validate_input(old_pw)
    if old_error:
        error.config(text=old_error)
        return False

    # Validate the input for old password
    new_error = security.validate_input(new_pw)
    if new_error:
        error.config(text=new_error)
        return False

    # Validate the input for confirmed new password
    confirm_error = security.validate_input(confirm_pw)
    if confirm_error:
        error.config(text=confirm_error)

    # Check if the old password matches the stored password
    check_value = da.fetch_password(pw_id, MASTER_PASSWORD)
    if check_value[1] != old_pw:
        error.config(text="Incorrect old password.")
        return False

    # Check if the new password matches to the confirmed password
    if new_pw != confirm_pw:
        error.config(text="Passwords do not match.")
        return False

    # Modify the password in the database
    da.modify_password(pw_id, new_pw, MASTER_PASSWORD)
    return True


"""
Save the user's new password after verifying the old password and ensuring correctness of the new password.

Args:
    old_pw (str): The old password.
    new_pw (str): The new password.
    confirm_pw (str): The confirmation of the new password.
    label_error (tk.Label): The label widget used to display error messages.

Returns:
    bool: True if the password change is successful, False otherwise.
"""
def save_user_password(old_pw, new_pw, confirm_pw, label_error):
    global MASTER_PASSWORD, USER_ID
    # Validate the input for old password
    old_error = security.validate_input(old_pw)
    if old_error:
        label_error.config(text=old_error)
        return

    global MASTER_PASSWORD
    # Check if the old password matches the stored password
    if old_pw != MASTER_PASSWORD:
        label_error.config(text="Incorrect old password.")
        return False

    # Check and validate the new password
    if not check_password(new_pw, label_error):
        return False

    # Check and validate the confirmed new password
    if not check_password(confirm_pw, label_error):
        return False

    # Check if the new password matces the confirmed password
    if new_pw != confirm_pw:
        label_error.config(text="Passwords do not match.")
        return False

    # Change the user's password in the database
    da.change_user_password(USER_ID, MASTER_PASSWORD, new_pw)

    # Empty master password and user id values
    MASTER_PASSWORD=None
    USER_ID = None
    return True


"""
Delete the user from the database and close the popup window.

Args:
    popup (tk.Toplevel): The popup window to be closed after the user is deleted.

Returns:
    bool: Always returns True.
"""
def delete_user(popup):
    # Delete the user from the database
    da.delete_user(USER_ID)

    # Destroy the popup window
    popup.destroy()
    return True


"""
Return the current user's ID.

Returns:
    int: The ID of the current user.
"""
def return_user_id():
    return USER_ID


"""
Return the current user's master password.

Returns:
    str: The master password of the current user.
"""
def return_master_pw():
    return MASTER_PASSWORD


"""
Empties variables USER_ID and MASTER_PASSWORD.

Returns:
    None
"""
def reset_pw_and_userid():
    global USER_ID, MASTER_PASSWORD
    # Set USER_ID and MASTER_PASSWORD values to None
    USER_ID = None
    MASTER_PASSWORD = None
