import tkinter as tk
import password_manager as pw
import data_access as da
import security
from zxcvbn import zxcvbn
import time

PASSWORD_LIST = None


"""
Clear all widgets from the frame.

This function destroys all widgets within the frame, effectively clearing the frame.
"""
def clear_frame():
    # Destroy all widgets within the frame
    for widget in frame.winfo_children():
        widget.destroy()


"""
Save a new password to the database.

Args:
    website_name (str): The name of the website associated with the password.
    username (str): The username for the website.
    password (str): The password for the website.
    error (Label): The error label to display any validation errors.

Returns:
    bool: True if the password was successfully saved, False otherwise.
"""
def save_password(website_name, username, password, error):

    # validate website name
    website_error = security.validate_input(website_name)
    if website_error:
        error.config(text=website_error)
        return False

    # Validate username
    username_error = security.validate_input(username)
    if username_error:
        error.config(text=username_error)
        return False

    # Validate password
    password_error = security.validate_input(password)
    if password_error:
        error.config(text=password_error)
        return False

    # Add password to the database
    da.add_password(pw.return_user_id(), website_name, username, password, pw.return_master_pw())

    # Update the password list
    PASSWORD_LIST.add_passwords(da.fetch_passwords(pw.return_user_id()))
    return True


"""
Create a Text widget displaying password requirements.

Args:
    parent (Tkinter widget): The parent widget to contain the Text widget.

Returns:
    Tkinter Text: The Text widget displaying password requirements.
"""
def create_password_requirements_text(parent):
    # Create a Text widget
    text = tk.Text(parent, height=6, width=50, background='white', foreground='cyan')

    # Insert password requirements text
    text.insert(tk.END, "Password Requirements:\n")
    text.insert(tk.END, "- Length: 12 or more characters\n")
    text.insert(tk.END, "- Must contain at least one uppercase letter\n")
    text.insert(tk.END, "- Must contain at least one lowercase letter\n")
    text.insert(tk.END, "- Must contain at least one number\n")
    text.insert(tk.END, "- Must contain at least one symbol\n")
    text.config(state=tk.DISABLED)  # Disable editing
    return text


"""
Delete a password and update the GUI accordingly.

Args:
    pw_id (int): The ID of the password to be deleted.
    popup (Tkinter widget): The popup window containing the password.

Returns:
    None
"""
def password_deletion(pw_id, popup):
    # Delete the password
    da.delete_password(pw_id)

    # Fetch updated passwords
    passwords = da.fetch_passwords(pw.return_user_id())

    # Update the password list in the GUI
    PASSWORD_LIST.add_passwords(passwords)

    # Destroy the popup window
    popup.destroy()

    # Return to the main view
    main_view()


"""
Create a text widget displaying the estimated strength of the password.

Args:
    pw (str): The password to be evaluated.
    parent (Tkinter widget): The parent widget to contain the text widget.
    website_name (str): The name of the website associated with the password.
    row (int): The row position in the parent widget grid.
    username (str, optional): The username associated with the password. Defaults to None.

Returns:
    None
"""
def create_pw_estimate_text(pw, parent, website_name,row, username=None):
    # Define password strength scale
    pw_scale = ['Very weak Password', 'Weak Password', 'Moderate Password', 'Strong Password', 'Very Strong Password']

    # Evaluate password strength using zxcvbn
    if username is None:
        result = zxcvbn(pw, [website_name])
    else:
        result = zxcvbn(pw, [website_name, username])

    # Create a text widget to display password strength
    text = tk.Text(parent, height=3, width=50, background='white', foreground='cyan')

    # Insert password score and corresponding scale
    text.insert(tk.END, f"Password score (scale 0-4): {result['score']} {pw_scale[result['score']]}\n")

    # Insert feedback and suggestions
    for value in result['feedback']['suggestions']:
        text.insert(tk.END, f"{value}")

    # Place the text widget in the parent widget grid
    text.grid(row=row, column=0, columnspan=3, padx=10, pady=5)


"""A custom Tkinter frame for displaying a catalog of passwords.

This frame includes a canvas with vertical and horizontal scrollbars
to accommodate a large number of passwords. It dynamically adds labels
for each password entry, allowing users to view, copy, modify, and delete
passwords interactively.

Attributes:
    canvas (tk.Canvas): The canvas widget for displaying password entries.
    frame (tk.Frame): The frame widget inside the canvas.
    v_scroll (tk.Scrollbar): The vertical scrollbar for the canvas.
    h_scroll (tk.Scrollbar): The horizontal scrollbar for the canvas.
    password_labels (list): A list to store labels for password entries.

Methods:
    __init__: Initialize the PasswordCatalog frame.
    add_passwords: Add password entries to the catalog.
    on_frame_configure: Handle frame resizing events.
    on_canvas_configure: Handle canvas resizing events.
"""
class PasswordCatalog(tk.Frame):
    def __init__(self, master, passwords):
        super().__init__(master)

        # Initialize components
        self.canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0)
        self.frame = tk.Frame(self.canvas)
        self.v_scroll = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.h_scroll = tk.Scrollbar(self, orient="horizontal", command=self.canvas.xview)

        self.canvas.configure(yscrollcommand=self.v_scroll.set, xscrollcommand=self.h_scroll.set)

        # Pack components
        self.v_scroll.pack(side="right", fill="y")
        self.h_scroll.pack(side="bottom", fill="x")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.create_window((4, 4), window=self.frame, anchor="nw", tags="self.frame")

        # Bind events
        self.frame.bind("<Configure>", self.on_frame_configure)
        self.canvas.bind("<Configure>", self.on_canvas_configure)

        # Store password labels
        self.password_labels = []

        # Add passwords
        self.add_passwords(passwords)

    def add_passwords(self, passwords):
        # Clear existing labels
        for label_set in self.password_labels:
            for label in label_set:
                label.destroy()

        # Update with new passwords
        for i, password_info in enumerate(passwords):
            id_value = password_info[0]
            website_name = password_info[1]

            # Create masked password
            masked_password = "*" * 8

            # Create labels for website, username, and password
            website_label = tk.Label(self.frame, text=f"Website: {website_name}")
            website_label.grid(row=i, column=0, padx=10, pady=5, sticky="we")

            username_label = tk.Label(self.frame, text=f"Username: {masked_password}")
            username_label.grid(row=i, column=1, padx=10, pady=5, sticky="we")

            password_label = tk.Label(self.frame, text=f"Password: {masked_password}")
            password_label.grid(row=i, column=2, padx=10, pady=5, sticky="we")

            # Show button
            show_button = tk.Button(self.frame, text="Show")
            show_button.grid(row=i, column=3, padx=10, pady=5)
            show_button.config(command=lambda pw_id=id_value,user_label=username_label, pw_label=password_label,
                             button=show_button: pw.show_password(pw_id, user_label, pw_label, button))

            # Copy button
            copy_button = tk.Button(self.frame, text="Copy Password", command=lambda pw_id=id_value: copy_to_clipboard
                                                                                (da.fetch_password(pw_id,
                                                                                pw.return_master_pw())[1]))
            copy_button.grid(row=i, column=4, padx=10, pady=5)

            # Modify button
            modify_button = tk.Button(self.frame, text="Modify", command=lambda pw_id=id_value, website=website_name:
                                                                            modify_password_view(pw_id, website))
            modify_button.grid(row=i, column=5, padx=10, pady=5)

            # Delete button
            delete_button = tk.Button(self.frame, text="Delete", command=lambda pw_id=id_value: delete_password_window(pw_id))
            delete_button.grid(row=i, column=6, padx=10, pady=5)

            # Store the labels for future reference
            self.password_labels.append((website_label, username_label, password_label, show_button, modify_button,
                                         copy_button,
                                         delete_button))

        # Update frame width based on widget sizes
        self.frame.update_idletasks()  # Update the frame to get accurate sizes
        max_width = max(self.frame.winfo_reqwidth(), self.canvas.winfo_width())  # Get the maximum width needed
        self.canvas.itemconfigure("self.frame", width=max_width)  # Set the width of the frame

    def on_frame_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def on_canvas_configure(self, event):
        self.canvas.configure(width=600)


"""Copy the provided entry to the clipboard.

Args:
    entry (str): The text to be copied to the clipboard.

Returns:
    None
"""
def copy_to_clipboard(entry):
    # Clear the clipboard and append the provide entry
    root.clipboard_clear()
    root.clipboard_append(entry)
    # Update the clipboard contents and return to the main view
    root.update()
    main_view()


"""
Function to log out the user from the application.

Clears the current frame, resets the global variables `MASTER_PASSWORD` and `USER_ID` to empty values,
and displays the login view to allow another user to log in.
"""
def logout_function():
    clear_frame() # Clear the current frame
    pw.reset_pw_and_userid() # Reset global variables MASTER_PASSWORD and USER_ID
    login_view() # Display the login view for another user to log in


"""
Sets up the login interface with username and password entry fields, a checkbox to reveal the password,
a link to the registration view, error message labels, and a login button.

The function clears the frame before adding new widgets and defines event handlers to enable the login button
only when both the username and password fields are non-empty. It also provides functionality to reveal the password
using a checkbox and includes error message labels to display any login-related errors.

Args:
    None

Returns:
    None
"""
def login_view(attempts=0):
    # Clear the frame before adding new widgets
    clear_frame()

    # Define maximum number of login attempts
    MAX_LOGIN_ATTEMPTS = 5

    # Define initial disbalement duration in seconds
    INITIAL_DISABLEMENT_DURATION = 30

    # Define amount by which duration increases per failed attempt
    DISABLEMENT_DURATION_INCREMENT = 10

    # Counter to track login attempts
    login_attempts = attempts

    # Timestamp of the last failed login attempt
    last_failed_attempt_time = 0

    disablement_duration = 0

    def enable_login_button(*args):
        nonlocal login_attempts, last_failed_attempt_time

        current_time = time.time()
        # Check if the login button should be enabled
        if entry_username.get() and entry_password.get() and \
                (login_attempts < MAX_LOGIN_ATTEMPTS or current_time - last_failed_attempt_time > disablement_duration):
            button_login.config(state="normal")  # Enable the login button
        else:
            button_login.config(state="disabled")  # Disable the login button

    def handle_login():
        nonlocal login_attempts, last_failed_attempt_time, disablement_duration

        success = pw.user_login(entry_username.get(), entry_password.get(), label_error_login)
        if success:
            main_view()
        else:
            login_attempts += 1
            if login_attempts == MAX_LOGIN_ATTEMPTS:
                current_time = time.time()
                last_failed_attempt_time = current_time
                disablement_duration = INITIAL_DISABLEMENT_DURATION
                label_error_login.config(text=f"Too many fail attempts. Try again in {disablement_duration} seconds.")
                enable_login_button()
            if login_attempts > MAX_LOGIN_ATTEMPTS:
                current_time = time.time()
                last_failed_attempt_time = current_time
                disablement_duration += DISABLEMENT_DURATION_INCREMENT
                label_error_login.config(text=f"Too many fail attempts. Try again in {disablement_duration} seconds.")
                enable_login_button()

    # Header and instructions for login view
    label_header_login = tk.Label(frame, text="Login", font=("Arial", 16, "bold"))
    label_header_login.grid(row=0, column=0, columnspan=4, padx=10, pady=5, sticky='nsew')

    # Username label and entry field
    label_username = tk.Label(frame, text="Username:")
    label_username.grid(row=2, column=0, padx=10, pady=5)
    entry_username = tk.Entry(frame)
    entry_username.grid(row=2, column=1, padx=10, pady=5)
    entry_username.bind("<KeyRelease>", enable_login_button)

    # Password label and entry field
    label_password = tk.Label(frame, text="Password:")
    label_password.grid(row=3, column=0, padx=10, pady=5)
    entry_password = tk.Entry(frame, show="*")  # Show asterisks for password
    entry_password.grid(row=3, column=1, padx=10, pady=5)
    entry_password.bind("<KeyRelease>", enable_login_button)

    # Reveal Password checkbox
    show_password = tk.BooleanVar()
    check_show_password = tk.Checkbutton(frame, text="Show Password", variable=show_password,
                                         command=lambda: pw.toggle_password_visibility(show_password, entry_password))
    check_show_password.grid(row=3, column=2, columnspan=2, padx=10, pady=5)

    # Link to registration view
    new_user_label = tk.Label(frame, text="New user? Register", font=("Arial", 8, "underline"),
                              fg="blue", cursor="hand2")
    new_user_label.grid(row=4, column=0, padx=(10, 5), pady=5, sticky='nsew')
    new_user_label.bind("<Button-1>", lambda event: register_view(login_attempts))

    # Error messages
    label_error_login = tk.Label(frame, text="", fg="red")  # Define label_error_login
    label_error_login.grid(row=5, column=0, columnspan=3, padx=(5, 10), pady=5)

    # Login button
    button_login = tk.Button(frame, text="Login", state="disabled", command=lambda: handle_login())
    button_login.grid(row=4, column=1, columnspan=1, padx=(10, 5), pady=5)

    # Set frame dimensions
    frame.config(width=800, height=800)


"""
Sets up the registration interface with username and password entry fields, a link to the login view,
error message labels, and a register button.

The function clears the frame before adding new widgets and provides functionality to register a new user
by entering a username and password. It also includes error message labels to display any registration-related errors.

Args:
    None

Returns:
    None
"""
def register_view(attempts):
    clear_frame()
    frame.grid_columnconfigure(0, weight=1)
    frame.grid_rowconfigure(0, weight=1)

    # Function to enable the save button when all fields are filled
    def enable_register_button(*args):
        if entry_username_register.get() and entry_password_register.get() and entry_confirm_password.get():
            button_register.config(state="normal")
        else:
            button_register.config(state="disabled")

    # Header and instructions for register view
    label_header_register = tk.Label(frame, text="Registration", font=("Arial", 16, "bold"))
    label_header_register.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky='nsew')

    label_instructions_register = tk.Label(frame, text="Please choose a username and password to register.")
    label_instructions_register.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky='nsew')

    # Username label and entry field
    label_username_register = tk.Label(frame, text="Username:")
    label_username_register.grid(row=2, column=0, padx=10, pady=5, sticky='nsew')
    entry_username_register = tk.Entry(frame)
    entry_username_register.grid(row=2, column=1, padx=10, pady=5, sticky='nsew')
    entry_username_register.bind("KeyRelease", enable_register_button())

    # Password label and entry field
    label_password_register = tk.Label(frame, text="Password:")
    label_password_register.grid(row=3, column=0, padx=10, pady=5)
    entry_password_register = tk.Entry(frame, show="*")  # Show asterisks for password
    entry_password_register.grid(row=3, column=1, padx=10, pady=5, sticky='nsew')
    entry_password_register.bind("KeyRelease", enable_register_button())

    # Confirm Password label and entry field
    label_confirm_password_register = tk.Label(frame, text="Confirm Password:")
    label_confirm_password_register.grid(row=4, column=0, padx=10, pady=5, sticky='nsew')
    entry_confirm_password = tk.Entry(frame, show="*")  # Show asterisks for password
    entry_confirm_password.grid(row=4, column=1, padx=10, pady=5)
    entry_confirm_password.bind("KeyRelease", enable_register_button())

    # Reveal Password checkbox
    show_password = tk.BooleanVar()
    check_show_password = tk.Checkbutton(frame, text="Show Password", variable=show_password,
                                         command=lambda: pw.toggle_password_visibility(show_password,
                                                                                       entry_confirm_password))
    check_show_password.grid(row=4, column=2, columnspan=2, padx=10, pady=5)

    # Already have an account button
    already_have_account_label = tk.Label(frame, text="Already have an account?",
                                          font=("Arial", 8, "underline"),
                                          fg="blue", cursor="hand2")
    already_have_account_label.grid(row=5, column=0, padx=(5, 10), pady=5, sticky="nsew")
    already_have_account_label.bind("<Button-1>", lambda event: login_view(attempts))

    # Error messages
    label_error_register = tk.Label(frame, text="", fg="red")  # Define label_error_login
    label_error_register.grid(row=7, column=0, columnspan=3, padx=(5, 10), pady=5, sticky='nsew')

    # Register button
    button_register = tk.Button(frame, text="Register",state="disabled",
                                command=lambda: login_view() if pw.register_user(entry_username_register.get(),
                                                                                      entry_password_register.get(),
                                                                                      entry_confirm_password.get(),
                                                                                      label_error_register) else None)
    button_register.grid(row=5, column=1, padx=(10, 5), pady=5, sticky="nsew")
    frame.config(width=800, height=800)

    # Password requirements text field
    password_requirements_text = create_password_requirements_text(frame)
    password_requirements_text.grid(row=6, column=0, columnspan=3, padx=10, pady=10)

"""
Sets up the main interface with buttons for changing the user's password, deleting the user,
adding a new password, searching for passwords, displaying existing passwords, generating passwords,
logging out, and exiting the application.

The function clears the frame before adding new widgets and provides functionality for various actions
such as changing the password, adding a new password, searching for passwords, and logging out.

Args:
    None

Returns:
    None
"""
def main_view():
    # Clear the frame to prepare for the main view layout
    clear_frame()

    # Configure grid layout for flexible resizing
    frame.grid_columnconfigure(0, weight=1)
    frame.grid_rowconfigure(0, weight=1)

    # Button for changing user's password
    change_pw_button = tk.Button(frame, text="Change user's password", command=change_pw_view)
    change_pw_button.grid(row=0, column=0, padx=10, pady=10)

    # Button for deleting user
    deletion_button = tk.Button(frame, text="Delete user", command=delete_user_window)
    deletion_button.grid(row=0, column=1, padx=10, pady=10)

    # Main label
    main_label = tk.Label(frame, text="Welcome to Password Manager!",font=("Arial", 16, "bold") )
    main_label.grid(row=1, column=0, columnspan=2, sticky="we")

    # Empty label for spacing
    empty_label = tk.Label(frame, text="")
    empty_label.grid(row=2, column=0, columnspan=2, sticky="we")

    # Button for adding new password
    plus_button = tk.Button(frame, text="Add new password", command=add_password_view)
    plus_button.grid(row=3, column=0, padx=10,pady=10, sticky="we")

    # Label and entry for searching passwords
    search_label = tk.Label(frame, text="Search: ")
    search_label.grid(row=4, column=0, padx=10, pady=10, sticky="w")
    search_entry = tk.Entry(frame)
    search_entry.grid(row=4, column=1, padx=10, pady=10, sticky="w")
    search_entry.bind("<KeyRelease>", lambda event: filter_and_update(search_entry.get()))

    # Password catalog widget for displaying passwords
    PASSWORD_LIST = PasswordCatalog(frame, da.fetch_passwords(pw.return_user_id()))
    PASSWORD_LIST.grid(row=5, column=0, columnspan=2, sticky="we")

    # Button for generating password
    generate_button = tk.Button(frame, text="Generate Password", command=generate_password_window)
    generate_button.grid(row=6, column=0, padx=10, pady=10, sticky="we")

    # Button for logging out
    logout_button = tk.Button(frame, text="Logout", command=lambda:logout_function())
    logout_button.grid(row=7, column=0, padx=10, pady=10, sticky="we")

    # Button for exiting the application
    exit_button = tk.Button(frame, text="Exit", command=lambda: root.quit())
    exit_button.grid(row=7, column=1, padx=10, pady=10, sticky="we")

    # Function for filtering passwords based on search text
    def filter_and_update(search_text):
        filtered_passwords = pw.filter_passwords(search_text)
        PASSWORD_LIST.add_passwords(filtered_passwords)

    # Configure frame size
    frame.config(width=1200, height=1200)


"""
Sets up the interface for adding new password information. It includes entry fields for
website name, username, and password, along with buttons for returning to the main view,
estimating password strength, and saving the password information.

Args:
    None

Returns:
    None
"""
def add_password_view():
    # Clear the frame to prepare for the add password view layout
    clear_frame()

    # Configure grid layout for flexible resizing
    frame.grid_columnconfigure(0, weight=1)
    frame.grid_rowconfigure(0, weight=1)

    # Function to enable the save button when all fields are filled
    def enable_save_button(*args):
        if entry_website.get() and entry_username.get() and entry_password.get():
            button_save.config(state="normal")
        else:
            button_save.config(state="disabled")

    # Header and instructions for add view
    label_header_add = tk.Label(frame, text="Add new password information", font=("Arial", 16, "bold"))
    label_header_add.grid(row=0, column=0, columnspan=2, padx=10, pady=5)

    label_instructions_add = tk.Label(frame, text="Enter website's name, username and password.")
    label_instructions_add.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

    # Website name label and entry field
    label_website_add = tk.Label(frame, text="Website's name: ")
    label_website_add.grid(row=2, column=0, padx=10, pady=5)
    entry_website = tk.Entry(frame)
    entry_website.grid(row=2, column=1, padx=10, pady=5)
    entry_website.bind("<KeyRelease>", enable_save_button)

    # Username label and entry field
    label_username_add = tk.Label(frame, text="Username for website: ")
    label_username_add.grid(row=3, column=0, padx=10, pady=5)
    entry_username = tk.Entry(frame)
    entry_username.grid(row=3, column=1, padx=10, pady=5)
    entry_username.bind("<KeyRelease>", enable_save_button)

    # Password label and entry field
    label_password_add = tk.Label(frame, text="Password: ")
    label_password_add.grid(row=4, column=0, padx=10, pady=5)
    entry_password = tk.Entry(frame, show="*")
    entry_password.grid(row=4, column=1, padx=10, pady=5)
    entry_password.bind("<KeyRelease>", enable_save_button)

    # Reveal Password checkbox
    show_password = tk.BooleanVar()
    check_show_password = tk.Checkbutton(frame, text="Show Password", variable=show_password,
                                         command=lambda: pw.toggle_password_visibility(show_password, entry_password))
    check_show_password.grid(row=4, column=2, columnspan=2, padx=10, pady=5)

    # Return button
    button_return = tk.Button(frame, text="Return", command=lambda: main_view())
    button_return.grid(row=5, column=0, padx=10, pady=5)

    # Error messages
    label_error_add = tk.Label(frame, text="", fg="red")  # Define label_error_login
    label_error_add.grid(row=7, column=0, columnspan=2, padx=(5, 10), pady=5)

    #Estimate button
    estimate_button = tk.Button(frame, text="Estimate Password", command=lambda:
                                                                create_pw_estimate_text(entry_password.get(), frame,
                                                                                        entry_website.get(),6,
                                                                                        entry_username.get))
    estimate_button.grid(row=5, column=1, padx=10, pady=5)

    # Save button
    button_save = tk.Button(frame, text="Save information", state="disabled",
                            command=lambda: main_view() if save_password(entry_website.get(),
                                                          entry_username.get(),
                                                          entry_password.get(),
                                                          label_error_add) else None)
    button_save.grid(row=5, column=2, padx=10, pady=5)
    frame.config(width=800, height=800)


"""
Opens a popup window to generate a strong password. It provides an option to show the password, regenerate it,
copy it to the clipboard, and exit the window.

Args:
    None

Returns:
    None
"""
def generate_password_window():
    # Create a popup window for generating passwords
    password_popup = tk.Toplevel(root)
    password_popup.title("Generate Strong Password")
    password_popup.geometry("400x400")

    # Generate a strong password
    password = security.generate_password()

    # Label to display the generated password
    password_label = tk.Label(password_popup, text="Generated Password")
    password_label.grid(row=0,column=0, padx=10, pady=5)

    # Entry field to display the generated password
    password_entry = tk.Entry(password_popup, show="*")
    password_entry.grid(row=0, column=1, padx=10, pady=5)
    password_entry.insert(0, password)

    # Checkbox to toggle visibility of the password
    show_generated_pw = tk.BooleanVar()
    check_show_password = tk.Checkbutton(password_popup, text="Show Password", variable=show_generated_pw,
                                         command=lambda: pw.toggle_password_visibility(show_generated_pw, password_entry))
    check_show_password.grid(row=0, column=2, padx=10, pady=5)

    # Button to regenerate the password
    regenerate_button = tk.Button(password_popup, text="Regenerate",
                                  command=lambda: pw.regenerate_password(password_entry))
    regenerate_button.grid(row=1, column=0, padx=10, pady=5)

    # Button to copy the password to clipboard
    copy_button = tk.Button(password_popup, text="Copy to Clipboard",
                            command=lambda: copy_to_clipboard(password_entry.get()))
    copy_button.grid(row=1, column=1, padx=10, pady=5)

    # Button to exit the popup window
    exit_button = tk.Button(password_popup, text="Exit",
                            command=lambda: password_popup.destroy())
    exit_button.grid(row=1, column=2, padx=10, pady=5)


"""
Displays a view to modify a password for a specific website.

Args:
    pw_id (int): The ID of the password to modify.
    website (str): The name of the website associated with the password.

Returns:
    None
"""
def modify_password_view(pw_id, website):
    # Clear the frame and configure column and row weights
    clear_frame()
    frame.grid_columnconfigure(0, weight=1)
    frame.grid_rowconfigure(0, weight=1)

    # Function to enable the save button when all fields are filled
    def enable_save_button(*args):
        if entry_old_pw.get() and entry_new_pw.get() and entry_confirm_pw.get():
            button_save.config(state="normal")
        else:
            button_save.config(state="disabled")

    # Header and instructions for add view
    label_header_add = tk.Label(frame, text="Change password", font=("Arial", 16, "bold"))
    label_header_add.grid(row=0, column=0, columnspan=2, padx=10, pady=5)

    label_instructions_modify = tk.Label(frame, text="Enter website's old and new password.")
    label_instructions_modify.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

    label_website_name = tk.Label(frame, text=f"Website: {website}")
    label_website_name.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

    # Old password label and entry field
    label_old_pw = tk.Label(frame, text="Old password: ")
    label_old_pw.grid(row=4, column=0, padx=10, pady=5)
    entry_old_pw = tk.Entry(frame, show="*")
    entry_old_pw.grid(row=4, column=1, padx=10, pady=5)
    entry_old_pw.bind("<KeyRelease>", enable_save_button())

    # Checkbox to toggle visibility of the old password
    show_old_password = tk.BooleanVar()
    check_show_password = tk.Checkbutton(frame, text="Show old password", variable=show_old_password,
                                         command=lambda: pw.toggle_password_visibility(show_old_password, entry_old_pw))
    check_show_password.grid(row=4, column=2, padx=10, pady=5)

    # New password label and entry field
    label_new_pw = tk.Label(frame, text="New password: ")
    label_new_pw.grid(row=5, column=0, padx=10, pady=5)
    entry_new_pw = tk.Entry(frame, show="*")
    entry_new_pw.grid(row=5, column=1, padx=10, pady=5)
    entry_new_pw.bind("<KeyRelease>", enable_save_button())

    # Confirm password and entry field
    label_confirm_pw = tk.Label(frame, text="Confirm new password: ")
    label_confirm_pw.grid(row=6, column=0, padx=10, pady=5)
    entry_confirm_pw = tk.Entry(frame, show="*")
    entry_confirm_pw.grid(row=6, column=1, padx=10, pady=5)
    entry_confirm_pw.bind("<KeyRelease>", enable_save_button())

    show_new_pw = tk.BooleanVar()
    check_show_new_pw = tk.Checkbutton(frame, text="Show new password", variable=show_new_pw,
                                       command=lambda: pw.toggle_password_visibility(show_new_pw, entry_confirm_pw))
    check_show_new_pw.grid(row=6, column=2, padx=10, pady=5)

    # Return button
    button_return_modify = tk.Button(frame, text="Return", command=lambda: main_view())
    button_return_modify.grid(row=7, column=0, padx=10, pady=5)

    # Error messages
    label_error_modify = tk.Label(frame, text="", fg="red")  # Define label_error_login
    label_error_modify.grid(row=9, column=0, columnspan=2, padx=(5, 10), pady=5)

    #Estimate button
    estimate_button = tk.Button(frame, text="Estimate Password", command=lambda:
                                                                create_pw_estimate_text(entry_new_pw.get(), frame,
                                                                                        website, 8))
    estimate_button.grid(row=7, column=1, padx=10, pady=5)

    # Save button
    button_save = tk.Button(frame, text="Save changes", state="disabled", command=lambda: main_view() if pw.change_password
                                                                                        (pw_id,
                                                                                        entry_old_pw.get(),
                                                                                        entry_new_pw.get(),
                                                                                        entry_confirm_pw.get(),
                                                                                        label_error_modify) else None)
    button_save.grid(row=7, column=2, padx=10, pady=5)
    frame.config(width=800, height=800)


"""
Displays a confirmation window to delete a password.

Args:
    pw_id (int): The ID of the password to delete.

Returns:
    None
"""
def delete_password_window(pw_id):
    # Create a new popup window
    popup = tk.Toplevel(root)
    popup.title("Delete Confirmation")

    # Display a label asking for confirmation
    label = tk.Label(popup, text="Are you sure you want to delete the password?")
    label.pack(padx=10, pady=10)

    # Button for confirm deletion
    yes_button = tk.Button(popup, text="Yes", command=lambda: password_deletion(pw_id, popup))
    yes_button.pack(side="right", padx=10, pady=10)

    # Button to cancel deletion
    no_button = tk.Button(popup, text="No", command=popup.destroy)
    no_button.pack(side="left", padx=10, pady=10)


"""
Displays a view for changing the user's password.

Returns:
    None
"""
def change_pw_view():
    # Clear the frame
    clear_frame()

    # Function to enable the save button when all fields are filled
    def enable_save_button(*args):
        if entry_old_pw.get() and entry_new_pw.get() and entry_confirm.get():
            save_button.config(state="normal")
        else:
            save_button.config(state="disabled")

    # Configure grid
    frame.grid_columnconfigure(0, weight=1)
    frame.grid_rowconfigure(0, weight=1)

    # Headers and instructions
    label_header = tk.Label(frame, text="Change password", font=("Arial", 16, "bold"))
    label_header.grid(row=0, column=0, columnspan=2, padx=10, pady=5)

    label_instructions = tk.Label(frame, text="Enter old and new password.")
    label_instructions.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

    # Old password label and entry field
    label_old_pw = tk.Label(frame, text="Old password: ")
    label_old_pw.grid(row=2, column=0, padx=10, pady=5)
    entry_old_pw = tk.Entry(frame, show="*")
    entry_old_pw.grid(row=2, column=1, padx=10, pady=5)
    entry_old_pw.bind("<KeyRelease>", enable_save_button())

    # Checkbox to toggle visibility of old password
    show_old_pw = tk.BooleanVar()
    check_show_old_pw = tk.Checkbutton(frame, text="Show old password", variable=show_old_pw,
                                       command=lambda: pw.toggle_password_visibility(show_old_pw, entry_old_pw))
    check_show_old_pw.grid(row=2, column=2, padx=10, pady=5)

    # Label and entry field for new password
    label_new_pw = tk.Label(frame, text="New password: ")
    label_new_pw.grid(row=3, column=0, padx=10, pady=5 )
    entry_new_pw = tk.Entry(frame, show="*")
    entry_new_pw.grid(row=3, column=1, padx=10, pady=5)
    entry_new_pw.bind("<KeyRelease>", enable_save_button())

    # Label and entry field for new password confirmation
    label_confirm = tk.Label(frame, text="Confirm password: ")
    label_confirm.grid(row=4, column=0, padx=10, pady=5)
    entry_confirm = tk.Entry(frame, show="*")
    entry_confirm.grid(row=4, column=1, padx=10, pady=5)
    entry_confirm.bind("<KeyRelease>", enable_save_button())

    # Checkbox to toggle visibility of new password
    show_new_pw = tk.BooleanVar()
    check_show_new = tk.Checkbutton(frame, text="Show new password", variable=show_new_pw,
                                    command=lambda: pw.toggle_password_visibility(show_new_pw, entry_confirm))
    check_show_new.grid(row=4, column=2, padx=10, pady=5)

    # Return button
    return_button = tk.Button(frame, text="Return", command=lambda: main_view())
    return_button.grid(row=5, column=0, padx=10, pady=5)

    # Error label
    label_error = tk.Label(frame, text="", fg="red")
    label_error.grid(row=7, column=0, columnspan=3, padx=10, pady=5)

    # Password requirements textfield
    password_requirements_text = create_password_requirements_text(frame)
    password_requirements_text.grid(row=6, column=0, columnspan=3, padx=10, pady=10)

    save_button = tk.Button(frame, text="Save Information",state="disabled",
                            command=lambda: login_view() if pw.save_user_password(entry_old_pw.get(),
                                                                                   entry_new_pw.get(),
                                                                                   entry_confirm.get(),
                                                                                   label_error) else None)
    save_button.grid(row=5, column=1, padx=10, pady=5)


"""
Displays a confirmation window to delete the user account.

Args:
    None

Returns:
    None
"""
def delete_user_window():
    # Create a new popup window
    popup = tk.Toplevel(root)
    popup.title("Delete Confirmation")

    # Display a label asking for confirmation
    label = tk.Label(popup, text="Are you sure you want to delete the user?"
                                 " All information will be deleted from the database.")
    label.pack(padx=10, pady=10)

    # Button to confirm deletion
    yes_button = tk.Button(popup, text="Yes", command=lambda:login_view() if pw.delete_user(popup) else None)
    yes_button.pack(side="right", padx=10, pady=10)

    # Button to cancel deletion
    no_button = tk.Button(popup, text="No", command=popup.destroy)
    no_button.pack(side="left", padx=10, pady=10)


root = tk.Tk()
root.title("Password Manager")

root.geometry("800x800")


PASSWORD_LIST = PasswordCatalog(root, [])


frame = tk.Frame(root)
frame.place(relx=0.5, rely=0.5, anchor="center")

frame.config(width=800, height=800)
# Initially show the login frame
login_view()

# Run the Tkinter event loop
root.mainloop()
