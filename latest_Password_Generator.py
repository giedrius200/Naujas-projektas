import tkinter as tk
from tkinter import messagebox, simpledialog
import string
import random
import os
import sys
from cryptography.fernet import Fernet, InvalidToken
import shutil
import hashlib

def copy_to_clipboard(data):
    try:
        import pyperclip
        pyperclip.copy(data)
    except ImportError:
        messagebox.showinfo("Info", "Pyperclip not installed. Cannot copy to clipboard.")

class PasswordChecker:
    def __init__(self, password):
        self.password = password

    def count_chars(self, charset):
        return len([char for char in self.password if char in charset])

    def strength(self):
        score = 0
        lowercase_count = self.count_chars(string.ascii_lowercase)
        uppercase_count = self.count_chars(string.ascii_uppercase)
        digit_count = self.count_chars(string.digits)
        punctuation_count = self.count_chars(string.punctuation)
        whitespace_count = self.count_chars(string.whitespace)

        score += lowercase_count * 0.5
        score += uppercase_count * 0.5
        score += digit_count * 0.5
        score += punctuation_count
        score += whitespace_count * 1.5
        score += len(self.password) * 0.5

        max_score = len(self.password) * 1.5

        strength_label = ""
        if score < 10:
            strength_label = "Weak"
        elif score < 20:
            strength_label = "Normal"
        elif score < 30:
            strength_label = "Good"
        elif score < 40:
            strength_label = "Strong"
        else:
            strength_label = "Super Strong"

        return {
            "strength_label": strength_label,
            "lowercase_count": lowercase_count,
            "uppercase_count": uppercase_count,
            "digit_count": digit_count,
            "punctuation_count": punctuation_count,
            "whitespace_count": whitespace_count,
            "total_score": score,
            "max_score": max_score
        }

class PasswordGenerator:
    def __init__(self, length, use_digits=True, use_lowercase=True, use_uppercase=True, use_special=True,
                 use_whitespace=False):
        self.length = length
        self.use_digits = use_digits
        self.use_lowercase = use_lowercase
        self.use_uppercase = use_uppercase
        self.use_special = use_special
        self.use_whitespace = use_whitespace

    def generate(self):
        charset = ""
        if self.use_digits:
            charset += string.digits
        if self.use_lowercase:
            charset += string.ascii_lowercase
        if self.use_uppercase:
            charset += string.ascii_uppercase
        if self.use_special:
            charset += string.punctuation
        if self.use_whitespace:
            charset += string.whitespace

        return ''.join(random.choice(charset) for _ in range(self.length))

class PasswordManager:
    def __init__(self, username, is_signup=False):
        self.username = username
        self.user_directory = f"data/{self.username}"
        self.passwords = {}
        self.file_password = None
        self.fernet = None

        if is_signup and os.path.exists(self.user_directory):
            messagebox.showinfo("Signup Error", "This username already exists. Please choose a different one.")
            return

        if not os.path.exists(self.user_directory):
            os.makedirs(self.user_directory, exist_ok=True)

        if os.path.exists(os.path.join(self.user_directory, "passwords.txt")):
            self.initialize_fernet()
            self.load_passwords_from_file()
        else:
            self.file_password = self.generate_file_password()
            self.copy_file_password_to_clipboard()
            messagebox.showinfo("File Password",
                                f"Your file password is: {self.file_password}\n"
                                "It has been copied to the clipboard for your convenience. "
                                "Please remember this password!")
            self.initialize_fernet()
            self.create_empty_passwords_file()

    def create_empty_passwords_file(self):
        encrypted_data = self.fernet.encrypt(str({}).encode())
        with open(os.path.join(self.user_directory, "passwords.txt"), "wb") as file:
            file.write(encrypted_data)

    def copy_file_password_to_clipboard(self):
        if self.file_password:
            copy_to_clipboard(self.file_password)

    def generate_file_password(self):
        return Fernet.generate_key().decode()

    def initialize_fernet(self):
        while True:
            if not self.file_password:
                self.file_password = simpledialog.askstring("File Password", "Enter your file password:")

            try:
                self.fernet = Fernet(self.file_password.encode())
                break  # If successful, break out of the loop
            except (ValueError, InvalidToken):
                choice = messagebox.askyesno("Invalid Password", 
                                            "Invalid file password. Do you want to generate a new one?")
                if choice:
                    self.file_password = self.generate_file_password()
                    self.copy_file_password_to_clipboard()
                    messagebox.showinfo("File Password",
                                        f"Your new file password is: {self.file_password}\n"
                                        "It has been copied to the clipboard. Please remember this password!")
                    self.fernet = Fernet(self.file_password.encode())
                    self.save_passwords_to_file()  # Re-encrypt the passwords file with the new file password
                    break  # Exit the loop after generating a new file password
                else:
                    self.file_password = None  # Reset the file password to prompt the user again




    def store_password(self, website, password):
        encrypted_password = self.fernet.encrypt(password.encode()).decode()
        self.passwords[website] = encrypted_password
        self.save_passwords_to_file()

    def decode_password(self, encoded_password):
        try:
            decoded_password = self.fernet.decrypt(encoded_password.encode()).decode()
            return decoded_password
        except InvalidToken:
            return "Decryption Error"

    def retrieve_password(self, website):
        encrypted_password = self.passwords.get(website)
        if encrypted_password:
            return self.fernet.decrypt(encrypted_password.encode()).decode()
        return None

    def save_passwords_to_file(self):
        encrypted_data = self.fernet.encrypt(str(self.passwords).encode())
        with open(os.path.join(self.user_directory, "passwords.txt"), "wb") as file:
            file.write(encrypted_data)

    def load_passwords_from_file(self):
        with open(os.path.join(self.user_directory, "passwords.txt"), "rb") as file:
            encrypted_data = file.read()
            try:
                decrypted_data = self.fernet.decrypt(encrypted_data)
                self.passwords = eval(decrypted_data.decode())
            except InvalidToken:
                self.file_password = None
                self.initialize_fernet()
                self.load_passwords_from_file()  # Recursive call to try loading again with the new fernet key


    def save_and_exit(self):
        self.save_passwords_to_file()
        sys.exit()

    def view_all_passwords(self):
        passwords_text.delete(1.0, tk.END)
        for website, encrypted_password in self.passwords.items():
            decrypted_password = self.decode_password(encrypted_password)
            passwords_text.insert(tk.END, f"Website: {website}\nPassword: {decrypted_password}\n\n")

    def delete_password(self):
        if not self.passwords:
            messagebox.showinfo("No Passwords", "No passwords stored.")
            return

        stored_websites = list(self.passwords.keys())
        selected_website = simpledialog.askstring("Delete Password",
                                                  "Enter the website for which you want to delete the password:",
                                                  initialvalue=stored_websites[0])

        if selected_website:
            if selected_website in self.passwords:
                del self.passwords[selected_website]
                self.save_passwords_to_file()
                messagebox.showinfo("Password Deleted", f"Password for {selected_website} has been deleted.")
            else:
                messagebox.showinfo("Website Not Found", f"Website '{selected_website}' not found in stored passwords.")

    def export_to_txt(self):
        with open(os.path.join(self.user_directory, "exported_passwords.txt"), "w") as file:
            for website, encrypted_password in self.passwords.items():
                decrypted_password = self.decode_password(encrypted_password)
                file.write(f"Website: {website}\nPassword: {decrypted_password}\n\n")
        messagebox.showinfo("Export Successful", "Passwords have been exported to exported_passwords.txt in your directory.")

class UserAuth:
    def __init__(self):
        self.users_db = "users_db.txt"
        if not os.path.exists(self.users_db):
            with open(self.users_db, 'w') as f:
                pass

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def sign_up(self, username, password):
        with open(self.users_db, 'a') as f:
            f.write(f"{username}:{self.hash_password(password)}\n")

    def log_in(self, username, password):
        with open(self.users_db, 'r') as f:
            lines = f.readlines()
            for line in lines:
                user, hashed_password = line.strip().split(":")
                if user == username and hashed_password == self.hash_password(password):
                    return True
            return False

def launch_login_signup_screen():
    def log_in():
        username = simpledialog.askstring("Log In", "Enter your username:")
        password = simpledialog.askstring("Log In", "Enter your login password:", show="*")
        if user_auth.log_in(username, password):
            login_signup_screen.destroy()
            launch_main_app(username)
        else:
            messagebox.showerror("Error", "Invalid username or password.")

    def sign_up():
        username = simpledialog.askstring("Sign Up", "Enter your desired username:")
        user_directory = f"data/{username}"

        # Check if user directory already exists
        if os.path.exists(user_directory):
            messagebox.showerror("Error", "This username already exists. Please choose a different one.")
            return

        password = simpledialog.askstring("Sign Up", "Enter your desired login password:", show="*")
        user_auth.sign_up(username, password)
        
        # Create a temporary password manager instance to generate a file password
        temp_password_manager = PasswordManager(username)
        temp_password_manager.copy_file_password_to_clipboard()
        
        messagebox.showinfo("Success", "Account created successfully! Your file password has been copied to the clipboard. Please save it securely.")
        login_signup_screen.destroy()
        launch_main_app(username)

    login_signup_screen = tk.Tk()
    login_signup_screen.title("Login or Sign Up")

    login_button = tk.Button(login_signup_screen, text="Log In", command=log_in)
    signup_button = tk.Button(login_signup_screen, text="Sign Up", command=sign_up)

    login_button.pack(pady=10)
    signup_button.pack(pady=10)

    login_signup_screen.mainloop()

def launch_main_app(username):
    global root, password_manager
    root = tk.Tk()
    root.title("Password Manager")
    password_manager = PasswordManager(username)

    # GUI Functions
    def check_password_strength():
        password_to_check = simpledialog.askstring("Check Password Strength", "Enter the password:")
        if password_to_check:
            checker = PasswordChecker(password_to_check)
            strength_stats = checker.strength()
            messagebox.showinfo(
                "Password Strength",
                f"Password Strength: {strength_stats['strength_label']}\n"
                f"Lowercase characters: {strength_stats['lowercase_count']}\n"
                f"Uppercase characters: {strength_stats['uppercase_count']}\n"
                f"Digits: {strength_stats['digit_count']}\n"
                f"Special characters: {strength_stats['punctuation_count']}\n"
                f"Whitespace characters: {strength_stats['whitespace_count']}\n"
                f"Total Score: {strength_stats['total_score']} out of {strength_stats['max_score']}")   

    def generate_password():
        length = simpledialog.askinteger("Generate Password", "Enter desired password length:")
        if length:
            use_digits = messagebox.askyesno("Generate Password", "Include digits (0-9)?")
            use_lowercase = messagebox.askyesno("Generate Password", "Include lowercase letters (a-z)?")
            use_uppercase = messagebox.askyesno("Generate Password", "Include uppercase letters (A-Z)?")
            use_special = messagebox.askyesno("Generate Password", "Include special characters (!@#$%^&*()_-+=<>?)?")
            use_whitespace = messagebox.askyesno("Generate Password", "Include whitespace characters?")

            generator = PasswordGenerator(
                length,
                use_digits=use_digits,
                use_lowercase=use_lowercase,
                use_uppercase=use_uppercase,
                use_special=use_special,
                use_whitespace=use_whitespace
            )

            generated_password = generator.generate()
            messagebox.showinfo("Generated Password", f"Generated Password: {generated_password}")
            save_to_manager = messagebox.askyesno("Save to Password Manager",
                                                "Do you want to save this password to the password manager?")
            if save_to_manager:
                website = simpledialog.askstring("Save Password", "Enter the website for which this password was generated:")
                if website:
                    password_manager.store_password(website, generated_password)
                    messagebox.showinfo("Password Saved", f"Password saved for {website}!")

    def store_password():
        website = simpledialog.askstring("Store Password", "Enter the website for which you want to store a password:")
        password = simpledialog.askstring("Store Password", "Enter the password:")
        if website and password:
            password_manager.store_password(website, password)

    def retrieve_password():
        website = simpledialog.askstring("Retrieve Password", "Enter the website for which you want to retrieve the password:")
        if website:
            password = password_manager.retrieve_password(website)
            if password:
                copy_to_clipboard(password)
                messagebox.showinfo("Password Retrieved", f"Password for {website}:\n{password}\n\n"
                                                         "The password has been copied to the clipboard.")
            else:
                messagebox.showinfo("Password Not Found", f"Password for {website} not found.")

    def delete_password():
            password_manager.delete_password()

    def display_stored_passwords():
        passwords_text.config(state="normal")  # Enable text box for editing
        passwords_text.delete(1.0, tk.END)  # Clear the text box

        # Define font styles
        passwords_text.tag_configure("header", font=("Arial", 14, "bold"))
        passwords_text.tag_configure("details", font=("Consolas", 13))

        # Insert header with the "header" tag
        passwords_text.insert(tk.END, "Stored Passwords:\n", "header")

        for website, password in password_manager.passwords.items():
            decoded_password = password_manager.decode_password(password)
            
            # Insert website and password details with the "details" tag
            passwords_text.insert(tk.END, f"Website: {website}\n", "details")
            passwords_text.insert(tk.END, f"Password: {decoded_password}\n\n", "details")

        passwords_text.config(state="disabled")  # Disable text box for editing


    # Password Manager buttons
    store_password_button = tk.Button(root, text="Store Password", command=store_password)
    retrieve_password_button = tk.Button(root, text="Retrieve Password", command=retrieve_password)
    view_passwords_button = tk.Button(root, text="View Stored Passwords", command=display_stored_passwords)
    delete_password_button = tk.Button(root, text="Delete Password", command=delete_password)
    return_to_menu_button = tk.Button(root, text="Return to Main Menu", command=root.destroy)

    # Position the buttons
    store_password_button.grid(row=6, column=0, padx=10, pady=5)
    retrieve_password_button.grid(row=6, column=1, padx=10, pady=5)
    view_passwords_button.grid(row=7, column=0, padx=10, pady=5)
    delete_password_button.grid(row=7, column=1, padx=10, pady=5)
    return_to_menu_button.grid(row=8, column=0, columnspan=2, pady=10)

    # Add a button to generate and copy the file password
    generate_file_password_button = tk.Button(root, text="Copy file password to Clipboard",
                                              command=lambda: password_manager.copy_file_password_to_clipboard())
    generate_file_password_button.grid(row=8, column=0, padx=10, pady=5, columnspan=2)

    # Create a text widget to display stored passwords
    passwords_text = tk.Text(root, wrap=tk.WORD, state="disabled")
    passwords_text.grid(row=9, column=0, padx=10, pady=10, columnspan=2, sticky="nsew")

    # Configure the grid to expand the row and column containing passwords_text
    root.grid_rowconfigure(9, weight=1)
    root.grid_columnconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)

    # Menu Bar
    menubar = tk.Menu(root)
    root.config(menu=menubar)

    file_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Exit", command=lambda: password_manager.save_and_exit())
    
    file_menu.add_command(label="Export to TXT", command=password_manager.export_to_txt)

    password_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Password", menu=password_menu)
    password_menu.add_command(label="Check Password Strength", command=check_password_strength)
    password_menu.add_command(label="Generate Password", command=generate_password)

    root.mainloop()

if __name__ == '__main__':
    user_auth = UserAuth()
    launch_login_signup_screen()
