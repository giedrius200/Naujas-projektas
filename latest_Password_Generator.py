import string
import random
import os
import sys
import hashlib
from cryptography.fernet import Fernet

# Utility Functions
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def copy_to_clipboard(data):
    try:
        import pyperclip
        pyperclip.copy(data)
    except ImportError:
        print("Pyperclip not installed. Cannot copy to clipboard.")

# Password Strength Checker
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

# Password Generator
class PasswordGenerator:
    def __init__(self, length, use_digits=True, use_lowercase=True, use_uppercase=True, use_special=True, use_whitespace=False):
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

# Password Manager
class PasswordManager:
    def __init__(self, username):
        self.username = username
        self.user_directory = f"data/{self.username}"
        self.passwords = {}
        self.file_password = None
        self.fernet = None

        if not os.path.exists(self.user_directory):
            os.makedirs(self.user_directory, exist_ok=True)

        if os.path.exists(os.path.join(self.user_directory, "passwords.txt")):
            self.initialize_fernet()
            self.load_passwords_from_file()
        else:
            self.file_password = self.generate_file_password()
            print(f"Your file password is: {self.file_password}\nPlease remember this password!")
            self.initialize_fernet()

    def generate_file_password(self):
        return Fernet.generate_key().decode()

    def initialize_fernet(self):
        while True:
            if not self.file_password:
                self.file_password = input("Enter your file password: ")

            try:
                self.fernet = Fernet(self.file_password.encode())
                break  # If successful, break out of the loop
            except ValueError:
                print("Invalid file password. Please enter a valid 44-character file password.")
                self.file_password = None  # Reset the file password to prompt the user again
                
    def store_password(self, website, password):
        encrypted_password = self.fernet.encrypt(password.encode()).decode()
        self.passwords[website] = encrypted_password

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
            decrypted_data = self.fernet.decrypt(encrypted_data)
            self.passwords = eval(decrypted_data.decode())
        
    def view_all_passwords(self):
        for website, encrypted_password in self.passwords.items():
            decrypted_password = self.fernet.decrypt(encrypted_password.encode()).decode()
            print(f"Website: {website}, Password: {decrypted_password}")

def create_login(username):
    password = input(f"Create a login password for {username}: ")
    user_directory = f"data/{username}"
    os.makedirs(user_directory, exist_ok=True)

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    with open(f"{user_directory}/login_info.txt", "w") as f:
        f.write(f"{username},{password_hash}")
    print(f"Login created successfully for {username}!")

def verify_login(username, password):
    user_directory = f"data/{username}"
    if os.path.exists(f"{user_directory}/login_info.txt"):
        with open(f"{user_directory}/login_info.txt", "r") as f:
            stored_username, stored_password_hash = f.readline().strip().split(",")
        entered_password_hash = hashlib.sha256(password.encode()).hexdigest()
        return username == stored_username and entered_password_hash == stored_password_hash
    return False

def user_login():
    username = input("Enter your username: ")
    user_directory = f"data/{username}"

    if os.path.exists(user_directory):
        while True:  # Keep prompting until a correct password is entered or the user decides to exit
            password = input("Enter your login password: ")
            if verify_login(username, password):
                print(f"Login successful for {username}!")
                return username
            else:
                print("Invalid password. Please try again.")
                continue_choice = input("Do you want to try again? (yes/no): ").lower()
                if continue_choice != "yes":
                    print("Goodbye!")
                    sys.exit()
    else:
        print(f"Username '{username}' does not exist. Would you like to create a new account? (yes/no)")
        choice = input(": ").lower()
        if choice == "yes":
            create_login(username)
            return username
        else:
            print("Goodbye!")
            sys.exit()

def password_manager_menu(password_manager):
    while True:
        print("\nPassword Manager Menu:")
        print("1. Store Password")
        print("2. Retrieve Password")
        print("3. View Stored Passwords")
        print("4. Return to Main Menu")
        choice = input("Enter your choice: ")

        if choice == "1":
            website = input("Enter the website for which you want to store a password: ")
            password = input("Enter the password: ")
            password_manager.store_password(website, password)
        elif choice == "2":
            website = input("Enter the website for which you want to retrieve the password: ")
            password_manager.retrieve_password(website)
        elif choice == "3":
            password_manager.view_all_passwords()
            input("\nPress Enter to return to the manager menu...")
            clear_screen()
        elif choice == "4":
            break
        else:
            print("Invalid choice. Please try again.")

def main():
    username = user_login()
    password_manager = PasswordManager(username)
    try:
        while True:
            print("\nMain Menu:")
            print("1. Check Password Strength")
            print("2. Generate Password")
            print("3. Password Manager")
            print("4. Exit")
            choice = input("Enter your choice: ")

            if choice == "1":
                print("\nCheck Password Strength:")
                print("1. Enter password manually")
                print("2. Select from stored passwords")
                sub_choice = input("Enter your choice: ")

                if sub_choice == "1":
                    password_to_check = input("Enter the password: ")
                elif sub_choice == "2":
                    if not password_manager.passwords:
                        print("No passwords stored yet.")
                        continue
                    print("\nStored Websites:")
                    for idx, website in enumerate(password_manager.passwords.keys(), 1):
                        print(f"{idx}. {website}")
                    website_choice = int(input("Select a website by number: "))
                    website = list(password_manager.passwords.keys())[website_choice - 1]
                    password_to_check = password_manager.retrieve_password(website)
                else:
                    print("Invalid choice. Please try again.")
                    continue

                checker = PasswordChecker(password_to_check)
                strength_stats = checker.strength()
                print(f"\nPassword Strength for '{password_to_check}': {strength_stats['strength_label']}")
                print(f"Lowercase characters: {strength_stats['lowercase_count']}")
                print(f"Uppercase characters: {strength_stats['uppercase_count']}")
                print(f"Digits: {strength_stats['digit_count']}")
                print(f"Special characters: {strength_stats['punctuation_count']}")
                print(f"Whitespace characters: {strength_stats['whitespace_count']}")
                print(f"Total Score: {strength_stats['total_score']} out of {strength_stats['max_score']}")
                input("\nPress Enter to return to the main menu...")
                clear_screen()
            elif choice == "2":
                length = int(input("Enter desired password length: "))
                use_digits = input("Include digits (0-9)? (yes/no): ").lower() == "yes"
                use_lowercase = input("Include lowercase letters (a-z)? (yes/no): ").lower() == "yes"
                use_uppercase = input("Include uppercase letters (A-Z)? (yes/no): ").lower() == "yes"
                use_special = input("Include special characters (e.g., !@#$%^&*)? (yes/no): ").lower() == "yes"
                use_whitespace = input("Include whitespace (spaces)? (yes/no): ").lower() == "yes"
                generator = PasswordGenerator(length, use_digits, use_lowercase, use_uppercase, use_special, use_whitespace)
                generated_password = generator.generate()
                print(f"Generated Password: {generated_password}")
                save_to_manager = input("Do you want to save this password to the password manager? (yes/no): ").lower()
                if save_to_manager == "yes":
                    website = input("Enter the website for which this password was generated: ")
                    password_manager.store_password(website, generated_password)
                    print(f"Password saved for {website}!")
            elif choice == "3":
                password_manager_menu(password_manager)
            elif choice == "4":
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
    except KeyboardInterrupt:
        print("\nDetected keyboard interrupt. Saving passwords and exiting...")
        password_manager.save_passwords_to_file()
        sys.exit()


if __name__ == '__main__':
    main()