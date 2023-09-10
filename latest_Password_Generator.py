import string
import random
import pyperclip
import os
import sys
import hashlib
from os import system
from cryptography.fernet import Fernet

def _copy_(data):
    pyperclip.copy("{}".format(data))

def clear_screen():
    return system("cls")

class PasswordChecking:
    def Num_of_lowercase(self, _String):
        return len([i for i in _String if i in string.ascii_lowercase])

    def Num_of_uppercase(self, _String):
        return len([i for i in _String if i in string.ascii_uppercase])

    def Num_of_letters(self, _String):
        return len([i for i in _String if i in string.ascii_letters])

    def Num_of_digits(self, _String):
        return len([i for i in _String if i in string.digits])

    def Num_of_punctuation(self, _String):
        return len([i for i in _String if i in string.punctuation])

    def Num_of_whitespace(self, _String):
        return len([i for i in _String if i in string.whitespace])

class PasswordCheckingStrength(PasswordChecking):
    def __init__(self):
        self._lowercase = {1: 0.5, 2: 0.5, 4: 2, 6: 3}
        self._uppercase = {1: 0.5, 2: 0.5, 4: 2, 6: 3}
        self._letters = {4: 2, 6: 2, 8: 2, 12: 4}
        self._digits = {1: 0.5, 2: 0.5, 4: 2, 6: 3}
        self._whitespace = {1: 1, 2: 1.5, 4: 2}
        self._special_character = {1: 1, 2: 1.5, 4: 2}

        self.keys_group = [
            self._lowercase, self._uppercase,
            self._letters, self._digits, self._whitespace,
            self._special_character
        ]

    def get_strength_point(self, Password):
        Key_data = [
            self.Num_of_lowercase(Password), self.Num_of_uppercase(Password),
            self.Num_of_letters(Password), self.Num_of_digits(Password),
            self.Num_of_whitespace(Password), self.Num_of_punctuation(Password)
        ]

        Points = 0
        for ii in range(len(self.keys_group)):
            kgro = self.keys_group[ii]

            for i in kgro:
                if i <= Key_data[ii]:
                    Points += kgro[i]

        if 20 >= len(Password):
            Points += (len(Password) / 2)
        else:
            Points += 10

        return Points

    def password_strength(self, Points):
        if Points <= 10:
            return "Strength: Weak"
        elif 10 < Points <= 15:
            return "Strength: Normal"
        elif 15 < Points <= 20:
            return "Strength: Good"
        elif 20 < Points <= 30:
            return "Strength: Strong"
        elif 30 < Points <= 44.5:
            return "Strength: Strongest"
        elif Points >= 45:
            return "Strength: Super Strong"

    def main(self):
        while True:
            print('\n' + "q | STOP".center(20, '-'))
            Password = input(":")
            Points = self.get_strength_point(Password)

            print("Points : ", Points)
            print("Length : ", len(Password))
            print(self.password_strength(Points))

            if Password == "q":
                clear_screen()
                break

class PasswordGenerator(PasswordCheckingStrength):
    def about_password(self):
        print(("-" * 20) + "q | Stop" + ("-" * 20))

        print("\nWhat You Want Into Your Password:")
        Length_pass = int(input("Length: "))

        querys = ["Digits (y/n):", "Lowercase (y/n):", "Uppercase (y/n):",
                  "Special Characters (y/n):", "Whitespace (y/n):"]
        yn_list = list()

        for i in range(5):
            _input = input(querys[i])
            if _input != 'y' and _input != 'Y':
                yn_list.append('n')
            else:
                yn_list.append(_input)

        self.generate_password(Length_pass, yn_list)

    def generate_password(self, Length_pass, yn_list):
        clear_screen()
        Keyboard = [
            list(string.digits), list(string.ascii_lowercase),
            list(string.ascii_uppercase), list(string.punctuation), [' ']
        ]
        Demand_list = []

        for i in range(5):
            if yn_list[i] == 'y' or yn_list[i] == 'Y':
                for ii in range(Length_pass):
                    rrc = random.choice(Keyboard[i])
                    Demand_list.append(rrc)

        password_ = []
        for o in range(Length_pass):
            rp = random.choice(Demand_list)
            password_.append(rp)

        print('-' * (10 + len(password_)))
        PP = "".join(password_)
        print("Password: {}".format(PP))

        point = self.get_strength_point(password_)
        print("Points : ", point)
        print(self.password_strength(point))

        print('-' * (10 + len(password_)))

        print("Password Is Copied To Clipboard\n")
        data = "".join(password_)
        _copy_(data)

        dec = input("\nPress Enter To Generate Again\nPress 'cn' To Create New: ")
        if dec == 'cn':
            self.about_password()
        else:
            return self.generate_password(Length_pass, yn_list)

class PasswordManager:
    def __init__(self, username):
        self.username = username
        self.user_directory = f"data/{self.username}"
        self.passwords = {}
        self.login_password = None
        self.file_password = None
        self.fernet = None

        if os.path.exists(self.user_directory):
            # Check if the passwords.txt file exists in the user's directory
            if os.path.exists(os.path.join(self.user_directory, "passwords.txt")):
                self.load_passwords_from_file()
                self.enter_file_password()
            else:
                choice = input("Passwords file not found. Do you want to generate a new file password or exit? (generate/exit): ")
                if choice.lower() == 'generate':
                    self.file_password = self.generate_file_password()
                    print(f"Your file password is: {self.file_password}\n Slaptažodį būtinai įsiminkite")
                    input("Press Enter to continue...")
                elif choice.lower() == 'exit':
                    print("Goodbye!")
                    sys.exit()
        else:
            print(f"User directory '{self.user_directory}' does not exist. Create an account first.")
            sys.exit()

        # Initialize Fernet based on the user's choice
        self.initialize_fernet()
    
    def generate_file_password(self):
        file_password = Fernet.generate_key().decode()
        return file_password
    
    def enter_file_password(self):
        # Ask the user to enter a previously generated file password
        while True:
            file_password = input("Enter your previously generated file password: ")
            if len(file_password) == 44:  # Fernet key must be 44 characters long
                self.file_password = file_password
                break
            else:
                print("Invalid file password. Please enter a valid 44-character file password.")


    def initialize_fernet(self):
        while self.file_password is None:
            self.enter_file_password()
        try:
            self.fernet = Fernet(self.file_password.encode())
            self.decrypt_passwords()  # Decrypt passwords when the app starts
        except ValueError:
            print("Invalid file password. Please create or enter a valid 44-character file password.")
            self.enter_file_password()

    def store_password(self, website, password):
        if self.fernet is None:
            print("Please initialize the Fernet encryption first.")
            return

        encrypted_password = self.fernet.encrypt(password.encode()).decode()
        self.passwords[website] = encrypted_password
        print(f"Password for {website} stored successfully!")

    def retrieve_password(self, website):
        if self.fernet is None:
            print("Please initialize the Fernet encryption first.")
            return

        if website in self.passwords:
            encrypted_password = self.passwords[website]
            decrypted_password = self.fernet.decrypt(encrypted_password.encode()).decode()
            print(f"Password for {website}: {decrypted_password}")
        else:
            print(f"No password found for {website}.")

    def decrypt_passwords(self):
        if self.fernet is not None:
            try:
                with open(f"{self.user_directory}/passwords.txt", "rb") as f:
                    encrypted_data = f.read()
                    decrypted_data = self.fernet.decrypt(encrypted_data)
                    self.passwords = eval(decrypted_data.decode())
                    print("Passwords decrypted successfully.")
            except FileNotFoundError:
                print("No passwords file found. No passwords decrypted.")
        else:
            print("File password is required to decrypt passwords. Please create or enter the file password.")

    def view_passwords(self):
        if not self.passwords:
            print("No passwords stored yet.")
        else:
            print("Stored Passwords:")
            for website, encrypted_password in self.passwords.items():
                decrypted_password = self.fernet.decrypt(encrypted_password.encode()).decode()
                print(f"Website: {website}, Password: {decrypted_password}")  # Display actual passwords

    def save_passwords_to_file(self):
        if self.fernet is not None:
            # Encrypt the passwords before saving them
            encrypted_data = self.fernet.encrypt(str(self.passwords).encode())

            # Open the file in binary write mode
            with open(f"{self.user_directory}/passwords.txt", "wb") as f:
                f.write(encrypted_data)

            print("Passwords saved to file.")
        else:
            print("File password is required to save passwords to a file. Please create or enter the file password.")
    
    def load_passwords_from_file(self):
        if self.fernet is not None:
            try:
                with open(f"{self.user_directory}/passwords.txt", "rb") as f:
                    encrypted_data = f.read()
                    decrypted_data = self.fernet.decrypt(encrypted_data)
                    self.passwords = eval(decrypted_data.decode())
                    print("Passwords loaded successfully.")
            except FileNotFoundError:
                print("No passwords file found. No passwords loaded.")
        else:
            print("File password is required to load passwords from a file. Please create or enter the file password.")
    
    def main_menu(self):
        while True:
            print("\nPassword Manager Menu:")
            print("1. Retrieve Password")
            print("2. Store Password")
            print("3. View Stored Passwords")
            print("4. Back to Main Menu")
            choice = input("Enter your choice: ")

            if choice == "1":
                website = input("Enter the website for which you want to retrieve the password: ")
                self.retrieve_password(website)
            elif choice == "2":
                website = input("Enter the website for which you want to store a password: ")
                password = input("Enter the password: ")
                self.store_password(website, password)
            elif choice == "3":
                self.view_passwords()
            elif choice == "4":
                break
            else:
                print("Invalid choice. Please try again.")

    def run(self):
        self.decrypt_passwords()  # Decrypt passwords when the app starts
        self.main_menu()  # Start the password manager main menu

def create_login(username):
    password = input(f"Create a login password for {username}: ")

    # Create a directory for the user's data
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

        if username == stored_username and entered_password_hash == stored_password_hash:
            return True
    return False

def login(username):
    while True:
        user_directory = f"data/{username}"

        if os.path.exists(user_directory):
            while True:
                password = input("Enter your login password: ")
                if verify_login(username, password):
                    print(f"Login successful for {username}!")
                    return
                else:
                    print("Invalid username or password. Please try again.")
        else:
            print(f"Username '{username}' does not exist. Would you like to create a new account? (yes/no)")
            choice = input(": ").lower()
            if choice == "yes":
                create_login(username)
                print("Account created successfully!")
            else:
                print("Goodbye!")
                sys.exit()

def exit_program(password_manager):
    if password_manager:
        password_manager.save_passwords_to_file()  # Save passwords before exiting
    print("Programa baigia darbą. Viso gero!")
    sys.exit()

def change_password(username):
    user_directory = f"data/{username}"

    if os.path.exists(f"{user_directory}/login_info.txt"):
        with open(f"{user_directory}/login_info.txt", "r") as f:
            stored_username, stored_password_hash = f.readline().strip().split(",")
        print(f"Changing password for user: {stored_username}")

        current_password = input("Enter your current password: ")

        if verify_login(stored_username, current_password):
            new_password = input("Enter a new password: ")
            new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()

            with open(f"{user_directory}/login_info.txt", "w") as f:
                f.write(f"{stored_username},{new_password_hash}")

            print("Password changed successfully!")
        else:
            print("Invalid current password. Password change failed.")
    else:
        print("No login information found. Create a login first.")

def main(username):
    login(username)
    password_manager = PasswordManager(username)  # Initialize password manager object
    while True:
        try:
            clear_screen()
            print("\nMain Menu:")
            print("1. Check Password Strength")
            print("2. Generate Password")
            print("3. Exit")
            print("4. Change Master Password")
            print("5. Password Manager")
            ur = int(input(":"))
            if ur == 1:
                PasswordCheckingStrength().main()
            elif ur == 2:
                PasswordGenerator().about_password()
            elif ur == 3:
                exit_program(password_manager)
            elif ur == 4:
                change_password(username)
            elif ur == 5:
                password_manager.main_menu()
        except KeyboardInterrupt:
            exit_program(password_manager)

if __name__ == '__main__':
    username = input("Enter your username: ")
    main(username)
