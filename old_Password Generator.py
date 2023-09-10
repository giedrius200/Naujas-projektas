import string
import subprocess 
import random
import pyperclip
import os
import sys
import hashlib
from cryptography.fernet import Fernet
from os import system


def _copy_(data):
    pyperclip.copy("{}".format(data))

def clear_screen():     # clear Screen
    return system("cls")

class stringc:
    def Num_of_lowercase(self, _String):
        return len([i for i in _String if i in string.ascii_lowercase])

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


#-  -   -   Password Checking  -   -   -   -#

class Password_Checking(stringc):
    def __init__(self):
        self._lowercase = {1:0.5, 2:0.5, 4:2, 6:3}
        self._uppercase = {1:0.5, 2:0.5, 4:2, 6:3}
        self._letters = {4:2, 6:2, 8:2, 12:4}
        self._digits = {1:0.5, 2:0.5, 4:2, 6:3}
        self._whitespace = {1:1, 2:1.5, 4:2}
        self._special_character = {1:1, 2:1.5, 4:2}

        self.keys_group = [self._lowercase, self._uppercase, 
            self._letters, self._digits, self._whitespace, 
            self._special_character]

    def get_strength_point(self, Password):
        self.Key_data = [self.Num_of_lowercase(Password), self.Num_of_uppercase(Password),
            self.Num_of_letters(Password), self.Num_of_digits(Password), 
            self.Num_of_whitespace(Password), self.Num_of_punctuation(Password)]
        # print(Key_data)
        
        self.Points = 0
        for ii in range(len(self.keys_group)):
            self.kgro = self.keys_group[ii]

            for i in self.kgro:
                if i <= self.Key_data[ii]:
                    self.Points += self.kgro[i]
        
        if 20 >= len(Password):
            self.Points += (len(Password)/2)
        else :
            self.Points += 10

        return self.Points

    def Password_strength(self, Points):
        if Points <= 10: return "Strength: Weak"
        elif Points > 10 and Points <= 15: return "Strength: Normal"
        elif Points > 15 and Points <= 20: return "Strength: Good"
        elif Points > 20 and Points <= 30: return "Strength: Strong"
        elif Points > 30 and Points <= 44.5: return "Strength: Strongest"
        elif Points >= 45:  return "Strength: Super Strong"

    def main(self):
        while True:
            print('\n')
            print("q | STOP".center(20,'-'))    
            self._Password = input(":")
            self.Points = self.get_strength_point(self._Password)
            
            print("Points : ",self.Points)
            print("Length : ",len(self._Password))
            print(self.Password_strength(self.Points))
            
            if self._Password == "q": 
                clear_screen()
                break


#-  -   -    Password_genrator   -   -   -#

#Information About Password
class Password_Genrator(Password_Checking):

    def About_Password(self):
        # global Length_pass      #length of the password | used in Genrates_password()
        # global yn_list          # yes/No list created with loop | used in Genrates_password()

        print(("-"*20) + "q | Stop" + ("-"*20) )  

        print("\nWhat You Want InTo our Password:")
        self.Length_pass = int(input("Length: "))

        self.querys =["Digits (y/n):", "lowercase (y/n):", "uppercare (y/n):", 
                "Spical Charaters (y/n):", "whitespace (y/n):"]      #printing To get Input
        self.yn_list = list()

        for i in range(5):      # Getting Input using loop
            _input = input(self.querys[i])
            if _input != 'y' and _input != 'Y': self.yn_list.append('n')
            else: self.yn_list.append(_input)

        # print(yn_list)
        self.Genrates_password()

    # Password Genrates Here:
    def Genrates_password(self):
        clear_screen()
        self.Keyboard = [list(string.digits), list(string.ascii_lowercase), list(string.ascii_uppercase), 
                list(string.punctuation), [' ']]   #data get from inbuilt string module
        self.Demand_list = []        #demand list which user has demand for digits or lowercase or..., {y/n}
        
        for i in range(5):
            if self.yn_list[i] == 'y' or self.yn_list[i] == 'Y':
                for ii in range(self.Length_pass):
                    rrc = random.choice(self.Keyboard[i])
                    self.Demand_list.append(rrc)
        
        self.password_ = []          #final Password list choice from Demand_list using random
        for o in range(self.Length_pass):
            rp = random.choice(self.Demand_list)
            self.password_.append(rp)

        # Finnaly Print : STUF :

        print('-' * (10+len(self.password_)))
        #printing password and points and strength
        PP = "".join(self.password_)
        print("Password: {}".format(PP))

        point = Password_Checking().get_strength_point(self.password_)
        print("Points : ",point)
        print(Password_Checking().Password_strength(point))
        
        print('-' * (10+len(self.password_)))

        print("Password Is Copy To Clipboard\n")        #To Copy Password
        data = "".join(self.password_)
        # subprocess.run("clip",universal_newlines=True, input=data)
        _copy_(data)
        #genrate again or not ? 
        dec = input("\nPress Enter To Gen Again\nPress ' cn ' To Create New :")
        if dec == 'cn' : self.About_Password()    
        else: return self.Genrates_password()

def create_login():
    username = input("Create a username: ")
    password = input("Create a password: ")
    
    # Hash the password before storing it
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    with open("login_info.txt", "w") as f:
        f.write(f"{username},{password_hash}")
    print("Login created successfully!")

def verify_login(username, password):
    # Read stored login information
    if os.path.exists("login_info.txt"):
        with open("login_info.txt", "r") as f:
            stored_username, stored_password_hash = f.readline().strip().split(",")
        
        # Hash the entered password for verification
        entered_password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if username == stored_username and entered_password_hash == stored_password_hash:
            return True
    return False

def login():
    if os.path.exists("login_info.txt"):
        while True:
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            if verify_login(username, password):
                print("Login successful!")
                break
            else:
                print("Invalid username or password. Please try again.")
    else:
        print("Create the initial login.")
        create_login()
    
def exit_program():
    print("Programa baigia darbą. Viso gero!")
    sys.exit()

def change_password():
    if os.path.exists("login_info.txt"):
        with open("login_info.txt", "r") as f:
            stored_username, stored_password_hash = f.readline().strip().split(",")
        print(f"Changing password for user: {stored_username}")
        
        # Prompt for the current password for verification
        current_password = input("Enter your current password: ")
        
        # Verify the current password
        if verify_login(stored_username, current_password):
            new_password = input("Enter a new password: ")
            
            # Hash the new password before storing it
            new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
            
            with open("login_info.txt", "w") as f:
                f.write(f"{stored_username},{new_password_hash}")
            
            print("Password changed successfully!")
        else:
            print("Invalid current password. Password change failed.")
    else:
        print("No login information found. Create a login first.")

class PasswordManager:
    def __init__(self):
        self.passwords = {}
        self.file_password = None
        self.fernet = None

        self.load_passwords_from_file()
        self.load_file_password()

    def create_file_password(self):
        # Generate a random 32-character base64 password
        file_password = Fernet.generate_key().decode()
        self.file_password = file_password

        # Save the generated password securely, e.g., in a file
        with open("file_password.txt", "w") as f:
            f.write(file_password)

        print("File password created successfully!")

    def load_file_password(self):
        # Load the stored file password
        if os.path.exists("file_password.txt"):
            with open("file_password.txt", "r") as f:
                self.file_password = f.read()

    def generate_key(self):
        if self.file_password:
            return hashlib.sha256(self.file_password.encode()).digest()
        else:
            print("Invalid or missing file password. Please create a new one.")

    def initialize_fernet(self):
        self.fernet = Fernet(self.generate_key())

    def create_password(self, website, username, password):
        if not self.fernet:
            print("File password is required to create passwords. Please create or enter the file password.")
            return

        if website not in self.passwords:
            self.passwords[website] = {}

        self.passwords[website][username] = password
        print("Password created successfully!")

    def save_passwords_to_file(self):
        if not self.fernet:
            print("File password is required to save passwords to a file. Please create or enter the file password.")
            return

        encrypted_data = self.fernet.encrypt(str(self.passwords).encode())

        with open("passwords.enc", "wb") as f:
            f.write(encrypted_data)
        print("Passwords saved securely!")

    def load_passwords_from_file(self):
        if not self.fernet:
            print("File password is required to load passwords from a file. Please create or enter the file password.")
            return

        if os.path.exists("passwords.enc"):
            with open("passwords.enc", "rb") as f:
                encrypted_data = f.read()

            decrypted_data = self.fernet.decrypt(encrypted_data)
            self.passwords = eval(decrypted_data.decode())
        else:
            self.passwords = {}

    def view_passwords_in_app(self):
        if not self.fernet:
            print("File password is required to view passwords. Please create or enter the file password.")
            return

        if not self.passwords:
            print("No passwords stored.")
            return

        print("Stored Passwords:")
        for website, creds in self.passwords.items():
            print(f"Website: {website}")
            for username, password in creds.items():
                print(f"Username: {username}, Password: {password}")
            print()

def main():
    login()
    password_manager = PasswordManager()
    while True:
        try:
            clear_screen()
            print("\n1 | Check Password Strength\n2 | Generate Password\n3 | Exit Program\n4 | Change Login Password\n5 | Store Password\n6 | View Stored Passwords")
            ur = int(input(":"))
            if ur == 1:
                Password_Checking().main()
            elif ur == 2:
                Password_Genrator().About_Password()
            elif ur == 3:
                exit_program()
            elif ur == 4:
                change_password(password_manager)
            elif ur == 5:
                if not password_manager.fernet:
                    print("File password is required to create passwords. Please create or enter the file password.")
                else:
                    website = input("Enter website: ")
                    username = input("Enter username: ")
                    password = input("Enter password: ")
                    password_manager.create_password(website, username, password)
            elif ur == 6:
                password_manager.view_passwords_in_app()
        except KeyboardInterrupt:  # Catch KeyboardInterrupt (Ctrl+C) to exit gracefully
            exit_program()

if __name__ == '__main__':
    main()