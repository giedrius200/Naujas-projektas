import tkinter as tk
from tkinter import messagebox, simpledialog
import string
import random
import os
import sys
from cryptography.fernet import Fernet, InvalidToken
import shutil
import hashlib

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
