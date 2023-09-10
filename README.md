# Password Utilities Suite

This suite provides a set of utilities to manage and assess passwords. The main features include password strength checking, password generation, and a basic password manager.

## Features:

1. **Password Strength Checker**: Determine the strength of a given password.
2. **Password Generator**: Create strong passwords based on user preferences.
3. **Password Manager**: Store, retrieve, and view passwords for different websites. Passwords are encrypted using the Fernet symmetric encryption.

## Modules:

- **Pyperclip**: Used to copy the password to the clipboard.
- **OS and Sys**: Basic system operations and exit control.
- **Hashlib**: SHA256 hashing for user passwords.
- **Cryptography's Fernet**: For encrypting stored passwords.

## Classes:

1. **PasswordChecking**: Contains methods to count occurrences of different types of characters in a given string.
2. **PasswordCheckingStrength**: Inherits from `PasswordChecking` and provides functionality to determine password strength.
3. **PasswordGenerator**: Inherits from `PasswordCheckingStrength` and provides password generation functionality.
4. **PasswordManager**: Allows users to store and retrieve passwords for different websites. The passwords are stored in an encrypted format.

## Usage:

### Password Strength Checker:

The main method will prompt the user to enter a password. The strength of the password will be displayed based on various metrics.

```python
checker = PasswordCheckingStrength()
checker.main()
```
### Password Generator:

Use the about_password method to prompt the user for password preferences and generate a password accordingly.

```python

generator = PasswordGenerator()
generator.about_password()
```

### Password Manager:

Initialize the manager with a username, then call the run method.

```python

manager = PasswordManager("YourUsername")
manager.run()
```

### Remember: Before using the manager for a user, you need to call the create_login method for that user.

```python

create_login("YourUsername")
```

### Additional Functions:

1. **login**: Authenticates a user using their login password.
2. **create_login**: Allows a new user to create a password for accessing the suite.
3. **verify_login**: Verifies the hashed login password against the stored hash for a given user.
4. **change_password**: Allows a user to change their login password.

### Important:

Always remember the file password given by the password manager. It is crucial for decrypting stored passwords.
