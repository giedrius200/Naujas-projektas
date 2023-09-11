# Password Manager

A simple and secure password manager built using Python's `tkinter` for GUI and `cryptography` for encryption.

## Features

- **User Authentication**: Users can sign up with a unique username and password. Existing users can log in.
- **Password Storage**: Store passwords securely for different websites.
- **Password Retrieval**: Retrieve stored passwords with ease.
- **Password Generation**: Generate strong passwords based on user preferences.
- **Password Strength Checker**: Check the strength of any password.
- **Secure Encryption**: Passwords are encrypted using Fernet symmetric encryption.
- **Clipboard Integration**: Easily copy passwords to the clipboard.

## Dependencies

- `tkinter`: For the graphical user interface.
- `cryptography`: For encrypting and decrypting stored passwords.
- `hashlib`: For hashing user login passwords.
- `pyperclip`: For clipboard operations (optional).

## How to Use

1. Run the script.
2. If you're a new user, sign up with a unique username and password.
3. Upon successful sign-up, a file password will be generated and copied to your clipboard. This is used for encrypting your stored passwords. Keep it safe!
4. Log in with your username and password.
5. Use the main application window to store, retrieve, delete, and view passwords. You can also generate strong passwords and check the strength of any password.

## Notes

- Always remember your login password and the generated file password. Losing the file password means you won't be able to decrypt your stored passwords.
- The application uses SHA-256 hashing for user login passwords and Fernet symmetric encryption for encrypting stored passwords.

## Future Enhancements

- Implement a backup and restore feature.
- Add multi-factor authentication for added security.
- Improve the user interface for a better user experience.
