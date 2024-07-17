# AES-256 Encryption/Decryption App

This is a simple Python application that encrypts and decrypts messages using AES-256 encryption. The application allows the user to choose between encrypting and decrypting a message, providing a secure way to handle sensitive information.

## Features

- AES-256 encryption using a user-provided key.
- AES-256 decryption using a user-provided key.
- Salt and IV are generated automatically and included in the encrypted message.
- User-friendly command-line interface.

## Requirements

- Python 3.6 or higher
- `cryptography` library

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/a6s1/cryptography.git
   cd aes256-encryption-app
   ```

2. **Create a virtual environment (optional but recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the required libraries:**
   ```bash
   pip install cryptography
   ```

## Usage

Run the application using the following command:
```bash
python aes256_app.py
```

### Encrypting a Message

1. Choose to encrypt a message by typing `encrypt` when prompted.
2. Enter the message you want to encrypt.
3. Enter the encryption key.
4. The encrypted message will be displayed.

### Decrypting a Message

1. Choose to decrypt a message by typing `decrypt` when prompted.
2. Enter the encrypted message.
3. Enter the decryption key.
4. The decrypted message will be displayed.

## Example

### Encryption

```bash
Do you want to encrypt or decrypt a message? (enter 'encrypt' or 'decrypt'): encrypt
Please enter the message to encrypt: This is a secret message.
Please enter the encryption key: my_secure_key
Encrypted Data:
U2FsdGVkX19IVkYXd0NGOTNjVkc4Q1F3WlJtY2NIR2p3RW5yVXp3c21PYkNUaz0=
```

### Decryption

```bash
Do you want to encrypt or decrypt a message? (enter 'encrypt' or 'decrypt'): decrypt
Please enter the encrypted message: U2FsdGVkX19IVkYXd0NGOTNjVkc4Q1F3WlJtY2NIR2p3RW5yVXp3c21PYkNUaz0=
Please enter the decryption key: my_secure_key
Decrypted Message: This is a secret message.
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request if you have any improvements or bug fixes.

