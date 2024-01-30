# File Encryptor/Decryptor

This Python script provides a simple command-line interface to encrypt or decrypt files in a specified directory using the AES (Advanced Encryption Standard) algorithm in CBC (Cipher Block Chaining) mode.

## Prerequisites

- Python 3.10 
- Cryptodome library 
- tqdm library 

## Usage

1. Clone or download the script to your local machine.

2. Install the required libraries:

    ```bash
    pip install -r requirements.txt
    ```

3. Open a terminal or command prompt and navigate to the directory containing the script.

4. Run the script with the desired options. Example commands:

    - To encrypt files in a directory:
      ```bash
      python aes_crypt.py /path/to/directory --encrypt
      ```

    - To decrypt files in a directory:
      ```bash
      python aes_crypt.py /path/to/directory --decrypt
      ```

    - To specify a key and initialization vector (IV) file:
      ```bash
      python aes_crypt.py /path/to/directory --encrypt --key-file key.txt --iv-file iv.txt
      ```

    - If no key and IV file is provided, the script will prompt you to enter a password for key and IV generation.

## Options

- `directory`: The directory containing files to process.

- `--encrypt`: Encrypt files in the specified directory.

- `--decrypt`: Decrypt files in the specified directory.

- `--key-file`: File containing the decryption key (optional).

- `--iv-file`: File containing the initialization vector (IV) (optional).


**Note:** Ensure that you have appropriate permissions to read, write, and execute files in the specified directory. Use this script responsibly, and always keep your encryption keys secure.

**Disclaimer:** This script is provided as-is without any warranty. Use it at your own risk.
