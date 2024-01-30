import argparse
from hashlib import md5
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import os
from tqdm import tqdm
import time


class FileEncryptorDecryptor:
    def __init__(self, key_length=32, key_hex=None, iv_hex=None):
        self.key_length = key_length
        self.key_hex = key_hex
        self.iv_hex = iv_hex

        if self.key_hex is None or self.iv_hex is None:
            self.generate_key_and_iv()

    def derive_key_and_iv(self, password, salt):
        d = d_i = b''
        while len(d) < self.key_length + 16:
            d_i = md5(d_i + password + salt).digest()
            d += d_i
        return d[:self.key_length], d[self.key_length:self.key_length + 16]

    def generate_key_and_iv(self):
        password = input("Enter password for key and IV generation: ").encode('utf-8')
        salt = os.urandom(16)
        key, iv = self.derive_key_and_iv(password, salt)
        self.key_hex = key.hex()
        self.iv_hex = iv.hex()

        print('Generated key: ' + self.key_hex)
        print('Generated IV: ' + self.iv_hex)

    def get_key_and_iv(self):
        return bytes.fromhex(self.key_hex), bytes.fromhex(self.iv_hex)

    def encrypt_file(self, input_path):
        key, iv = self.get_key_and_iv()
        cipher = AES.new(key, AES.MODE_CBC, iv)

        try:
            with open(input_path, 'rb') as in_file:
                plaintext = in_file.read()
                ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

            with open(input_path + '.enc', 'wb') as out_file:
                out_file.write(cipher.iv)
                out_file.write(ciphertext)
        finally:
            cipher = None

    def decrypt_file(self, input_path):
        key, iv = self.get_key_and_iv()

        try:
            with open(input_path, 'rb') as in_file:
                iv = in_file.read(AES.block_size)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                ciphertext = in_file.read()

                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

            with open(input_path[:-4], 'wb') as out_file:
                out_file.write(plaintext)
        finally:
            cipher = None

    def process_directory(self, directory, encrypt=True):
        key, iv = self.get_key_and_iv()
        start_time = time.time()
        print('using key: ' + self.key_hex)
        print('using iv: ' + self.iv_hex)
        for root, dirs, files in os.walk(directory):
            total_files = len(files)
            for i, file in enumerate(tqdm(files, desc=f'Processing {"Encrypting" if encrypt else "Decrypting"}', unit='file', ncols=80, leave=False)):
                input_path = os.path.join(root, file)

                if encrypt:
                    self.encrypt_file(input_path)
                    os.remove(input_path)
                else:
                    self.decrypt_file(input_path)
                    os.remove(input_path)
        elapsed_time = time.time() - start_time
        print(f'finished in {time.strftime("%H:%M:%S", time.gmtime(elapsed_time))}')



def parse_args():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt files in a directory.')
    parser.add_argument('directory', help='Directory containing files to process')
    parser.add_argument('--encrypt', action='store_true', help='Encrypt files in the directory')
    parser.add_argument('--decrypt', action='store_true', help='Decrypt files in the directory')
    parser.add_argument('--key-file', help='File containing the decryption key')
    parser.add_argument('--iv-file', help='File containing the initialization vector (IV)')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    if args.encrypt and args.decrypt:
        print("Error: Please choose either --encrypt or --decrypt, not both.")
    elif not args.encrypt and not args.decrypt:
        print("Error: Please specify either --encrypt or --decrypt.")
    else:
        key_hex = None
        iv_hex = None

        if args.key_file:
            with open(args.key_file, 'r') as key_file:
                key_hex = key_file.read().strip()

        if args.iv_file:
            with open(args.iv_file, 'r') as iv_file:
                iv_hex = iv_file.read().strip()

        encryptor_decryptor = FileEncryptorDecryptor(key_hex=key_hex, iv_hex=iv_hex)

        if args.encrypt:
            encryptor_decryptor.process_directory(args.directory, encrypt=True)
        else:
            encryptor_decryptor.process_directory(args.directory, encrypt=False)

