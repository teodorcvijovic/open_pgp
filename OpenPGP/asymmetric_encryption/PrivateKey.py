import datetime
import hashlib
import binascii

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import padding

from GlobalVariables import globalVariables
from exceptions.PassphraseNotValid import PassphraseNotValid


class PrivateKey:

    def __init__(self, public_key, private_key, username, email, passphrase, derived_from_algorithm):
        self.public_key = public_key
        self.timestamp = datetime.datetime.now()
        self.username = username
        self.email = email
        self.derived_from_algorithm = derived_from_algorithm

        # calculating key id
        public_key_hex = binascii.hexlify(public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode('utf-8')

        self.key_id = int(public_key_hex, 16) % (2 ** 64)

        # saving passphrase hash
        salt = b'salt'
        iv = b'01234567'
        # key derivation function
        kdf = PBKDF2HMAC(algorithm=hashlib.sha1(), length=24, salt=salt, iterations=100000,
                         backend=default_backend())
        passphrase_bytes = passphrase.encode('utf-8')
        self.hashed_passphrase = kdf.derive(passphrase_bytes)

        # encrypting the private key with 3DES where key=hashed_passphrase
        algorithm = algorithms.TripleDES(self.hashed_passphrase)

        # converting private key to byte .PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        padder = padding.PKCS7(algorithm.block_size).padder()
        padded_private_key_pem = padder.update(private_key_pem) + padder.finalize()

        cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        self.encrypted_private_key = encryptor.update(padded_private_key_pem) + encryptor.finalize()

    @classmethod
    def load_from_file(cls, private_key_filename, public_key_filename, passphrase):
        with open(public_key_filename, 'r') as file:
            file_content = file.read()
            # pay attention: format of .pem file
            algo, username, email, public_key_pem = file_content.split('#')

            public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
        with open(private_key_filename, 'r') as file:
            file_content = file.read()
            # pay attention: format of .pem file
            algo, username, email, private_key_pem = file_content.split('#')

            private_key = load_pem_private_key(private_key_pem.encode('utf-8'), passphrase.encode('utf-8'))

        return PrivateKey(public_key, private_key, username, email, passphrase, int(algo))

    def get_private_key(self, passphrase):
        # hash the passphrase and check if stored hash is same as just calculated hash
        salt = b'salt'
        iv = b'01234567'
        kdf = PBKDF2HMAC(algorithm=hashlib.sha1(), length=24, salt=salt, iterations=100000,
                         backend=default_backend())
        passphrase_bytes = passphrase.encode('utf-8')
        hashed_passphrase = kdf.derive(passphrase_bytes)

        if hashed_passphrase != self.hashed_passphrase:
            raise PassphraseNotValid()

        # if passphrase is correct, decrypt the encrypted private key with 3DES
        algorithm = algorithms.TripleDES(hashed_passphrase)

        cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        private_key_pem = decryptor.update(self.encrypted_private_key) + decryptor.finalize()

        private_key = load_pem_private_key(private_key_pem, password=None)

        return private_key

    def save_public_key_to_pem(self):
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # pay attention: format of .pem file
        file_data = str(self.derived_from_algorithm) + '#' + self.username + '#' + self.email + '#' + public_key_pem

        filename = f'{globalVariables.PRIVATE_KEYRING_PAIRS}/{str(self.key_id)}_public.pem'
        with(open(filename, 'w')) as f:
            f.write(file_data)

    def save_private_key_to_pem(self, passphrase):
        private_key = self.get_private_key(passphrase)

        passphrase_bytes = passphrase.encode('utf-8')

        private_key_pem_new = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase_bytes)
        ).decode('utf-8')

        # pay attention: format of .pem file
        file_data = str(self.derived_from_algorithm) + '#' + self.username + '#' + self.email + '#' + private_key_pem_new

        filename = f'{globalVariables.PRIVATE_KEYRING_PAIRS}/{str(self.key_id)}_private.pem'
        with(open(filename, 'w')) as f:
            f.write(file_data)
