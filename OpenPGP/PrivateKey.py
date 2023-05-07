import datetime
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import binascii
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import padding

from GlobalVariables import globalVariables

class PrivateKey:

    def __init__(self, public_key, private_key, user_id, passphrase, derived_from_algorithm):
        self.public_key = public_key
        self.timestamp = datetime.datetime.now()
        self.user_id = user_id
        self.derived_from_algorithm = derived_from_algorithm

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        salt = b'salt'
        iv = b'01234567'
        kdf = PBKDF2HMAC(algorithm=hashlib.sha1(), length=24, salt=salt, iterations=100000,
                         backend=default_backend())
        bytes = passphrase.encode('utf-8')
        self.pass_hash = key = kdf.derive(bytes)

        algorithm = algorithms.TripleDES(key)

        padder = padding.PKCS7(algorithm.block_size).padder()
        padded_key = padder.update(private_key_pem) + padder.finalize()

        cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        self.encrypted_private_key = encryptor.update(padded_key) + encryptor.finalize()

        public_key_hex = binascii.hexlify(public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode('utf-8')

        self.key_id = int(public_key_hex, 16) % (2 ** 64)

    @classmethod
    def load_from_file(self, private_key_filename, public_key_filename, passphrase):
        public_key = private_key = email = algo = None
        with open(public_key_filename, 'r') as file:
            content = file.read()
            algo, email, public_key_pem = content.split('#')

            public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
        with open(private_key_filename, 'r') as file:
            content = file.read()
            algo, email, private_key_pem = content.split('#')

            private_key = load_pem_private_key(private_key_pem.encode('utf-8'), passphrase.encode('utf-8'))

        return PrivateKey(public_key, private_key, email, passphrase, int(algo))

    def get_private_key(self, passphrase):

        salt = b'salt'
        iv = b'01234567'
        kdf = PBKDF2HMAC(algorithm=hashlib.sha1(), length=24, salt=salt, iterations=100000,
                         backend=default_backend())
        bytes = passphrase.encode('utf-8')
        key = kdf.derive(bytes)

        if (key != self.pass_hash):
            raise Exception('Passphrase not valid!')

        algorithm = algorithms.TripleDES(key)

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

        file_data = self.user_id + '#' + public_key_pem

        filename = str(self.key_id) + '_public.pem'
        with(open(filename, 'w')) as f:
            f.write(file_data)

    def save_private_key_to_pem(self, passphrase):
        private_key = self.get_private_key(passphrase)

        bytes = passphrase.encode('utf-8')

        private_key_pem_new = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(bytes)
        ).decode('utf-8')

        file_data = self.user_id + '#' + private_key_pem_new

        filename = str(self.key_id) + '_private.pem'
        with(open(filename, 'w')) as f:
            f.write(file_data)