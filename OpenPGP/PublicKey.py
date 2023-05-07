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


class PublicKey:

    def __init__(self, public_key, user_id, derived_from_algorithm):
        self.public_key = public_key
        self.timestamp = datetime.datetime.now()
        self.user_id = user_id
        self.derived_from_algorithm = derived_from_algorithm

        public_key_hex = binascii.hexlify(public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode('utf-8')

        self.key_id = int(public_key_hex, 16) % (2 ** 64)

    @classmethod
    def load_from_file(self, public_key_filename):
        public_key = email = None
        with open(public_key_filename, 'r') as file:
            content = file.read()
            algo, email, public_key_pem = content.split('#')

            public_key = load_pem_public_key(public_key_pem.encode('utf-8'))

        return PublicKey(public_key, email, int(algo))

    def save_public_key_to_pem(self):
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        file_data = self.user_id + '#' + public_key_pem

        filename = str(self.key_id) + '_public.pem'
        with(open(filename, 'w')) as f:
            f.write(file_data)