import datetime
import binascii

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from GlobalVariables import globalVariables


class PublicKey:

    def __init__(self, public_key, username, email, derived_from_algorithm):
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

    @classmethod
    def load_from_file(self, public_key_filename):
        with open(public_key_filename, 'r') as file:
            content = file.read()
            algo, username, email, public_key_pem = content.split('#')

            public_key = load_pem_public_key(public_key_pem.encode('utf-8'))

        return PublicKey(public_key, username, email, int(algo))

    def save_public_key_to_pem(self):
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # pay attention: format of .pem file
        file_data = str(self.derived_from_algorithm) + '#' + self.username + '#' + self.email + '#' + public_key_pem

        filename = f'{globalVariables.PUBLIC_KEYRING_PAIRS}/{str(self.key_id)}_public.pem'
        with(open(filename, 'w')) as f:
            f.write(file_data)
