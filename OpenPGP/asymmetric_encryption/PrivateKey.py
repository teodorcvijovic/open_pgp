import base64
import datetime
import hashlib
import binascii

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import padding
from Crypto.PublicKey import ElGamal

from GlobalVariables import globalVariables
from exceptions.PassphraseNotValid import PassphraseNotValid


class PrivateKey:

    @classmethod
    def load_public_key_from_pem(cls, pem, derived_from_algorithm):
        if derived_from_algorithm == globalVariables.ElGamal:

            p_base64 = pem.split("Parameter-p: ")[1].split("\n")[0]
            g_base64 = pem.split("Parameter-g: ")[1].split("\n")[0]
            y_base64 = pem.split("Public-Value-y: ")[1].split("\n")[0]

            p = int.from_bytes(base64.b64decode(p_base64), 'big')
            g = int.from_bytes(base64.b64decode(g_base64), 'big')
            y = int.from_bytes(base64.b64decode(y_base64), 'big')

            public_key = ElGamal.construct((p, g, y))
        else:
            public_key = load_pem_public_key(pem.encode('utf-8'))

        return public_key

    @classmethod
    def load_private_key_from_pem(cls, pem, derived_from_algorithm, passphrase):
        if derived_from_algorithm == globalVariables.ElGamal:

            x_base64 = pem.split("Private-Value: ")[1].split("\n")[0]
            p_base64 = pem.split("Parameter-p: ")[1].split("\n")[0]
            g_base64 = pem.split("Parameter-g: ")[1].split("\n")[0]
            y_base64 = pem.split("Public-Value-y: ")[1].split("\n")[0]

            x = int.from_bytes(base64.b64decode(x_base64), 'big')
            p = int.from_bytes(base64.b64decode(p_base64), 'big')
            g = int.from_bytes(base64.b64decode(g_base64), 'big')
            y = int.from_bytes(base64.b64decode(y_base64), 'big')

            private_key = ElGamal.construct((p, g, y, x))
        else:
            private_key = load_pem_private_key(pem.encode('utf-8'), passphrase.encode('utf-8'))

        return private_key

    @classmethod
    def convert_public_key_to_pem(cls, public_key, derived_from_algorithm):
        if derived_from_algorithm == globalVariables.ElGamal:
            p = int(public_key.p)
            g = int(public_key.g)
            y = int(public_key.y)

            public_key_pem = f"-----BEGIN PUBLIC KEY-----\n"
            public_key_pem += f"Parameter-p: {base64.b64encode(p.to_bytes((p.bit_length() + 7) // 8, 'big')).decode()}\n"
            public_key_pem += f"Parameter-g: {base64.b64encode(g.to_bytes((g.bit_length() + 7) // 8, 'big')).decode()}\n"
            public_key_pem += f"Public-Value-y: {base64.b64encode(y.to_bytes((y.bit_length() + 7) // 8, 'big')).decode()}\n"
            public_key_pem += f"-----END PUBLIC KEY-----\n"
        else:
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

        return public_key_pem

    @classmethod
    def convert_private_key_to_pem(cls, private_key, derived_from_algorithm, passphrase_bytes = None):
        if derived_from_algorithm == globalVariables.ElGamal:
            p = int(private_key.p)
            g = int(private_key.g)
            y = int(private_key.y)
            x = int(private_key.x)

            private_key_pem = f"-----BEGIN PRIVATE KEY-----\n"
            private_key_pem += f"Private-Value: {base64.b64encode(x.to_bytes((x.bit_length() + 7) // 8, 'big')).decode()}\n"
            private_key_pem += f"Parameter-p: {base64.b64encode(p.to_bytes((p.bit_length() + 7) // 8, 'big')).decode()}\n"
            private_key_pem += f"Parameter-g: {base64.b64encode(g.to_bytes((g.bit_length() + 7) // 8, 'big')).decode()}\n"
            private_key_pem += f"Public-Value-y: {base64.b64encode(y.to_bytes((y.bit_length() + 7) // 8, 'big')).decode()}\n"
            private_key_pem += f"-----END PRIVATE KEY-----\n"
        elif not passphrase_bytes:
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
        else:
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase_bytes)
            ).decode('utf-8')

        return private_key_pem

    @classmethod
    def convert_private_key_to_hex(cls, private_key, derived_from_algorithm, passphrase):
        if derived_from_algorithm == globalVariables.ElGamal:
            p = int(private_key.p)
            g = int(private_key.g)
            y = int(private_key.y)
            x = int(private_key.x)

            key_data = p.to_bytes((p.bit_length() + 7) // 8, byteorder='big') + \
                       g.to_bytes((g.bit_length() + 7) // 8, byteorder='big') + \
                       y.to_bytes((y.bit_length() + 7) // 8, byteorder='big') + \
                       x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')

            private_key_hex = hashlib.sha1(key_data).hexdigest()
        else:
            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('utf-8'))
            )

            private_key_hex = binascii.hexlify(private_key_bytes).decode('utf-8')

        return private_key_hex

    @classmethod
    def convert_public_key_to_hex(cls, public_key, derived_from_algorithm):
        if derived_from_algorithm == globalVariables.ElGamal:
            p = int(public_key.p)
            g = int(public_key.g)
            y = int(public_key.y)

            key_data = p.to_bytes((p.bit_length() + 7) // 8, byteorder='big') + \
                       g.to_bytes((g.bit_length() + 7) // 8, byteorder='big') + \
                       y.to_bytes((y.bit_length() + 7) // 8, byteorder='big')

            public_key_hex = hashlib.sha1(key_data).hexdigest()
        else:
            public_key_hex = binascii.hexlify(public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode('utf-8')

        return public_key_hex

    def __init__(self, public_key, private_key, username, email, passphrase, derived_from_algorithm):
        self.public_key = public_key
        self.timestamp = datetime.datetime.now()
        self.username = username
        self.email = email
        self.derived_from_algorithm = derived_from_algorithm

        # calculating key id
        public_key_hex = self.convert_public_key_to_hex(public_key, derived_from_algorithm)

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
        private_key_pem = self.convert_private_key_to_pem(private_key, derived_from_algorithm).encode('utf-8')

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
            algo = int(algo)

            public_key = PrivateKey.load_public_key_from_pem(public_key_pem, algo)
        with open(private_key_filename, 'r') as file:
            file_content = file.read()
            # pay attention: format of .pem file
            algo, username, email, private_key_pem = file_content.split('#')
            algo = int(algo)

            private_key = PrivateKey.load_private_key_from_pem(private_key_pem, algo, passphrase)

        return PrivateKey(public_key, private_key, username, email, passphrase, algo)

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

        if self.derived_from_algorithm == globalVariables.ElGamal:
            private_key_pem_decoded = private_key_pem.decode('utf-8')

            x_base64 = private_key_pem_decoded.split("Private-Value: ")[1].split("\n")[0]
            p_base64 = private_key_pem_decoded.split("Parameter-p: ")[1].split("\n")[0]
            g_base64 = private_key_pem_decoded.split("Parameter-g: ")[1].split("\n")[0]
            y_base64 = private_key_pem_decoded.split("Public-Value-y: ")[1].split("\n")[0]

            x = int.from_bytes(base64.b64decode(x_base64), 'big')
            p = int.from_bytes(base64.b64decode(p_base64), 'big')
            g = int.from_bytes(base64.b64decode(g_base64), 'big')
            y = int.from_bytes(base64.b64decode(y_base64), 'big')

            private_key = ElGamal.construct((p, g, y, x))
        else:
            private_key = load_pem_private_key(private_key_pem, password=None)

        return private_key

    def save_public_key_to_pem(self):

        public_key_pem = self.convert_public_key_to_pem(self.public_key, self.derived_from_algorithm)

        # pay attention: format of .pem file
        file_data = str(self.derived_from_algorithm) + '#' + self.username + '#' + self.email + '#' + public_key_pem

        filename = f'{globalVariables.PRIVATE_KEYRING_PAIRS}/{str(self.key_id)}_public.pem'
        with(open(filename, 'w')) as f:
            f.write(file_data)

    def save_private_key_to_pem(self, passphrase):
        private_key = self.get_private_key(passphrase)

        passphrase_bytes = passphrase.encode('utf-8')

        private_key_pem_new = self.convert_private_key_to_pem(private_key, self.derived_from_algorithm, passphrase_bytes)

        # pay attention: format of .pem file
        file_data = str(self.derived_from_algorithm) + '#' + self.username + '#' + self.email + '#' + private_key_pem_new

        filename = f'{globalVariables.PRIVATE_KEYRING_PAIRS}/{str(self.key_id)}_private.pem'
        with(open(filename, 'w')) as f:
            f.write(file_data)
