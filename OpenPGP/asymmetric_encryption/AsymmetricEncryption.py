import binascii
import hashlib

from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Signature import PKCS1_v1_5
from Crypto.Util.number import bytes_to_long, long_to_bytes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from Crypto.PublicKey import ElGamal
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP

from GlobalVariables import globalVariables
from asymmetric_encryption.PrivateKey import PrivateKey
from asymmetric_encryption.PublicKey import PublicKey


class AsymmetricEncryption:

    @classmethod
    def asymmetric_key_generate(cls, algorithm, key_length):
        if algorithm == globalVariables.RSA:
            rsa_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_length
            )
            rsa_public_key = rsa_private_key.public_key()

            return rsa_public_key, rsa_private_key

        elif algorithm == globalVariables.DSA:
            dsa_private_key = dsa.generate_private_key(key_size=key_length)
            dsa_public_key = dsa_private_key.public_key()

            return dsa_public_key, dsa_private_key

        elif algorithm == globalVariables.ElGamal:
            rand = Random.new().read

            elgamal_private_key = ElGamal.generate(key_length, rand)
            elgamal_public_key = elgamal_private_key.publickey()

            return elgamal_public_key, elgamal_private_key

    @classmethod
    def encrypt_with_public_key(cls, public_key: PublicKey, data):
        algorithm = public_key.derived_from_algorithm
        encrypted_data = None

        if algorithm == globalVariables.RSA:
            encrypted_data = public_key.public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        elif algorithm == globalVariables.ElGamal:
            p = int(public_key.public_key.p)
            g = int(public_key.public_key.g)
            y = int(public_key.public_key.y)

            k = bytes_to_long(get_random_bytes(32))
            shared_secret = pow(y, k, p)
            data_num = bytes_to_long(data)
            ciphertext_part = pow(g, k, p)
            shared_secret_part = (data_num * shared_secret) % p

            encrypted_data = str(ciphertext_part) + '\n' + str(shared_secret_part)
            encrypted_data = encrypted_data.encode('utf-8')
        elif algorithm == globalVariables.DSA:
            # we use DSA only for signature
            pass

        return encrypted_data

    @classmethod
    def decrypt_with_private_key(cls, private_key: PrivateKey, encrypted_data, passphrase):
        algorithm = private_key.derived_from_algorithm
        decrypted_private_key = private_key.get_private_key(passphrase)
        data = None

        if algorithm == globalVariables.RSA:
            data = decrypted_private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        elif algorithm == globalVariables.ElGamal:
            p = int(private_key.public_key.p)
            x = int(private_key.get_private_key(passphrase).x)
            ciphertext_part, shared_secret_part = encrypted_data.decode('utf-8').split('\n')
            ciphertext_part = int(ciphertext_part)
            shared_secret_part = int(shared_secret_part)
            shared_secret = pow(ciphertext_part, x, p)
            data_num = (shared_secret_part * pow(shared_secret, -1, p)) % p
            data = long_to_bytes(data_num)

        elif algorithm == globalVariables.DSA:
            # we use DSA only for signature
            pass

        return data

    @classmethod
    def sign_with_private_key(cls, private_key: PrivateKey, data, passphrase):
        algorithm = private_key.derived_from_algorithm
        decrypted_private_key = private_key.get_private_key(passphrase)
        signature = None

        if algorithm == globalVariables.RSA:
            signature = private_key.get_private_key(passphrase).sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA1()
            )
            return signature

            # signature = decrypted_private_key.encrypt(
            #     data,
            #     padding.OAEP(
            #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
            #         algorithm=hashes.SHA256(),
            #         label=None
            #     )
            # )
        elif algorithm == globalVariables.DSA:
            signature = decrypted_private_key.sign(
                data,
                hashes.SHA256()
            )
        elif algorithm == globalVariables.ElGamal:
            # we use ElGamal only for encryption
            pass

        return signature

    @classmethod
    def verify_signature(cls, public_key: PublicKey, signature, hash):
        algorithm = public_key.derived_from_algorithm

        if algorithm == globalVariables.RSA:
            try:
                public_key.public_key.verify(
                    signature,
                    hash,
                    padding.PKCS1v15(),
                    hashes.SHA1()
                )
                return True
            except Exception:
                return False

        elif algorithm == globalVariables.DSA:
            try:
                public_key.public_key.verify(
                    signature,
                    hash,
                    hashes.SHA256()
                )
                return True
            except InvalidSignature:
                return False
        elif algorithm == globalVariables.ElGamal:
            # we use ElGamal only for encryption
            pass
