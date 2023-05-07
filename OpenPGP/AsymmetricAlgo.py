from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding
from Crypto.PublicKey import ElGamal
from Crypto import Random
from cryptography.hazmat.primitives import hashes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP

from GlobalVariables import globalVariables


class AsymmetricAlgorithms:

    @classmethod
    def asymmetric_key_generate(cls, name, mail, algorithm, key_length):
        if algorithm == globalVariables.RSA:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_length
            )
            public_key = private_key.public_key()

            return public_key, private_key

        elif algorithm == globalVariables.DSA:
            dsa_private_key = dsa.generate_private_key(key_size=key_length)
            dsa_public_key = dsa_private_key.public_key()

            return dsa_public_key, dsa_private_key

        elif algorithm == globalVariables.ElGamal:
            rand = Random.new().read
            elgamal_key = ElGamal.generate(key_length, rand)

            elgamal_private_key = elgamal_key
            elgamal_public_key = elgamal_key.publickey()

            return elgamal_public_key, elgamal_private_key

    @classmethod
    def encrypt_with_public_key(cls, public_key, data):
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
            cipher = PKCS1_OAEP.new(public_key.public_key)
            encrypted_data = cipher.encrypt(pad(data, 256))

        return encrypted_data

    @classmethod
    def decrypt_with_private_key(cls, private_key, encrypted_data, passphrase):
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
            cipher = PKCS1_OAEP.new(decrypted_private_key)
            data = unpad(cipher.decrypt(encrypted_data), 256)

        return data

    @classmethod
    def sign_with_private_key(cls, private_key, data, passphrase):
        algorithm = private_key.derived_from_algorithm
        decrypted_private_key = private_key.get_private_key(passphrase)
        signature = None

        if algorithm == globalVariables.RSA:
            signature = decrypted_private_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        elif algorithm == globalVariables.DSA:
            signature = decrypted_private_key.sign(
                data,
                hashes.SHA256()
            )

        return signature

    @classmethod
    def verify_signature(cls, public_key, signature, hash):
        algorithm = public_key.derived_from_algorithm

        if algorithm == globalVariables.RSA:
            received_hash = public_key.public_key.decrypt(
                signature,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return received_hash == hash
        elif algorithm == globalVariables.DSA:
            try:
                public_key.verify(
                    signature,
                    hash,
                    hashes.SHA256()
                )
                return True
            except InvalidSignature:
                return False